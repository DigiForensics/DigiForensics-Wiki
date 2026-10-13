---
title: "plist 与偏好设置"
slug: "computer-plist-spotlight-plist"
canonical: "https://www.digiforensics.cn/wiki/computer-plist-spotlight-plist"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:49+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "computer"
space: "计算机取证"
node_path: ["plist 与 Spotlight"]
---

# plist 与偏好设置

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/computer-plist-spotlight-plist)

<a id="section-1"></a>

## 一、概述

macOS 没有注册表。系统与应用配置散落成一个个属性列表文件（plist），这就是它的"注册表等价物"。

`~/Library/Preferences/com.apple.finder.plist` 装的是 Finder 的全部配置，落在的位置相当于 Windows 的 `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer`。

从 Windows 过来的人会连续踩空，两处。

**同一逻辑配置在磁盘上可能是二进制格式。**

| 格式 | 开头 | 可读性 | 常见位置 |
|---|---|---|---|
| **XML** | `<?xml version="1.0" ...?>` | 人可读 | 手写配置、`.strings` 资源 |
| **二进制** | `bplist00`（8 字节魔数） | **不可读** | **绝大多数系统与应用偏好** |
| JSON | —（`plutil` 可输出） | 可读 | 脚本中间格式 |

实测本机 `com.apple.finder.plist` 就是 binary plist。直接 `cat` 或 `grep` 全部无效——本篇要先解决的就是这个。

**同一份偏好可能存在三份副本**，分别落在 `Preferences/com.x.y.plist`、`Preferences/ByHost/com.x.y.<UUID>.plist`、以及内存中的 `cfprefsd` 缓存里。

只查其中一份就下结论，是最常见的误判来源。

**在取证流程中的位置**：本篇是 macOS 取证的**配置层入口**，在完成只读挂载或物理镜像之后、进入应用数据与日志分析之前做。它产出的键值对是后续时间线重建的锚点之一（多数 plist 带 `修改日期` 字段），也是判断"用户改过什么设置"的直接依据。**上游依赖**是 [Mac 取证工件地图](../computer-security/computer-security-security-artifact-map.md)（`~/Library/` 下面有哪些目录、各自装什么）与 [Spotlight 索引与元数据](computer-plist-spotlight-spotlight.md)（用 `mdfind` 按 bundle id 定位偏好文件，比全盘遍历快得多）。`cfprefsd` 缓存的分析属内存取证，参考 [内存证据的可采性与报告](../../memory/memory-artifact/memory-artifact-memory-evidence-and-reporting.md)；改包与权限痕迹走 [Quarantine 与 Gatekeeper](../computer-security/computer-security-quarantine-gatekeeper.md)。

**本篇处理的证据形态**（先确认文件类型，再谈读法）：

| 位置 | 文件名形态 | 取证时要注意 |
|---|---|---|
| `~/Library/Preferences/` | `com.bundle.id.plist` | bundle id 权威值在 `CFBundleIdentifier` 键里，文件名对不上时以键为准 |
| `~/Library/Preferences/ByHost/` | `com.bundle.id.<UUID>.plist` | 同一 bundle 按用户与主机域各存一份，UUID 后缀必须和用户目录对应起来 |
| `~/Library/Managed Preferences/` | 同上命名的 plist | MDM 下发，优先级最高、改不了也删不掉；这里出现的值是管理员设的，不是用户设的 |
| `/Library/Preferences/`、`/Library/Managed Preferences/` | 系统级 plist | 与用户级同名文件并存时，优先级按 macOS 规则，不按修改时间 |
| `~/Library/Containers/<bundle-id>/Data/Library/Preferences/` | 沙盒应用私有 plist | 10.14 之后的应用大量落在这里，不扫等于漏掉整个应用生态 |

二进制 plist 里有几个可用的定长锚点：文件头 8 字节 `bplist00`、文件末尾的 `trailer` 结构（给出偏移表与对象表的位置）、布尔值固定用 `0x08` / `0x09`、`CFString` 的 tag 是 `0x5A`。手工解析时按这些走，不要去猜整体长度，也不要把二进制 plist 当 UTF-8 去 `strings` 后就下结论——中文键值会被切断。

某个应用当前与历史上的配置状态（哪些键被写过）、某项功能是否被显式关闭过、是否有 MDM 或安装配置文件在托管这台机器、同一 bundle 在不同用户下的配置是否不一致。

**键值只说明配置状态，不说明执行事实**——关掉某项功能的键，不等于对应行为没发生；磁盘上也不留"是谁改的"，值可能来自用户点击、应用自动迁移或 MDM 下发。plist 的 `修改日期` 是**最后一次写入该文件的时刻，不是这个键被改动的时间**，批量导入配置会把整个文件的日期刷成同一时刻。ByHost 与主文件不一致时**判断不了哪份更新**，合并规则受 `cfprefsd` 运行时状态影响。阴性结果必须限定范围："在 `~/Library/Preferences/` 与 `ByHost/` 下未发现该 bundle id 的偏好文件"，未扫的 `Managed Preferences`、系统级目录与容器内 plist 属于未覆盖范围。另外 `defaults read` 读的是 `cfprefsd` 合并后的视图，直接改磁盘文件会被它覆盖回去——**改证据的经典死路**。plist 里也不存访问频率这类运行时数据，那些在 `~/Library/Application Support/` 与统一日志里，不要在 plist 里没找到就认为某项功能没被用过。

**读者前提**：需要能分辨 binary plist 与 XML plist 的文件头，并接受"先转成 XML 或用 `plutil` 输出 JSON 再分析"这一步是强制的；需要理解 `cfprefsd` 同时是偏好设置的读路径与合并路径，这是三份副本优先级问题的根源；知道 plist 的键名在不同 macOS 大版本之间会增删迁移，老案例里的键在新系统上可能根本不存在。

---
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 二进制 plist 的结构

plist 本质就是键值对序列化，能装字符串、整数、布尔、日期、数据、数组、字典。二进制格式的布局：

```
偏移 0    8 字节魔数 "bplist00"
偏移 8    对象表（字符串 / 整数 / 字典 / 数组 ...）
末尾-32   Trailer：偏移表位置、对象引用大小、顶层对象偏移、对象总数
更靠末尾  Offset Table：偏移表（★ 与 Trailer 一起在文件尾部）
```

**Trailer 与偏移表在文件末尾**，这与多数格式相反。

后果很直接：文件尾部一旦被截断，前面内容再完整也无法解析——`plutil -lint` 报错往往就指向这里，是判断 plist 是否被截断或篡改的关键检查点。

```bash
xxd -l 8 com.apple.finder.plist
# → 00000000: 6270 6c69 7374 3030  bplist00
file com.apple.finder.plist
# → Apple binary property list
```

<a id="section-4"></a>

### 2.2 `plutil`：取证的主力工具

`plutil` 是 Apple 自带工具，能读两种格式，是离线分析的首选。

| 命令 | 作用 | 取证用途 |
|---|---|---|
| `plutil -p file` | 人类可读打印（`=>` 风格） | 快速查看；**输出格式不稳定，不适合机器解析** |
| `plutil -lint file` | 语法检查 | 验证是否完整、是否被截断 |
| `plutil -convert xml1 -o - file` | 转 XML 输出到 stdout | **把二进制转成可 grep 的文本**（最高频） |
| `plutil -extract <key> <fmt> -o - file` | 提取某个键 | 精确取值，如 `-extract Downloads raw` |
| `plutil -type <key> file` | 取键的类型 | 判断值是数组还是字典 |

> ⚠️ `-convert` 若不给 `-o`，会直接写回原文件。 分析原始证据时**必须用 `-o -`**（stdout）或 `-o /tmp/x.xml`（工作副本），**绝不能原地转换**。

<a id="section-5"></a>

### 2.3 三个存储位置与优先级

```
① ~/Library/Preferences/com.vendor.app.plist              ← 通用配置（应用主配置）
② ~/Library/Preferences/ByHost/com.vendor.app.<UUID>.plist ← 绑定到某台具体机器的配置
③ cfprefsd 守护进程的内存缓存                            ← 运行时视图
```

| 位置 | 何时使用 | 取证含义 |
|---|---|---|
| `Preferences/` | 默认配置 | 应用的主配置来源 |
| `Preferences/ByHost/` | 配置需与机器绑定 | 文件名含**本机 Hardware UUID** |
| `cfprefsd` 缓存 | 运行时 | **命令看到的值未必等于磁盘上的值** |

ByHost 的取证价值首先在文件名结构：

```
com.adobe.headlightscc.00000000-0000-4000-8000-000000000001.plist
└──────── 应用 bundle ID ────────┘ └──── 本机 Hardware UUID ────┘
```

这个 UUID 就是本机 Hardware UUID（`system_profiler SPHardwareDataType` 可查）。上例 UUID 为虚构值；核查时应读取检材的 Hardware UUID，并与 `~/Library/Keychains/` 下的目录名比对。

所以 ByHost 的文件名能直接回答两个问题：

- **确认这些偏好属于本机**，而不是从其他机器拷贝而来
- **发现异常**：若 ByHost 里出现**多个不同 UUID**，说明该用户在这台机器上出现过其他机器的硬件标识，成因需另证，不能直接等同于"导入过其他机器配置"

<a id="section-6"></a>

### 2.4 `defaults` 与磁盘文件的对应关系

| `defaults` 域 | 对应文件 |
|---|---|
| `defaults read <domain>` | `~/Library/Preferences/<domain>.plist` |
| `defaults read NSGlobalDomain` | `~/Library/Preferences/.GlobalPreferences.plist` |
| `defaults read com.apple.finder` | `~/Library/Preferences/com.apple.finder.plist` |
| `defaults -currentHost read <domain>` | 走 `ByHost/` 目录 |

> `defaults write` / `defaults delete` 会修改系统配置，对原始证据绝不可用，取证只用 `defaults read`。

而且它读的是**本机的 `cfprefsd`**，对镜像里的 plist 通常无效——**读镜像文件应直接用 `plutil`**。

<a id="section-7"></a>

### 2.5 `cfprefsd` 对取证的三个具体影响

| 问题 | 说明 | 对策 |
|---|---|---|
| 命令读到的可能是缓存值 | `defaults read` 走 `cfprefsd`，与磁盘 plist 存在时间差 | **以磁盘 plist 为准**，`defaults` 仅交叉参考 |
| 关机不保证立即落盘 | 正常关机流程会刷缓存；**强制断电可能丢失最近的偏好变更** | 缺失的变更不等于没发生设置 |
| 强制断电留下不一致态 | 缓存里的新值未写回，磁盘上是旧值 | **磁盘值是"最后一次成功落盘"的状态** |

**实操结论**：报告里引用偏好设置时必须注明读取方式（`plutil` 读盘还是 `defaults` 读缓存）。

两个值不一致本身就是有价值的发现——可能意味着程序崩溃被强杀、偏好被外部工具直接改盘、或有人手工编辑了 plist。

<a id="section-8"></a>

### 2.6 `.GlobalPreferences.plist` 与 `Mobile Documents`

`.GlobalPreferences.plist` 是 `NSGlobalDomain` 的落盘位置，**以点号开头**，`ls` 不带 `-a` 看不到。实测内容（节选）：

```bash
plutil -p ~/Library/Preferences/.GlobalPreferences.plist | grep -E 'Apple(Locale|Languages|InterfaceStyle)'
#   "AppleInterfaceStyle" => "Dark"
#   "AppleLanguages" => [ "zh-Hans-CN" ]
#   "AppleLocale" => "zh_CN"
```

| 键 | 取证价值 |
|---|---|
| `AppleLanguages` / `AppleLocale` | **用户语言环境**，可佐证"是否本人操作" |
| `AppleInterfaceStyle` | 深色 / 浅色模式 |
| `AppleMeasurementUnits` / `AppleMetricUnits` | 公制 / 英制 |
| `AppleICUForce24HourTime` | 12 / 24 小时制——**影响日志时间显示的解读** |

`~/Library/Mobile Documents/`（macOS 10.15+；10.14 时代在 `~/Mobile Documents/`）是 iCloud Drive 的本地同步目录。

其下 `~apple` 是实际内容区（`~` 是 Apple 用来转义 `/` 的规则，不是文件名的正常字符）。

| 现象 | 正确解释 |
|---|---|
| `~apple/CloudDocs/` | 系统管理的内部结构，不是用户文档 |
| 出现 `.icloud` 后缀文件 | **仅云端有副本、本地未下载**，不代表文件已删除 |
| 文件 mtime 异常新 | iCloud 同步会更新 mtime，**不等于编辑时间** |

---

<a id="section-9"></a>

## 三、操作步骤

<a id="section-10"></a>

### 3.1 第 1 步：确认格式与完整性

```bash
P=~/Library/Preferences/com.vendor.app.plist
file "$P"        # → Apple binary property list 或 XML document
xxd -l 8 "$P"    # bplist00 = 二进制；3c3f786d6c = "<?xml" = XML
plutil -lint "$P"  # → xxx.plist: OK（语法完整）
```

`plutil -lint` 通过只是"文件完整"的必要验证。

报出 `Encountered unknown tag` 之类的错误，说明文件可能被截断或改写——**这本身是重要发现**。

<a id="section-11"></a>

### 3.2 第 2 步：读取与提取

```bash
plutil -p "$P"                                   # 人类可读全量打印
plutil -convert xml1 -o - "$P" | grep -A5 -i 'ServerURL'   # ★ 转 XML 后 grep
plutil -extract Downloads raw -o - "$P"          # 精确提取某个键
plutil -type Downloads "$P"                      # 查看键的类型
```

<a id="section-12"></a>

### 3.3 第 3 步：三位置完整清点

```bash
EV=/mnt/mac-data/Users/liwei
ls -1 "$EV/Library/Preferences"/*.plist 2>/dev/null | wc -l       # ① 通用偏好数量
ls -1 "$EV/Library/Preferences/ByHost"/*.plist 2>/dev/null | wc -l # ② ByHost 偏好
# ③ ByHost 文件名中的 UUID（<bundle-id>.<UUID>.plist）
ls -1 "$EV/Library/Preferences/ByHost"/*.plist 2>/dev/null \
  | sed -E 's|.*/||; s|\.plist$||; s|.*\.||' | sort -u
# → 应只有一个 UUID；出现多个即为拷机 / 迁移痕迹
```

<a id="section-13"></a>

### 3.4 第 4 步：重点应用配置

```bash
# Safari 下载记录（10.14+ 随沙盒迁入容器，两处都查）
find "$EV/Library" -name 'Downloads.plist' -path '*Safari*' 2>/dev/null
plutil -p "$EV/Library/Containers/com.apple.Safari/Data/Library/Safari/Downloads.plist" 2>/dev/null
# 后台项目录（现代登录项，10.14+）
plutil -p /var/db/com.apple.backgroundtaskmanagement/Contents/Info.plist 2>/dev/null | head -40
# 网络配置
plutil -p /mnt/mac-data/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist
# IM 客户端
for f in "$EV"/com.tencent.xinWeChat.plist "$EV"/org.telegram.desktop.plist; do
  [ -f "$f" ] && { echo "--- $f"; plutil -p "$f" | head -20; }
done
```

<a id="section-14"></a>

### 3.5 第 5 步：验证

| 验证对象 | 方法 | 通过标准 |
|---|---|---|
| plist 完整未截断 | `plutil -lint` | 输出 `: OK` |
| 格式判断正确 | `file` + `xxd -l 8` | `bplist00` 或 `<?xml` |
| 转换未改原件 | 转换前后 `shasum` 比对 | 完全一致 |
| ByHost 归属本机 | 与 Hardware UUID 比对 | 相同则归属本机 |
| `defaults` 与 `plutil` 一致 | 两者读同一键 | **不一致本身就是发现** |

```bash
shasum -a 256 "$P" > /tmp/pre.sha256
plutil -convert xml1 -o - "$P" > /tmp/view.xml
shasum -a 256 -c /tmp/pre.sha256      # → OK，证明未改动原文件
```

---
<a id="section-15"></a>

## 四、常见陷阱

★ 标记表示该操作会导致原始检材永久灭失或不可逆改变，执行前必须停下来确认。

<a id="section-16"></a>

### 4.1 格式与完整性

<a id="section-17"></a>

#### 陷阱 1：★ `plutil -convert` 不带 `-o`，原地改写检材里的二进制 plist

**现象**：为把二进制 plist 转成可 grep 的文本，直接执行 `plutil -convert xml1 com.vendor.app.plist`，然后 `grep` 该文件。

**原因**：`-convert` 若不给 `-o`，会直接写回原文件。 分析者习惯把它当成"输出到屏幕"的转换命令（因为 `-p` 确实是打印），而 `-convert` 的默认行为是**原地写入**。加上这一步通常在挂载点内进行，于是检材里的二进制 plist 被替换成了 XML 文件。

**影响**：不可逆，后果严重。

原始 plist 的字节内容、格式（`bplist00` 魔数）、`btime`、哈希全部改变。

这个文件是某个应用配置存在的直接证据——被改写后，它的二进制格式特征消失了，`file` 命令会报 "XML document" 而不再是 "Apple binary property list"，**你无法再证明检材里原本是二进制 plist**。完整性链出现无法解释的断点。

**核查**：转换必须输出到 stdout 或证据目录，绝不原地：

```bash
P="$EV/Library/Preferences/com.vendor.crmclient.plist"
shasum -a 256 "$P" > /tmp/crm.sha256                       # 先固定原文件哈希
plutil -convert xml1 -o - "$P" > /evidence/crmclient.xml  # -o - 输出到 stdout
shasum -a 256 -c /tmp/crm.sha256                          # → OK，证明原文件未变
```

案例第 2 步的顺序是标准范式：先哈希 → 转换到证据目录 → 复校哈希。

三步都做，才在报告里写下"证明转换未改动原文件"这句话。没有复校，这句话就是没有依据的。

<a id="section-18"></a>

#### 陷阱 2：把 `plutil -lint` 通过当成"文件未被改动过"

**现象**：`plutil -lint com.vendor.app.plist` 返回 `OK`，报告写「该配置文件完整，未被篡改」。

**原因**：`-lint` 只做语法检查，验证的是"这个文件能否被解析"，不验证"内容是否被改过"。 攻击者用 `plutil` 或 `defaults` 正常改写偏好后，文件语法完全合法，`-lint` 照样返回 `OK`。`plutil` 是官方工具，它写出的 plist 不会有任何结构问题。

**影响**：把语法完整当内容可信，等于用格式检查器做内容审计。

这个错误很自然——`-lint` 的输出是 "OK"，看起来像一个完整性结论。

**核查**：**`-lint` 的通过只支撑一个命题**：

> 「`plutil -lint` 返回 OK，说明该文件**语法完整、可正常解析**；二进制格式的 Trailer 与偏移表位于文件末尾（见 2.1），语法可解析意味着尾部结构完好，**文件未被截断**。该检查不涉及内容是否被修改。」

内容是否被改过靠另外的证据：文件自身时间戳（`btime`/`mtime`/`ctime`）、与同类配置的取值逻辑是否自洽、应用内写入的业务时间戳（见陷阱 6），以及其它来源的交叉印证。

<a id="section-19"></a>

#### 陷阱 3：plist 被截断时，把解析失败当成"文件不存在"

**现象**：`plutil -convert xml1 -o - some.plist` 报 `Encountered unknown tag` 或 `Invalid object in plist`，分析者认为该配置"未安装"或"已损坏无价值"，从清单里剔除。

**原因**：二进制 plist 的 Trailer 与偏移表在文件末尾——这与多数格式相反。**文件尾部一旦被截断，前面内容再完整也无法解析**，因为解析器需要从尾部读取偏移表位置。`plutil -lint` 报错往往就指向这里。这恰恰说明文件被截断过，是一个重要发现，而不是"文件无效"。

**影响**：把"被截断"读成"不存在"，你会错过一个明确指向数据销毁行为的证据。

而且截断过的文件仍可能保留可读的字符串——通过 `strings` 可以捞回部分键值线索。

**核查**：**解析失败是发现，要记录并深挖**：

```bash
P=some.plist
file "$P"; xxd -l 8 "$P"                          # 魔数是否为 bplist00
ls -l "$P"; stat -f 'btime=%SB mtime=%Sm ctime=%Sc' -t '%Y-%m-%d %H:%M:%S' "$P"
plutil -lint "$P"                                  # 记录完整报错
ls -l "$P"                                         # 文件大小 vs 正常 plist 的大小
strings -n 6 "$P" | head -40                       # 部分键值可能仍可捞回
```

体积显著小于同类 plist + 语法报错 = 截断的强信号。

报告里这么写：「该 plist 大小仅 N 字节（同应用其他 plist 约 M 字节），`plutil -lint` 报尾部结构损坏，判定为**被截断的文件**。尾部 Trailer 与偏移表缺失，主体内容无法解析；`strings` 提取到以下残留键值……」

「被截断」是可辩护的结论，「无法解析所以无价值」不是。

<a id="section-20"></a>

#### 陷阱 4：用 `plutil -p` 的输出做机器解析或跨版本比对

**现象**：把 `plutil -p` 的输出喂给脚本做键值提取，或把两次不同系统上 `plutil -p` 的输出做 diff。

**原因**：`-p` 的输出格式是为人类阅读设计的，2.2 明确标注"输出格式不稳定，不适合机器解析"。 布尔值的呈现方式、数组的换行规则、嵌套结构的缩进都可能随版本变化；输出里还带 `=>` 风格标记而非标准键值分隔。

**影响**：用 `-p` 输出做自动化提取，容易漏键或错位。

跨系统 diff 时会把格式差异误读成配置差异，产生大量假差异，掩盖真正的差异。

**核查**：机器处理一律用 `-convert xml1 -o -` 转成 XML 再处理，XML 是有规范的结构化格式；`-p` 只用于人工快速浏览。需要精确取单键时用 `-extract <key> <fmt> -o -`，需要判类型时用 `-type <key>`：

```bash
plutil -convert xml1 -o - "$P" | grep -A3 -i 'ServerURL'    # ★ 转 XML 后再 grep
plutil -extract Downloads raw -o - "$P"                     # 精确取值
plutil -type Downloads "$P"                                 # 判断值是数组还是字典
```

<a id="section-21"></a>

### 4.2 读取方式与配置来源

<a id="section-22"></a>

#### 陷阱 5：用 `defaults read` 读镜像里的 plist，拿到的是分析机的值

**现象**：在分析机上执行 `defaults read com.vendor.crmclient` 想看镜像里的配置，输出为空或返回"域不存在"；或者更糟，**返回了分析机上同名域的真实配置**，被写进报告。

**原因**：`defaults` 读的是本机的 `cfprefsd` 守护进程，对镜像里的 plist 通常无效。 两条路径都会出错：无同名域时返回空/报错，容易被读成"检材里没有该配置"；分析机恰好装过同名应用时**返回的是分析机的真实值**，格式完全正常、看起来像有效证据。

**影响**：后者更危险：报告里会出现一份完全属于分析机的配置数据，包括服务器地址、账号 ID。委托方拿这些值去核实会发现完全对不上，而错误已经写进了交付材料。

`defaults write` / `defaults delete` 更严重：它们会修改系统配置，对原始证据绝不可用。

**核查**：读镜像文件一律直接用 `plutil`，`defaults` 只在原机上做交叉参考：

```bash
plutil -convert xml1 -o - /mnt/mac-data/Users/<user>/Library/Preferences/<domain>.plist
```

同时，`defaults write` / `defaults delete` 在取证环境里应当被视为禁止操作——它们不只是"读了镜像"，还会改动分析机，或在误配时改动挂载点。

报告里凡引用偏好设置，必须注明读取方式（`plutil` 读盘还是 `defaults` 读缓存），这个标注本身就是防止误引用的护栏。

<a id="section-23"></a>

#### 陷阱 6：把文件 `mtime` 当作"配置生效时间"

**现象**：`com.vendor.crmclient.plist` 的 `mtime` 是 2024-09-17，报告写「该配置于 9 月 17 日被设置，账号 `WF-2287` 于该日启用」。

**原因**：文件 `mtime` 是"偏好文件最后一次被写入的时间"，不等于"某个具体键的设置时间"。 任何一次 `defaults write` 都会推进整个文件的 `mtime`，无论改的是哪个键。应用每次启动也可能重写整个偏好。一个 plist 里有几十个键，它们各自的设置时间在文件层面完全无法区分。

**影响**：把所有键的时间锚定到同一个 `mtime`，会让时间线失真。

而 plist 里确实存在可信的键级时间——应用自己写入的日期类型字段（见陷阱 7）。放弃它而用 `mtime` 是白白丢掉了更好的证据。

**核查**：键级时间优先用应用自己写的业务时间字段，文件时间只作参考：

```bash
stat -f 'btime=%SB  mtime=%Sm  ctime=%Sc' -t '%Y-%m-%d %H:%M:%S' "$P"
plutil -convert xml1 -o - "$P" | grep -B1 -A1 -iE 'SyncTime|LoginTime|LastUsed|CreatedAt'
```

报告分两层写：**文件层**（`btime`/`mtime`/`ctime` 各是什么、说明"该文件最后一次被写入"）+ **键层**（`LastSyncTime` = 2024-09-17T09:22:41Z，说明"该应用记录的最后同步时刻"）。

**不要把文件时间说成键的设置时间。**

<a id="section-24"></a>

#### 陷阱 7：忽略 plist 里应用自己写入的日期类型字段

**现象**：plist 里明明有 `<key>LastSyncTime</key><date>2024-09-17T09:22:41Z</date>`，分析者只看了文件系统时间戳，报告里没提这个字段。

**原因**：应用按业务逻辑写入的日期类型字段，可信度高于文件系统 `mtime`。 原因是它由应用在特定业务动作发生时主动记录，**不随拷贝、解压等文件搬运动作改变**——`mtime` 会随这些操作变化，业务时间不会。反过来，一个被 `cp -p` 保留 `mtime` 的文件，`mtime` 可能完全失真。

**影响**：忽略了这类字段，就丢掉了本篇最可靠的时间锚点，反而去依赖容易被污染的 `mtime`。

案例第 2 步明确指出这一点：「`LastSyncTime` 是应用自己写入的日期类型，不是文件系统时间戳——这类应用内时间戳可信度高于 mtime，因为它按业务逻辑记录，不受拷贝、解压影响。」

**核查**：转 XML 后系统性搜出所有日期类型字段，作为时间线的优先锚点：

```bash
plutil -convert xml1 -o - "$P" | grep -B1 '<date>' 
# <key>LastSyncTime</key>  <date>2024-09-17T09:22:41Z</date>
```

注意这类字段的时间是 **UTC**（以 `Z` 结尾），与本机本地时间差一个时区——案例里 09:22:41Z 对应本地 17:22:41 (+08:00)。**换算必须在报告里写出来**，否则与其它本地时间证据对不上。

<a id="section-25"></a>

#### 陷阱 8：只查 `Preferences/`，漏掉 `ByHost/` 目录

**现象**：清点了 486 个 `Preferences/*.plist`，得出"已全面排查该用户偏好设置"，报告结论完备；却完全没看 `Preferences/ByHost/` 里的 37 个文件。

**原因**：2.3 讲了三个存储位置，ByHost 承载"绑定到某台具体机器"的配置。 它的文件名结构是 `com.adobe.headlightscc.00000000-0000-4000-8000-000000000001.plist`——应用 bundle ID + 本机 Hardware UUID。凡是"与硬件相关"的偏好（显示器配置、外设、音量、色彩配置、部分授权）都落在这里。只看 `Preferences/` 会漏掉整整一类配置。

**影响**：「已全面排查」的表述被证伪——只要对方指出 ByHost 里有相关内容，你的排除结论就失效了。

**核查**：三个位置都要清点，且 ByHost 的文件名要单独做 UUID 提取分析：

```bash
ls -1 "$EV/Library/Preferences/ByHost"/*.plist 2>/dev/null | wc -l
ls -1 "$EV/Library/Preferences/ByHost"/*.plist 2>/dev/null \
  | sed -E 's|.*/||; s|\.plist$||; s|.*\.||' | sort -u     # 提取全部 UUID
system_profiler SPHardwareDataType 2>/dev/null | grep -i 'Hardware UUID'
```

提取出的 UUID 集合与本机 Hardware UUID 逐一比对，出现多个不同 UUID 本身就是一条独立发现：**该用户目录里存在其他机器的硬件标识**，其成因（外接显示器迁移、系统迁移助手、配置拷贝）需另证。案例第 3 步正是这样发现异常的。

<a id="section-26"></a>

### 4.3 键值语义

<a id="section-27"></a>

#### 陷阱 9：把 `~/Library/Mobile Documents/` 里的异常当作用户行为

**现象**：`Mobile Documents` 下出现 `.icloud` 后缀文件，报告写「该文件已被删除」；或看到 `mtime` 异常新的文件，写「该文件在近期被编辑」。

**原因**：**2.6 的对照表列了三种系统行为的正确解释**：① `~apple/CloudDocs/` 是系统管理的内部结构，**不是用户文档**（`~` 是 Apple 用来转义 `/` 的规则，不是文件名的正常字符）；② `.icloud` 后缀表示"仅云端有副本、本地未下载"，不代表文件已删除；③ iCloud 同步会更新 `mtime`，文件 mtime 异常新不等于编辑时间。

**影响**：这三条都会产出直接错误的结论。

"文件已删除"会让调查去找删除者，"mtime 新 = 刚编辑"会让调查去找编辑者——两个方向都可能指向错误的人。

而 `Mobile Documents` 下的路径如果没有正确转义，会被读成不存在的目录名。

**核查**：**先判断路径归属，再判断文件状态**：

```bash
ls -la "$EV/Library/Mobile Documents/~apple/CloudDocs/" 2>/dev/null   # 系统内部结构
find "$EV/Library/Mobile Documents/" -name '*.icloud' 2>/dev/null    # 仅云端副本
```

三者分开表述：`~apple/CloudDocs/` 下的内容不作为用户文档证据；`.icloud` 文件表示该文件在云端有副本、本地未下载，不能作为删除证据；iCloud 卷的 `mtime` 不作为编辑时间依据，编辑时间需另证（应用内业务时间字段、同步日志、或云端副本的对比）。

注意 macOS 10.15 起路径是 `~/Library/Mobile Documents/`，10.14 时代在 `~/Mobile Documents/`，两处都要看。

<a id="section-28"></a>

### 4.4 结论表述

<a id="section-29"></a>

#### 陷阱 10：把"偏好里有服务器地址和账号"直接写成"该机曾成功登录该系统"

**现象**：从 `com.vendor.crmclient.plist` 提取到 `ServerHost = crm.partner-portal.example`、`AccountID = WF-2287`，报告写「该机曾登录并使用客户管理系统」。

**原因**：配置里存在凭据/地址，证明的是"该机被配置为可使用这个系统"，不证明"曾实际登录成功"。 中间隔着若干环节：配置可能是批量分发的模板、可能是他人帮助配置、可能登录从未成功（口令过期、账号停用、网络不通）。`AccountID` 甚至可能只是本地缓存的显示名，服务端是否有这个账号要另外确认。

**影响**：这是从"能力/配置"跳到"行为/事实"的跳跃，与包管理器篇里"装了工具 ≠ 用过工具"是同一类错误。它给出的结论需要举证，而偏好文件完全无法支撑——委托方可能会据此认定"该员工确实访问了客户系统"，进而做出不当的解雇或法律决定。

**核查**：**结论分层，把配置证据与访问证据分开**：

> 「偏好文件 `com.vendor.crmclient.plist` 中含服务器地址 `crm.partner-portal.example` 与账号标识 `WF-2287`（`LastSyncTime` 记录的最后同步时间为 2024-09-17T09:22:41Z）。该证据证明本机被配置为可使用该系统，不证明曾成功登录或实际访问。实际访问需另寻证据：本地缓存的会话数据、浏览/网络痕迹、服务端日志、该应用的其它本地工件。」

`LastSyncTime` 是个特殊的例外——**它记录的是一次实际发生的同步动作**，比单纯的配置存在性强一档。

但也要注意它只证明"客户端视角发生过同步"，仍需服务端记录确认。

<a id="section-30"></a>

## 五、案例示例

<a id="section-31"></a>

### 5.1 ByHost 下的异机 UUID 配置与拷贝时间锚定

**场景**

MacBook Air（Apple Silicon M1，macOS 14，FileVault 已解锁）。委托方为外贸公司，需查明"该机是否配置过某客户管理系统的账号与服务器地址"。检材 `DigiForensics.dd`（raw APFS 容器镜像）。

ByHost 目录的 UUID 后缀是个不需要解析内容的判别器——先看后缀是否等于本机 Hardware UUID，再决定要不要进内容。

**处置过程**

第 1 步，定位与格式确认：

```bash
EV=/mnt/mac-data/Users/wangfang
ls -1 "$EV/Library/Preferences"/*.plist 2>/dev/null | wc -l         # → 486 个通用偏好
ls -1 "$EV/Library/Preferences/ByHost"/*.plist 2>/dev/null | wc -l   # → 37 个 ByHost
ls -1 "$EV/Library/Preferences" | grep -i crm                        # → com.vendor.crmclient.plist

P="$EV/Library/Preferences/com.vendor.crmclient.plist"
plutil -lint "$P"     # → com.vendor.crmclient.plist: OK   ✓ 未截断
```

`plutil -lint` 是必须的第一步：plist 是二进制格式，被截断的 plist 无法解析。

不先验证格式完整性，后面 `plutil -convert` 失败会让人误以为是格式转换问题。

第 2 步，提取配置（`-o -` 保证输出到 stdout，不改动原文件）：

```bash
shasum -a 256 "$P" > /tmp/crm.sha256
plutil -convert xml1 -o - "$P" > /evidence/crmclient.xml
shasum -a 256 -c /tmp/crm.sha256     # → OK，证明转换未改动原文件 ✓
grep -E -A2 'ServerHost|AccountID|LastSyncTime' /evidence/crmclient.xml
```

```xml
<key>ServerHost</key>   <string>crm.partner-portal.example</string>
<key>AccountID</key>    <string>WF-2287</string>
<key>LastSyncTime</key> <date>2024-09-17T09:22:41Z</date>
<key>AutoUpload</key>   <true/>
```

`LastSyncTime` 是应用自己写入的日期类型，不是文件系统时间戳，可信度与成立条件见陷阱 7。

第 3 步，ByHost UUID 交叉验证（**本案的关键发现**）：

```bash
# 本机 Hardware UUID
ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'
# 7A1E4C09-2B38-4D15-9E77-0C3F8B2A6D41

# ByHost 下的全部 UUID
ls -1 "$EV/Library/Preferences/ByHost"/*.plist | sed -E 's|.*/||; s|\.plist$||; s|.*\.||' | sort -u
# 7A1E4C09-2B38-4D15-9E77-0C3F8B2A6D41     ← 本机
# 3D6B9F12-58A4-4E27-B0C9-5F81D47E3A2B     ← ★ 另一个 UUID
```

37 个 ByHost 文件里出现了属于另一台主机的 UUID。

第 4 步，看那个异机 UUID 对应的内容：

```bash
BH="$EV/Library/Preferences/ByHost/com.vendor.crmclient.3D6B9F12-58A4-4E27-B0C9-5F81D47E3A2B.plist"
plutil -convert xml1 -o - "$BH" | grep -E -A1 'ServerHost|AccountID'
# <key>ServerHost</key>   <string>crm-internal.example.net</string>     ← 与主配置不同的域名
# <key>AccountID</key>    <string>WF-1104</string>                     ← 与 WF-2287 不同账号
```

不仅来源机器不同，`ServerHost` 与 `AccountID` 也都不同——不是同一份配置被改了个位置，而是**另一个环境的配置**。

第 5 步，时间线锚定（**用 APFS btime，不用 mtime**）：

```bash
stat -f 'btime=%SB  mtime=%Sm  %N' -t '%Y-%m-%d %H:%M:%S' "$P"
# btime=2024-06-11 10:03:22   mtime=2024-09-17 09:22:44

stat -f 'btime=%SB  mtime=%Sm  %N' -t '%Y-%m-%d %H:%M:%S' "$BH"
# btime=2024-08-03 16:44:51   mtime=2024-08-03 16:44:51   ← 两者相同 = 一次性拷贝
```

ByHost 文件的 btime 与 mtime 完全相同，与"新建后只写一次、之后未修改"的形态一致，是拷贝的信号之一。

而主配置的 `mtime`（09:22:44）比应用自记的 `LastSyncTime`（09:22:41）**晚 3 秒**——两个独立来源相互印证。

第 6 步，全局偏好与 iCloud 检查：

```bash
plutil -p "$EV/Library/Preferences/.GlobalPreferences.plist" | grep -E 'AppleLocale|AppleICUForce24'
# AppleLocale = "zh_CN"；AppleICUForce24HourTime = true
ls -1 "$EV/Library/Mobile Documents/~apple/" 2>/dev/null | head -3
# 2024年报价单.xlsx   客户合同   产品图册
ls -1 "$EV/Library/Mobile Documents/" 2>/dev/null | grep -c '\.icloud'   # → 3
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 该机曾配置 CRM 系统，账号 WF-2287 | plist 中 `ServerHost` + `AccountID` | 强 |
| 最后同步时间 2024-09-17 09:22:41 | 应用内 `LastSyncTime` + 文件 mtime（差 3 秒） | 强（双源印证） |
| ByHost 下存在属于**另一台主机**的配置 | UUID 与本机不符 + `ServerHost`/`AccountID` 均不同 + btime=mtime 一致 | 强 |
| 拷贝发生于 2024-08-03 16:44:51 | 该 ByHost 文件的 `btime`/`mtime` | 中（**拷贝者身份不可确定**） |
| 3 个文件仅云端有副本 | `.icloud` 占位文件存在 | 中（**不能推断"文件已丢失"**） |

**误判对照**

本案最容易得出的错误结论是「ByHost 下存在一份 `com.vendor.crmclient` 配置，指向另一个服务器 `crm-internal.example.net`，账号 `WF-1104`，说明用户 `wangfang` 登录了另一个客户管理系统的账号 WF-1104，即存在账号混用/越权访问行为」。

正确判据是 ByHost 目录的 UUID 后缀语义，两点：

1. ByHost 的命名规则是 `<bundle-id>.<HardwareUUID>.plist`。这个后缀是 macOS 用来区分"本机生成的偏好"与"从其他机器同步过来的偏好" 的机制——`cfprefsd` 在把偏好写入 ByHost 时会带上本机的 Hardware UUID。因此一个不是本机 UUID 的文件名，本身就意味着"这份文件不是本机 cfprefsd 写出来的"。 本案 UUID `3D6B9F12-...` 与本机 `7A1E4C09-...` 不符，这是**结构性判据，不需要看内容**。
2. `btime` = `mtime`（2024-08-03 16:44:51）是拷贝的一个信号：偏好文件被本机 `cfprefsd` 改写时，`mtime` 会随写入推进，而 `btime` 不变；两者相等说明自创建起 `mtime` 未被推进过，与一次性落盘吻合，但同一个值也可能来自保留时间戳的复制手段，需与 UUID 不符和内容差异同时成立才成立。

**按错误判据走的代价**：会得出一个指向具体越权行为的指控（"登录了 WF-1104 账号"），而实际上该账号从未在本机登录过。后果有两层：

- 委托方会追查 `WF-1104` 这个账号在 CRM 系统侧的登录记录，发现该账号从未从这台机器发起登录，从而对整份报告的可信度产生怀疑；
- 更实际的是，会误判 `wangfang` 的行为性质——"登录他人账号"与"拷贝了他人的配置文件"是完全不同的两件事，前者是主动的越权，后者可能是帮同事排查问题时顺手拷贝的。定性错误会直接影响人事处置。

第二个易错点：因为主配置的 `AccountID` 是 WF-2287、异机 ByHost 的 `AccountID` 是 WF-1104，就推断"这台机器同时使用了两个账号"。 正确判据是主配置（`~/Library/Preferences/com.vendor.crmclient.plist`）与 ByHost 是两个不同用途的位置：

- **主配置**是"应用级共享配置"，`AccountID` 记录当前登录的账号（WF-2287），由 `cfprefsd` 正常维护；
- **ByHost** 存的是"按主机区分的差异化设置"（如窗口位置、面板状态），**正常情况下只会存在本机 UUID 那一份**。

ByHost 里出现异机 UUID 的文件，不是"第二个账号被使用了"，而是"有一份不属于本机的文件被放到了这里"。 这份文件里的 `AccountID: WF-1104` 是**拷贝过来时携带的旧值**，不代表本机当前状态，更不代表本机曾以该账号登录过。

**准确表述**：「`~/Library/Preferences/ByHost/` 下存在一份 UUID 为 `3D6B9F12-...`（非本机）的 CRM 偏好文件，内容含 `AccountID: WF-1104`。该文件系 2024-08-03 16:44:51 一次性拷贝至本机，本案无任何证据表明 WF-1104 曾在本机登录或被使用。」

---

<a id="section-32"></a>

### 5.2 偏好域归属的账号归属与删除痕迹

**场景**

同系列 MacBook（Apple Silicon，macOS 14），委托方在发现拷机配置后追问"是否存在把配置拷给别人（外发）的行为"。检材 `DigiForensics.dd`（APFS 容器镜像）。

`ByHost/` 目录自身的时间戳变化能独立标记"该目录发生过增删"。

**处置过程**

第 1 步，先看 ByHost 目录自身的三个时间（**目录时间戳是目录项变动的记账**）：

```bash
BH=/mnt/mac-data/Users/wangfang/Library/Preferences/ByHost
stat -f 'btime=%SB  mtime=%Sm  ctime=%Sc  %N' -t '%Y-%m-%d %H:%M:%S' "$BH"
# btime=2024-06-11 10:03:22   mtime=2024-09-17 09:22:44   ctime=2024-09-17 09:22:44
```

目录 mtime 与主配置的 mtime 完全一致（09:22:44），说明 09:17 那次同步时 ByHost 目录里有文件被写过。

但这只说明"目录项有变动"，往哪变还不知道。

第 2 步，列出全部 ByHost 文件并按时间排序（**找时间簇**）：

```bash
ls -lt "$BH"/*.plist | head -8
# -rw-r--r-- 1 wangfang staff  882 2024-09-17 09:22:44 com.vendor.crmclient.7A1E4C09-....plist
# -rw-r--r-- 1 wangfang staff  640 2024-08-03 16:44:51 com.vendor.crmclient.3D6B9F12-....plist  ← ★
# -rw-r--r-- 1 wangfang staff  1024 2024-06-11 10:03:22 com.apple.finder.7A1E4C09-....plist
# ...
# → 只有 1 个文件是 2024-08-03 的，形成孤立时间簇
```

第 3 步，**判定"拷入"还是"拷出"——这是本案的核心**：

```bash
# 拷入的特征：新文件出现 → 目录 mtime 前进
# 拷出的特征：文件消失 → 目录 mtime 也前进
# 关键：本机 UUID 的文件全部健在，异机 UUID 的文件也健在
ls -1 "$BH"/*.plist | sed -E 's|.*/||' | grep -c '7A1E4C09'    # 36 个本机
ls -1 "$BH"/*.plist | sed -E 's|.*/||' | grep -c '3D6B9F12'    # 1 个异机
# → 37 个文件全在，ByHost 目录当前没有任何文件缺失的迹象
```

第 4 步，查是否有"复制出去"的独立证据（**U 盘/外接盘/压缩包**）：

```bash
# 外接卷挂载记录
ls -1 /Volumes/ 2>/dev/null
# EVIDENCE-USB   ← 现场另扣押的 U 盘

# 拷贝类痕迹：查找以配置为源生成的压缩包/备份
mdfind -onlyin /mnt/mac-data/Users/wangfang \
  "kMDItemFSName == '*.zip' || kMDItemFSName == '*.dmg' || kMDItemFSName == '*.tar.gz'" 2>/dev/null
# /Users/wangfang/Downloads/prefs-backup-20240803.zip    ← ★ 与拷贝同日
```

第 5 步，验证压缩包内容（**这是决定性的一步**）：

```bash
unzip -l /mnt/mac-data/Users/wangfang/Downloads/prefs-backup-20240803.zip
#   6 files, 1.2 MB
#   ByHost/com.vendor.crmclient.3D6B9F12-58A4-4E27-B0C9-5F81D47E3A2B.plist   640
#   ByHost/com.apple.finder.7A1E4C09-2B38-4D15-9E77-0C3F8B2A6D41.plist          1024
#   com.vendor.crmclient.plist                                                 512
#   ...
# → ★ 包内含异机 UUID 的那份 → 拷贝是"取"（从别处拿），不是"送"（给出去）

stat -f 'btime=%SB  mtime=%Sm' -t '%Y-%m-%d %H:%M:%S' \
  /mnt/mac-data/Users/wangfang/Downloads/prefs-backup-20240803.zip
# btime=2024-08-03 17:02:08   mtime=2024-08-03 17:02:08
```

第 6 步，交叉 Quarantine（**该 zip 是否来自浏览器**）：

```bash
xattr -p com.apple.quarantine /mnt/mac-data/Users/wangfang/Downloads/prefs-backup-20240803.zip 2>/dev/null
# （无输出）→ 无 Quarantine 标记
# → 意味着不是通过浏览器/Safari/Chrome 下载的，是本机或挂载卷上直接生成/复制的
```

**结论**

- **配置是"拷入"而非"拷出"**，判据是决定性的：压缩包 `prefs-backup-20240803.zip`（btime/mtime 均 2024-08-03 17:02:08）**包内含那份异机 UUID 的 ByHost 文件**。文件从压缩包进入本机，方向只能是**从别处取得**。而 ByHost 目录内 **37 个文件全部健在**（36 本机 + 1 异机），**目录内无缺失项**，不支持"拷出"。
- 完整时序（时间锚点强度高，四个来源吻合）：
  - **16:44:51** — 异机 ByHost 配置文件 `btime`=`mtime`（拷入本机）
  - **17:02:08** — 备份压缩包 `btime`=`mtime`（生成压缩包，与上一事件相隔 17 分 17 秒）
  - 两者在同一天、同一小时内，**构成一次完整的"取得配置 + 打包备份"动作序列**。
- **压缩包无 Quarantine 标记**，说明它不是浏览器下载路径产生的。xattr 可被移除或随复制丢失，因此该属性只支撑"与浏览器下载路径不一致"，不足以单独确定它的生成方式。
- 对委托方问题的准确答复：「该机上的异机配置来自一次外部取得，随后被本地打包为 `prefs-backup-20240803.zip` 留存。本案无证据表明 `wangfang` 将本机配置复制给第三方——ByHost 目录无文件缺失，压缩包内容指向"取"而非"送"。该动作的性质（帮同事排查 vs 违规留存他人配置）需结合 `WF-1104` 账户归属与业务授权情况判断，取证手段无法确定动机。」

**误判对照**

本案最容易得出的错误结论是「`wangfang` 的 Downloads 里有一个包含所有 ByHost 配置的压缩包，且该包生成于拷贝当天，说明她在收集他人机器的配置信息并打包留存，这是数据外流的直接证据」。

**正确判据是压缩包内容的"方向性"，三点**：

1. **看包内文件的来源标记**。`unzip -l` 显示包内含 `com.vendor.crmclient.3D6B9F12-....plist`——UUID 后缀是 `3D6B9F12`（另一台机器）。如果这是"打包外传"，包里应该是**本机 UUID `7A1E4C09`** 的文件（那才是她机器上的东西）。包里装着别台机器的配置，说明这个包是从别处收集来的，不是从这里发出去的。
2. **看本机侧的存量是否减少**。ByHost 目录 37 个文件**一个不少**（36 本机 + 1 异机）。"拷出"必然导致本机某份文件消失或被移走，**目录内无缺失项就直接排除了这个方向**。目录 mtime 前进只能说明"目录项有变动"，变动可以是"新增"也可以是"删除"，必须结合存量清点才能定向。
3. **看 Quarantine 标记**。该 zip 无 `com.apple.quarantine` 扩展属性，说明它不是浏览器下载的。**一个真正的外发动作通常伴随网络侧证据**（上传、发邮件、拷贝到 U 盘），而本案既无 Quarantine、也无外接卷写入痕迹（`EVIDENCE-USB` 需单独核查是否有写入记录），**网络与外发两条路径均无证据**。

**按错误判据走的代价**：会得出"数据外流已成立"的定性结论，并据此建议对 `wangfang` 启动纪律处分甚至报警。

而正确结论是"一次外部配置取得 + 本地备份"。两者的法律性质与后果差异极大——前者是数据泄露，后者可能只是同事间的技术协助。

取证报告里这种方向性错误最不可接受，因为它直接指向对具体自然人的不当定性。

第二个易错点：因为 16:44:51（拷入配置）与 17:02:08（生成压缩包）相隔仅 17 分钟，就推断"这两个动作是同一批操作"。 正确判据是两个时间戳分别来自不同文件，且各自只说明"该文件被写入的时刻"：

- 16:44:51 是**异机 ByHost 文件**的 `btime`=`mtime`，说明这份配置此刻进入本机；
- 17:02:08 是**压缩包**的 `btime`=`mtime`，说明压缩包此刻生成。

17 分钟的间隔是"时间接近"，不是"因果证明"。严格说，正确的表述是"两次文件写入事件在时间上高度接近，构成可能相关的序列"；要确认因果，需要证据表明压缩包的内容来自 16:44 拷入的那份文件——本案恰恰正是通过 `unzip -l` 看到了包内含该文件，才建立了内容层面的联系。只有时间接近而无内容验证，不能定性为"同一操作"。

---

<a id="section-33"></a>

### 5.3 反例：移动优先偏好与 CFPreferences 守护进程缓存

**场景**

某台 MacBook Pro（Intel，macOS 13），委托方询问"该机是否启用了文件自动上传到云盘"。检材 `DigiForensics.dd`（APFS 容器镜像），委托方在初步检查中看到偏好里有 `AutoUpload = true` 与 `UploadOnWifiOnly = false`，怀疑"文件会在无网络保护的情况下自动上传"。

这类"看起来是危险开关"的键，真实语义往往与字面理解相反；而 CFPreferences 的缓存机制又会制造"值不可信"的假象。

**处置过程**

第 1 步，取出偏好并看它的完整键集（**不能只看单个键**）：

```bash
P=/mnt/mac-data/Users/lifang/Library/Preferences/com.vendor.backupclient.plist
plutil -lint "$P"
# com.vendor.backupclient.plist: OK
plutil -convert json -o - "$P" | python3 -m json.tool
```

```json
{
  "AccountID": "LF-3390",
  "AutoUpload": true,
  "AutoUploadScope": "manual-selection-only",
  "ExcludePatterns": ["**/.git", "**/node_modules"],
  "LastSyncTime": "2025-02-11T08:14:22Z",
  "LastSyncDirection": "download",
  "UploadOnWifiOnly": false,
  "AutoUploadEnabledByUser": false,
  "ServerHost": "sync.vendor-backup.example"
}
```

**四个键共同决定语义**：`AutoUpload: true` 但 `AutoUploadScope: manual-selection-only` 且 `AutoUploadEnabledByUser: false`。

第 2 步，查应用实际行为（**偏好只是配置，不是行为**）：

```bash
/usr/bin/log show --directory /mnt/mac-data/var/db/diagnostics \
  --start "2025-02-01" --end "2025-02-28" --style compact \
  --predicate 'process == "backupclient"' | grep -iE 'upload|download|skip' | tail -6
# 2025-02-11 08:14:22.881  backupclient[3301]: sync start direction=download
# 2025-02-11 08:16:40.220  backupclient[3301]: 3 files downloaded
# 2025-02-14 20:02:11.004  backupclient[3301]: sync start direction=download
# 2025-02-14 20:04:55.771  backupclient[3301]: 1 file downloaded
# 2025-02-19 09:33:20.118  backupclient[3301]: auto-upload skipped (scope=manual-selection-only)
# → ★ 关键：auto-upload 确实被调用，但被 scope 规则跳过
# → 所有实际 sync 均为 download 方向，零 upload
```

第 3 步，统计整个日志期的方向（**这是行为层面的定案**）：

```bash
/usr/bin/log show --directory /mnt/mac-data/var/db/diagnostics \
  --start "2024-11-01" --end "2025-02-28" --style compact \
  --predicate 'process == "backupclient" AND eventMessage CONTAINS "sync start"' \
  | grep -oE 'direction=[a-z]+' | sort | uniq -c
#    47 direction=download
#     0 direction=upload
# → 三个月 47 次同步，全部为下载，零上传
```

第 4 步，**处理 CFPreferences 缓存问题**（`cfprefsd` 会缓存偏好，磁盘上的 plist 可能滞后）：

```bash
# 确认缓存文件与磁盘 plist 是否一致
ls -la /mnt/mac-data/var/folders/*/*/C/com.apple.cfprefsd.plist 2>/dev/null
# -rw-r--r-- 1 lifang staff 24576 2025-02-11 08:14:23 /var/folders/xx/.../C/com.vendor.backupclient.plist

# 提取缓存中的值并与磁盘 plist 比对
plutil -convert json -o - /mnt/mac-data/var/folders/*/*/C/com.vendor.backupclient.plist 2>/dev/null \
  | python3 -c "import json,sys;d=json.load(sys.stdin);print({k:d.get(k) for k in ('AutoUpload','AutoUploadScope','LastSyncDirection')})"
# {'AutoUpload': True, 'AutoUploadScope': 'manual-selection-only', 'LastSyncDirection': 'download'}

# 两者是否一致
diff <(plutil -convert json -o - "$P") \
     <(plutil -convert json -o - /mnt/mac-data/var/folders/*/*/C/com.vendor.backupclient.plist 2>/dev/null) \
  && echo "缓存与磁盘一致" || echo "★ 缓存与磁盘不一致，需以两者中较新者为准"
```

第 5 步，检查容器/沙盒内的其他副本（**同一偏好可能有多份**）：

```bash
find /mnt/mac-data -name 'com.vendor.backupclient.plist' 2>/dev/null
# /Users/lifang/Library/Preferences/com.vendor.backupclient.plist                       ← 用户级
# /Users/lifang/Library/Containers/com.vendor.backupclient/Data/Library/Preferences/  ← 沙盒副本
# /Users/lifang/Library/Group Containers/*/Preferences/                                ← 共享容器副本
for f in $(find /mnt/mac-data -name 'com.vendor.backupclient.plist'); do
  printf '%-90s mtime=%s\
' "$f" "$(stat -f '%Sm' -t '%Y-%m-%d %H:%M' "$f")"
done | sort -k2
# 用户级     mtime=2025-02-11 08:14:23
# 沙盒副本   mtime=2025-02-11 08:14:24
# 共享容器   mtime=2025-01-08 11:22:07   ← ★ 明显落后
```

**结论**

- `AutoUpload: true` 不等于"文件会自动上传"。完整键集显示 `AutoUploadScope: manual-selection-only`（仅限用户手动选中的文件）、`AutoUploadEnabledByUser: false`（该开关未被用户启用）。这三个键的组合语义是"自动上传功能存在但受限于手动选择范围"，单看 `AutoUpload: true` 会严重误读。
- **行为层面零上传**：2024-11 至 2025-02 共 47 次同步，全部为 `direction=download`，`direction=upload` 为 0 次。且 2025-02-19 有一条明确的 `auto-upload skipped (scope=manual-selection-only)` 日志，**直接证明该机制在运行时被正确限制**。**日志是行为的权威记录，偏好只是意图声明。**
- CFPreferences 缓存与磁盘 plist 内容一致（两个关键键逐项比对无差异），**不存在"磁盘 plist 滞后于实际配置"的问题**。这一点必须验证后再下结论，否则会误以为看到的偏好不是生效中的配置。
- 存在 3 份副本，其中共享容器副本 mtime 为 2025-01-08，明显落后于另两份（2025-02-11）。**取哪一份决定了结论**——本案三份的三个关键键值一致，因此不影响结论；若不一致，取权威来源的判定规则见 2.5，本篇不另立标准。
- 对委托方问题的准确答复：「**该机未发生自动上传。**`AutoUpload` 键虽为 true，但受 `AutoUploadScope: manual-selection-only` 与 `AutoUploadEnabledByUser: false` 双重限制；行为日志证实 2024-11 至 2025-02 的 47 次同步全部为下载方向，零上传记录，且有一条明确的自动上传被跳过日志。前提声明：本结论基于应用自身日志的覆盖期；`UploadOnWifiOnly: false` 意味着若上传被触发将不限于 Wi-Fi，但该功能在本期从未被触发。」

**误判对照**

本案最容易得出的错误结论是「偏好里 `AutoUpload: true` 且 `UploadOnWifiOnly: false`，说明该机被配置为在任意网络下自动上传文件，委托方的数据有自动外发风险，应立即禁用该功能并启动泄露排查」。

**正确判据是三个具体键的组合语义 + 行为日志**，两层：

1. **单个布尔键不构成配置语义**。`AutoUpload: true` 与 `AutoUploadScope: manual-selection-only`、`AutoUploadEnabledByUser: false` **同时存在**。后者两个键构成**范围限定与启用状态**的双重约束。判据是"哪些键与它同时存在"，不是"它的值是什么"。 偏好文件的字段命名高度依赖各应用实现，**跨应用推断布尔键含义是误判的高发区**。
2. **偏好是意图声明，日志是行为事实**。`direction=upload` 在 47 次同步里出现 **0 次**，而 2025-02-19 那条 `auto-upload skipped (scope=manual-selection-only)` 更是**运行时约束的直接证据**。**当偏好与日志冲突时，日志优先**——因为偏好可能因配置错误、迁移、默认值而与实际行为不符。

**按错误判据走的代价**：会启动一次不必要的数据泄露排查——扫描所有上传日志、网络流量、文件访问记录，耗时长且最终一无所获。

而真正值得关注的 `UploadOnWifiOnly: false` 本身不是问题（它只在上传被触发时才有意义，而上传从未发生），问题被定位错了。

更实际的是，这类"看到危险开关就报警"的结论会稀释报告的可信度——当报告里出现一个经不起推敲的定性，委托方对整份报告其他结论（包括那些真正重要的）的信任度都会下降。

第二个易错点：因为 `cfprefsd` 有缓存机制，就断定"磁盘上的 plist 不可信，要以内存缓存为准"（或反过来只看缓存）。正确判据是**两者都要取，并比对**：

- 本案验证后两者一致，因此不影响结论；
- 若不一致，权威来源的判定规则见 2.5（磁盘 plist 与 `cfprefsd` 缓存的优先级），并把差异写入报告；
- 若缓存文件不存在（如 `/var/folders` 下找不到），则直接以磁盘 plist 为准，并在报告中说明未发现缓存副本——而不是假称"已核对缓存"。

本案第三节之所以能给出确定结论，正是因为做了这个比对。跳过这一步而直接采信任一份，都可能得出与实际生效配置不符的结论。

---

<a id="section-34"></a>

## 六、扩展阅读方向

**前置与基础。** bplist 的二进制布局要先立住：Trailer 记录偏移表位置，
对象引用表决定了同一个对象如何被多处引用。这三张表读通了，才有资格自己写解析器——
现成工具碰到畸形引用常常直接放弃，而损坏恰恰是最有价值的现场状态。
另一头是 cfprefsd 的缓存同步机制，强制断电会在磁盘 plist 与内存缓存之间
留下不一致态，它与 `defaults` 命令的交互决定了哪些修改其实从未落盘。

**同层深入。** `SystemConfiguration.plist` 是网络侧最重的 plist，
VPN、代理、网络服务的枚举方式要单独读一遍。配置迁移留下的痕迹同样值得追：
迁移助理（Migration Assistant）搬过 home 目录之后，ByHost 下为什么会冒出
多个 UUID 变体，以及哪个才是当前生效的那个。

**相邻议题。** 沙盒化应用把偏好搬进了
`~/Library/Containers/<bundle>/Data/Library/Preferences/`，与主域偏好并存，
只扫 `~/Library/Preferences` 会整片漏掉。时间戳体系得分层看：APFS 的
btime/mtime、`plutil` 输出里的时间、应用自己写下的时间戳，
三者可信度不同，混着用会把「文件被改」误当成「配置被改」。

**工具与判据。** 解析层靠 `plutil` 与批处理的 `plistutil`，
索引层用 [《Spotlight索引与元数据》](computer-plist-spotlight-spotlight.md)
补上「用户实际打开过什么」这一维。配置项被改的时间点要回到 launchd 的
加载记录里对应，见 [《统一日志与LaunchAgents》](../computer-log-persistence/computer-log-persistence-macos-unified-logs-and-launch-agents.md)。

**判据与反例。** 偏好键不存在经常被写成「用户没改过设置」，
但也可能是迁移时整目录搬走、可能被清理工具抹平、还可能是 ByHost 的
UUID 选错了对象——原机取证只有能对上 `cfprefsd` 当前生效值的那份才算直接证据，
镜像上的多副本则要看磁盘值与缓存视图分别说明了什么。
把这条链上的工件组织成完整调查步骤见
[《macOS取证实战流程》](../computer-security/computer-security-security-investigation-workflow.md)。

---

<a id="section-35"></a>

## 七、命令速查

```bash
# ===== 1. 格式与完整性 =====
P=~/Library/Preferences/com.vendor.app.plist
file "$P"                # Apple binary property list / XML document
xxd -l 8 "$P"            # bplist00 = 二进制；3c3f786d6c = "<?xml"
plutil -lint "$P"        # → xxx.plist: OK

# ===== 2. 读取与提取 =====
plutil -p "$P"                                        # 人类可读（格式不稳定）
plutil -convert xml1 -o - "$P"                        # ★ 转 XML 到 stdout
plutil -convert xml1 -o - "$P" | grep -A5 -i 'ServerURL'
plutil -extract Downloads raw -o - "$P"               # 精确提取键
plutil -type Downloads "$P"                           # 键类型
# ⚠️ -convert 不带 -o 会写回原文件 → 破坏证据同一性

# ===== 3. 三位置清点 =====
EV=/mnt/mac-data/Users/wangfang
ls -1 "$EV/Library/Preferences"/*.plist 2>/dev/null | wc -l
ls -1 "$EV/Library/Preferences/ByHost"/*.plist 2>/dev/null | wc -l
ls -1 "$EV/Library/Preferences/ByHost"/*.plist 2>/dev/null \
  | sed -E 's|.*/||; s|\.plist$||; s|.*\.||' | sort -u
# → 多个 UUID = 存在其他主机的配置（拷机痕迹）
# 本机 Hardware UUID：system_profiler SPHardwareDataType

# ===== 4. 重点应用 =====
find "$EV/Library" -name 'Downloads.plist' -path '*Safari*' 2>/dev/null
plutil -p /var/db/com.apple.backgroundtaskmanagement/Contents/Info.plist 2>/dev/null | head -40
plutil -p /mnt/mac-data/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist
plutil -p "$EV/Library/Preferences/.GlobalPreferences.plist" | grep -E 'AppleLocale|AppleICUForce24'

# ===== 5. defaults（仅在线系统，仅交叉参考）=====
defaults read NSGlobalDomain                          # ↔ .GlobalPreferences.plist
defaults read com.apple.finder                        # ↔ com.apple.finder.plist
defaults -currentHost read com.vendor.app             # ↔ ByHost/ 下的部分
defaults read com.apple.finder FXPreferredViewStyle   # 读嵌套键

# ===== 6. 时间戳与验证 =====
stat -f 'btime=%SB  mtime=%Sm  %N' -t '%Y-%m-%d %H:%M:%S' "$P"
# btime == mtime → 典型的一次性拷贝特征
shasum -a 256 "$P" > /tmp/pre.sha256
plutil -convert xml1 -o - "$P" > /tmp/view.xml
shasum -a 256 -c /tmp/pre.sha256      # 验证转换未改动原文件

# ===== 7. iCloud 痕迹 =====
ls -1 "$EV/Library/Mobile Documents/~apple/" 2>/dev/null        # 10.15+ 路径
ls -1 "$EV/Library/Mobile Documents/" 2>/dev/null | grep -c '\.icloud'   # 云端占位数
# 10.14 时代路径是 ~/Mobile Documents/，按检材版本确认
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — macOS 取证 — plist 与偏好设置」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《plist 与偏好设置》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-mem.raw` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
