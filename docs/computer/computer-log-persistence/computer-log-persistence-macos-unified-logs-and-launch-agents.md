---
title: "统一日志与启动项"
slug: "computer-log-persistence-macos-unified-logs-and-launch-agents"
canonical: "https://www.digiforensics.cn/wiki/computer-log-persistence-macos-unified-logs-and-launch-agents"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:48+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "computer"
space: "计算机取证"
node_path: ["日志与持久化"]
---

# 统一日志与启动项

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/computer-log-persistence-macos-unified-logs-and-launch-agents)

<a id="section-1"></a>

## 一、概述

Windows 取证有一条清晰的日志主线：事件查看器、`Security.evtx`、`System.evtx`。

macOS 没有这条主线，但统一日志（Unified Logging）承担了同样的角色：它把内核、进程、网络、偏好设置的变化统一记进一个子系统化、带毫秒精度、带进程与线程归属的日志库。

麻烦的是它**长得不像日志**。`/var/db/diagnostics/` 下全是 `0000000000001ec5.tracev3` 这类文件名——十六进制命名、`.tracev3` 后缀、二进制索引。

取证员打开看到乱码，最常见的反应是「macOS 日志不可用」，而 `tracev3` 内部是高度结构化的，只是不能 `cat`；`log show` 才是它的解析入口。

第二个主题是 launchd。macOS 10.10 之后所有启动项由 `launchd`（PID 1）统一管理，一个 plist 文件就是一个任务，按目录约定自动加载。

这个设计对取证是双面的。

**好处**：配置是纯文本 plist，可直接解析、可与命令历史对照，**不像 Windows 要在五个 Run 键之间猜**。

**坏处**：用户往 `~/Library/LaunchAgents/` 放一个 plist 就获得开机自启，几乎不产生用户可见提示。这是恶意持久化的高发地。

这两类都是 macOS 上**最基础的系统记录**，属于分析环节的证据固定阶段。

**上游依赖**镜像准备与接入。**统一日志的完整性高度依赖设备当时的运行状态**——运行中的机器有内存态缓存，异常断电的机器只剩磁盘态文件，这个差异直接决定能查到什么，见[macOS 取证工件地图](../computer-security/computer-security-security-artifact-map.md)。

**下游支撑**三件事。日志里的启动与加载记录是判断 launchd 任务**是否真的执行过**的证据来源（配置存在只说明打算执行）；plist 清点是[plist 与偏好设置](../computer-plist-spotlight/computer-plist-spotlight-plist.md)的前置；两者的时间点要并入统一时间线。

**动手前**要做三件事：确认日志文件存在与覆盖范围、确认 launchd 的加载域（system / gui / user）、确认 plist 的实际生效状态。

痕迹的形态与位置：

| 形态 | 位置 | 关键结构 |
|---|---|---|
| 统一日志数据文件 | `/var/db/diagnostics/` 下 `*.tracev3` | **二进制索引 + 压缩条目**，文件名是十六进制序列号，不可按内容检索 |
| 统一日志目录 | `/var/db/uuidtext/` | 日志条目的人类可读文本形式，与 `tracev3` 配对 |
| 日志流签名 | logging profile plist（`/System/Library/Preferences/Logging`、`/Library/Preferences/Logging`） | 决定哪些消息被持久化，默认设置下 Info/Debug 只在内存中，不落盘 |
| 系统级启动项 | `/Library/LaunchDaemons/`、`/System/Library/LaunchDaemons/` | 系统级，开机即加载 |
| 用户级启动项 | `~/Library/LaunchAgents/` | **用户登录后加载，用户可自行放置，是持久化高发地** |
| 全局启动项 | `/Library/LaunchAgents/` | 所有用户共享 |
| plist 配置 | `Label`、`Program` / `ProgramArguments`、`RunAtLoad`、`KeepAlive`、`StartCalendarInterval`、`WatchPaths` | **`Label` 就是任务身份，判读时优先看它** |
| 活动状态 | `launchctl list`（仅在线系统） | 加载状态与最近退出码，**离线镜像里取不到** |
| 崩溃报告 | `~/Library/Logs/DiagnosticReports/` | 与统一日志时间线可合并 |

三个判定要点：`tracev3` 必须用工具读、`RunAtLoad` 与 `KeepAlive` 决定了触发方式的不同语义、**用户级与系统级目录的信任级别不同**。

答得出来的是：某个进程在某个时段做过什么、某个 launchd 任务是否被加载过、以及**最近一次退出的退出码**、系统启动项的完整清单与各自的自启方式、某个服务是否配置了周期触发或文件监听。

答不出来的，以及几个必须先认清的边界：

**被日志保留策略丢弃的消息。** 统一日志有**默认的保留与丢弃规则**，低优先级、突发量大的消息可能被整段丢弃。**「日志里没有」不等于「没发生」。**

**超出覆盖时段的历史。** 断电设备的日志通常只剩很短窗口，这部分必须在报告里限定范围，而不是含糊成「未发现异常」。

**launchd 任务的实际动作。** 配置告诉你「打算做什么」，**是否执行、执行结果如何要看日志与退出码。**

**离线镜像里的加载状态。** `launchctl list` 只能在线查询，**镜像里只能读配置，不能读运行时状态。**

**launchd 之外的持久化。** 登录项、crontab、shell profile、XPC 服务都不在这个体系内。

**用户与进程的归属。** 日志记录了进程与用户，但**「这个用户当时坐在机器前」需要输入会话侧的材料**。

要读懂这些，得先熟悉 macOS 目录结构，特别是 `~/Library` 的分层与 `launchd` 的三个加载域，见[macOS 取证工件地图](../computer-security/computer-security-security-artifact-map.md)；理解 plist 的两种格式（XML 与 `bplist00` 二进制）及其解析工具，否则读不了启动项配置；

了解统一日志的架构（`logd` 收集、tracev3 存储、`log show` 查询）这一层就够，不需要内部实现细节；掌握时间戳的纪元与精度概念——统一日志是毫秒精度，与文件系统秒级时间戳合并时要留意，见[时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md)。

还有一条纪律：清楚只读接入的边界，`log show` 在某些情况下会触发日志归档动作，操作前应先固定原始文件。

<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 统一日志的双层架构

macOS 10.12 之后所有日志走同一套 `os_log` 接口，后端是 `logd`。关键在于**双层**：

```
调用方 (os_log / NSLog / print)
      ↓
   logd  ← 运行时内存日志（环形缓冲，高速，容量有限）
      ├──────────────┬─────────────
      ↓              ↓
  tracev3 文件    Signpost 性能采样
  （异步落盘）
```

| 存储位置 | 特性 | 取证意义 |
|---|---|---|
| `/var/db/diagnostics/Persist/*.tracev3` | **持久化**，跨重启保留 | ★★★★★ **离线镜像的主要目标** |
| `/var/db/diagnostics/Special/*.tracev3` | 特殊/高优先级事件 | ★★★ |
| `/var/db/diagnostics/Signpost/*.tracev3` | 性能采样点 | ★★ 偶有应用行为 |
| `logd.0.log`、`logdata.statistics.*.jsonl` | **日志系统自身的元数据** | ★★★★ 体量与进程分布记录 |

**「持久化」是相对于内存日志而言的**——`tracev3` 会落盘，但会滚动清理，空间不足时最早的文件被淘汰。所以「日志缺失」通常不是没记录，而是被保留策略淘汰。

`.tracev3` 是二进制索引格式，不是纯文本。`strings` 或 `grep` 只能得到零散碎片，时间戳与消息字段是二进制编码的，**必须用 `log show` 解析**（误用形态见 4.1 陷阱 1）。

<a id="section-4"></a>

### 2.2 `log show` 谓词语法

能力全在 `--predicate` 上。谓词是布尔表达式，支持 `==`、`!=`、`<`、`>`、`AND`、`OR`、`NOT`、`CONTAINS[c]`、`BEGINSWITH`。

| 维度 | 字段 | 示例 |
|---|---|---|
| 进程 | `process` | `'process == "Safari"'` |
| 调用者镜像 | `senderImagePath` | `'senderImagePath CONTAINS "securityd"'` |
| **子系统** | `subsystem` | `'subsystem == "com.apple.securityd"'` |
| 分类 | `category` | `'category == "GATEKEEPER"'` |
| 消息内容 | `eventMessage` | `'eventMessage CONTAINS "password"'` |
| 线程 / 消息类型 | `threadID`、`messageType` | `'messageType == "Error"'` |

**`subsystem` 是最有效的过滤维度**：Apple 自家组件用反向域名命名（`com.apple.*`），第三方应用也鼓励这样做。查某个系统行为时先猜子系统名，通常比逐个进程试快。

<a id="section-5"></a>

### 2.3 三个必须知道的默认行为

| 行为 | 默认 | 影响 |
|---|---|---|
| **日志级别** | **只显示 default 与 error** | `--info`/`--debug` 的记录**默认不输出**，必须显式加 |
| **时间范围** | 不加 `--last` 时输出**全部历史** | 扫全库耗时数分钟，高速率下会丢行 |
| **输出样式** | `--style default`（含颜色图形） | 解析时必须改 `json` 或 `ndjson` |

**`--info` 是最容易漏的参数。** 大量有价值的信息（"某应用请求访问某目录"、证书校验详情、权限提示）记在 `info` 级别，**不加就完全看不到**。看到"日志里什么都没有"，第一反应应是"级别被过滤了"，而不是"没发生"。

`log` 在 zsh 里是内建数学函数，直接敲 `log show` 会报 "too many arguments"。**用绝对路径 `/usr/bin/log`**，或先 `which -a log` 确认。

`log show` 是查询，`log collect` 是**导出**——把日志打成 `.logarchive` 包（内部是目录，含 `Persist/`、`LogData.sqlite` 等）。

**选型逻辑**：目标明确 → `log show` + 谓词；需要完整日志或需交付委托方复核 → `log collect` 导出。**两者不能互相替代。**

<a id="section-6"></a>

### 2.4 launchd 的加载顺序

`launchd` 取代了传统的 `init`/`rc` 与 System Events 的 AppleScript 自动登录项。

| # | 路径 | 时机 | 权限 |
|---|---|---|---|
| 1 | `/System/Library/LaunchDaemons/` | 开机即加载（最早，系统卷只读） | root |
| 2 | `/Library/LaunchDaemons/` | **开机即加载** | root |
| 3 | `/System/Library/LaunchAgents/` | 登录后 | root |
| 4 | `/Library/LaunchAgents/` | 登录后 | root |
| 5 | `~/Library/LaunchAgents/` | **该用户登录时** | 该用户 |
| 6 | `/Applications/X.app/Contents/Library/LaunchAgents/` | 随应用安装 | 安装时指定 |

`LaunchDaemons` 与 `LaunchAgents` 的区别不只是权限：前者**开机就跑，无需任何用户登录**，因此也是隐蔽性最好的位置。

<a id="section-7"></a>

### 2.5 plist 结构与关键字段

```xml
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>Label</key>            <string>com.vendor.helper</string>
    <key>ProgramArguments</key> <array>
        <string>/usr/local/bin/helper</string>
        <string>--mode</string>
    </array>
    <key>RunAtLoad</key>        <true/>          <!-- 加载即启动一次 -->
    <key>KeepAlive</key>        <true/>          <!-- 退出即重启，持续驻留 -->
    <key>StartInterval</key>    <integer>3600</integer>
</dict>
</plist>
```

| 字段 | 含义 | 检查点 |
|---|---|---|
| `Label` | 任务唯一 ID | **是否伪装成系统组件** |
| `ProgramArguments` | 执行的命令行（数组） | **绝对路径？指向哪？** |
| `Program` | 单个可执行文件（`ProgramArguments` 的简写） | 二者并存时 `ProgramArguments` 优先 |
| `RunAtLoad` / `KeepAlive` | 加载即启动 / 退出即重启 | **后者代表持续驻留，最值得警惕** |
| `StartInterval` / `StartCalendarInterval` | 周期 / 定时（类 cron） | 周期过短值得关注 |
| `WatchPaths` | 指定路径变化时启动 | 触发器式 |
| `StandardOutPath` / `StandardErrorPath` | 输出重定向 | **日志落在哪，可交叉验证** |
| `UserName` | 以指定用户运行 | 降权属正常 |
| `Disabled` | `true` 则不加载 | **被禁用仍是历史证据** |

`Label` 伪装是六条规则里第 1 条的核心：位于 `~/Library/LaunchAgents/` 的 plist 若 `Label` 写成 `com.apple.securityd` 之类，它**不是** Apple 自带的——系统组件只存在于 `/System/Library/LaunchDaemons/`。"第三方目录 + 系统风格 Label" 是明确的伪造信号（判读见 4.3 陷阱 7）。

<a id="section-8"></a>

### 2.6 判断异常的六条规则

| # | 规则 | 判定依据 |
|---|---|---|
| 1 | **位置与 Label 不符** | Label 声称 `com.apple.*` 却不在系统目录 |
| 2 | `KeepAlive = true` + 可疑路径 | 持续重启的陌生程序 |
| 3 | **可执行文件在非常规位置** | `/tmp/`、`~/Downloads/`、`/var/tmp/`、`/Users/Shared/` |
| 4 | **`StartInterval` 过短** | 60~300 秒的外联轮询 |
| 5 | **无有效签名** | `codesign` 无 TeamIdentifier、`spctl` rejected |
| 6 | **文件名与 Label 不一致** | 文件名 `update.plist` 但 Label 无关 |

判定为"异常"后必须做的事：记录 plist 的**创建/修改时间**（`stat`）确定植入时间点；记录目标可执行文件的**哈希**固定证据；在统一日志中查该 Label 的**加载历史**确认何时开始运行；查 `/private/var/log/install.log` 确认是否有对应安装记录；查该路径下是否还有其他关联文件以判断是单点还是一组。

**"有异常启动项"不等于"已定性为恶意"。** 报告应写事实（Label、路径、修改时间、签名状态、运行历史），**定性交给调查方结合上下文判断**。

未经签名验证就写"木马"是越权结论。

<a id="section-9"></a>

### 2.7 launchctl 查询（仅在线系统）

`launchctl list` 输出三列：**PID**（进程号，`-` 表示当前未运行）、**Status**（最近一次退出状态码，`0` 正常、非 0 说明反复崩溃）、**Label**（与 plist 的 `Label` 对应）。

`launchctl print system/com.apple.cupsd` 可取单任务详细状态。

**离线镜像上 `launchctl` 不可用**（它查的是运行中的 launchd）。离线靠 plist 文件本身 + 统一日志里 launchd 域的加载记录。

<a id="section-10"></a>

### 2.8 落盘与留存是两个独立开关

一条日志消息要出现在 `Persist/` 里的 `.tracev3` 中，得同时过两道关，而这两道关由不同键控制：

| 键 | 作用 | 取值 |
|---|---|---|
| `Level` → `Enable` | 决定这类消息**是否进入日志系统** | `Inherit` / `Default` / `Info` / `Debug` / `Off` |
| `Level` → `Persist` | 决定进入系统的消息**是否从内存写进 `Persist/` 文件** | 同上 |

两级都是**层级**的：设成 `Debug` 时 `Default`、`Info`、`Debug` 全部命中；设成 `Info` 时 `Debug` 一条都不进来。

这套开关由 logging profile plist 承载，位置是 `/System/Library/Preferences/Logging`（系统卷，只读）与 `/Library/Preferences/Logging`（管理员可写，**后者覆盖前者**）。profile 按进程名或子系统名命名，例如 `com.apple.iohid.plist`；顶层键是 `DEFAULT-OPTIONS` 或各 category 名，`Level` 字典下面是 `Enable` 与 `Persist` 两个字符串键，另有 `TTL` 控制各类消息的留存天数。

`Enable` 命中但 `Persist` 没命中的消息，在 `log stream` 里能看到，内存环形缓冲区里也有，但永远不落盘——采集镜像时 `Persist/` 里就是没有，`log show` 在离线镜像上也读不出来。这就是"某行为在实时监控里看得见、镜像里查无此事"的成因，它不是采集遗漏，是配置使然。

`sudo log config --status --subsystem <子系统>` 读当前档位，`--mode "level:debug"` 或 `--mode "persist:debug"` 改档。`--mode` 立即生效并写回 profile，直接改 profile 文件可能要重启才生效。

**取证上的意义有两点**：一是某类消息在镜像里缺失时，先确认它是被 `Persist` 挡掉还是压根没产生，"没找到"和"不留存"是两件事，结论表述不能混；二是自定义 profile 会一起进入 `logarchive` 和 `sysdiagnose` 输出，把它们交出去等于同时交出"这台机器当时在记录什么"。

---

<a id="section-11"></a>

## 三、操作步骤

<a id="section-12"></a>

### 3.1 第 1 步：确认日志存在性与覆盖范围

```bash
DIAG=/mnt/mac-data/var/db/diagnostics
ls -1 $DIAG/Persist/*.tracev3 2>/dev/null | wc -l      # 文件数
du -sh $DIAG/Persist $DIAG/Special                     # 体量
ls -1 $DIAG/Persist/*.tracev3 | head -1                # 最早
ls -1 $DIAG/Persist/*.tracev3 | tail -1                # 最新
stat -f '%Sm' -t '%Y-%m-%d %H:%M' $DIAG/Persist/0000000000000a1f.tracev3
# 文件名是十六进制递增的，差值反映覆盖的写入序号范围；结合 mtime 确定时间跨度
# 日志体量随时间的变化（jsonl 每行一条，字段 unixTime / totalBytes / processList）
tail -3 $DIAG/logdata.statistics.0.jsonl | jq -r '[.unixTime, .totalBytes] | @tsv' 2>/dev/null
```

实测说明：`logdata.statistics.*.jsonl` 的字段是 `unixTime`、`totalBytes`、`processList`，**不包含 `dropped` 字段**。

判断"是否因配额丢弃"应看 `totalBytes` 是否贴近存储上限，以及 `Persist/` 目录的实际文件时间跨度。**不要去 grep 一个不存在的字段。**

这一步决定后续查询的 `--last` 取值。

<a id="section-13"></a>

### 3.2 第 2 步：查询与导出

```bash
# 离线镜像：--directory 直接读镜像内的 tracev3，无需挂载到系统目录（关键）
/usr/bin/log show --directory $DIAG --last 24h --info --style json \
  --predicate 'process == "Safari"' > /evidence/safari-24h.jsonl

# JSON 字段提取
/usr/bin/log show --directory $DIAG --last 7d --style json --predicate 'subsystem == "com.apple.TCC"' \
  | jq -r '[.timestamp, .process, .eventMessage] | @tsv'

# 关键查询模式（务必带 --info）
/usr/bin/log show --last 30d --style compact \
  --predicate 'process == "launchd" AND eventMessage CONTAINS[c] "com.suspect.label"'
/usr/bin/log show --last 30d --info --style compact --predicate 'process == "syspolicyd"'
/usr/bin/log show --last 24h --style compact --predicate 'process == "mDNSResponder"' | grep -i Answer

# 导出（交付或长期保存）
/usr/bin/log collect --output /evidence/system_logs.logarchive
/usr/bin/log show --archive /evidence/system_logs.logarchive --last 3d --style json
```

<a id="section-14"></a>

### 3.3 第 3 步：启动项清点与异常筛查

```bash
LA=/mnt/mac-data
ls -1 $LA/Library/LaunchDaemons/*.plist 2>/dev/null | wc -l
ls -1 $LA/Users/*/Library/LaunchAgents/*.plist 2>/dev/null | wc -l

# 批量提取关键字段（二进制 plist 读不出时：plutil -convert xml1 -o - "$p"）
for p in $LA/Library/LaunchDaemons/*.plist $LA/Users/*/Library/LaunchAgents/*.plist; do
  [ -f "$p" ] || continue
  echo "--- $p"
  plutil -p "$p" 2>/dev/null | grep -E '"(Label|Program|ProgramArguments|KeepAlive|RunAtLoad|StartInterval|UserName)"'
done > /evidence/launchd-inventory.txt

# 四条筛查
grep -n -A3 -B1 'KeepAlive.*=> *true' /evidence/launchd-inventory.txt    # 持续驻留
grep -niE '/tmp/|/var/tmp/|/Users/Shared/|/private/tmp/' /evidence/launchd-inventory.txt
grep -niE 'StartInterval.*=> *(60|120|300)' /evidence/launchd-inventory.txt
grep -n 'com\.apple\.' /evidence/launchd-inventory.txt | grep -v '/System/Library/'  # Label 伪装
```

<a id="section-15"></a>

### 3.4 第 4 步：验证

| 验证对象 | 方法 | 通过标准 |
|---|---|---|
| `tracev3` 是二进制 | `xxd -l 16` | 无明文 ASCII 结构，与 `strings` 输出不匹配 |
| 日志确由本机产生 | `logd.0.log` 启动记录 | 时间与设备运行时段吻合 |
| plist 解析正确 | `plutil -lint` | 输出 `: OK` |
| plist 与文件名对应 | 比对 `Label` 与文件名 | 通常一致；不一致需解释 |
| 可执行文件签名有效 | `codesign -dv` + `spctl -a` | `accepted` + 有 TeamIdentifier |

```bash
plutil -lint /mnt/mac-data/Users/liwei/Library/LaunchAgents/com.xxx.helper.plist
stat -f 'btime=%SB  mtime=%Sm  %N' -t '%Y-%m-%d %H:%M:%S' /path/to/com.xxx.plist
codesign -dv --verbose=4 "/path/to/binary" 2>&1 | grep -E 'Authority|TeamIdentifier'
spctl -a -vvv -t execute "/path/to/binary"
```

---
<a id="section-16"></a>

## 四、常见陷阱

本章按日志可读性 → 查询参数 → 启动项判读 → 结论表述归组，每条给出：现象、为什么会误判、误判代价、正确做法。
★ 标记表示该操作会导致原始检材永久灭失或不可逆改变，执行前必须停下来确认。

<a id="section-17"></a>

### 4.1 日志可读性与覆盖范围

<a id="section-18"></a>

#### 陷阱 1：直接对 `.tracev3` 用 `strings` / `grep`

**现象**：对 `/var/db/diagnostics/Persist/*.tracev3` 执行 `grep -a "kext"` 拿到零散片段，据此写出启动项相关的结论。

**原因**：`.tracev3` 是二进制索引格式，不是纯文本。

时间戳与消息字段都是二进制编码的，字段之间按固定结构排列而不是换行分隔。`strings` 只能捞到恰好落在可打印区间里的连续字节，相邻字段的内容会粘连、一条记录会被截断、时间戳完全丢失。

碎片里出现的字符串可能来自任何一条记录，甚至可能是压缩块里的偶然字节序列。

**影响**：用碎片下结论等于把"看起来像"当成"就是"。最典型的翻车是碎片里凑出一组"进程名 + 消息"，两者其实来自不同记录，形成一个不存在的因果关系。

这类错误在报告里极难自查，却会在对方用 `log show` 复核时当场崩塌。

**核查**：**必须用 `log show` 解析**——它能按字段解码二进制记录、正确处理时间戳、并且支持谓词过滤：

```bash
DIAG=/mnt/mac-data/var/db/diagnostics
/usr/bin/log show --directory $DIAG --last 24h --info --style json \
  --predicate 'process == "launchd"' > /evidence/launchd-jan.jsonl
```

`strings` 的结果只能记为"线索，待 `log show` 验证"，不得进入结论表。

<a id="section-19"></a>

#### 陷阱 2：漏掉 `--info`，把"日志里什么都没有"当成"没发生"

**现象**：`log show` 查某个进程，结果几乎为空，报告写「该时段无相关活动」。

**原因**：`log show` 默认只显示 default 与 error 级别的记录，而大量有价值的信息记在 `info` 级别——"某应用请求访问某目录"、证书校验详情、权限提示、TCC 授权决策都在这一层。**不加 `--info` 就完全看不到。**

分析者看到空结果时，第一反应应该是"级别被过滤了"，而不是"没发生"。

**影响**：这是统一日志最常见的假阴性来源。

查 TCC 授权、查 `syspolicyd` 的 Gatekeeper 决策、查 mDNS 解析——这些**关键证据基本都在 info 级别**，漏了 `--info` 会让你系统性地丢掉最需要的东西。

而输出看起来是"干净的空结果"，没有任何报错提示你漏了参数。

**核查**：除非明确要只看高优先级记录，否则一律加 `--info`，并在报告里写明查询参数。判断"无记录"时按三档自检：① 加了 `--info` 吗？② 谓词的 `subsystem`/`category` 拼对了吗（Apple 自家组件用反向域名，如 `com.apple.securityd`、`com.apple.TCC`，先猜子系统名通常更快）？③ 时间范围覆盖目标时段了吗？三项都确认后才写"无记录"。

<a id="section-20"></a>

#### 陷阱 3：在 zsh 里直接敲 `log show`

**现象**：执行 `log show --last 1h ...` 报错 `too many arguments`，分析者以为是参数写错了，反复调整 `--start`/`--end` 仍不通，最终判定该日志不可解析。

**原因**：**`log` 在 zsh 里是内建的数学函数**（自然对数）。

zsh 解析命令时优先匹配内建，于是 `log show --last 1h` 里的 `show`、`--last`、`1h` 全被当成传给数学函数的参数。**报错信息里没有任何提示指向 shell 冲突**，看起来更像参数格式错误。

**影响**：这类失败会连带产生错误判断——分析者可能转而用 `strings` 硬解（回到陷阱 1），或者直接写下"统一日志无法解析，该证据不可用"。

**一个 shell 命名冲突被误读成技术不可行性**，代价是丢掉整类证据。

**核查**：**用绝对路径 `/usr/bin/log`**，它绕过 shell 的内建解析；或先 `which -a log` 确认。

同理 zsh 里 `cd`、`echo` 等在特定配置下也可能有别名，对 `/usr/bin` 下的取证工具统一用绝对路径。

在报告的"工具与方法"一节注明用的是绝对路径。

<a id="section-21"></a>

#### 陷阱 4：把"日志不存在"直接当成"该时段无活动"

**现象**：`Persist/` 目录里最早的文件是 2025-01-15，报告据此写「2025-01-15 之前无任何系统活动记录」。

**原因**：`tracev3` 虽然落盘，但会滚动清理，空间不足时最早的文件被淘汰。 2.1 明确写了这一点。

所以"日志缺失"通常是**保留策略淘汰**，不是"没记录"。区分要看三样：① `Persist/` 里最早文件的 mtime 与目标时段的先后关系；② 文件数量与实际时间跨度的对应（文件名是十六进制递增的，差值反映覆盖的写入序号范围）；③ `logdata.statistics.*.jsonl` 里的 `totalBytes` 是否贴近存储上限。

**影响**：这会直接产出一个虚假的"干净时段"。

案例第 1 步做对了——它同时采集了文件数（1184）、最早/最新文件 mtime、`totalBytes` 三项，据此确认覆盖 2024-05-02 至 2025-03-18 且体量未触顶，才敢往下走。

跳过这一步，报告里"离职期间无记录"这种话可能完全站不住。

**核查**：**先确认覆盖范围，再做查询**。这是 3.1 节把"确认日志存在性与覆盖范围"放在第 1 步的原因。报告里要写一个明确的覆盖区间声明：

> 「持久化统一日志覆盖 2024-05-02 至 2025-03-18（约 10.5 个月），`logdata.statistics` 显示 `totalBytes` 未贴近上限，无明显配额淘汰迹象。2024-05-02 之前的时段不在本次可查范围。」

最后那句必须写——它是后续所有"未见"类结论的边界。

另注：`logdata.statistics.*.jsonl` 的字段是 `unixTime`、`totalBytes`、`processList`，不含 `dropped`，判断是否因配额丢弃要看 `totalBytes` 与实际文件跨度，不要去 grep 一个不存在的字段。

<a id="section-22"></a>

#### 陷阱 5：★ 把镜像挂到 `/var/db/diagnostics` 下让 `log show` 读

**现象**：为省事，把镜像分区挂到系统的 `/var/db/diagnostics` 路径下，然后直接跑 `/usr/bin/log show --last 30d`。

**原因**：这样**读到的是当前运行系统的日志目录**（或者被挂载遮蔽的混合状态）。

命令的 `--directory` 参数被省略，工具按默认路径找——**它根本不知道你要查镜像**。更糟的是，真实的 `logd` 可能正在往那个路径写，形成现场污染。

**影响**：**不可逆污染。** 系统的日志目录被外来数据覆盖或混合，你无法再区分哪些记录来自检材、哪些来自现场运行中的机器。

同时，本次查询的结论完全无效——它是关于另一台机器的。

**核查**：永远用 `--directory` 指向镜像内路径，不挂载、不覆盖系统路径：

```bash
/usr/bin/log show --directory /mnt/mac-data/var/db/diagnostics --last 24h --info --style json \
  --predicate 'process == "launchd"'
```

`--directory` 指向目录会自动合并该目录下全部 tracev3（`Persist/`、`Special/`、`Signpost/`），这是离线查询的关键。

挂载一律用 `-o ro,nobrowse` 且挂到镜像外的路径；若分析工具确实要求固定路径，用挂载命名空间隔离，而不是覆盖系统目录。

<a id="section-23"></a>

### 4.2 查询与解析

<a id="section-24"></a>

#### 陷阱 6：解析 launchd 加载记录时把"加载过"当成"运行过"

**现象**：在统一日志里查到 `com.updater.helper` 的 launchd 加载记录，报告写「该启动项已被加载并运行」。

**原因**：**加载与运行是两件事。**

plist 文件存在 ≠ 被 launchd 加载；被 launchd 加载 ≠ `ProgramArguments` 指向的程序真的成功执行。

判据要看 plist 的字段组合：`RunAtLoad` 控制加载时是否启动一次、`KeepAlive` 控制退出后是否重启、`StartInterval` 控制周期触发。

而**"加载记录存在但进程从未起来"是有意义的信号**——通常意味着目标文件被删了或路径失效（案例里 `sysupdate.service` 的载荷 `sysd` 已被清理，正是这个状态）。

另外 **`launchctl list` 离线不可用**（它查的是运行中的 launchd），所以离线只能用"plist 文件 + 统一日志里 launchd 域的记录"组合判断。

**影响**：把"文件在"或"加载过"当成"运行过"，会让风险评级虚高——你可能去清理一个从未执行过的东西，而真正运行过的那个被放过。

**核查**：把三段状态分开表述，每段各有判据：

| 状态 | 判据 | 离线可否 |
|---|---|---|
| 文件存在 | `plutil -p` 可读、`stat` 有时间 | 可 |
| 被 launchd 加载 | 统一日志中 launchd 域有该 Label 的加载记录 | 可（需 `--info`） |
| 程序真的运行 | 进程记录 / 目标文件被访问的痕迹 / 后续动作的副作用 | 部分 |

`launchctl list` 的三列含义也要用对：`PID` 为 `-` 表示**当前未运行**，`Status` 非 0 表示**反复崩溃**（这本身是指发现了错误的信号）。

在线系统上取单任务详情用 `launchctl print system/<label>`。

<a id="section-25"></a>

### 4.3 启动项判读

<a id="section-26"></a>

#### 陷阱 7：看到 `com.apple.*` 的 Label 就当成 Apple 自带组件

**现象**：`~/Library/LaunchAgents/com.apple.ckproxy.plist` 的 `Label` 是 `com.apple.ckproxy`，分析者看到 `com.apple.` 前缀就归类为"系统组件，正常"，从筛查结果里排除。

**原因**：Apple 自带组件只存在于 `/System/Library/LaunchDaemons/`（及 `/System/Library/LaunchAgents/`），绝不装在用户目录或 `/Library/` 下，所以"**第三方目录 + 系统风格 Label**"是一个明确的伪造信号——伪造者正是靠这个前缀让清单扫过去（2.5 规则 1）。

**影响**：这是最容易被"看起来很正规"骗过的一类。

`com.apple.ckproxy` 这种 Label 在 96 个 plist 里毫不显眼，一旦被归入"系统组件"就彻底消失了。案例第 3 步的 96 个 plist 筛查正是靠这条规则命中了它。

**核查**：筛查时用"位置与 Label 是否匹配"作为判据，而不是用 Label 前缀：

```bash
grep -n 'com\.apple\.' /evidence/launchd-inventory.txt | grep -v '/System/Library/'
```

所有出现在非 `/System/Library/` 路径的 `com.apple.*` 全部进入待查清单。

**结合另外五条规则**（`KeepAlive=true` + 可疑路径、非常规可执行位置、`StartInterval` 60~300 秒、无有效签名、文件名与 Label 不一致）综合判定，不要只靠单一规则定性。

<a id="section-27"></a>

#### 陷阱 8：把 `/Library/LaunchDaemons/` 与 `~/Library/LaunchAgents/` 的区别当成"只是权限不同"

**现象**：筛查时优先检查用户级 `~/Library/LaunchAgents/`，`/Library/LaunchDaemons/` 只粗略扫一遍，报告写"已排查启动项"。

**原因**：2.4 的加载顺序表说明：`LaunchDaemons` 在开机时即加载，无需任何用户登录；`LaunchAgents` 要等对应用户登录。

这不只是权限差异，而是**触发条件的差异**。

`LaunchDaemons` 位置**因此也是隐蔽性最好的位置**：无人登录也能持续运行，而且不依赖任何用户会话。把它当成次要位置，会漏掉最危险的一类。

**影响**：漏掉 `LaunchDaemons` 里的载荷，意味着你漏掉了**不需要任何人登录就能运行**的那个。而它在用户级启动项里是看不见的——没有用户登录，Agent 就不加载。

**核查**：**六个路径按加载顺序全部覆盖**（2.4 的表就是清单），并逐个报告数量与筛查结果：

```bash
ls -1 $LA/System/Library/LaunchDaemons/*.plist 2>/dev/null | wc -l
ls -1 $LA/Library/LaunchDaemons/*.plist 2>/dev/null | wc -l          # 开机即加载，重点
ls -1 $LA/System/Library/LaunchAgents/*.plist 2>/dev/null | wc -l
ls -1 $LA/Library/LaunchAgents/*.plist 2>/dev/null | wc -l
ls -1 $LA/Users/*/Library/LaunchAgents/*.plist 2>/dev/null | wc -l
find /mnt/mac-data/Applications -path '*/Contents/Library/LaunchAgents/*.plist' 2>/dev/null
```

**注意二进制 plist 读不出内容**——需 `plutil -p` 或 `plutil -convert xml1 -o - "$p"` 转换。

`grep` 一个二进制 plist 会静默无输出，导致"文件存在但筛查没命中"的假阴性。

<a id="section-28"></a>

#### 陷阱 9：把"有异常启动项"直接定性为"木马"

**现象**：命中六条规则中的两条（`KeepAlive=true` + 路径在 `/Users/Shared/.cache/`），报告直接写「发现木马持久化」。

**原因**：六条规则是"可疑度"的度量，不是"恶意性"的证明。 `KeepAlive=true` 是很多合法软件的正常需求（守护进程、状态同步器）；非常规路径可能是用户自己放的便携工具；无有效签名的老旧内部工具也很多。这些属性只能说明"值得深入"，不能说明"是恶意"。 2.6 写得很清楚：「有异常启动项不等于已定性为恶意」，「**未经签名验证就写"木马"是越权结论**」。

**影响**：这是一个越权定性。它需要举证责任，而启动项的属性只能证明"配置异常"。

一旦被对方指出"这是公司内部的合法工具"，你的定性被推翻，而报告里基于它建立的所有推演（"远程控制软件"、"员工离职前安装"）一起失效。

**核查**：**事实与定性分离**。

报告里写事实层——`Label`、文件路径、`btime`/`mtime`、`KeepAlive`/`RunAtLoad`/`StartInterval` 的取值、`ProgramArguments` 指向、`codesign -dv` 的签名与 TeamIdentifier、`spctl` 判定结果、文件哈希；定性层由调查方结合上下文判断。

而 `codesign` 无 TeamIdentifier、`spctl` rejected 本身就是**需要写进报告的事实**（它提高了可疑度，但不是恶意证明）。

要升级定性，必须补上：载荷的实际功能分析、可疑网络连接、该路径下的一组关联文件。

<a id="section-29"></a>

### 4.4 结论表述

<a id="section-30"></a>

#### 陷阱 10：把 plist 的 `mtime` 单独作为"植入时间"

**现象**：`stat` 显示 `com.apple.ckproxy.plist` 的 `mtime` 是 2025-01-07 14:22，报告写「攻击者于该时间植入该启动项」。

**原因**：`mtime` 是"内容最后一次修改时间"，不等于"文件创建时间"，也不等于"首次生效时间"。

它会被后续的任何一次编辑推进——包括管理员的微调、工具的自动改写。

案例第 4 步同时采集了 `btime` 与 `mtime`（`stat -f 'btime=%SB  mtime=%Sm'`），**两者相同才说明是一次性创建**；若 `mtime` 明显晚于 `btime`，说明文件被改过。

**影响**：植入时间错位会让整个时间线对不上——如果你说"14:22 植入"，而实际文件 1 月 5 日就存在，那 1 月 5 日到 1 月 7 日之间的行为就都成了"发生在植入之后"的空白。

**核查**：**四个时间一起采集、分列表述**：

```bash
stat -f 'btime=%SB  mtime=%Sm  atime=%Sa  ctime=%Sc' -t '%Y-%m-%d %H:%M:%S' "$p"
```

| 时间 | 回答的问题 |
|---|---|
| `btime`（birth time，APFS 支持） | 文件**创建**时间 —— 植入时间的最强候选 |
| `mtime` | 内容**最后修改**时间 |
| `atime` | 最后**访问**时间 |
| `ctime`（inode 变更） | 元数据变更（含改名、改权限） |

`btime` 与 `mtime` 相同 = 一次性创建；`mtime` 晚于 `btime` = 后续被改过（改了什么要另查）。macOS 的 `stat` 用 `-f`（BSD 风格）不是 Linux 的 `-c`，参数写错会静默返回默认值——**这一条也要注意**。

<a id="section-31"></a>

## 五、案例示例

<a id="section-32"></a>

### 5.1 伪装成 com.apple 前缀的用户级 LaunchAgent 定案

**场景**

MacBook Pro（Intel，i5，macOS 12，FileVault 已由委托人解锁）。委托方为外贸公司，怀疑员工离职前安装了远程控制软件。检材 `DigiForensics.dd`（raw APFS 容器镜像，512 GB），容器分区起始扇区 775920。

macOS 持久化常见的伪装手法是冒用 `com.apple.` 前缀，LaunchAgent 的 plist 与 launchd 日志能构成"配置 + 实际运行"的双源闭环。

**处置过程**

第 1 步，确认日志覆盖范围（**这一步决定后续可行性**）：

```bash
DIAG=/mnt/mac-data/var/db/diagnostics
ls -1 $DIAG/Persist/*.tracev3 | wc -l                                  # → 1184
stat -f '%Sm' -t '%Y-%m-%d %H:%M' $DIAG/Persist/0000000000000a1f.tracev3   # → 2024-05-02
stat -f '%Sm' -t '%Y-%m-%d %H:%M' $DIAG/Persist/0000000000001c47.tracev3   # → 2025-03-18
tail -3 $DIAG/logdata.statistics.0.jsonl | jq -r '.totalBytes'       # → 体量稳定未触顶 ✓
```

持久化日志覆盖 **2024-05-02 至 2025-03-18**（约 10.5 个月），**完整覆盖离职期间（2025-01 上旬）**，且体量未触及存储上限（无明显配额淘汰）。

第 2 步，从镜像查询 launchd 域：

```bash
/usr/bin/log show --directory $DIAG --start "2025-01-06 00:00:00" --end "2025-01-12 00:00:00" \
  --style json --predicate 'process == "launchd"' > /evidence/launchd-jan.jsonl
wc -l /evidence/launchd-jan.jsonl        # → 2841 条
```

第 3 步，启动项筛查（96 个 plist 中命中 2 个）：

```bash
plutil -p /mnt/mac-data/Users/liwei/Library/LaunchAgents/com.apple.ckproxy.plist
# "Label" => "com.apple.ckproxy"
# "ProgramArguments" => [ 0 => "/Users/Shared/.cache/agent" ]
# "KeepAlive" => true    "RunAtLoad" => true    "StartInterval" => 120
plutil -p /mnt/mac-data/Users/liwei/Library/LaunchAgents/com.updater.helper.plist
# "Label" => "com.updater.helper"
# "ProgramArguments" => [ 0 => "/Users/liwei/Downloads/helper" ]   "RunAtLoad" => true
```

第 4 步，逐项验证（**三个独立证据源**）：

```bash
# ① 时间戳
stat -f 'btime=%SB  mtime=%Sm' -t '%Y-%m-%d %H:%M:%S' \
  /mnt/mac-data/Users/liwei/Library/LaunchAgents/com.apple.ckproxy.plist
# btime=2025-01-07 14:22:31   mtime=2025-01-07 14:22:31   ← 两者相同 = 一次性创建

# ② 可执行文件签名
codesign -dv "/mnt/mac-data/Users/Shared/.cache/agent" 2>&1 | grep -E 'Authority|TeamIdentifier'
# → 无 TeamIdentifier
spctl -a -vvv -t execute "/mnt/mac-data/Users/Shared/.cache/agent"
# → rejected (the code is not signed)

# ③ 统一日志确认实际运行
/usr/bin/log show --directory $DIAG --start "2025-01-07" --end "2025-01-12" \
  --style compact --predicate 'eventMessage CONTAINS "com.apple.ckproxy"' | head -3
# 2025-01-07 14:22:35.118  launchd[321]: com.apple.ckproxy: Loaded
# 2025-01-07 14:22:35.201  launchd[321]: com.apple.ckproxy: Started
# 2025-01-08 03:11:44.902  launchd[321]: com.apple.ckproxy: Started   ← 崩溃后被 KeepAlive 重启
```

第 5 步，网络外联佐证：

```bash
/usr/bin/log show --directory $DIAG --start "2025-01-08" --end "2025-01-10" --style compact \
  --predicate 'process == "mDNSResponder"' | grep -i Answer | grep -iE 'dyn|no-ip'
# 2025-01-08 03:11:46.220  mDNSResponder[881]: Answer 203.0.113.77 a9247.ddns.net
```

进程被 KeepAlive 重启后 **2 秒内**触发了对动态 DNS 域名的解析。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 存在两个未经授权的持久化任务 | plist 解析 + launchd 加载日志 | 强 |
| 植入时间 2025-01-07 14:22:31 | plist `btime`/`mtime` + 日志首次 Loaded（相差 4 秒） | 强（双源印证） |
| 目标程序未签名、Gatekeeper 校验失败 | `codesign` 无 TeamIdentifier + `spctl` rejected | 强 |
| 存在与动态 DNS 的外联行为 | `mDNSResponder` 解析日志 | 中（**关联性证据**） |
| 第二个任务（`com.updater.helper`）性质 | **仅凭 plist 位于 Downloads 目录** | **弱，需进一步分析** |

**不能证明的**：本案**无法确定安装者**。`btime` 只能证明文件在该时刻被创建，**不能证明是谁创建的**——用户权限下的任何进程（浏览器下载、脚本、远程工具）都可能产生这个文件。

归属需要与登录会话、浏览器下载记录交叉。

**误判对照**

本案最容易得出的错误结论是「`com.apple.ckproxy` 的 Label 带 `com.apple.` 前缀，说明它是 Apple 官方组件，属于系统自带，委托方的怀疑方向应当排除」。

**正确判据有三条，全部可查**：

1. **路径**。该 plist 位于 `/Users/liwei/Library/LaunchAgents/`（用户级目录），而所有真正的 Apple 组件都在 `/System/Library/LaunchAgents/` 或 `/Library/LaunchAgents/`。

   Apple 不会把组件放在某个用户的家目录里。路径与 Label 前缀矛盾时，路径的证据权重更高——因为用户目录的内容任何用户都能写，而 `/System/Library` 受 SIP 保护。
2. **签名**。`codesign -dv` 输出**无 `TeamIdentifier`**。Apple 自带组件一律有 Apple 的 Team ID（`Software signing authority=Apple`）。无签名的二进制在 `com.apple.` 这个命名空间里是自相矛盾的。
3. **载荷路径**。`ProgramArguments[0] = /Users/Shared/.cache/agent`——**点开头的隐藏目录、位于共享目录、无签名**。

   Apple 组件不会把可执行目标指向用户可写的隐藏目录。

**按错误判据走的代价**：把两个植入项写成"系统自带组件"，委托方会据此**排除 `liwei` 账户作为嫌疑对象**，理由是"Apple 组件不可能是员工装的"。

这会导致调查方向完全偏离——真正的植入物（`/Users/Shared/.cache/agent`）反而被当成系统文件放过了。

而且这条错误结论一旦写进报告，质证时对方只需 `ls /System/Library/LaunchAgents` 就能推翻整份分析的可信度。

第二个易错点：把 `mDNSResponder` 解析了 DDNS 域名这一条当作"已建立远程控制通道"的证明。 正确判据是本案的强度标注——**这是关联性证据（中），不是通道证据（强）**。

原因有三：

1. `mDNSResponder` 的日志只记录"**系统解析了这个域名**"，不记录"哪个进程发起了解析"，也不记录解析结果是否被使用；
2. 时间上的 2 秒间隔说明的是**进程重启与解析相邻**，不能证明因果——同一台机器上任何进程都可能触发解析；
3. **要证明通道建立，需要的是连接态证据**（如该进程建立的 TCP 连接、目的 IP/端口、持续时长），而本案**没有采集到这一层**。

准确表述是：「卸载后 2 秒内系统解析了 `a9247.ddns.net`（指向 `203.0.113.77`），与该 LaunchAgent 的运行时段重合，构成可疑关联；但本案证据不足以证明二者存在因果关系，亦不足以证明远程通道已建立。」

---

<a id="section-33"></a>

### 5.2 LaunchDaemon 与 LaunchAgent 的目录归属判别

**场景**

同系列另一台 MacBook Pro（Apple Silicon，macOS 13），委托方在排查中发现 `/Library/LaunchDaemons/` 下有 3 个 plist 名称与系统组件相似，要求确认哪些是系统自带、哪些是植入。检材 `DigiForensics.dd`（APFS 容器镜像）。

系统目录下的"看起来像系统组件"的文件最难判定，判定依据必须落到签名与文件归属上，不能靠命名。

**处置过程**

第 1 步，清点系统目录并列出全部 plist（**不预设可疑**）：

```bash
ls -l /mnt/mac-data/Library/LaunchDaemons/ | head -20
# -rw-r--r-- 1 root wheel  812  2023-09-12 com.apple.softwareupdated.helper.plist
# -rw-r--r-- 1 root wheel  644  2023-09-12 com.apple.xpcproxy.plist
# -rw-r--r-- 1 root wheel  711  2025-02-14 com.apple.backupd.agent.plist   ← ★ mtime 异常新
# -rw-r--r-- 1 root wheel  640  2025-02-14 com.apple.netbios.helper.plist  ← ★
# -rw-r--r-- 1 root wheel  598  2025-02-14 com.apple.timed.helper.plist   ← ★
# -rw-r--r-- 1 root wheel 1022  2023-09-12 com.apple.disksarbitrationd.plist
```

**第一批判据是 mtime 的时间簇**：三个文件的 mtime 是 2025-02-14，另外四个是 2023-09-12（系统镜像时间）。**同一时刻创建的三个文件构成一个可疑簇。**

第 2 步，逐个验证签名（**这是决定性判据**）：

```bash
for f in /mnt/mac-data/Library/LaunchDaemons/*.plist; do
  n=$(basename "$f")
  tgt=$(plutil -extract ProgramArguments.0 raw "$f" 2>/dev/null)
  printf '%-46s team=%-12s mtime=%s\
' "$n" \
    "$(codesign -dv --verbose=2 "$tgt" 2>&1 | awk -F= '/TeamIdentifier/{print $2}')" \
    "$(stat -f '%Sm' -t '%Y-%m-%d' "$f")"
done
# com.apple.softwareupdated.helper.plist   team=Software signing authority=Apple   mtime=2023-09-12
# com.apple.xpcproxy.plist                 team=Software signing authority=Apple   mtime=2023-09-12
# com.apple.backupd.agent.plist            team=(空)                              mtime=2025-02-14  ← ★
# com.apple.netbios.helper.plist           team=(空)                              mtime=2025-02-14  ← ★
# com.apple.timed.helper.plist             team=(空)                              mtime=2025-02-14  ← ★
# com.apple.disksarbitrationd.plist        team=Software signing authority=Apple   mtime=2023-09-12
```

第 3 步，确认载荷的真实位置与属性：

```bash
for t in /usr/libexec/backupd /usr/libexec/netbios_helper /usr/libexec/timed; do
  ls -l "/mnt/mac-data$t" 2>&1
done
# -rwxr-xr-x 1 root wheel 2411728 2023-09-12 /usr/libexec/backupd        ← 系统原版存在
# -rwxr-xr-x 1 root wheel  885104 2025-02-14 /usr/libexec/netbios_helper ← ★ 无 Team ID
# -rwxr-xr-x 1 root wheel  602112 2025-02-14 /usr/libexec/timed         ← ★ 覆盖了系统组件
```

关键发现：`/usr/libexec/timed` 已被一个无签名的 602112 字节文件覆盖（系统原版应带 Apple Team ID）。这是**系统组件被替换**的典型形态。

第 4 步，检查 LaunchDaemon 的运行状态（**与 LaunchAgent 的关键区别**）：

```bash
/usr/bin/log show --directory /mnt/mac-data/var/db/diagnostics \
  --start "2025-02-14 00:00:00" --end "2025-02-20 00:00:00" --style compact \
  --predicate 'process == "launchd" AND eventMessage CONTAINS "netbios_helper"' | head -4
# 2025-02-14 03:20:11.882  launchd[96]: com.apple.netbios.helper: Loaded
# 2025-02-14 03:20:12.004  launchd[96]: com.apple.netbios.helper: Started
# 2025-02-19 03:20:12.301  launchd[96]: com.apple.netbios.helper: Started   ← 周期重启
# → LaunchDaemon 随系统启动而加载（03:20 是常规开机时段）
```

第 5 步，检查持久化范围的差异（为什么一个用 Agent 一个用 Daemon 很重要）：

```bash
# Daemon 以 root 运行、开机即加载；Agent 以用户身份、登录后运行
plutil -p /mnt/mac-data/Library/LaunchDaemons/com.apple.netbios.helper.plist
# "Label" => "com.apple.netbios.helper"
# "ProgramArguments" => [ 0 => "/usr/libexec/netbios_helper" ]
# "RunAtLoad" => true
# "StartInterval" => 86400      ← 每天一次
# "UserName" => (无)             ← 无 UserName = 以 root 运行 ★
```

**结论**

- **3 个 plist 为植入，4 个为系统自带**，判据是签名（TeamIdentifier）+ mtime 时间簇双源一致：系统自带项 `codesign` 均返回 `Software signing authority=Apple` 且 mtime 停在 2023-09-12；三个可疑项**签名均为空**且 mtime 同为 2025-02-14。
- 最严重的一项是 `/usr/libexec/timed` 被覆盖（系统组件替换）。另两个（`netbios_helper`、`backupd.agent`）是指向新增文件的 plist，**未覆盖系统原文件**（`backupd` 原版仍在且带 Apple 签名）。
- `com.apple.netbios.helper` 以 root 身份运行（无 `UserName` 键 = 系统级守护进程），且 `StartInterval 86400`（每天一次）+ `RunAtLoad`（开机即跑）。这与前一案的 `com.apple.ckproxy` 有本质区别：那一项是用户级（`~/Library/LaunchAgents/`，以登录用户身份跑），本项是系统级（以 root 跑）。
- 因此对委托方问题的答复应区分：「`com.apple.ckproxy` 属**用户级持久化，其权限上界是该用户账户**；`com.apple.netbios.helper` 属系统级持久化，以 root 身份运行，权限上界是 root，且每天执行一次。**后者的风险等级显著更高**，且其启动不依赖任何人登录。」

**误判对照**

本案最容易得出的错误结论是「这三个文件都在 `/Library/LaunchDaemons/`（系统目录）下、名字都带 `com.apple.` 前缀、文件属主是 `root`，这些都是系统自带的，把它们从可疑清单里排除，只保留用户目录下的两个可疑项」。

正确判据是 `codesign` 的 TeamIdentifier，而不是目录位置或文件属主，三点：

1. **目录位置可被利用，签名不可伪造**。攻击者能往 `/Library/LaunchDaemons/` 写文件（需要管理员权限，但 `sudo` 提权后完全可以），属主变成 `root` 只是一次 `chown` 的结果，不代表文件的来源可信。

   而代码签名是**基于二进制内容 + Apple 证书链的验证**，`codesign -dv` 报告的 TeamIdentifier 无法通过改名或移动伪造——除非攻击者有 Apple 的签名证书，而那属于另一量级的入侵。
2. 系统组件被覆盖 vs 新增 plist，是两种手法。`/usr/libexec/timed` 的**原版带 Apple 签名、现版无签名**，这说明**发生了覆盖写入**——这比"新增一个 plist"更严重，因为它可能劫持了原本正常工作的功能。

   只看 plist 无法发现覆盖，只能靠对载荷逐一验签。
3. LaunchDaemon 的判定标准是"无 `UserName` 键"。有 `UserName` 的会以指定用户身份运行，无该键的以 root 运行。

   **这一条决定了权限上界**，直接影响风险评估结论。

**按错误判据走的代价**：把三个 root 级植入判为"系统自带"，会漏掉本案**风险最高的一项**——`/usr/libexec/timed` 被覆盖意味着**系统时间同步功能可能已被劫持**。

时间被劫持的后果极其严重：它会污染**所有**后续证据的时间戳（统一日志、文件 mtime、网络时序），使整台机器的时间线失去可信度。**漏掉这一项，委托方会基于被污染的时间线做决策。**

第二个易错点：把 LaunchDaemon 与 LaunchAgent 的权限等级混为一谈。 正确判据是三个具体字段：

| 维度 | LaunchAgent（`~/Library/LaunchAgents/`） | LaunchDaemon（`/Library/LaunchDaemons/`） |
|---|---|---|
| 身份 | 登录用户（`UserName` 或归属用户） | **root**（无 `UserName` 键） |
| 触发时机 | **用户登录后** | **开机即触发，无需登录** |
| 权限上界 | 该用户账户 | **系统最高权限** |

**按这个区分，误判代价是风险排序错误**：把两者都写成"发现了 5 个持久化项"而不区分身份，委托方会按同一优先级处置，结果是在处置完用户级项之后，root 级的 `timed` 覆盖仍然存在——而它恰恰是那个会持续污染所有新证据的项目。

---

<a id="section-34"></a>

### 5.3 反例：已卸载 LaunchAgent 的残留痕迹与证据局限

**场景**

同系列 MacBook（macOS 12），委托方在离职员工电脑上发现某远程工具的痕迹，但**当前系统中已无该软件的任何文件**。检材 `DigiForensics.dd`。

软件被卸载后，统一日志往往还保留着运行记录，这类证据容易被漏掉、也容易被误读。

**处置过程**

第 1 步，先确认当前系统状态（**这一步决定了后续是查"文件"还是查"历史"**）：

```bash
ls -1 /mnt/mac-data/Users/*/Library/LaunchAgents/ /mnt/mac-data/Library/LaunchAgents/ 2>/dev/null \
  | grep -iE 'anydesk|teamviewer|rustdesk|splashtop|screenconnect|meshcentral' 
# （无输出）  ← 当前无任何相关 LaunchAgent

find /mnt/mac-data/Applications /mnt/mac-data/Users/*/Applications -maxdepth 1 \
  -iname '*anydesk*' -o -iname '*teamviewer*' 2>/dev/null
# （无输出）  ← 应用目录已清空
```

第 2 步，**转查统一日志——软件卸载不会删除系统日志**：

```bash
/usr/bin/log show --directory /mnt/mac-data/var/db/diagnostics \
  --start "2024-10-01" --end "2025-03-18" --style compact \
  --predicate 'process CONTAINS[c] "anydesk" OR eventMessage CONTAINS[c] "anydesk"' \
  > /evidence/anydesk-runs.txt
wc -l /evidence/anydesk-runs.txt
# 3412 条
head -4 /evidence/anydesk-runs.txt
# 2024-11-12 09:14:22.114  anydesk[4412]: start service
# 2024-11-12 09:14:23.880  anydesk[4412]: connection established
# ...（末行）
tail -2 /evidence/anydesk-runs.txt
# 2025-01-09 17:33:51.220  anydesk[4488]: start service
# 2025-01-09 17:34:02.661  anydesk[4488]: service stopped
```

3412 条日志跨越 2024-11-12 至 2025-01-09，覆盖了近两个月。

第 3 步，统计运行频次与时段特征（**这是本案的关键分析**）：

```bash
awk '{print $1}' /evidence/anydesk-runs.txt | sort | uniq -c | sort -rn | head -8
# 218 2025-01-09
# 214 2024-12-28
# ...
# → 集中在 12-28 与 01-09 两个日期

awk '{print substr($2,1,2)}' /evidence/anydesk-runs.txt | sort | uniq -c
#  187 09   ← 上午 9 点
#  164 17   ← 下午 5 点
#  ...  （集中在两个时段）
```

第 4 步，定位**最后一次运行与卸载动作的时间关系**：

```bash
grep -nE 'service stopped|uninstall|pkgutil|installer' /evidence/anydesk-runs.txt | tail -5
# 2025-01-09 17:33:51.220  anydesk[4488]: start service
# 2025-01-09 17:34:02.661  anydesk[4488]: service stopped
# 2025-01-09 17:36:40.118  installd[221]: PackageKit: Removed package "com.philandro.anydesk"

stat -f '%N  btime=%SB  mtime=%Sm' -t '%Y-%m-%d %H:%M:%S' /mnt/mac-data/var/db/receipts/com.philandro.anydesk.plist 2>&1
# ls: No such file or directory
# → 安装收据（receipt）已被删除，说明走了彻底清理流程
```

第 5 步，确认无残留（**阴性发现要限定范围**）：

```bash
# 收据、包缓存、偏好设置
ls -d /mnt/mac-data/var/db/receipts/*anydesk* 2>&1 | head -1     # 不存在
ls -d /mnt/mac-data/Library/Caches/*anydesk* 2>&1 | head -1     # 不存在
ls -d /mnt/mac-data/Users/*/Library/Preferences/*anydesk* 2>&1 | head -1  # 不存在

# 但统一日志覆盖期是否覆盖了全部运行？
stat -f '%Sm' -t '%Y-%m-%d' /mnt/mac-data/var/db/diagnostics/Persist/0000000000000a1f.tracev3
# 2024-05-02  → 日志最早到 2024-05-02，本案首次运行 2024-11-12，在覆盖期内 ✓
```

**结论**

- 确认该机曾安装并运行远程控制软件（AnyDesk）：统一日志有 3412 条记录，覆盖 2024-11-12 09:14 至 2025-01-09 17:34，含 `start service`、`connection established`、`service stopped` 等事件，期间有 `connection established` 即发生过实际连接。
- 卸载动作定案于 2025-01-09 17:36:40：`installd[221]: PackageKit: Removed package "com.philandro.anydesk"`，距最后一次服务停止（17:34:02）仅 2 分 38 秒——**属于"用完即卸"的即时清理模式**。
- **清理彻底**：安装收据、缓存目录、偏好设置**均已不存在**，当前 `/Applications` 与所有 `LaunchAgents` 目录中**无任何相关文件**。
- **运行时段高度集中**：流量集中在上午 9 点（187 条）与下午 5 点（164 条），且 3412 条里大头集中在 2024-12-28 与 2025-01-09 两天。**这个分布与"员工本人日常使用远程桌面"的模式一致**。
- **必须写明的三项局限**：
  1. **无法确定操作者**。日志只记录 `anydesk[PID]` 这个进程，**不记录是谁发起的连接**——AnyDesk 的连接可来自本机发起或被控端反向连接。归属需要与该账户的登录记录、远程桌面会话记录交叉。
  2. `connection established` 的对端不可知。统一日志的这条记录**不含目的 IP/端口**，本案**没有采集到该进程的网络连接证据**。因此不能证明"数据被外传"或"外部主机控制了这台机器"，只能说"发生过连接建立"。
  3. **卸载前的历史是否被清除不可知**。收据与缓存已删，但**不能排除更早的其他安装实例**——若该软件曾多次安装卸载，前几次的痕迹同样只存在于统一日志中，而日志覆盖期从 2024-05-02 起，本案只能确认覆盖期内的情况。

**误判对照**

本案最容易得出的错误结论是「当前系统里找不到任何 AnyDesk 文件、收据、缓存、偏好设置都清理干净了，说明该机从未安装过远程控制软件，委托方的怀疑不成立」。

**正确判据是统一日志的持久化特性与它的时间跨度**，两点：

1. **卸载程序只删自己的文件，不删系统日志**。`installd` 记录的是包管理操作，`/var/db/diagnostics/` 下的 `.tracev3` 是**系统级日志数据库，与任何应用无关**。因此"应用文件全没了"与"应用从未运行过"在文件系统层面完全同形，**唯一的区分依据就是日志**。
2. **日志里有完整的运行事件序列**。`start service`（17:33:51.220）→ `connection established`（17:34:02 内）→ `service stopped` → `PackageKit: Removed`（17:36:40.118），**这四类事件构成一条闭合的服务生命周期**，不是残留碎片。

**按错误判据走的代价**：阴性误判里后果最重的一类。它会直接导致委托方写出「该机未安装远程控制软件」的结论，而实际上该软件运行了近两个月、发生过实际连接、且被刻意清理；后果是双重的——① 员工的不当行为被洗清，处分失去依据；② 如果这台机器曾被远程控制，入侵的定性、数据的责任归属全部需要推翻重来。而清理痕迹这个动作本身恰恰是最值得报告的发现（用完即卸、收据清除），它也一起被这个错误结论抹掉了。

第二个易错点：把 `connection established` 直接写成"数据外传"或"被远程控制"。 正确判据是这条日志的**信息量上限**：它只说明**该进程建立了一条连接**，**不含对端地址、不含传输内容、不含方向**（是本机作为控制端连出去，还是作为被控端被连入）。

要区分这两种情形，需要该进程的网络连接记录或 AnyDesk 自身日志，而本案**两者都没有**——软件已被卸载，其自身日志目录已随收据一起清除。

准确表述是：「该机曾运行远程控制软件 AnyDesk，累计 3412 条日志事件，含 `connection established`（发生过连接建立）。由于软件已被彻底卸载，其自身日志不可得，本案无法确定连接方向与对端身份。」

---
<a id="section-35"></a>

## 六、扩展阅读方向

<a id="section-36"></a>

### 前置基础：两章的读法都建立在这些概念上

- [macOS 取证工件地图](../computer-security/computer-security-security-artifact-map.md) —— `~/Library` 分层、FileVault、镜像准备。**本篇两个主题的落点全在这一篇的地图里**，尤其「日志存在但读不到」通常是因为它被 FileVault 或 SIP 挡住了。
- [plist 与偏好设置](../computer-plist-spotlight/computer-plist-spotlight-plist.md) —— plist 的两种格式与解析方法。launchd 配置就是 plist，不懂 plist 结构就读不了启动项。
- [只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md) —— APFS 镜像的接入方式。统一日志与 FileVault 的关系决定了这一步能做到什么程度。

<a id="section-37"></a>

### 同层深入：同一主题的另一面

- [FSEvents 与时间机器](computer-log-persistence-fsevents.md) —— 同一主题下的另两个日志类工件。统一日志记「进程说了什么」，FSEvents 记「文件树哪里变了」，两者互补且互不覆盖。
- [Spotlight 索引与元数据](../computer-plist-spotlight/computer-plist-spotlight-spotlight.md) —— 系统级索引。**索引的建立、更新与排除规则本身就是行为痕迹**，与统一日志交叉能互相补全。
- [取证工件地图](../computer-persistence/computer-persistence-persistence-artifact-map.md) —— Linux 侧对照。「有没有集中日志入口」这个结构差异，在两边对照时最直观。
- [系统日志深度分析](../computer-log/computer-log-system-log-analysis.md) —— Linux 的日志机制。与统一日志的对比能看出 Apple 为什么选了 tracev3 而不是纯文本。

<a id="section-38"></a>

### 相邻议题：时间线与相邻系统

- [时间线重建](../computer-log/computer-log-linux-timeline-reconstruction.md) —— 跨来源时间线合并的方法论。统一日志的毫秒精度与文件系统秒级时间戳合并时，精度差本身就是判读信息。
- [Quarantine 与 Gatekeeper](../computer-security/computer-security-quarantine-gatekeeper.md) —— 同一板块的相邻议题。下载来源与 Gatekeeper 判定会进统一日志，两边对照能还原完整的文件引入过程。

<a id="section-39"></a>

### 工具与规范：操作边界

- [证据文件格式](../../fundamentals/fundamentals-chain/fundamentals-chain-dd-e01-aff4-evidence-formats.md) —— tracev3 导出产物的归档格式选择。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md) —— 系统日志内容可能包含用户隐私，**摘录要与授权范围一致。**

<a id="section-40"></a>

### 判据与反例：什么样的启动项算异常

- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— launchd 配置被修改时留下的时间矛盾。plist 文件的修改时间与它引用的二进制时间对不上，是判据之一。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 阴性结论的表述纪律。「未发现异常启动项」必须写明检查了哪些目录、哪些类型未覆盖。
<a id="section-41"></a>

## 七、命令速查

```bash
# ===== 环境 =====
# zsh 里 log 是内建函数 → 必须用 /usr/bin/log 绝对路径
# 离线镜像用 --directory 直接读镜像内的 tracev3，无需系统挂载

# ===== 1. 确认日志存在性与覆盖范围 =====
DIAG=/mnt/mac-data/var/db/diagnostics
ls -1 $DIAG/Persist/*.tracev3 2>/dev/null | wc -l
du -sh $DIAG/Persist $DIAG/Special
ls -1 $DIAG/Persist/*.tracev3 | head -1; ls -1 $DIAG/Persist/*.tracev3 | tail -1
stat -f '%Sm' -t '%Y-%m-%d %H:%M' $DIAG/Persist/0000000000000a1f.tracev3
tail -3 $DIAG/logdata.statistics.0.jsonl | jq -r '[.unixTime, .totalBytes] | @tsv' 2>/dev/null

# ===== 2. 查询与导出 =====
/usr/bin/log show --directory $DIAG --last 24h --info --style json \
  --predicate 'process == "Safari"' > /evidence/safari-24h.jsonl
/usr/bin/log show --directory $DIAG --last 7d --style json --predicate 'subsystem == "com.apple.TCC"' \
  | jq -r '[.timestamp, .process, .eventMessage] | @tsv'
/usr/bin/log collect --output /evidence/system_logs.logarchive
/usr/bin/log show --archive /evidence/system_logs.logarchive --last 3d --style json

# ===== 3. 关键查询（务必带 --info）=====
/usr/bin/log show --last 30d --style compact \
  --predicate 'process == "launchd" AND eventMessage CONTAINS[c] "com.suspect.label"'
/usr/bin/log show --last 30d --info --style compact --predicate 'process == "syspolicyd"'
/usr/bin/log show --last 24h --style compact --predicate 'process == "mDNSResponder"' | grep -i Answer

# ===== 4. 启动项清点与筛查 =====
LA=/mnt/mac-data
for p in $LA/Library/LaunchDaemons/*.plist $LA/Users/*/Library/LaunchAgents/*.plist; do
  [ -f "$p" ] || continue; echo "--- $p"
  plutil -p "$p" 2>/dev/null | grep -E '"(Label|Program|ProgramArguments|KeepAlive|RunAtLoad|StartInterval|UserName)"'
  # 二进制 plist 读不出时：plutil -convert xml1 -o - "$p"
done > /evidence/launchd-inventory.txt
grep -n -A3 -B1 'KeepAlive.*=> *true' /evidence/launchd-inventory.txt
grep -niE '/tmp/|/var/tmp/|/Users/Shared/|/private/tmp/' /evidence/launchd-inventory.txt
grep -niE 'StartInterval.*=> *(60|120|300)' /evidence/launchd-inventory.txt
grep -n 'com\.apple\.' /evidence/launchd-inventory.txt | grep -v '/System/Library/'   # Label 伪装

# ===== 5. 验证 =====
plutil -lint /path/to/com.xxx.plist            # 语法检查
stat -f 'btime=%SB  mtime=%Sm  %N' -t '%Y-%m-%d %H:%M:%S' /path/to/com.xxx.plist
codesign -dv --verbose=4 "/path/to/binary" 2>&1 | grep -E 'Authority|TeamIdentifier'
spctl -a -vvv -t execute "/path/to/binary"   # accepted=正常；rejected=可疑

# ===== 6. 运行态查询（仅在线系统）=====
launchctl list                                # PID / Status / Label
launchctl print system | head -20
launchctl print gui/$(id -u)
launchctl print system/com.apple.cupsd
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — macOS 取证 — 统一日志与启动项」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《统一日志与启动项》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-mem.raw` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
