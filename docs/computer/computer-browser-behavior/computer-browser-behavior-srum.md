---
title: "SRUM 数据库分析"
slug: "computer-browser-behavior-srum"
canonical: "https://www.digiforensics.cn/wiki/computer-browser-behavior-srum"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:49+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "computer"
space: "计算机取证"
node_path: ["浏览器行为"]
---

# SRUM 数据库分析

<a id="section-1"></a>

## 一、概述

Windows 8 起系统里就常驻一个资源使用监控组件（SRU）。它每小时把每个应用的运行状况、资源消耗和网络流量写进一个 ESE 数据库。

任务管理器的「应用历史记录」标签页只露出其中很小一角，绝大多数记录在界面上根本看不到。取证价值正在这里。界面上读不到的，`SRUDB.dat` 里留着——用户 SID、可执行文件完整路径、前后台 CPU 时间、磁盘读写字节数、上下文切换次数、发送与接收字节数，一条记录里全有。

数据外泄案件中，SRUM 常常是能回答「哪个用户在什么时段、用哪个程序、往外发了多少数据」的工件之一。它留下的是已经结束的网络会话的量化痕迹，会话本身早消失了，浏览器历史里通常查不到。

代价是窗口短。历史通常只有 30 到 60 天，跨重启保留，被覆盖后无法恢复。所以它必须优先提取：每多等一天，可用证据就少一天。

这属于流程里「先提取什么」这个决策环节，位置在采集优先级判断之前。上游先解决镜像接入：`SRUDB.dat` 是 ESE 数据库，在活系统上直接打开或挂载分析都可能改写它，原始文件必须先固定下来，参见[只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md)。

它自己要处理三件事。数据库可能被占用，也可能处于未正常关闭状态，得先判断可读性再决定是否修复；SID 必须关联到用户名，否则数据再准也落不到具体的人身上；时间基准要显式转换，SRUM 原始 ESE 字段与不同解析工具导出的时间格式可能不同，必须先确认该字段的实际编码与转换过程，不能一律按 Unix 秒处理。

下游依赖它的输出。网络发送字节数是外泄量化的核心输入。`UserInputTime` 接近 0 而 `Duration` 很大，说明程序在跑但没人操作——这个区分是判断自动化脚本与人工操作的关键。`InterfaceLuid` 还能把「在家大量外发」与「在公司正常同步」分开。

这些内容 SRUM 自己搞不定。程序执行要靠[Prefetch 深度解析](../computer-execution/computer-execution-prefetch.md)与[ShimCache 与 Amcache](../computer-execution/computer-execution-shimcache-amcache.md)确认，网络会话细节要靠[事件日志深度分析](../computer-registry-log/computer-registry-log-windows-event-log-analysis.md)。

落到具体表上：

| 表 | 主要字段 | 取证价值 |
|---|---|---|
| Application Resource Usage（`{D10CA2FE-...FA89}`） | `TimeStamp`、`AppId`、`UserId`、前后台 `CycleTime`、`BytesRead`/`BytesWritten` | **程序执行 + 用户归属 + 磁盘读写量** |
| App Timeline Provider（`{5C8CF1C7-...}`） | `AppId`、`UserId`、`EndTime`、`Duration`、`InFocusTime`、`UserInputTime` | **前台活跃时长、是否有真实用户输入** |
| Network Data Usage | `TimeStamp`、`AppId`、`UserId`、`BytesSent`、`BytesRecvd`、`InterfaceLuid`、`L2ProfileId` | **外泄量化的核心证据** |
| Network Connectivity Usage | 网络配置标识、连接时长、接口类型 | 印证「当时连的是哪类网络」 |
| Energy Usage | 累计电量消耗 | 长时间后台运行的旁证 |
| Push Notifications | 通知类型与数量 | 消息类应用活跃度 |
| 落点 | `%SystemRoot%\System32\SRU\SRUDB.dat` | ESE 数据库，**需专用工具读取，不能用 SQLite 工具** |

三处容易出错的判定先记下来。App Timeline 是独立 GUID，Win8.1 上找不到它属于正常状态——这张表自 Win10 1607 起才存在。`FA89` 与 `FA86` 只差一位，却是两张完全不同的表，不要混引。`Timestamp` 的基准是 Unix 秒，`Duration` 是毫秒，量纲要逐列确认。

据此能回答的是：某个可执行文件在某个小时段是否运行过、属于哪个用户、消耗了多少 CPU 与磁盘 I/O、发送与接收了多少字节、当时窗口在前台多久、检测到多少键盘鼠标输入，以及走的是哪块网卡。

回答不了的部分很多，外加三条必须先写进报告的时间语义结论：

- `Timestamp` 是记录的插入时间，不是行为发生时间。它表示「这一小时的数据被写入的时刻」，精度只有小时级，同一时间戳下常有多条记录共享它。
- 每小时首条与末条记录不精确对应真实的首次与末次执行。任何基于 SRUM 的时间断言都只能是估算，需要用 Prefetch、事件日志、NTFS 时间戳去收敛。
- 「某个程序跑过几小时」不等于「某个程序成功完成了某事」。SRUM 记的是资源消耗，不记行为结果。
- 具体传出了什么内容。字节数是量化指标，不是内容，内容判定要靠浏览器历史或代理侧日志。
- 被覆盖的时段。窗口通常只有 30 到 60 天，超出部分在镜像里就不存在。
- 网络会话的目的地。`InterfaceLuid` 给的是接口标识，不是远端地址，后者要靠网络侧或事件日志。
- `UserId` 对应的人。字段是 SID 字符串，必须关联注册表才能落到具体人，只报 SID 在报告里不可读。
- `AppId` 一定是路径。对第三方程序通常是可执行文件完整路径，对系统内置组件则可能是描述性名称，判断「是否用户态程序」时不能想当然。

相关基础包括：ESE 数据库的结构与读取方式，它是 Windows 自己的存储引擎，与 SQLite 完全不是一回事，误用 SQLite 工具只会得到无意义的输出；SID 与用户名的关联方法，基础在[注册表取证](../computer-registry-log/computer-registry-log-registry-forensics.md)的 hive 解析；

时间戳的纪元换算，SRUM 的 Unix 秒与 NTFS 的 FILETIME 之间需要显式转换；以及 Windows 的用户与网络配置概念，`InterfaceLuid` 与 `L2ProfileId` 的语义需要这块背景。

还有一条纪律：修复数据库是不可逆操作，只能在原始副本上做，原始文件的哈希必须先记录。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 位置与获取约束

数据库位于：

```text
C:\Windows\System32\sru\SRUDB.dat
```

它与注册表中的扩展描述键配套：

```text
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions
```

该键的每个子键对应一个 GUID 扩展及其配套 DLL，比如应用资源使用由 `appsruprov.dll` 提供、网络使用由 `nduprov.dll` 提供。

键里没有活动数据。它只描述数据库中会有哪些表，属于写入前的描述与缓冲配置，作用与数据库表结构对应，很容易被误当成数据源。

`SRUDB.dat` 是 ESE（Extensible Storage Engine，又称 Jet Blue）数据库，Active Directory、Windows Search 用的是同一引擎。

采集环节有两条硬约束：

- 在线系统上它被 Diagnostic Policy Service 等组件持有，通常无法直接复制，要通过卷影副本、离线磁盘、系统镜像或采集工具获取。
- 未正常关机时数据库可能处于非干净状态，解析前需要用 `esentutl` 修复。

<a id="section-4"></a>

### 2.2 落盘模型：为什么时间戳是「小时」

SRUM 的采集与写入模型决定了它的全部时间语义：

1. 运行时数据先进入内存或注册表侧的暂存结构；
2. 约每小时一次落盘到 `SRUDB.dat`；
3. 系统关机或重启时也会触发一次落盘。

由此推出三条硬约束（逐条判读与报告表述见 4.2 陷阱 4、陷阱 5）。

<a id="section-5"></a>

### 2.3 关键表与字段

| 表 | GUID | 主要字段 | 取证价值 |
| --- | --- | --- | --- |
| Application Resource Usage | `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}` | `TimeStamp`、`AppId`、`UserId`、前后台 `CycleTime`、`BytesRead`/`BytesWritten`、`NumReadOperations`/`NumWriteOperations` | **程序执行 + 用户归属 + 磁盘读写量** |
| **App Timeline Provider** | `{5C8CF1C7-7257-4F13-B223-970EF5939312}` | `AppId`、`UserId`、`EndTime`、`Duration`、`InFocusTime`、`UserInputTime` | **前台活跃时长、是否有真实用户输入** |
| Network Data Usage | `{973F5D5C-1D90-4944-BE8E-24B94231A174}` | `TimeStamp`、`AppId`、`UserId`、`BytesSent`、`BytesRecvd`、`InterfaceLuid`、`L2ProfileId` | **外泄量化的核心证据** |
| Network Connectivity Usage | `{DD6636C4-8929-4683-974E-22C046A43763}` | 网络配置标识、连接时长、接口类型 | 印证「当时连的是哪类网络」 |
| Energy Usage | `{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}` | 累计电量消耗 | 长时间后台运行的旁证 |
| Push Notifications | `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}` | 通知类型与数量 | 消息类应用活跃度 |

**两条对应关系值得记住**。

App Timeline Provider 是独立 GUID（`{5C8CF1C7-...}`），与 Application Resource Usage 的 `{D10CA2FE-...FA89}` 不是同一张表。后者采集自 Windows 8.1，App Timeline 自 Windows 10（1607）起才有，Win8.1 机器上找不到它是正常的，不构成取证失败。

`Application Resource Usage` 的 GUID 尾号是 `FA89`，Push Notifications 是 `FA86`，两者仅差一位却完全不是一回事，不要混引。

`UserId` 字段是 SID 字符串，必须与注册表中的用户名关联才能落到具体人（解析方法见 4.2 陷阱 6）：

```sql
SELECT name FROM sam WHERE label = 'Users' AND sid = 'S-1-5-21-...';
```

`AppId` 字段对第三方程序通常是可执行文件完整路径，对系统内置组件则可能是描述性名称而非路径，这一点在判断「是否用户态程序」时不能想当然。

`Network Data Usage` 的 `InterfaceLuid` 标识走的是哪块网卡，`L2ProfileId` 标识当时的网络配置档。笔记本在咖啡厅与在办公室对应不同接口，LUID 也不同，这个维度能把「在家大量外发」与「在公司正常同步」区分开。

App Timeline 的时间语义要单独说明。

`EndTime` 是该次运行的近似结束时刻，`Duration` 是总时长，单位为毫秒；`InFocusTime` 是窗口处于前台的时间，`UserInputTime` 是检测到键盘或鼠标输入的时间。

`UserInputTime` 接近 0 而 `Duration` 很大，意味着程序在跑但没有人操作它，这是判断自动化脚本与人工操作的关键区分。

<a id="section-6"></a>

### 2.4 时间字段基准

SRUM 表中的 `Timestamp` 字段是 Unix 纪元起的秒数，与 NTFS FILETIME（1601 起 100 纳秒）完全不同。

Timeline 表中的部分持续时间字段以微秒或毫秒表示，量纲同样要逐列确认，不能凭字段名猜单位。

把 SRUM 与 NTFS、事件日志对齐时，转换要显式完成：

```sql
datetime(Timestamp, 'unixepoch')            -- Unix 秒
-- 等价于 FILETIME 视角：
(Timestamp * 10000000) + 116444736000000000
```

<a id="section-7"></a>

## 三、操作步骤

<a id="section-8"></a>

### 3.1 提取与初步固定

在线系统先做卷影副本；离线检材从镜像中抽取：

```bash
mmls /work/DigiForensics.dd
fsstat -o 2048 /work/DigiForensics.dd

fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -Ei '/Windows/System32/sru/.*\.dat$' \
  | awk '{print $2}' \
  | while read -r ino; do
      icat -o 2048 /work/DigiForensics.dd "$ino" > "/evidence/sru/$(basename "${ino%%:*}").dat"
    done
```

同时提取关联的注册表 hive，用于 SID 解析与扩展表对照：

```bash
fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -Ei '/Windows/System32/config/(SOFTWARE|SYSTEM)$' | grep -E '^r/r' | awk '{print $2}' \
  | while read -r ino; do
      icat -o 2048 /work/DigiForensics.dd "$ino" > "/evidence/registry/$(basename "${ino%%:*}").hive"
    done
```

<a id="section-9"></a>

### 3.2 修复数据库

复制一份工作副本后再修复，不要在原始证据上操作：

```bash
cp "/evidence/sru/SRUDB.dat" "/evidence/sru/work/SRUDB.dat"
cd /evidence/sru/work
esentutl.exe /r SRUDB /i
esentutl.exe /p SRUDB.dat
```

如果 `esentutl` 报告日志文件缺失，可在工作目录补齐与数据库同名的日志文件占位后再试。具体错误码含义以实际系统输出为准，不要跳过失败直接进入解析。

<a id="section-10"></a>

### 3.3 解析导出

```bash
SrumECmd.exe -f "C:\evidence\sru\SRUDB.dat" `
  --csv "C:\evidence\out\srum" --csvf "srum_report.csv"
```

`SrumECmd` 会输出按表分类的 CSV，典型类别包括应用资源使用（AppResourceUseInfo）、应用时间线（AppTimelineProvider）与网络使用（NetworkUsages）。传入 `SOFTWARE` hive 可以自动把 SID 关联为用户名，省去手工查表。

<a id="section-11"></a>

### 3.4 手工查询核心表

用 `esedatabaseview` 或支持 ESE 的工具直接查看表结构后执行查询。先按「非常规应用 + 异常时段」过滤，再看网络用量：

```sql
-- 发送字节量 Top 20 的应用与用户
SELECT AppId, UserId, BytesSent, BytesRecvd,
       datetime(Timestamp,'unixepoch') AS hour_utc
FROM "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
ORDER BY BytesSent DESC
LIMIT 20;

-- 非常规可执行文件路径（系统目录之外的深路径）
SELECT AppId, UserId,
       datetime(Timestamp,'unixepoch') AS hour_utc,
       ForegroundBytesWritten AS fg_write
FROM "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"
WHERE AppId LIKE '%Users%' AND AppId LIKE '%.exe'
ORDER BY fg_write DESC;
```

<a id="section-12"></a>

### 3.5 与其他工件对齐

SRUM 单独只能给出「某小时某程序有活动」，必须交叉。

Prefetch 确认程序确实执行过，并给出执行次数与最后运行时间。事件日志用 `4624` 确认登录主体，`7045` 系统日志确认服务安装，判断是否为持久化。NTFS `$UsnJrnl` 确认文件创建与写入的具体时刻，把小时级估算收敛到分钟。防火墙或代理日志用接口 LUID 与时间窗去匹配真实连接。

若 SRUM 显示某程序在非工作时间有大量 `BytesSent`，而 Prefetch 记录的执行时间与之相符，两者互证后结论强度显著提升。
<a id="section-13"></a>

## 四、常见陷阱

<a id="section-14"></a>

### 4.1 采集与数据库处置

<a id="section-15"></a>

#### 陷阱 1：★ 在原始证据文件上跑 `esentutl` 修复数据库

**现象**

从镜像里 `icat` 出来的 `SRUDB.dat` 直接交给 `esentutl /r` 修复，解析成功后把修复后的文件留作工作副本，原始文件覆盖掉了。报告里写「已修复并解析 SRUDB」。

**原因**

`SRUDB.dat` 是 ESE 数据库，未正常关机时可能处于非干净状态，存在未提交事务、日志与数据库不一致，直接解析会失败或只解析出部分表。

修复确实必要。但要注意它的副作用：

- `esentutl /r` 会改写数据库结构，重建索引、回滚未提交事务、重写页结构
- `esentutl /p` 整理数据库时直接重写整个文件
- 修复后的文件不再等于磁盘上的原始内容，哈希改变

一旦在原始文件上做这些操作，「该文件与磁盘镜像一致」这个前提就没了。

SRUM 是案件中经常成为唯一量化证据的工件，它的原始性争议代价很高。

**影响**

- 检材哈希链断裂，无法自证未改写证据，质证时构成硬伤
- 修复过程可能丢弃未提交事务中的数据，而这部分数据恰恰可能是关键记录
- 「修复后能解析」这个结果无法说明修复前后的差异，报告无法交代处置过程

**核查**

原始文件只读留存，工作副本上修复，两份都要记录哈希：

```bash
# 第一步：原始抽取文件立即计算哈希并登记
shasum -a 256 /evidence/sru/SRUDB.dat | tee /evidence/sru/SRUDB.dat.sha256

# 第二步：复制工作副本后再修复
mkdir -p /evidence/sru/work
cp -p /evidence/sru/SRUDB.dat /evidence/sru/work/SRUDB.dat
cd /evidence/sru/work
esentutl.exe /r SRUDB /i      # 恢复一致性
esentutl.exe /p SRUDB.dat     # 整理

# 第三步：保留修复日志，它记录了丢弃了哪些事务
```

如果 `esentutl` 报告日志文件缺失，需要在工作目录补齐与数据库同名的日志文件占位后重试。修复日志必须附进证据卷宗，它说明「丢失了未提交事务」这个事实，是数据完整性判断的依据。

<a id="section-16"></a>

#### 陷阱 2：解析失败或只解析出部分表，写成"该时段无记录"

**现象**

`SrumECmd` 跑完输出里少了网络使用表，报告直接写「该时段无网络使用记录」。或者工具报了一串错误，结论写成「SRU 中无相关数据」。

**原因**

`SRUDB.dat` 未正常关机时处于非干净状态，跳过修复直接解析会出现多种失败形态：

- 完全打不开，报数据库版本或日志不一致
- 能打开但只解析出部分表，这种最有欺骗性，因为输出看起来是成功的
- 索引损坏导致查询结果不完整，条数明显偏少但没有报错

把这三种形态都写成「无记录」，方向完全错了。

数据可能就在库里，只是没解出来。

**影响**

- 「该时段无网络使用记录」是一个强否定结论，如果数据实际存在，报告就出现了与事实相反的陈述
- 跳过修复的成本极低，一次 `esentutl` 而已，而漏判的代价是丢掉案件唯一的量化证据
- 委托方可能据此判断该时段确实没有外发，从而放弃追查

**核查**

修复是前置步骤，不是可选项：

```bash
cd /evidence/sru/work
esentutl.exe /r SRUDB /i
esentutl.exe /p SRUDB.dat
SrumECmd.exe -f SRUDB.dat --csv /evidence/out/srum --csvf srum_report.csv

# 核对四张核心表是否齐全（缺表必须写明，不能当「无数据」）
ls /evidence/out/srum/ | grep -iE 'AppResourceUse|AppTimeline|NetworkUsage'
```

如果修复后确实仍缺表，报告按下面写：

> `SRUDB.dat` 经 `esentutl` 修复后，`Network Data Usage` 表（`{973F5D5C-…}`）仍无法读取，修复日志显示索引页损坏。该表的时段覆盖度未能确认，期间的发送/接收字节量未能验证。已改用 `$UsnJrnl` 与代理日志估算，见 5.3 节。

「未修复就放弃」与「修复后仍不可读」是两种完全不同的情况，报告里必须区分。

<a id="section-17"></a>

#### 陷阱 3：把注册表 `SRUM\Extensions` 当成活动数据源

**现象**

在 `SOFTWARE` hive 里找到 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions`，看到下面挂着十几个 GUID 子键和配套 DLL 名，就把它当成「SRUM 数据」来查使用记录；或者反过来，因为这个键里没有时间戳而认为 SRUM 没在工作。

**原因**

这个键里没有任何活动数据。

它的内容是：

- 每个子键对应一个 GUID 扩展标识，即 SRU 数据库中的表
- 值是实现该表的配套 DLL 名称，应用资源使用由 `appsruprov.dll` 提供、网络使用由 `nduprov.dll` 提供

它属于写入前的描述与缓冲配置，作用是告诉系统「数据库里会有哪些表、每张表由哪个组件负责写」。真正的活动记录全部在 `SRUDB.dat` 的 ESE 表里。

这个键还有一个很有迷惑性的特征：内容丰富、结构规整、每个子键都有 GUID 标识，看起来很像数据表定义，于是容易被误认成数据本身。

**影响**

- 从这个键推不出任何活动记录，写进报告就是捏造数据源
- 反向误判同样存在：认为键里没有时间戳就断定 SRUM 未启用，而实际上 SRUM 可能工作正常

**核查**

明确分工，二者配合使用：

| 来源 | 提供什么 | 不提供什么 |
| --- | --- | --- |
| `HKLM\…\SRUM\Extensions` | **表结构描述**：哪些 GUID 表存在、由哪个 DLL 写入 | **任何活动记录** |
| `SRUDB.dat` | 实际的活动记录与资源用量 | 表的定义说明 |

```bash
# 从 Extensions 键确认本机应有哪些表
reged -x /evidence/registry/SOFTWARE.hive \
  "Microsoft\Windows NT\CurrentVersion\SRUM\Extensions" 2>/dev/null | head -30

# 实际数据一律从数据库读
SrumECmd.exe -f SRUDB.dat --csv /evidence/out/srum --csvf srum_report.csv
```

`Extensions` 键的真正用途是核对表清单。如果某个 GUID 子键存在但数据库里读不到对应表，说明该表损坏或不可读，这是判断缺表成因的依据。

<a id="section-18"></a>

### 4.2 时间语义与字段判读

<a id="section-19"></a>

#### 陷阱 4：把 `Timestamp` 当成行为发生时间

**现象**

`Network Data Usage` 表中某条记录 `Timestamp` 对应 `2024-05-18 01:00`，`BytesSent` 为 1.8 GB，报告写「jwang 于 2024-05-18 01:00 发起 1.8 GB 外发」。

**原因**

SRUM 的落盘模型决定了 `Timestamp` 的语义：

1. 运行时数据先进入内存或注册表侧的暂存结构
2. 约每小时一次落盘到 `SRUDB.dat`
3. 系统关机或重启时也会触发一次落盘

所以 `Timestamp` 是记录的插入时间，也就是这一小时的数据被写入的时刻，不是行为发生时间。

由此推出三条硬约束：

- 精度只有小时级，无法定位到分钟或秒
- 同一时间戳下常有多条记录共享它，分属不同应用、不同用户、不同接口
- 首条与末条记录都只是采样边界，不精确对应真实的首次与末次执行

再往前一步，「01:00 这个桶」实际覆盖的是一个区间而不是一个时刻。

从 `01:00` 写入的那批数据，行为可能发生在 `00:05` 到 `01:55` 之间的任何位置。

**影响**

- 写出「01:00 发起外发」这种精确到时刻的断言，而这个时刻是落盘时刻，与行为时刻可能差近一小时
- 时刻断言一旦被质证（你怎么证明是 01:00 而不是 00:30），会影响整份报告的严谨性
- 与其他工件做时间对齐时，小时级偏移会导致看起来对不上，从而错误排除证据

**核查**

SRUM 的时间断言一律表述为小时区间，并说明区间含义：

```sql
SELECT AppId, UserId, BytesSent, BytesRecvd,
       datetime(Timestamp,'unixepoch') AS bucket_start_utc
FROM "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
ORDER BY BytesSent DESC LIMIT 20;
```

报告标准表述：

> `2024-05-18 01:00`（UTC）这一小时桶内，`C:\Users\jwang\…\python.exe` 记录到发送 1.8 GB、接收 41 MB。该时间戳为 SRUM 每小时落盘的插入时刻，实际行为发生在该小时区间内，非精确时刻。精确到分钟的时间由 `$UsnJrnl` 与 Prefetch 收敛（见下条）。

任何需要分钟级精度的结论，都必须由事件日志、Prefetch 或 NTFS 时间戳支撑，不能引用 SRUM。

<a id="section-20"></a>

#### 陷阱 5：只看首条和末条记录就断言程序运行时段

**现象**

某程序在同一小时桶内有多条记录，取 `min(TimeStamp)` 与 `max(TimeStamp)` 就得出「该程序从 01:00 运行到 03:00」，写进时间线当作精确的运行窗口。

**原因**

每小时周期性落盘意味着同一桶内的多条记录共享同一个 `Timestamp`，首末记录反映的是采样边界，不是真实起止：

- 同一桶内 5 条记录，`min` 和 `max` 的 `Timestamp` 完全相同，都是 01:00
- 真实运行时段可能从 01:03 开始、01:12 就结束了
- 也可能 01:00 就在跑，中间断续，01:58 仍在跑

能反映真实时长的字段是 `App Timeline Provider` 表的 `Duration`，单位为毫秒，它的时间语义需要单独说明：

| 字段 | 语义 |
| --- | --- |
| `EndTime` | 该次运行的近似结束时刻 |
| `Duration` | 总时长（毫秒） |
| `InFocusTime` | 窗口处于前台的时间 |
| `UserInputTime` | 检测到键盘/鼠标输入的时间 |

`UserInputTime` 接近 0 而 `Duration` 很大，说明程序在跑但没有人操作它。这是区分自动化脚本与人工操作的关键，也是本篇最重要的判读点之一。

**影响**

- 运行时段被写成看起来精确的窗口，实际误差可能达一小时
- 更严重的是丢掉 `UserInputTime` 这个维度：自动化脚本与人工操作在案件中的定性完全不同，漏看会把脚本行为说成人为操作
- 前后桶的 `Duration` 相加会重复计算（同一进程可能跨桶），总量虚高

**核查**

运行时段用 `App Timeline Provider` 的 `Duration` 表达，同时看 `UserInputTime`：

```sql
SELECT AppId, UserId, EndTime, Duration,
       InFocusTime, UserInputTime,
       -- 人工介入比例：接近 0 说明无用户操作
       ROUND(100.0 * UserInputTime / NULLIF(Duration,0), 2) AS input_pct
FROM "{5C8CF1C7-7257-4F13-B223-970EF5939312}"
WHERE AppId LIKE '%python%'
ORDER BY EndTime DESC;
```

判读分档：

| `input_pct` | 判读 |
| --- | --- |
| 接近 100% | `UserInputTime` 覆盖了 `Duration` 的绝大部分，与人工交互操作一致 |
| 10%–50% | 部分人工、部分自动 |
| **接近 0%** | **`UserInputTime` 远小于 `Duration`，与无人值守的自动化运行一致** |

分档只反映 `UserInputTime` 与 `Duration` 的比值，本身不构成"自动化"的结论。`UserInputTime` 的采集依赖系统级输入钩子，被安全软件干扰、远程会话输入、或者程序自身模拟输入都可能压低这个值；判定为自动化脚本前，需要结合命令行参数、父进程、计划任务或网络连接等同源工件交叉印证。

报告表述：

> 该 Python 进程在两个相邻小时桶内 `Duration` 合计约 5.9 小时，`UserInputTime` 合计不足 4 分钟（占比 < 0.2%），**判定为长时间后台自动化运行，无有效人工操作输入。** `EndTime` 为近似值，不作为精确结束时刻。

<a id="section-21"></a>

#### 陷阱 6：忘记 SID 解析就把 `UserId` 当成账号

**现象**

查询时直接输出 `UserId` 字段，看到 `S-1-5-21-3101292583-1443761041-1408775754-1103` 就写进报告，结论写「该 SID 对应用户在凌晨外发数据」。或者看到 `S-1-5-18` / `S-1-5-19`（服务账户）却当成普通用户。

**原因**

`UserId` 字段是 SID 字符串，必须与注册表中的用户名关联才能落到具体人。

服务账户 SID 与用户 SID 的活动含义也完全不同：

| SID 模式 | 含义 | 判读 |
| --- | --- | --- |
| `S-1-5-21-…-1001` 等 `RID ≥ 1000` | 交互式用户 | 需关联到具体人 |
| `S-1-5-18` | Local Service | 服务活动，通常正常 |
| `S-1-5-19` | Local Service（网络） | 同上 |
| `S-1-5-20` | Network Service | 同上 |
| `S-1-5-21-…-500` | 内置 Administrator | 需注意是否为提权后的交互 |

不解析就下结论会犯两类错：把服务账户的正常活动算到某个人头上，或者把用户的活动归给系统。

**影响**

- 责任归属错误，这是数据外泄案件里最不能出错的一环
- 服务账户（如备份、监控代理）的大流量被算到员工头上，可能冤枉人
- 报告里出现无法复核的 SID 字符串，读者无法验证归属

**核查**

SID 必须解析到用户名，并做双重确认：

```sql
-- 途径一：SAM hive
SELECT name FROM sam WHERE label = 'Users' AND sid = 'S-1-5-21-3101292583-…-1103';

-- 途径二：SOFTWARE hive 的 ProfileList，确认该 SID 有真实用户配置文件
-- HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>\ProfileImagePath
```

```bash
# 传入 SOFTWARE hive 让 SrumECmd 自动关联
SrumECmd.exe -f SRUDB.dat --reg SOFTWAREx64.hive --csv /evidence/out/srum --csvf srum.csv
```

报告必须写清解析链：

> 该记录 `UserId` 为 `S-1-5-21-…-1103`。在 SAM hive 的 `Users` 标签中按 `label` 查到对应条目指向 `MED\jwang`；同时在 `SOFTWARE` hive 的 `ProfileList` 下同一 SID 存在且 `ProfileImagePath` 有效，确认为本机真实交互式用户配置文件。该用户配置文件下的浏览器痕迹亦指向同一活动时段（见 5.5 节）。

<a id="section-22"></a>

#### 陷阱 7：把 `{D10CA2FE-…FA89}` 与 `{5C8CF1C7-…}` 混引，或在 Win8.1 上找不到 App Timeline 就判失败

**现象**

查询时把 Application Resource Usage 的 GUID 与 App Timeline Provider 的 GUID 混用，得到的字段对不上。更常见的是：在一台 Windows 8.1 机器上查不到 `{5C8CF1C7-…}` 表，报告写「App Timeline 表缺失，数据不完整」。

**原因**

这两张表是完全独立的两张表，GUID 不同，起始版本也不同：

| 表 | GUID | 起始版本 | 关键字段 |
| --- | --- | --- | --- |
| Application Resource Usage | `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}` | Windows 8.1 | `CycleTime`、`BytesRead`/`BytesWritten`、`NumReadOperations`/`NumWriteOperations` |
| App Timeline Provider | `{5C8CF1C7-7257-4F13-B223-970EF5939312}` | Windows 10（1607）起 | `EndTime`、`Duration`、`InFocusTime`、`UserInputTime` |

另外还有一个高频引号错误：Application Resource Usage 的 GUID 尾号是 `FA89`，Push Notifications 是 `FA86`，两者仅差一位却完全是不同的表。

**影响**

- 在 Win8.1 机器上找不到表被写成数据不完整，实际是该系统版本本来就没有这张表，属预期状态
- 混引 GUID 导致查询报错或返回错表数据，若未察觉会把一类指标当成另一类
- 把 `FA86` 当成 `FA89` 引到报告里，读者按图索骥找不到对应内容

**核查**

先确认系统版本，再按版本确定可用的表：

```bash
reged -x /evidence/registry/SYSTEM.hive "Select" 2>/dev/null | grep -i CurrentVersion
# 或从 SOFTWARE hive 读 ProductName / CurrentBuild
```

```sql
-- 逐表存在性检查：先列全库有哪些 GUID 表
-- esedatabaseview 或 SrumECmd 的 CSV 目录
ls /evidence/out/srum/ | grep -oE '\{[0-9A-F-]{36}\}'
```

按版本确定预期：

| 系统版本 | App Timeline（`{5C8CF1C7-…}`） | 报告表述 |
| --- | --- | --- |
| Windows 10 1607 及以上 | 应存在 | 缺失则说明表损坏或不可读 |
| Windows 8 / 8.1 | 本就不存在 | 「该系统版本早于 App Timeline 引入（Win10 1607），无此表属预期，不构成数据缺失」 |

分析报告和脚本里一律用完整 GUID 引用表，不使用缩写形式，避免 `FA86` 与 `FA89` 混引。

<a id="section-23"></a>

### 4.3 量化解读与结论边界

<a id="section-24"></a>

#### 陷阱 8：把 `AppId` 都当成可执行文件路径

**现象**

看到 `AppId` 字段是 `svchost.exe`、`MsMpEng.exe` 这类名称，就按「可执行文件名」去全盘搜索定位文件；或者反过来，看到 `AppId` 是一长串路径，就断定「这是用户态程序，非系统组件」。

**原因**

`AppId` 的取值有两种形态，取决于程序来源：

| `AppId` 形态 | 含义 | 示例 |
| --- | --- | --- |
| 可执行文件完整路径 | 第三方程序与多数系统程序 | `C:\Users\jwang\AppData\Local\Programs\Python\Python312\python.exe` |
| 描述性名称 | 部分系统内置组件，不是路径 | `svchost.exe`、`MsMpEng.exe`、`RuntimeBroker` |

由此有两个方向的问题。

用 `AppId` 里的名称去定位文件时，描述性名称可能定位不到实体文件；判断「是否用户态程序」时也不能想当然，路径形态的 `AppId` 才是可靠判据。

同时 `AppId` 里是路径这一点也带来一个反向陷阱：路径里出现 `Users` 目录不等于该文件一定是恶意，也不等于一定是用户主动安装的，可能是更新器解压的组件。

**影响**

- 用描述性名称搜索无结果，被写成「该程序未安装」或「文件已删除」，实际只是 `AppId` 不是路径
- 反向误判：把系统组件的正常流量算到用户程序头上

**核查**

先判断 `AppId` 形态，再决定后续动作：

```sql
-- 筛选真正可用的路径形态（非常规用户态程序）
SELECT AppId, UserId,
       datetime(Timestamp,'unixepoch') AS bucket_utc,
       ForegroundBytesWritten AS fg_write
FROM "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"
WHERE AppId LIKE '[A-Z]:\%'          -- 路径形态
  AND AppId LIKE '%Users%'          -- 用户目录下
  AND AppId LIKE '%.exe'            -- 可执行文件
ORDER BY fg_write DESC;

-- 单独列出非路径形态，理解为系统内置组件的常规活动
SELECT DISTINCT AppId FROM "{D10CA2FE-…FA89}" WHERE AppId NOT LIKE '[A-Z]:\%';
```

对路径形态的 `AppId`，还要做两项交叉：文件是否仍存在（用 MFT / Prefetch 核对）、是否在包管理或安装记录中。

用 `BytesSent` 排序时，系统组件的更新流量通常占据 Top 20 的绝大多数，必须逐条看而不是只取前几条。

<a id="section-25"></a>

#### 陷阱 9：把「N GB 发送量」直接等同于「N GB 敏感数据外泄」

**现象**

`Network Data Usage` 显示某程序在两个小时桶内发送 4.1 GB，报告直接写「外泄 4.1 GB 数据」，并把它作为结论的主要量化指标。

**原因**

`BytesSent` / `BytesRecvd` 只记录字节总量，不携带任何内容语义。

总量可能来自：

- 真实的外发数据
- 视频流、固件更新、系统遥测等大流量常规业务
- 压缩包内已有大量冗余但体积小的数据
- 重试与重复传输（同一份数据多次发送）

一个很有价值的判读角度是收发比。

若某进程在目标时段 `BytesRecvd`（41 MB）远小于 `BytesSent`（1.8 GB），说明该进程在本地已完成数据聚合与打包，外发时无需再拉取大量数据，这与「临时从云端下载再原样传走」的行为模式明显不同。

但这个判断是推断，不是直接证据。

**影响**

- 「外泄 4.1 GB」被委托方直接当作泄露数据量上报，对外公告、监管报备、损失认定都会基于这个数字
- 一旦后续证明其中大部分是正常流量，报告的量化结论就站不住了
- SRUM 无法提供内容的这一局限若不写明，等于把工具能力边界掩盖了

**核查**

量与质分开表述，并显式声明工具能力边界：

> **量**：`2024-05-18 01:00` 与 `02:00` 两个小时桶内，`C:\Users\jwang\…\python.exe` 累计发送约 4.1 GB、接收约 79 MB，净发送比约 52:1。
>
> **推断**：接收量远小于发送量，与「数据在本地完成聚合打包后外发」的行为模式一致，与「从云端下载后原样转发」不一致。此为基于收发比的推断，非直接证据。
>
> **能力边界**：SRUM 为小时级用量聚合，不记录传输内容、不记录协议与目的地址、不提供进程父子关系与命令行参数。因此本次无法证明外发内容的具体构成。内容层面的认定需依赖代理/防火墙日志、DLP 告警或端点侧证据。
>
> 不得将「4.1 GB 发送量」表述为「4.1 GB 医疗数据外泄」。

<a id="section-26"></a>

#### 陷阱 10：忽略 30–60 天历史窗口，被覆盖后写成"SRUM 无数据"

**现象**

案件涉及的时间跨度是三个月前，但 `SRUDB.dat` 中最早记录只到两个月前。报告写「该时段 SRUM 无记录，未见异常用量」，并以此认为该时段无外发行为。

**原因**

SRUM 的历史窗口通常只有 30 到 60 天，跨重启保留，被覆盖后无法恢复。

这是 ESE 数据库的固定空间分配与循环写入机制决定的，不是配置项能改的。

所以「SRUM 里没有」在跨越窗口的案件里是一个必然结果，而不是发现。

案件时间早于窗口时，SRUM 这个数据源从一开始就不适用。

同时这个工件还有个紧迫性：每多等一天，证据就少一天。等待密钥、等待授权、等待设备送达的每一天都在缩短窗口。

**影响**

- 把「不适用」写成「无异常」，把一个本该排除的时间段说成了已被清白覆盖
- 案件时间越久，越容易发生这类误判，而它最难被发现

**核查**

先确认案件时间与窗口边界的关系，再决定 SRUM 是否适用：

```bash
# 查 SRUM 实际的时间覆盖范围
sqlite3 /evidence/out/srum/*.csv "SELECT min(bucket_start_utc), max(bucket_start_utc) FROM network_usage;"
# 或在 ESE 库上查 Timestamp 的 min/max
```

按关系分档表述：

| 案件时间 vs 窗口 | 表述 |
| --- | --- |
| 落在窗口内 | 「可覆盖该时段」 |
| 早于窗口起点 | 「案件时段早于 SRUM 历史窗口（起点 X），本工件不适用。转向 Prefetch、MFT、事件日志与备份」 |
| 晚于窗口终点 | 检查是否系统时钟异常或取证时间早于最后落盘 |

排期上，SRUM 属于每多等一天就少一天的紧迫工件，应在证据固定阶段优先处理，而不是和其他工件一起排队。
<a id="section-27"></a>

## 五、案例示例

<a id="section-28"></a>

### 5.1 未修复的 SRUDB.dat 导致整表不可读与结论错误

**场景**

某医疗机构服务器 `MED-FILE-02` 报告有员工医疗数据外泄，需确定外泄程序、归属用户与外泄量级。

检材为服务器磁盘镜像，卷偏移 2048。委托方已在系统层面排查无果，需要从资源使用记录切入。

**处置过程**

第一步，提取数据库与辅助文件，并立即记录哈希：

```bash
mkdir -p /evidence/sru/work
cp /mnt/medfile02/Windows/System32/sru/SRUDB.dat /evidence/sru/work/
ls /evidence/sru/work/
shasum -a 256 /evidence/sru/work/SRUDB.dat | tee /evidence/sru/SRUDB.dat.sha256
# → 9b2e…7d41  SRUDB.dat
```

第二步，先在副本上尝试直接打开，观察失败形态：

```bash
cd /evidence/sru/work
python3 -c "
import sqlite3
try:
    c = sqlite3.connect('file:SRUDB.dat?mode=ro&immutable=1', uri=True)
    print(c.execute('select count(*) from {3844871e-e217-11d9-aa6d-00e04eb7f261}Data').fetchone())
except Exception as e:
    print('ERROR:', type(e).__name__, e)
"
# → ERROR: DatabaseError file is not a database
```

第三步，用 ESE 修复工具在副本上恢复一致性（`/r` 软恢复 → `/p` 补丁）：

```bash
cd /evidence/sru/work
esentutl /r SRUDB /i /l /evidence/sru/esentutl-r.log
esentutl /p SRUDB.dat /l /evidence/sru/esentutl-p.log
grep -iE 'error|dirty|commit' /evidence/sru/esentutl-p.log | head
```

```text
Repairing SRUDB.dat ...
Table: SruDbCheckpointTable  Dirty Pages: 3
Table: {3844871e-…}Data      Dirty Pages: 11
Operation completed successfully.
```

第四步，验证四张核心表是否可读：

```bash
python3 - <<'PY'
import sqlite3
c = sqlite3.connect("file:/evidence/sru/work/SRUDB.dat?mode=ro", uri=True)
for t in ("{9840C001-…}NetworkDataUsage",
          "{973F5D5C-…}NetworkConnectivityUsage",
          "{DD6636C4-…}ApplicationResourceUsage",
          "{D10CA2FE-…}EnergyUsage"):
    try:
        print(f"{t:42s} rows={c.execute(f'select count(*) from {t}').fetchone()[0]}")
    except Exception as e:
        print(f"{t:42s} ERROR {e}")
PY
```

```text
{9840C001-…}NetworkDataUsage                rows=1184362
{973F5D5C-…}NetworkConnectivityUsage        rows=  289104
{DD6636C4-…}ApplicationResourceUsage        rows=2418663
{D10CA2FE-…}EnergyUsage                     rows=  96431
```

第五步，固定「未修复就放弃」的失败结论作为对照基线：

```bash
# 假想的错误路径：直接查前 20 条 BytesSent
python3 - <<'PY'
# 若未修复：sqlite3 报 file is not a database
# 分析者常见反应是"该库损坏，不可用" → 报告写成"SRUM 无有效数据"
# 实际：损坏的是索引/日志页，Data 页主体仍可恢复
print("未修复 → 0 行可读；已修复 → 1,184,362 行")
PY
```

**结论**

未经处理的 `SRUDB.dat` 直接以 SQLite 打开报 `file is not a database`，四张核心表全部不可读。若此时放弃，会得出「SRUM 无有效数据、系统侧无外泄记录」这一与事实相反的结论。经 `esentutl /r` 与 `/p` 在副本上修复后，修复日志显示存在未正常关机留下的未提交事务与 14 个脏页，恢复完成后四张核心表全部可读，网络使用表 1,184,362 行、应用资源使用表 2,418,663 行。

本次的处置结论是：SRUDB.dat 属于「可修复的逻辑损坏」而非数据销毁，修复动作全程在工作副本上进行，原始检材哈希 `9b2e…7d41` 在修复前后一致，可证明修复未触及原始证据。

**误判对照**

本案例最典型的错误结论是把 `file is not a database` 直接判定为「数据库损坏、无可用数据」。

正确判据是 SRUDB.dat 并非 SQLite 原生数据库，而是 ESE（Extensible Storage Engine）数据库，SQLite 报「不是数据库」只说明格式不匹配，是用错了解析器，而非文件损坏；真正的损坏信号来自 ESE 层，也就是修复日志中的脏页计数与未提交事务。

按错误判据处置，代价是全案失去系统侧唯一的持续性流量记录，而这份数据恰好能回答「发了多少、哪个程序、哪个用户」三个核心问题；委托方会同时收到一份「系统侧未发现异常」的虚假否定结论。

第二处易错点是直接对**原始检材**执行 `esentutl /p` 补丁修复。

正确判据是 ESE 的 `/p` 会真实改写数据库页，无论是否「修复」，写入动作本身都会修改检材内容与哈希，破坏证据的完整性证明。

本案的处置顺序是先 `cp` 到 `/evidence/sru/work/`，所有修复命令都在副本上执行，修复前后对原始文件重算哈希并与证据登记表的 `9b2e…7d41` 比对一致。

按错误判据在原始镜像挂载点上直接修复，报告里所有基于该文件的结论都会因证据链完整性受质疑而在质证阶段失效，前期全部工作归零。

第三处易错点是修复成功后对四张表一视同仁地采信。

正确判据是 ESE 的事务粒度决定未提交事务只影响最后写入的那几张表与部分行。`ApplicationResourceUsage` 行数最多（2,418,663）且更新最频繁，受损概率最高，其末段时间桶可能缺失；而 `{973F5D5C-…}NetworkConnectivityUsage` 更新频率低、内容稳定，可靠性更高。

本案即使在修复后也应先检查各表的末行时间戳以界定数据截止点，而不是简单认为「修复了就是完整的」。

<a id="section-29"></a>

### 5.2 进程级流量排序锁定异常程序并回溯到具体用户

**场景**

修复后的数据库可用。委托方要求定位外泄程序、归属用户与外泄量级。系统上安装了大量安全软件与更新组件，表面流量噪音极大。分析要回答的是排序维度对识别结果的影响：按字节量排和按程序维度筛，结论完全相反。

**处置过程**

第一步，按 `BytesSent` 降序取前 20，先看排序结果的整体构成：

```bash
python3 - <<'PY'
import sqlite3
c = sqlite3.connect("file:/evidence/sru/work/SRUDB.dat?mode=ro", uri=True)
q = """SELECT AppId, UserId, BytesSent, BytesRecvd, TimeStamp
       FROM {9840C001-…}NetworkDataUsage
       ORDER BY BytesSent DESC LIMIT 20"""
rows = c.execute(q).fetchall()
sysc = sum(1 for r in rows if r[0].lower() in
           ("c:\\windows\\system32\\svchost.exe",
            "c:\\program files\\…\\msmpeng.exe",
            "c:\\windows\\softwareupdate\\wusearch.exe"))
print(f"前 20 条中系统组件占 {sysc} 条")
for r in rows[:3]:
    print(r)
PY
```

```text
前 20 条中系统组件占 19 条
('c:\\program files\\...\\msmpeng.exe', 'S-1-5-18', 2147483648, ...)
('c:\\windows\\system32\\svchost.exe',     'S-1-5-18', 1878003712, ...)
('c:\\users\\jwang\\appdata\\local\\programs\\python\\python312\\python.exe',
 'S-1-5-21-3101292583-1443761041-1408775754-1103', 2462910464, 43018107)
```

第二步，按程序路径而非按字节量排序，避开系统组件噪音：

```bash
python3 - <<'PY'
import sqlite3
c = sqlite3.connect("file:/evidence/sru/work/SRUDB.dat?mode=ro", uri=True)
q = """SELECT AppId, UserId, BytesSent, BytesRecvd,
              datetime(TimeStamp,'unixepoch','localtime')
       FROM {9840C001-…}NetworkDataUsage
       WHERE AppId LIKE '%python%' OR AppId LIKE '%\\\\	emp\\\\%'
          OR AppId LIKE '%\\\\appdata\\\\local\\\\	emp%'
       ORDER BY TimeStamp;"""
for r in c.execute(q):
    print(f"{r[4]}  sent={r[2]:>12,}  recv={r[3]:>11,}  {r[0]}")
PY
```

```text
2024-05-18 01:00:00  sent=  1932735283  recv=  43018107   …\python.exe
2024-05-18 02:00:00  sent=  2462910464  recv=  39845888   …\python.exe
```

第三步，解析表 GUID 字段 `TimeStamp` 的时间桶语义（按小时对齐的桶起点）：

```bash
python3 - <<'PY'
# 桶 01:00 与 02:00 各覆盖一小时，即行为发生在 01:00:00–02:59:59 区间
print("桶边界解释：TimeStamp=01:00:00 覆盖 01:00:00.000–01:59:59.999")
print("两桶合计 sent =", 1932735283 + 2462910464, "bytes =",
      round((1932735283+2462910464)/1024**3, 2), "GiB")
PY
```

第四步，把 SID 解析为用户名（SAM + ProfileList 双源）：

```bash
python3 - <<'PY'
SID = "S-1-5-21-3101292583-1443761041-1408775754-1103"
# SAM\Domains\Builtin\Users\Names 标签反查
print("SAM 反查 : MED\\jwang  (RID 1103)")
# ProfileList
print("ProfileList: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" + SID)
print("           → ProfileImagePath = C:\\Users\\jwang，本机真实用户配置文件")
PY
```

第五步，验证程序确实在事发时段执行过：

```bash
# Prefetch
python3 - <<'PY'
import struct, datetime
# PYTHON.EXE-*.pf 头部：运行次数 + 8 个执行时间槽
runs, = struct.unpack_from("<I", open("/mnt/medfile02/Windows/Prefetch/PYTHON.EXE-1A2B3C4D.pf","rb").read(4), 84)
slots = struct.unpack_from("<8I", open("/mnt/medfile02/Windows/Prefetch/PYTHON.EXE-1A2B3C4D.pf","rb").read(96), 92)
ts = [datetime.datetime(1601,1,1)+datetime.timedelta(microseconds=s*10) for s in slots if s]
print("运行次数 =", runs, " 末次运行 =", ts[-1])
PY
```

```text
运行次数 = 3  末次运行 = 2024-05-18 01:47:22
```

第六步，回溯脚本的落地时间：

```bash
python3 - <<'PY'
# $UsnJrnl 解析结果
print("2024-05-17 23:40:11  FILE_CREATE  C:\\Users\\jwang\\AppData\\Local\\Temp\\exfil_pkg.py")
print("2024-05-17 23:41:03  DATA_EXTEND  同文件 +14,822 字节")
PY
```

**结论**

按 `BytesSent` 降序取前 20，19 条属于 `svchost.exe`、`MsMpEng.exe`、`wusearch.exe` 等系统组件（`UserId = S-1-5-18`，即 `LocalSystem`（`LOCAL SERVICE` 对应 `S-1-5-19`）），属正常更新与扫描流量。唯一异常项为 `C:\Users\jwang\AppData\Local\Programs\Python\Python312\python.exe`，其 `UserId` 为 `S-1-5-21-3101292583-1443761041-1408775754-1103`，在 2024-05-18 的 01:00 与 02:00 两个小时桶内分别记录发送 1.80 GiB（1,932,735,283 字节）与 2.30 GiB（2,462,910,464 字节）、接收 41.05 MB 与 38.00 MB，合计净发送约 4.10 GiB。

该 SID 经 SAM 的 `Users` 标签反查指向 `MED\jwang`（RID 1103），并经 `ProfileList` 同一 SID 键确认 `ProfileImagePath = C:\Users\jwang`，为本机真实用户配置文件。Prefetch 中 `PYTHON.EXE` 的运行次数为 3、末次运行 2024-05-18 01:47:22，落在 01:00 桶内；

`$UsnJrnl` 显示脚本 `exfil_pkg.py` 于 2024-05-17 23:40:11 被创建、23:41:03 写入 14,822 字节，早于 SRUM 落盘时间。三条独立证据线（SRUM、Prefetch、NTFS）与代理日志在桶边界上吻合，可认定该程序在事发时段产生约 4.1 GiB 的净发送量。

**误判对照**

第二个高发误判是把「前 20 条流量里 19 条是系统组件」直接写成「流量以系统更新为主，不存在异常」。

正确判据是按字节量排序会被系统组件的持续后台流量淹没，异常项的识别必须换维度：按程序路径（如 `AppId LIKE '%python%'`、`LIKE '%\	emp\%'`）或按用户 SID（排除 `S-1-5-18`、`S-1-5-19` 等服务账户）筛选，才能让 4.1 GiB 的用户态异常从 1.8 GB 的系统更新噪声中浮出。

按错误判据处置的代价是本案直接漏检——`svchost.exe` 单条 1.87 GB 与目标程序合计 4.1 GiB 在同一排序表里位置相邻，只看字节量几乎不可能注意到。

第二处易错点是把 `python.exe` 当成「杀毒软件或系统组件的正常行为」。

正确判据是路径。异常项位于 `C:\Users\jwang\AppData\Local\Programs\Python\Python312\`，即用户私有目录下的解释器；系统 Python 或企业部署的解释器通常位于 `C:\Program Files\Python312\` 或 `C:\Python312\`，且以服务账户运行。

按错误判据把用户目录下的解释器流量归为系统行为，等于用「是 Python 写的」这一文件名层面的特征替代路径与账户两个真正的判据，在真实的员工自装脚本场景里会完全放过外泄行为。

第三处易错点是看到 `UserId` 为某 SID 就直接写用户姓名。

正确判据是 SID 到用户名的映射必须双源验证：SAM hive 的 `Users` 标签反查给出 `MED\jwang`，`ProfileList` 下同一 SID 键的 `ProfileImagePath` 确认为本机真实配置文件，两条都成立才能认定该 SID 属于本机真实用户，而不是域漫游、已删除用户或 SID 未分配。

按错误判据只做单源映射就写姓名，在 SID 被重复使用、或从旧镜像继承 ProfileList 残留的场景下会指向错误的人；一旦主体认定错误，报告的全部结论都要重来。

<a id="section-30"></a>

### 5.3 收发比推断与流量总量不等于数据外泄总量

**场景**

委托方要求给出外泄量级，并据此评估影响面。同时需要评估一个常见的推论是否成立：01:00 桶接收 41 MB、发送 1.8 GB，是否能说明数据是「现取现发」的。本案例给出的是结论分级方法：字节总量能支撑什么、不能支撑什么，以及推断与未证明之间的界线画在哪里。

**处置过程**

第一步，计算收发比并检查时间序列上的先后：

```bash
python3 - <<'PY'
rows = [("01:00", 1932735283, 43018107), ("02:00", 2462910464, 39845888)]
for h, s, r in rows:
    print(f"{h}  sent={s:>12,}  recv={r:>11,}  ratio={s/r:6.1f}:1  recv/sent={r/s*100:.2f}%")
tot_s = sum(r[1] for r in rows); tot_r = sum(r[2] for r in rows)
print(f"合计 sent={tot_s:,} ({tot_s/1024**3:.2f} GiB)  recv={tot_r:,} ({tot_r/1024**2:.1f} MiB)")
PY
```

```text
01:00  sent= 1932735283  recv=   43018107  ratio=  44.9:1  recv/sent=2.23%
02:00  sent= 2462910464  recv=   39845888  ratio=  61.8:1  recv/sent=1.62%
合计 sent=4395645747 (4.09 GiB)  recv=82863995 (79.0 MiB)
```

第二步，回溯事发时段之前的本地写入与打包痕迹：

```bash
python3 - <<'PY'
print("2024-05-17 22:10–23:30  $UsnJrnl：MED\\share\\ 下 1,842 个文件被读取（DATA_READ/READ 为 USN 不记录，需以访问时间辅助）")
print("2024-05-17 23:40:11      FILE_CREATE  …\\Temp\\exfil_pkg.py")
print("2024-05-17 23:52:07      FILE_CREATE  …\\Temp\\bundle_20240517.zip")
print("2024-05-17 23:52:31      FILE_CREATE  …\\Temp\\bundle_20240517.zip.part2")
PY
```

第三步，明确外泄内容假设的可证与不可证部分：

```bash
python3 - <<'PY'
# SRUM 只有字节量，没有任何内容字段
print("SRUDB 可证：程序 / 用户 / 时间桶 / 发送字节 / 接收字节")
print("SRUDB 不可证：传输内容、目标 IP、目标端口、协议、父进程、命令行")
PY
```

第四步，代理日志侧的独立印证与边界：

```bash
python3 - <<'PY'
print("代理日志：2024-05-18 01:00–03:00  来自 MED-FILE-02 内网 IP 10.20.3.41 的大流量 HTTPS 连接")
print("代理日志可见：会话时长、字节数、目标域名（若未解密则仅 IP + SNI）")
print("代理日志不可见：HTTPS 载荷内容")
PY
```

第五步，把结论分级写入报告：

```bash
python3 - <<'PY'
levels = [
 ("净发送 4.09 GiB", "SRUM 两桶字节量 + 代理日志", "强"),
 ("该发送由 jwang 账户下的 Python 解释器产生", "SRUM UserId + SAM/ProfileList 双源", "强"),
 ("数据在事发前已本地聚合打包", "收发比 45:1–62:1 + 本地 zip 创建记录", "中强（推断）"),
 ("外发内容为医疗数据", "—", "未证明"),
 ("具体外发文件清单", "—", "未证明"),
]
for a,b,c in levels: print(f"{a:36s} | {b:38s} | {c}")
PY
```

**结论**

两个桶的接收量分别仅为发送量的 2.23% 与 1.62%（收发比 44.9:1 与 61.8:1），合计发送 4,395,645,747 字节（4.09 GiB）、接收 82,863,995 字节（79.0 MiB）。结合事发前夜 `$UsnJrnl` 中 `bundle_20240517.zip` 与 `.zip.part2` 的创建记录，可推断数据在本地已完成聚合与打包，外发时无需再拉取大量数据；

该结论为推断，报告中明确标注。SRUM 能证明的是程序、用户、时间桶、字节收发量；它不能证明传输内容、目标 IP/端口、协议、父进程与命令行，代理日志在未解密 HTTPS 载荷时也只能给出字节数、时长与 SNI。因此报告结论分级为：「净发送 4.09 GiB」与「由 jwang 账户下的 Python 解释器产生」为强证据；

「数据已本地聚合打包」为中强（推断）；「外发内容为医疗数据」与「具体外发文件清单」标记为未证明。

**误判对照**

最容易出现的错误结论是「接收 41 MB、发送 1.8 GB，说明数据是现场从数据库现查现发，不存在预先打包」。

正确判据是收发比只反映该小时内的净流量方向，不区分数据来源——本地已存在的打包文件在上传时同样呈现极低接收量；而「现查现发」通常会伴随可观的接收量，用于拉取查询结果。

按错误判据得出「不存在预先打包」，会漏掉事发前夜 `bundle_20240517.zip` 创建这条最关键的准备行为，把一个「有预谋的打包上传」降格为「临时的数据搬运」，性质判断完全不同。

反向的风险也存在：仅凭收发比就断言「数据一定是打包好的」，同样是过度解读，必须与本地写入记录结合才能成立。

第二处高代价误判是把「净发送 4.09 GiB」直接写成「4.09 GiB 医疗数据外泄」。

正确判据是字节总量只反映传输规模，内容构成在 SRUM 中完全不可见——这 4.09 GiB 可能是压缩后的医疗数据，也可能是日志、备份、镜像或无关文件，甚至包含大量重传（同一字节被多次发送时字节总量照常累加）。

按错误判据写「4.09 GiB 医疗数据外泄」，一旦对方举证这批流量是数据库备份而非患者数据，报告的量级结论即被推翻；而委托方据此做的监管上报、通知义务判断已经发生，实际损害无法通过更正报告挽回。

第三处易错点是把 01:00 与 02:00 两个桶当成两次独立的外发行为，或写成「01:00 与 02:00 两次大规模外发」。

正确判据是 `TimeStamp` 字段是**按小时对齐的桶起点**，01:00 桶覆盖 01:00:00.000–01:59:59.999，02:00 桶覆盖紧随其后的一小时，两桶可能是同一次持续传输被切分的结果。

按错误判据写成两次独立行为，会在报告里虚构出一次并不存在的「第二次外发」，影响行为次数的认定；而正确表述是「01:00–02:59 期间持续产生净发送」。

---
<a id="section-31"></a>

## 六、扩展阅读方向

<a id="section-32"></a>

### 前置基础：数据能读出来、并且落到了具体的人

- [只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md) —— ESE 数据库在活系统上直接打开可能触发改写，固定原始文件是硬前提。
- [注册表取证](../computer-registry-log/computer-registry-log-registry-forensics.md) —— `UserId` 字段是 SID 字符串，必须关联 hive 才能落到用户名，否则数据再准在报告里也不可读。
- [时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md) —— SRUM 的 `Timestamp` 是 Unix 秒，与 NTFS FILETIME 完全不同，跨工件对齐时这是最常出错的一步。
- [取证工件地图](../computer-registry-log/computer-registry-log-windows-artifact-map.md) —— 卷与工件的准备，以及 Windows 版本差异的判定，Win8.1 与 Win10 的可用表不同。

<a id="section-33"></a>

### 同层深入：同一个问题的其它执行侧证据

- [Prefetch 深度解析](../computer-execution/computer-execution-prefetch.md) —— 「程序运行过」的第一顺位证据，它的时间由内核写入、精度到秒，正好补上 SRUM 的小时级粗粒度。
- [ShimCache 与 Amcache](../computer-execution/computer-execution-shimcache-amcache.md) —— 另一个执行侧工件。三者的可信度各不相同，交叉才能收敛。
- [事件日志深度分析](../computer-registry-log/computer-registry-log-windows-event-log-analysis.md) —— 网络会话与登录的细节。SRUM 给的是量与时段，这一篇给的是具体事件，两者拼起来才完整。
- [浏览器取证](computer-browser-behavior-browser-forensics.md) —— SRUM 说「Chrome 往外发了 800MB」，这一篇能回答「访问了哪些 URL」。

<a id="section-34"></a>

### 相邻议题：系统级行为与快照

- [Windows 11 与 Recall](computer-browser-behavior-windows11-recall.md) —— 系统级屏幕快照。Recall 记的是「屏幕上出现过什么」，SRUM 记的是「程序用了多少资源」，两者是不同维度的系统级记录。
- [用户行为痕迹](../computer-registry-log/computer-registry-log-user-activity-artifacts.md) —— `UserInputTime` 的另一种来源。SRUM 的输入时间与 UserAssist 的运行计数是同一件事的两个数据源。
- [proc 虚拟文件系统取证](../computer-shell/computer-shell-proc.md) —— Linux 侧没有系统级的资源使用统计库，等价能力要靠 `/proc` 的运行时快照与包的账本拼出来，两边的证据能力差异在这里最明显。

<a id="section-35"></a>

### 工具与规范：解析与保全

- [证据文件格式](../../fundamentals/fundamentals-chain/fundamentals-chain-dd-e01-aff4-evidence-formats.md) —— ESE 数据库的归档封装。
- [证据保管链与委托证明](../../fundamentals/fundamentals-chain/fundamentals-chain-chain-of-custody-and-authorization.md) —— SRUM 的保留窗口有限，「每多等一天就少一天」意味着提取时点本身就是证据链的一部分，需要记录。

<a id="section-36"></a>

### 判据与反例：哪些解释不能成立

- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— SRUM 的时间戳由系统写入，攻击者改不到，这正是它作为独立时钟的价值。反过来说，若某条记录的时间与 Prefetch 严重矛盾，矛盾本身就是发现。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 估算与断言的区分纪律。本篇 4.3 的结论边界来源：时间断言只能写成估算，量化指标必须写明统计窗口。
<a id="section-37"></a>

## 七、命令速查

```bash
# 1) 确认卷偏移
mmls /work/DigiForensics.dd
fsstat -o 2048 /work/DigiForensics.dd

# 2) 提取 SRUM 数据库（注意目录是 sru 而非 LogFiles）
fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -Ei '/Windows/System32/sru/SRUDB\.dat$' | grep -E '^r/r' | awk '{print $2}' \
  | while read -r ino; do
      icat -o 2048 /work/DigiForensics.dd "$ino" > /evidence/sru/SRUDB.dat
    done

# 3) 计算原始证据哈希（修复前记录）
sha256sum /evidence/sru/SRUDB.dat | tee /evidence/sru/SRUDB.dat.sha256

# 4) 复制工作副本并修复
cp /evidence/sru/SRUDB.dat /evidence/sru/work/SRUDB.dat
cd /evidence/sru/work && esentutl.exe /r SRUDB /i && esentutl.exe /p SRUDB.dat

# 5) 解析并导出 CSV
SrumECmd.exe -f "C:\evidence\sru\work\SRUDB.dat" `
  --csv "C:\evidence\out\srum" --csvf "srum_report.csv"

# 6) 递归批量解析多个镜像来源
SrumECmd.exe -d "C:\cases\srum" --csv "C:\evidence\out\srum_all"

# 7) 列出网络使用表记录按发送量排序
python3 - <<'PY'
import csv, collections
rows = list(csv.DictReader(open(r"C:\evidence\out\srum\NetworkUsages.csv", encoding="utf-8-sig")))
top = sorted(rows, key=lambda r: int(r.get("BytesSent") or 0), reverse=True)[:20]
for r in top:
    print(f'{r.get("AppId")}  {r.get("UserId")}  sent={r.get("BytesSent")}  ts={r.get("Timestamp")}')
PY

# 8) 从 SOFTWARE hive 查 SRUM 扩展描述
reg load HKLM\SRUM_SW "C:\evidence\registry\SOFTWARE.hive"
reg query HKLM\SRUM_SW\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions /s
reg unload HKLM\SRUM_SW

# 9) 交叉验证：Prefetch 中是否有对应程序
PECmd.exe -d "C:\evidence\Prefetch" --csv "C:\evidence\out\pf" --csvf "pf.csv"
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — SRUM 数据库分析」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《SRUM 数据库分析》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-mem.raw` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。

---
