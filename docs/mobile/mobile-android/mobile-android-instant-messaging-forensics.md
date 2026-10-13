---
title: "即时通讯取证"
slug: "mobile-android-instant-messaging-forensics"
canonical: "https://www.digiforensics.cn/wiki/mobile-android-instant-messaging-forensics"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:52+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "mobile"
space: "移动取证"
node_path: ["Android"]
---

# 即时通讯取证

<a id="section-1"></a>

## 一、概述

即时通讯数据在移动取证里证据价值高，也容易被整块漏掉。

难的不是解析。难的是解析之前的每一环都可能悄悄失败：包名找错、数据目录漏了用户、数据库只提了主库、加密没解开、时间戳量级判错。任何一环出错，产出的都是一份看起来完整、实际残缺的结果。

本篇给的是一条完整链路：找包名 → 找数据目录 → 找数据库文件 → 找加密 key → 解密 → 解析表。第三章按步展开。

为什么反复强调"可迁移"。国内案件碰到的 IM 应用版本众多，目录结构随时变，加密方案各不相同。任何绑定具体路径或具体算法的知识都会过期，上面这条判断框架不会。

**本篇给框架，不给某一版应用的目录字典。**

缺了这条框架，常见的后果是"记录只有 8000 条"这种结论。设备上实际有 12000 条，最近 4000 条还躺在 `-wal` 里没回写到主库。主库能正常打开、能列出表名、能查记录数，全程不报错（见 [2.3](#section-5)）。更麻烦的是时间戳量级判错之后把"案发前"读成"案发后"，整条时间线方向全反。

**在取证流程中的位置**：本篇位于**分析环的核心**，是把 [Android 数据存储总览](mobile-android-android-data-storage-overview.md) 提取到的应用目录变成案件可用证据的主要路径。

上游依赖私有目录的完整提取与用户档案枚举，多用户与工作资料必须分别处理。下游支撑三类结论：聊天内容的事实认定、时间线对齐、范围与缺口的书面表述。它同时是 [APK 逆向与 Manifest 分析](mobile-android-apk-manifest.md)、[Frida 动态 Hook](mobile-android-frida-dynamic-hooking.md)、[应用私有数据](mobile-android-sharedpreferences.md) 三篇共同的下游出口。

证据价值上，本篇反复强调三条硬规矩：

1. **聊天记录必须做完整性哈希**——"被篡改 / 被选择性提取"的质疑通常落在这个对象上。
2. **时间线必须能对齐**——IM 应用时间戳格式不统一（秒 / 毫秒、Cocoa / Unix、本地时区），错一格就可能把"案发前"读成"案发后"。
3. **提取范围必须写清楚**——"未获取"要写成"未获取"，不能沉默跳过。

本篇涉及的证据形态（保留真实产品的强制文件名）：

| 形态 | 具体位置 | 说明 |
|---|---|---|
| 库文件 | `EnMicroMsg.db`（微信）、`msg.db`（WhatsApp）、`r0.db`/`r1.db`（QQ 按账号分库） | 主体，**普遍为 SQLite** |
| WAL 三件套 | 同名 `.db-wal`、`.db-shm` | **必须同目录**，`-wal` 可能是数 MB 量级 |
| 账号目录 | `MicroMsg/<32位十六进制>/` | 多账号 / 多设备的维度线索 |
| 媒体目录 | `files/`、`/sdcard/Tencent/WeChat/` | 图片、视频、语音、文档 |
| 外部目录 | `Android/media/<包名>/`（卸载后保留） | 见 [2.2](#section-4) |
| 完整性记录 | 三件套的哈希、`PRAGMA integrity_check` 结果、合并前后 `count(*)` 差值 | **差值就是差点漏掉的记录量，要写进报告** |

某个时间点上账号登录过哪些账号、与谁的对话内容是什么、消息数量与时间范围、哪些内容已被删除但仍可从 freelist 恢复。

对方是否阅读，已读回执不能替代。消息是否被伪造，IM 应用的消息可被本机改写。聊天记录里的时间戳是否可信——应用层时间戳可被改，只有与文件系统 mtime、服务器侧记录交叉印证时强度才够。已卸载、`Android/data` 又被清除、委托方也没给导出文件的情况，本篇方法覆盖不了。

**关于获取解密 key 的边界**：合法途径包括委托方自愿提供、应用内导出的明文文件、**在已获书面授权的检材上做动态分析**（见 [第 4 步](#section-10)）、内存镜像中已解密的数据库页、应用自身的导出功能。

不建议针对商业 App 编写通用解密工具并分发。取证的目标是这一个检材里的证据，不是产品化。本篇不描述任何应用的密钥派生实现。

**读者前提**：需要 [SQLite 基础与结构](../mobile-database/mobile-database-sqlite.md) 的读写能力、[应用私有数据与 SharedPreferences](mobile-android-sharedpreferences.md) 的目录判读，以及 [时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md) 里的量级判定原则。

建议按第三章的顺序走，别跳步。每一步的结论都是下一步的前提。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 前四个环节在解决什么

| 步骤 | 解决什么 | 常见失败原因 |
|---|---|---|
| **① 找包名** | 确定目标进程与数据目录的入口 | 同名应用有多个包名（主应用/轻应用/分身） |
| **② 找数据目录** | 确定 `/data/user/0/<包名>/` 下的具体子目录 | 多用户、应用分身导致路径不同 |
| **③ 找数据库文件** | 定位 `*.db` 及其伴随文件 | 只看 `.db` 漏了 `-wal`/`-shm` |
| **④ 找加密 key** | 判断是否加密、从哪拿 | 未区分 SQLCipher 与应用自加密 |

容易被跳过的环节是第 ③ 步的"完整提取"，它带来的错误结论也较难自查。详见 [09](../mobile-database/mobile-database-sqlite-wal.md)。

<a id="section-4"></a>

### 2.2 公开可知的 IM 应用数据目录

下面这些目录结构都是广为公开的。各版本会变，务必以实际提取结果为准：

| 应用 | 包名 | 数据目录要点 | 备注 |
|---|---|---|---|
| 微信 | `com.tencent.mm` | `MicroMsg/`（主数据）、`files/`（媒体与文档）、`EnMicroMsg.db` | 聊天记录库需 key；`/sdcard/Tencent/WeChat/` 是外部目录 |
| QQ | `com.tencent.mobileqq` | `files/`、`r0.db` / `r1.db` …（按账号分库）、`msg.db` | 多账号分文件是 QQ 的特点 |
| WhatsApp | `com.whatsapp` | `databases/msgstore.db` | 通常需要转换或专用解析器 |
| Telegram | `org.telegram.messenger` | `databases/`（多个 `*.db`） | 部分内容在 `files/` |

> ⚠️ **关于微信 `MicroMsg` 目录**：`MicroMsg/<32位MD5形式的目录>/` 是公开可见的组织方式，用来区分账号与设备。这个 32 位十六进制串的来源与应用内存储的设备标识有关，可以当"多账号/多设备"的判定线索，但具体派生算法属于应用内部实现，本篇不做描述。
>
> ⚠️ **关于加密**：`EnMicroMsg.db` 这类库使用了加密，这是公开信息，`strings` 或 `PRAGMA` 都能探测确认。如何获得解密所需的 key，属于具体应用的逆向范畴，可能触及法律与授权边界。
>
> 合法途径有四种：① 委托方自愿提供、应用内导出的明文文件；② 在**已获书面授权的检材**上做动态分析（见 [04](mobile-android-frida-dynamic-hooking.md)）；③ 内存 dump 中已解密的数据库页，若案件中存在内存镜像；④ 应用自身的「导出聊天记录」功能产生的明文文件。
>
> 不建议针对商业 App 编写通用解密工具并分发给他人使用。取证的目标是获取**这一个检材**中的证据，不是产品化。

<a id="section-5"></a>

### 2.3 关键：`-wal` 与 `-shm` 必须一起提取

这是本篇后果最直接的技术点：漏取时结果是错的，而不是报错的。`app.db` 是主库，`app.db-wal` 是预写日志，**最近的写入在这里**，`app.db-shm` 是共享内存索引。

只提取 `app.db` 的话，`sqlite3 app.db ".tables"` 照样能列出表，`message` 表只有 8000 条，设备上实际有 12000 条。最近 4000 条还在 WAL 里没回写。

据此写下的「记录只有 8000 条」是错的。

正确做法是三个文件放在同一目录。`ls -l extracted/databases/` 确认三件套齐全，先 `PRAGMA wal_checkpoint(TRUNCATE)` 把 WAL 回写再计数。详见 [09-SQLite-WAL取证](../mobile-database/mobile-database-sqlite-wal.md)。

<a id="section-6"></a>

### 2.4 提取后的验证与时间线

数据库层面的验证，每一项都要在报告里体现：`PRAGMA integrity_check` 看结构是否完好，`.tables` 看表是否可读，`SELECT count(*)` 看记录数。

时间戳有三个坑。秒和毫秒混用，数值长度差 1000 倍。Cocoa 时间，iOS 生态常用，基准 2001-01-01，得加 `978307200`。时区，数据库存 UTC 而界面显示本地时区，SQLite 的 `unixepoch` 返回 UTC，要按当地时区换算。

```bash
# 安全的转换方式：先判断量级再转换
sqlite3 app.db "
SELECT CASE
         WHEN ts > 1000000000000000 THEN datetime(ts/1000000 + 978307200, 'unixepoch', '+8 hours')
         WHEN ts > 1000000000000    THEN datetime(ts/1000    + 978307200, 'unixepoch', '+8 hours')
         WHEN ts >  1000000000       THEN datetime(ts         + 978307200, 'unixepoch', '+8 hours')
       END AS time_str
FROM message ORDER BY ts LIMIT 20;"
```

> **Cocoa 时间基准 `978307200`** = 2001-01-01 00:00:00 UTC 的 Unix 秒数。加这个数只是换算基准，是否真的是 Cocoa 时间还得结合字段含义与量级判断（数值落在 0–约 8 亿之间才是 Cocoa）。别盲目加。

---

<a id="section-7"></a>

## 三、操作步骤

<a id="section-8"></a>

### 第 1–2 步：确认包名、提取完整数据目录（含 WAL）

```bash
# 列出所有 IM 相关包（关键词覆盖，务必补全目标应用）
adb shell pm list packages -f | grep -iE 'tencent|whatsapp|telegram|weibo|line|imo'
aapt dump badging base.apk | grep -E '^package|application-label'   # 确认包名对应哪个应用
adb shell pm list users                              # 多用户
adb shell su -c "ls -d /data/user/*/com.tencent.mm 2>/dev/null"       # 分身

PKG=com.tencent.mm
mkdir -p extracted && cd extracted
adb shell su -c "tar -cf - -C /data/user/0 $PKG" > im.tar   # ★ db / -wal / -shm 一起带走
sha256sum im.tar && tar -tf im.tar | wc -l && tar -xf im.tar
ls -l $PKG/databases/ $PKG/MicroMsg/*/EnMicroMsg.db* 2>/dev/null   # ★ 确认三件套齐全
find . -type f -exec sha256sum {} \; > hashes.txt
```

<a id="section-9"></a>

### 第 3 步：判断是否加密

```bash
# 方法 A：能否被识别为 SQLite
head -c 16 $PKG/MicroMsg/*/EnMicroMsg.db | xxd
# 期望：5351 4c69 7465 2066 6f72 6d61 7420 33 = "SQLite format 3"
# 实际：9a3f 27c1 ...（随机字节）            ← 加密

# 方法 B：让 sqlite3 自己报告
sqlite3 $PKG/MicroMsg/*/EnMicroMsg.db ".tables"
# file is not a database            ← 确认非明文 SQLite
# database disk image is malformed   ← 另一种表现

# 方法 C：熵值（加密文件接近 8.0）
ent $PKG/MicroMsg/*/EnMicroMsg.db 2>/dev/null || \
  python3 -c "
import math,collections,sys
d=open(sys.argv[1],'rb').read()
c=collections.Counter(d); n=len(d)
print('entropy = %.3f bits/byte' % (-sum((v/n)*math.log2(v/n) for v in c.values())))
" $PKG/MicroMsg/*/EnMicroMsg.db
# entropy = 7.998 bits/byte   ← 接近 8 = 加密或压缩
```

<a id="section-10"></a>

### 第 4 步：获取 key（合法途径）

| 途径 | 适用性 | 说明 |
|---|---|---|
| **委托方提供明文导出** | ★★★★★ 最优先 | 应用内"导出聊天记录"功能产生的文件 |
| **已授权的动态分析** | ★★★★ | 见 [04](mobile-android-frida-dynamic-hooking.md) |
| **内存镜像中的明文** | ★★★ | 若案件含 `DigiForensics-mem.raw`，可能含已解密页 |
| **应用登录的另一台设备** | ★★★ | 需另行取得该设备检材或授权 |

```bash
strings -n 8 DigiForensics-mem.raw | grep -c 'SQLite format 3'   # 远多于磁盘库数 → 内存中存在已解密的库
```

<a id="section-11"></a>

### 第 5 步：解密与表结构分析

```bash
# ① 永远在副本上操作（三件套一起复制）
cp EnMicroMsg.db       EnMicroMsg-copy.db
cp EnMicroMsg.db-wal   EnMicroMsg-copy.db-wal 2>/dev/null
cp EnMicroMsg.db-shm   EnMicroMsg-copy.db-shm 2>/dev/null

# ② SQLCipher 类加密的标准处理
sqlite3 EnMicroMsg-copy.db "PRAGMA key='<取得的key>';"
sqlite3 EnMicroMsg-copy.db ".tables"
sqlite3 EnMicroMsg-copy.db "PRAGMA integrity_check;"

# ③ 读表结构（先看结构，再决定 SELECT 什么）
sqlite3 EnMicroMsg-copy.db ".schema" ; sqlite3 EnMicroMsg-copy.db ".schema message"

# ④ 记录数与时间范围
sqlite3 EnMicroMsg-copy.db "SELECT count(*) FROM message;"
sqlite3 EnMicroMsg-copy.db "
SELECT datetime(min(CreateTime)/1000,'unixepoch','+8 hours') AS 最早,
       datetime(max(CreateTime)/1000,'unixepoch','+8 hours') AS 最晚 FROM message;"
```

> ⚠️ **表名与字段名因应用与版本而异**（微信历史上用过 `message`、`Msg`、`chatroom_*` 等不同结构；新版主库常按会话分表）。**不要把某个版本的表名当作通用知识。** 正确做法：`.tables` 看全貌 → `.schema` 看结构 → 再写查询。

<a id="section-12"></a>

### 第 6 步：导出、固化与三层验证

```bash
# ① 导出为 CSV（注意编码：e4bda0=UTF-8；b4f3=GBK，中文编码混杂是常态）
sqlite3 -header -csv EnMicroMsg-copy.db \
  "SELECT id, CreateTime/1000 AS ts, Type, Status, StrContent FROM message
   WHERE CreateTime BETWEEN 1717000000000 AND 1718000000000;" > messages-export.csv
file messages-export.csv && wc -l messages-export.csv

# ② 数据层验证
sqlite3 EnMicroMsg-copy.db "PRAGMA integrity_check;"       # ok
sqlite3 EnMicroMsg-copy.db "SELECT count(*) FROM message;"  # 与导出行数一致

# ③ 交叉层：同一时间点在其他工件中是否有对应痕迹
grep -rn '2024-08-15 21:33' extracted/shared_prefs/ | head
# prefs 中的 last_login_time 与消息时间吻合 → 两个独立来源印证 ✓

# ④ 完整性层：原始包 / 解密副本 / 导出件 三层哈希
sha256sum im.tar EnMicroMsg-copy.db messages-export.csv | tee export-hashes.txt
```

---
<a id="section-13"></a>

## 四、常见陷阱

聊天记录既是案件核心证据，也容易被技术细节做成「假阴性」和「假时间线」。

这一章按实际踩坑顺序排：提取完整性 → 时间语义 → 表结构认知 → 范围覆盖 → 结论表述。前两条造成的误判代价远高于后面几条，因为它们直接改变事实认定。

<a id="section-14"></a>

### 4.1 提取完整性

<a id="section-15"></a>

#### 陷阱 1：只提主库 `EnMicroMsg.db`，不带 `-wal` / `-shm`

**现象**：从设备提取到 `EnMicroMsg.db`，`sqlite3` 用口令打开后 `.tables` 正常列出 `message` 表，`count(*)` 得到 18402 条，时间范围截至 2024-08-24。报告写下「该时段聊天记录共 18402 条，此后无记录」。

**原因**：IM 应用几乎全用 WAL（预写日志）模式，新的消息先追加到 `-wal` 文件，事务提交后不立刻回写主库，要等 checkpoint 才批量合并。本案的 `-wal` 达 8 MB，说明有大量数据还没回写。

单独打开 `EnMicroMsg.db` 时，SQLite 读到的是上一次 checkpoint 时的完整快照。结构完好，`integrity_check` 通过，`count(*)` 返回一个完全合理的数字，唯独缺了最近这一段。它不会给任何提示。

**影响**：这个错误制造的是一个看起来完全正常的错误结论。

本案实际数据是 24193 条、截至 2024-08-31 23:33。只读主库得到 18402 条、截至 2024-08-24。5791 条消息被完整遗漏，而这 5791 条恰好覆盖了委托要求查明的那一周。

更麻烦的是这个结论会向下传导。「此后无记录」会被用来论证「约定没有后续跟进」「双方在案发后没有再联系」，而那些记录就在同一个提取目录的隔壁文件里。委托方拿着这个结论去做后续处置（质疑举报、认定事实），方向完全错位。

**核查**：整个目录打包，三个文件必须同在。提取后第一件事是确认三件套齐全，并把它们的体量当作提取完整性的第一道判据：

```bash
PKG=com.tencent.mm
# ① 目录级导出（-wal / -shm 天然包含）
adb shell su -c "tar -cf - -C /data/user/0 $PKG" > im.tar
sha256sum im.tar && tar -xf im.tar

# ② 第一时间确认三件套齐全，并看 -wal 的体量
ls -l $PKG/MicroMsg/*/EnMicroMsg.db*
# 412662784  EnMicroMsg.db
#   8388608  EnMicroMsg.db-wal   ← 8 MB：有大量数据未回写
#     32768  EnMicroMsg.db-shm

# ③ 反事实验证（强烈建议做一次，成本极低价值极高）
#    只用主库打开，得到"错误答案"
cp EnMicroMsg.db test-mainonly.db
sqlite3 test-mainonly.db "PRAGMA key='<口令>';"
sqlite3 test-mainonly.db "SELECT count(*), max(CreateTime) FROM message;"
# 18402 | 1724459642000   ← 偏早 7 天

# ④ 完整三件套，得到"正确答案"
cp EnMicroMsg.db DigiForensics-analysis.db && cp EnMicroMsg.db-wal DigiForensics-analysis.db-wal && cp EnMicroMsg.db-shm DigiForensics-analysis.db-shm
sqlite3 DigiForensics-analysis.db "PRAGMA key='<口令>';"
sqlite3 DigiForensics-analysis.db "SELECT count(*), max(CreateTime) FROM message;"
# 24193 | 1725118405000   ← 正确
```

**第 ③ 步建议固化到流程里。** 两条命令就把「我漏了多少」量化成一个具体数字，5791 条。这个数字可以直接写进报告的局限性说明，成为覆盖范围的客观依据。

<a id="section-16"></a>

#### 陷阱 2：把 WAL 里的「看不到」当成「已被删除」

**现象**：完整提取三件套后，打开数据库发现某些消息「不存在」，报告写「用户在 2024-08-20 删除了与 X 的相关聊天」，并把删除时间作为行为认定。

**原因**：这是把「未读取」误读为「已删除」的定性错误，而且它发生在最不该含糊的地方——「删除他人聊天」在多个司法辖区都是明确的独立行为，有时伴随独立的法律责任。

技术上，消息「看不到」至少有四种完全不同的原因：① 还在 `-wal` 里没回写，不是删除，是没读；② 在主库但被查询条件排除了，比如条件里带了时间范围或会话过滤；③ 应用层的「删除」在很多 IM 里是软删除，记录还在，只是被标记了状态位，用户界面不再显示；④ 真的被清理了，应用执行了数据清理或用户清过缓存。这四种在 SQL 层面的表现可能完全一致。

更关键的是，消息内容确实可能以另一种形式存在。多数 IM 会把被删除的引用、转发、撤回提示等写入会话的扩展字段，本案里就是 `BytesExtra`。主表记录消失不等于内容彻底消失。

**影响**：把技术现象当成行为认定，是取证结论越出证据范围的一类问题。

一旦「删除聊天」被写进报告并被采信：① 它成为一个独立的行为事实，可能被用于评价主观恶性；② 若实际上只是没读到或只是软删除，这个结论在质证时会被推翻，而推翻它会连带影响同一段落里其他基于同一提取的结论；③ 被删除的聊天往往涉及第三方，一个错误的「删除」认定还可能影响对第三方的评价。

**核查**：「读不到」与「被删除」之间必须有一道独立的验证，且「删除」的认定要分层：

```bash
# ① 排除「没读全」：先确认提取完整（WAL 已合并、三件套齐备）
ls -l EnMicroMsg.db* ; sqlite3 DigiForensics-analysis.db "PRAGMA wal_checkpoint(TRUNCATE);"
sqlite3 DigiForensics-analysis.db "SELECT count(*) FROM message;"

# ② 排除「查询条件误排」：全表无条件扫一次，不加任何 WHERE
sqlite3 DigiForensics-analysis.db "SELECT count(*), min(CreateTime), max(CreateTime) FROM message;"

# ③ 找软删除标记位：先看结构，再决定查哪个字段
sqlite3 DigiForensics-analysis.db ".schema message"
# 关注 Status / MsgStatus / IsDelete / 类似的整数状态字段
sqlite3 DigiForensics-analysis.db "SELECT Status, count(*) FROM message GROUP BY Status;"

# ④ 找扩展字段里的删除痕迹（撤回提示、引用残留）
sqlite3 DigiForensics-analysis.db "SELECT localId, CreateTime, hex(BytesExtra) FROM message
               WHERE StrContent LIKE '%撤回%' OR StrContent LIKE '%删除%' LIMIT 20;"

# ⑤ freelist 检查：已删除记录可能仍在页里（见 SQLite 系列第 01 篇）
sqlite3 DigiForensics-analysis.db "PRAGMA freelist_count;"
```

**报告表述要按证据强度分层，绝不合并**：

> **数据完整性说明**：本次提取到 `EnMicroMsg.db`（412 MB）及其 `-wal`（8 MB）、`-shm`（32 KB）三件套，共 3 个文件。WAL 合并前后记录数分别为 24193 条（合并后），与合并前差值已记录于 `wal-diff.txt`。
> **关于「未在主表中出现」的记录**：检索特定时段（2024-08-20）与会话组合时，有 N 条记录未出现在查询结果中。已排除「提取不完整」（三件套齐备且已 checkpoint）与「查询条件误排」（已做无条件全表扫描）两项原因。
> **删除行为的认定状态**：**本报告不认定用户实施了删除行为。** 现有数据只能支持「该记录不在主表查询结果中」。是否属于应用层软删除、是否可在扩展字段或 SQLite 空闲页中检出，本次未完成验证。

最后一句是关键。把「已排除的原因」写出来，把「未验证的项」也写出来，读者才知道这个结论的边界在哪。

<a id="section-17"></a>

### 4.2 时间语义与对齐

<a id="section-18"></a>

#### 陷阱 3：秒与毫秒混用，时间线整体偏移 1000 倍

**现象**：查询出来的时间显示为 `2024-01-17 06:14`，而案发时间在 `2024-08-15`。分析人员调整了 `WHERE` 条件的量级后发现数量对不上，最终认为「数据库里没有案发时段的记录」。

**原因**：IM 应用的时间戳存储，秒级与毫秒级混用是常态，而且不同表、不同字段可能不一致。本案的 `CreateTime` 是毫秒（`1724459642000`），除以 1000 才对。

判断量级的方法很直接：11 位数字约对应 2001–2286 年的秒级时间戳，13 位数字对应毫秒级。误用除数 1000 会让 13 位数变成 13 位小数或异常值，误用除数 1 则让 13 位数溢出到 2040 年之后。

表现形式通常是「时间看起来不对但不知道哪里不对」。SQLite 的 `datetime()` 遇到超范围值会返回 NULL 或不报错，最隐蔽的形态是整列都变成空值，而分析者把它理解为「这一列没有数据」。

**影响**：时间线错位就是「案发前」与「案发后」的区别。

本案中权重最高的三条消息是「明天下午三点交货」「老地方是哪个」「仓库后面的空地」。方向字段 `IsSender` 和时间如果同时被读错，整个对话的语义关系就颠倒了，「被要求」会变成「主动提出」，这会直接影响共同犯罪故意的认定。

而时间线在报告里通常是排版最整齐的部分，看着可信，也较少被质疑。

**核查**：先判定量级，再转换，转换后用已知锚点验证。

```bash
# ① 先看原始值的长度分布，一眼判断量级
sqlite3 DigiForensics-analysis.db "SELECT CreateTime, length(CAST(CreateTime AS TEXT)) AS digits
               FROM message ORDER BY CreateTime DESC LIMIT 5;"
# 1725118405000 | 13   ← 13 位 = 毫秒级

# ② 转换：毫秒 → 秒 → unixepoch → 本地时区
sqlite3 DigiForensics-analysis.db "SELECT datetime(CreateTime/1000,'unixepoch','+8 hours') FROM message
               ORDER BY CreateTime LIMIT 3;"
# 2024-08-15 21:41:12

# ③ 双向验证：转换后的时间应落在合理区间，且与文件 mtime、prefs 时间吻合
ls -l --time-style=full-iso EnMicroMsg.db*      # 库文件 mtime
grep -n 'last_login_time' extracted/shared_prefs/*.xml   # 应用最后登录时间
# 三者应落在同一时间窗内 —— 这是判定转换正确的关键判据
```

**第 ③ 步的「双向验证」不能省。** 单向转换看不出错，一定要拿一个独立的时间锚点来对照：文件 mtime、prefs 里的 `last_login_time`，或者另一条证据的时间。锚点对了，转换就是对的；差了几小时甚至几年，说明有问题。这个锚点方法在所有时间戳处理里通用。

<a id="section-19"></a>

#### 陷阱 4：时区换算缺失，把 UTC 直接当本地时间

**现象**：`sqlite3 db "SELECT datetime(ts,'unixepoch') FROM message"` 的输出直接写进时间线，与通话记录、短信时间、委托方提供的导出文件对照，发现普遍差 8 小时。分析人员「按经验」把所有时间都加 8 小时，直到某一个点对上了。

**原因**：SQLite 的 `unixepoch` 返回 UTC，IM 应用的界面显示设备本地时区。这 8 小时的差是系统的、有规律的，不是随机的。

而它错得非常隐蔽：所有时间点会整齐地平移，看起来仍是一份自洽的、顺序正确的时间线，唯一的表现是「与外部证据对不上」。

同一个时区换算错误在不同条目上不会互相抵消——错误一致地重复出现，不代表证据被多次印证。

更麻烦的是处理这类问题时的常见做法——「试到对上为止」。不同的证据被用不同的偏移量对齐，最后得到一份内部不一致、只是为了迁就某个对照点而拼出来的时间线。而且设备时区本身是用户可改的，`persist.sys.timezone` 属性与系统设置都能改，「8 小时」这个默认值不能想当然。

**影响**：跨来源时间线会整体错位。

8 小时足以把「案发当天下午」变成「次日凌晨」，行为的定性随之改变：是否在案发时段内、有没有机会实施、有无时间冲突。在需要证明「某人在某时段不具备作案条件」的案件里，8 小时的错位会直接制造出错误的不在场证明。

这类错误在复核时也很难被发现。每份证据单独看都对，只有横向比对才暴露，而横向比对通常不做。

**核查**：时间基准在提取阶段就固定，转换时显式指定时区并全表统一：

```bash
# ① 提取时记录时间基准（与 [01 篇] 相同的三件套）
adb shell date ; date ; adb shell getprop persist.sys.timezone
# 记录：设备侧 2024-09-01 09:14:02 CST；分析机 2024-09-01 09:20:11 CST；时区 Asia/Shanghai (UTC+8)

# ② 所有 SQL 统一显式指定偏移量，不依赖默认值
sqlite3 DigiForensics-analysis.db "SELECT datetime(CreateTime/1000,'unixepoch','+8 hours') AS t,
                      CreateTime FROM message LIMIT 5;"

# ③ 全表横切：以「时间在某个已知事件前后」为锚点验证
#    例：委托方提供的导出文件最后一条是 2024-08-31 23:50，
#    设备端 max(CreateTime) 换算后应略早于该时刻（同步延迟）而不是晚数小时
sqlite3 DigiForensics-analysis.db "SELECT datetime(max(CreateTime)/1000,'unixepoch','+8 hours') FROM message;"
# 2024-08-31 23:33:25  ← 与导出文件 23:50 吻合 ✓ 时区正确
```

报告里每一条时间都要带时区标注，写成 `2024-08-15 21:41:12 (UTC+8)`，而不是 `2024-08-15 21:41:12`。这样读报告的人能自己判断时区假设是否成立。

<a id="section-20"></a>

#### 陷阱 5：把 Cocoa 时间当 Unix 时间，或盲目加 `978307200`

**现象**：iOS 生态相关的证据（从另一台 iOS 设备、云端导出、或跨端备份里取出的时间戳）落在 `1970-01-01` 附近或 `2001-01-01` 附近。分析人员按「Cocoa 时间要加 978307200」处理，转换后时间对了，于是把这个规则套用到其它来源的时间戳上。

**原因**：Cocoa 时间的基准是 2001-01-01 00:00:00 UTC（Unix 秒 978307200），这是 Cocoa 生态的历史遗留。

但「Cocoa 时间」这个说法本身在取证语境里是个陷阱。同一个生态里的时间戳，基准可能是 Cocoa 秒、可能是 Unix 秒、也可能是毫秒，还可能已经是转换后的本地时间。光看「来自 iOS」判断不出来。

判定只能靠量级。Cocoa 秒的取值大致在 0 到 8 亿之间（2001 年到 2027 年），超出这个范围的肯定不是 Cocoa 秒。至于「加一次 978307200 之后时间看起来对了」，不能当判据——Unix 秒加了这个常数也会落在一个看起来合理的时间上。

**影响**：基准换算错误的后果是整体位移，而且位移量固定。加错一次或漏加一次，时间线整体偏移若干年或若干天，形式上它仍是一份完整、有序、可读的时间线。

跟陷阱 4 叠加时更危险。两个方向的错位可能互相抵消一部分，让结果「看起来大部分对」，而这恰恰是最难发现的情形。

**核查**：量级判定必须先做，判定结论要写进记录：

```bash
# ① 判定量级：数值范围决定处理路径
python3 -c "
n = 1725118405000
if n < 1_000_000_000:      print('量级：秒级（10 位以下）')
elif n < 100_000_000_000: print('量级：毫秒级（11-12 位）')
elif n < 10**15:           print('量级：微秒/纳秒级，需再确认')
else:                      print('量级：非 Unix 系，另有基准')
print('若按 Unix 秒解读:', n)
# 量级：毫秒级（11-12 位）→ 1725118405000 秒 ≈ 2024-09-01，落在合理区间 → 判为毫秒 Unix
# 若按 Unix 秒解读 → 远未来 → 与之矛盾 → 排除
"

# ② Cocoa 判定：值域 0 ~ 8 亿才可能是 Cocoa 秒
python3 -c "
n = 740000000
print('在 Cocoa 合理值域内（2001~2027）' if 0 <= n < 800_000_000 else '不在 Cocoa 值域')"

# ③ 换算后必须用独立锚点验证（与陷阱 4 第 ③ 步同一个方法）
```

§2.4 里那个 `CASE WHEN` 分量级的写法是对的方向，它至少做到了「先判断量级再转换」。但要理解它的三个分支不是「Cocoa / 毫秒 / 秒」三种格式，而是「先按量级切，再按基准换」。`+ 978307200` 只能在确认基准是 Cocoa 的前提下加，量级判定替代不了基准判定。

<a id="section-21"></a>

### 4.3 表结构与内容

<a id="section-22"></a>

#### 陷阱 6：把某个版本的表名当通用知识

**现象**：按之前处理过的某个版本的写法，直接执行 `SELECT TalkerName, StrContent FROM message WHERE …`，报错 `no such table: message`。换了个表名后查出来内容，但字段名也不对，勉强拼凑出一条查询。

**原因**：IM 应用的数据库结构随版本演进差异极大。微信历史上用过 `message`、`Msg`、按会话分表的结构，新版主库的组织方式又不同；QQ 是按账号分库（`r0.db`、`r1.db`…），每个库的表结构还可能不同。这些变化是应用开发方的选择，不遵循任何通用约定。

更危险的是，「这条查询在某个版本上跑通了」的记忆会被误用成「这个结构是通用的」，尤其在跨案件、跨版本的工作里。它导致的不是报错，而是错位的结果：如果表名恰好存在但含义变了（比如字段 `Type` 在旧版是消息类型、在新版是别的），查出来的内容看着合理，但含义全错。

**影响**：这是「错误但看起来正确」的一类。

表名报错只损失时间，改一下就好。表名存在而字段含义变了，产出的是一份完全错误的内容分析。而在聊天记录里，字段含义决定了证据的方向与性质：`IsSender` 是 1 还是 0 决定「谁说的」，`Type`/`SubType` 决定是文本还是语音还是文件。判断错了，「他说了」会变成「他被告知了」。

**核查**：每个库、每个版本都走「看全貌 → 看结构 → 再写查询」三步，不套用历史查询。

```bash
# ① 表全貌
sqlite3 DigiForensics-analysis.db ".tables"
# message  ChatRoom  contact  session  MediaMSG

# ② 结构：先看完整建表语句，不要凭表名猜字段
sqlite3 DigiForensics-analysis.db ".schema message"
# CREATE TABLE message (localId INTEGER PRIMARY KEY, TalkerName TEXT,
#   MsgSvrID INTEGER, Type INTEGER, SubType INTEGER, IsSender INTEGER,
#   CreateTime INTEGER, Status INTEGER, StrContent TEXT, BytesExtra BLOB, ...)

# ③ 字段语义靠取值分布反推，不靠记忆
sqlite3 DigiForensics-analysis.db "SELECT IsSender, count(*) FROM message GROUP BY IsSender;"
# 0 | 11874   ← 收到
# 1 | 12319   ← 发出
sqlite3 DigiForensics-analysis.db "SELECT Type, SubType, count(*) FROM message GROUP BY Type, SubType ORDER BY count(*) DESC;"
# Type/SubType 组合与其记录数的对应关系，就是这个版本的字段含义表
sqlite3 DigiForensics-analysis.db "SELECT max(length(StrContent)), avg(length(StrContent)) FROM message;"

# ④ 抽样人工核对：抽几条看看内容是否与字段推断一致
sqlite3 -header -line DigiForensics-analysis.db "SELECT localId, Type, SubType, IsSender,
    substr(StrContent,1,40) AS c FROM message ORDER BY CreateTime DESC LIMIT 5;"
```

第 ③ 步是核心方法。「取值分布 + 抽样人工核对」是确定字段语义可依赖的方式，不随版本和应用变化。把字段含义表写进报告，它既是分析产物，也是复核时的检查清单。

<a id="section-23"></a>

#### 陷阱 7：只看主表，漏掉扩展字段里的关键内容

**现象**：`StrContent` 字段里只有简短的占位内容（「[图片]」「[语音]」「[文件]」），报告写「聊天记录中未发现交易相关的图片或语音内容」。

**原因**：现代 IM 的消息体是「主表 + 扩展字段」两层结构。主表存元数据与文本占位，具体内容在扩展 BLOB 字段里。本案的 `BytesExtra` 就是这样，语音消息的文件名、时长、实际内容指针都在里面。

分析者只读主表，看到的是一列占位符，于是得出「没有实质内容」的结论，而实质内容就在隔壁字段里躺着。这个误判的隐蔽性在于占位符不是空的，它看起来像数据，所以不会触发「字段为空」的警觉。

**影响**：这会系统性漏掉一整类证据。

语音消息在交易类、诈骗类案件里往往是核心证据。「你在哪个银行」「明天下午几点」这类内容经常是语音说的，主表里只有一个 `[语音]`。漏掉这一层，等于漏掉了整条语音证据线。被删除或撤回消息的引用、转账凭证信息（`BytesExtra` 里常有收款方字段）、位置共享的内容，也都在这一层。

**核查**：先看 BLOB 字段的分布与体量，再决定解析方式：

```bash
# ① 有多少行带扩展数据，体量多大
sqlite3 DigiForensics-analysis.db "SELECT count(*), avg(length(BytesExtra)), max(length(BytesExtra))
               FROM message WHERE BytesExtra IS NOT NULL;"

# ② 按消息类型分组看：哪种类型必有扩展字段
sqlite3 DigiForensics-analysis.db "SELECT Type, SubType, count(*),
               sum(CASE WHEN BytesExtra IS NOT NULL THEN 1 ELSE 0 END) AS 带扩展
               FROM message GROUP BY Type, SubType ORDER BY count(*) DESC;"

# ③ 导出 BLOB 逐个看结构（不同应用/版本的前缀不同，需自行判读）
sqlite3 DigiForensics-analysis.db "SELECT localId, hex(BytesExtra) FROM message
               WHERE Type=34 AND BytesExtra IS NOT NULL LIMIT 1;" | tee extra-hex.txt
xxd -r -p extra-hex.txt > extra.bin
strings -n 4 extra.bin | head -20
# 前 4 字节常为总长度，随后是文件名、时长、路径或密钥材料

# ④ 语音/图片/文件的实际内容在 files/ 目录或 /sdcard 对应路径下
find $PKG/MicroMsg/ -type f \( -name '*.amr' -o -name '*.mp4' -o -name '*.jpg' -o -name '*.dat' \) \
  | head -20 ; du -sh $PKG/MicroMsg/*/files/ 2>/dev/null
```

**报告里要把「消息体是两层结构」这件事写清楚**，并说明本次对扩展字段的解析深度：

> **消息内容解析范围**：`message` 表共 24193 条。已按 `Type`/`SubType` 分布统计（见下表），其中文本类 N 条内容完整读取；语音类 N 条、图片类 N 条、文件类 N 条的内容位于 `BytesExtra` 扩展字段，本次仅完成语音类的前缀结构解析（前 4 字节长度 + 文件名字段），未逐条解析；相关媒体文件位于 `MicroMsg/<账号目录>/files/`，共 N 个文件，**未与消息记录做逐条关联**。
> **未覆盖范围**：① 图片与文件的扩展字段内容；② 语音文件的内容本身（仅按文件名关联，未做语音转写）；③ 已撤回/已删除消息在扩展字段中的引用痕迹。

写清「解析到了哪一层」比写「已解析」重要得多。

<a id="section-24"></a>

### 4.4 范围覆盖与结论表述

<a id="section-25"></a>

#### 陷阱 8：只分析当前登录账号，漏掉设备上的其他账号数据

**现象**：设备上只提取了 `MicroMsg/` 下当前账号对应的那一个 32 位目录的数据，报告写「该设备微信聊天记录已完整提取」。

**原因**：IM 应用普遍支持多账号登录，而数据组织方式是「按账号分目录」——微信是 `MicroMsg/<32位十六进制>/`，QQ 更典型，`r0.db`、`r1.db` 按账号分文件。

多账号的成因很多：主号与小号（常见于赌博、诈骗案件）、工作与私人分离，以及「装完删」的前置行为，先用一个号加好友或收款，用完退出登录甚至清除数据。这些目录在退出登录后并不会被删除，除非用户主动执行了清除数据。它们是「账号切换」行为的直接痕迹。

只取当前登录账号的目录，等于把「这台设备用过几个号」这个关键问题整个跳过。

**影响**：在系列案件里，「同设备多账号」是把分散案件串起来的关键线索。

漏掉它意味着：① 报告无法回答「该设备是否用于多个身份」；② 其他账号下的聊天记录完全没被提取，委托方要求的「聊天记录」在范围上就是不完整的；③ 更隐蔽的是结论表述的越界——「已完整提取」在技术上直接不成立，而它是报告中会被摘录的一句。反向的危害也存在：某个账号下的数据被用过却未提取，「该设备未参与该行为」的结论就没有事实基础。

**核查**：账号维度必须枚举，不能只看当前登录态：

```bash
PKG=com.tencent.mm
# ① 数据目录：按 32 位目录逐个枚举（微信形态）
adb shell su -c "ls -l /data/user/0/$PKG/MicroMsg/" | tee accounts-wechat.txt
# 2f8a...c31  ← 当前登录账号
# a47b...90e  ← ★ 另一个账号，mtime 2024-05-11，已非当前登录

# ② QQ 形态：按账号分库
adb shell su -c "ls -l /data/user/0/com.tencent.mobileqq/*.db" | tee accounts-qq.txt
# r0.db（账号 1）r1.db（账号 2）r2.db ← ★ 三个账号

# ③ 每个账号目录都要：提取 + 完整性检查 + 报告
for d in $(ls extracted/$PKG/MicroMsg/); do
  echo "=== 账号目录 $d"
  ls -l extracted/$PKG/MicroMsg/$d/*.db*
  sqlite3 "extracted/$PKG/MicroMsg/$d/EnMicroMsg-copy.db" \
    "PRAGMA key='<口令>'; SELECT count(*), min(CreateTime), max(CreateTime) FROM message;"
done

# ④ 与账号切换痕迹交叉：各目录的 mtime 排序即账号使用时段
find extracted/$PKG/MicroMsg/ -maxdepth 1 -type d -printf '%T@ %p\
' | sort -n
```

**报告表述模板**：

> **账号覆盖**：目标应用数据目录下共发现 **3 个账号数据目录**（`2f8a…c31`、`a47b…90e`、`7c05…1d4`），其中 1 个为设备交付时的当前登录账号，另 2 个为历史账号。
> **各账号数据范围**：
>
> | 账号目录 | 最后修改时间 | 库文件 | 记录数 | 时间范围 | 处理状态 |
> |---|---|---|---|---|---|
> | `2f8a…c31` | 2024-08-31 | EnMicroMsg.db | 24193 | 2024-01 至 2024-08 | **已解密并分析** |
> | `a47b…90e` | 2024-05-11 | EnMicroMsg.db | 3182 | 2023-11 至 2024-05 | **已提取，未解密**（口令未取得） |
> | `7c05…1d4` | 2023-12-03 | EnMicroMsg.db | 447 | 2023-12 | **已提取，未解密** |
>
> 本报告的聊天记录结论仅覆盖 `2f8a…c31` 一个账号。 另两个历史账号的数据已提取并固定哈希，但因未取得对应口令而未解密，**其内容未做任何判断**。
> **账号切换行为**：三个目录的 mtime 分别为 [时间]，**表明该设备在不同时期使用过至少三个账号**。该结论的证据为目录的最后修改时间，具体切换时点需结合各账号数据内容确定。

<a id="section-26"></a>

#### 陷阱 9：★ 在原始库上执行 `PRAGMA` 或任何写入操作

**现象**：为了「让 WAL 回写以便完整读取」，直接在提取出的 `EnMicroMsg.db` 原件上执行了 `PRAGMA wal_checkpoint(TRUNCATE)`；或者为了「看能不能打开」，在原件上试了几个口令。

**原因**：`PRAGMA` 里有一部分是写操作。`wal_checkpoint(TRUNCATE)` 会把 WAL 内容回写主库并清空 WAL 文件；`PRAGMA journal_mode`、`PRAGMA key` 失败多次、乃至 SQLite 为了恢复而回放 WAL，都会在文件上产生写入。反复尝试错误口令这个动作本身也可能改变文件状态，部分加密实现在多次失败后会把库标记为需要更多密钥轮次。

这些操作做完之后，原始提取件的哈希变了。

而更根本的问题是：原件是证据，分析对象应该是它的副本。在原件上操作，让「证据原件」与「分析对象」变成了同一个东西，这在举证上是一个无法解释的形态。

**影响**：直接破坏证据的原始性，而且不可逆。

后果有三层：① 原件哈希与提取时记录的不一致，而这个不一致没法解释成「正常现象」——复核方会认为提取件被篡改，实际上只是被写入了；② WAL 被 TRUNCATE 后内容合并进主库，数据没丢，但「WAL 里有什么」这个问题的可回答性消失了，而这个问题本身在提取阶段就有观测价值；③ 原件一旦被改动，就再也回不到提取时的状态，包括那个 8 MB 的 WAL。

**核查**：原件只读，一切操作在副本上。副本的复制要三件套齐全。

```bash
# ① 原件立即设为只读（这是最有效的一道保险）
chmod -R a-w extracted/$PKG/MicroMsg/*/EnMicroMsg.db*
sha256sum extracted/$PKG/MicroMsg/*/EnMicroMsg.db* > originals.sha256

# ② 副本必须三件套齐全，否则 WAL 关联不上
cp EnMicroMsg.db       EnMicroMsg-copy.db
cp EnMicroMsg.db-wal   EnMicroMsg-copy.db-wal 2>/dev/null
cp EnMicroMsg.db-shm   EnMicroMsg-copy.db-shm 2>/dev/null

# ③ 差分验证：checkpoint 前后各查一次，差值就是 WAL 里的数据量
sqlite3 EnMicroMsg-copy.db "PRAGMA key='<口令>';"
sqlite3 EnMicroMsg-copy.db "SELECT count(*) FROM message;"                # 18402
sqlite3 EnMicroMsg-copy.db "PRAGMA wal_checkpoint(TRUNCATE);"
sqlite3 EnMicroMsg-copy.db "SELECT count(*) FROM message;"                # 24193
# 差值 5791 = 只存在于 WAL 中的消息数 ← 这是重要发现，要写进报告

# ④ 原件哈希复核：确认始终未变
sha256sum -c originals.sha256
```

**报告里要写清原件与副本的关系**：

> **原始提取件**：`EnMicroMsg.db`（412 MB，SHA-256 `a1b2…`）、`EnMicroMsg.db-wal`（8 MB，SHA-256 `c3d4…`）、`EnMicroMsg.db-shm`（32 KB）——三件套自提取起已设为只读，全部操作在副本上进行，操作前后哈希一致（`sha256sum -c` 通过）。
> **分析副本**：`EnMicroMsg-copy.db` 系列，已执行 `PRAGMA wal_checkpoint(TRUNCATE)`，其哈希与原件不同，属预期（该操作写入数据）。副本的哈希单独记录于 `copy-hashes.txt`。
> **WAL 数据量**：合并前后记录数差值为 5791 条，**即最近一次 checkpoint 后新增的消息数**。该数值与 `-wal` 文件的 8 MB 体量相互印证。

注意最后一句。「差值」本身是一个结论，它比「WAL 很大」这个观察更有价值，而且只有在原件未被污染的情况下才有意义。

<a id="section-27"></a>

#### 陷阱 10：报告写「聊天记录已提取」，但实际未解密

**现象**：报告结论部分写「已完成目标应用聊天记录的提取与解析」，而实际情况是：数据目录已打包、`EnMicroMsg.db` 已提取并哈希，但**因未取得有效口令，库内容未做任何读取**，报告中没有任何一条来自聊天记录的内容。

**原因**：「提取」与「解析」是两个不同层级的动作，而中文里「提取聊天记录」可以指其中任何一个。

写报告时，提取动作已经完成且有哈希为证，心里默认「记录已经拿到了」；解析做不成时，又容易觉得那是分析环节的事，不影响「提取完成」这个结论。于是「提取」这个词在报告里承担了一个它本来不承担的语义。相似的表述还有「已完成目标应用数据提取与分析」「聊天记录已获取」，都在把一个动作的成功说成全流程的成功。

**影响**：报告表述会掩盖「以为自己找到了但其实没有」。

委托方看到「聊天记录已提取」，会认为核心证据已到手，据此推进案件，而实际上最需要的那部分内容一个字都没读到。等委托方后来发现，受损的不只是这个结论，而是整份报告的可信度——「连『提取』和『解析』都分不清」这个判断会延伸到所有其他结论上。法律风险是真实存在的：报告作为证据材料，对已获取证据范围的描述不准确，可能在质证时构成对检材状态的错误陈述。

**核查**：用状态词，不用完成时动词。四个状态必须区分清楚：

| 状态 | 含义 | 允许的表述 |
|---|---|---|
| **已解密并分析** | 库已打开、内容已读、结论有据 | 「已解密并分析，明细见 4.2 节」 |
| **部分解密** | 多个库中部分解开 | 「4 个库中 3 个已解密，`DigiForensics-log.db` 未解密（原因：）」 |
| **已提取未解密** | 文件已取得并固定哈希，内容未读 | 「**已提取并哈希固定，未解密**；未取得有效口令，**本报告不对其内容作任何判断**」 |
| **未获取** | 文件未取得 | 「未获取，原因：[权限/加密/设备未解锁]」 |

报告里必须有一张覆盖状态表，把每个库、每个账号目录的状态逐项列出（见陷阱 8 的表格）。这张表的作用是让「未完成的部分」变成显式的、有限的、可交接的工作项，而不是一个笼统的空白。

**同时，「阴性发现」必须限定范围**：

> **关于「未发现交易相关聊天」的说明**：本次分析在 `2f8a…c31` 账号目录（已解密，`message` 表 24193 条，时间范围 2024-01 至 2024-08）中，按关键词 `交货 / 地点 / 汇款` 与 `Type`/`SubType` 分布两个维度检索，**未发现**明确约定交易地点与时间的文本消息。
> **未覆盖范围**：① 另两个历史账号（`a47b…90e`、`7c05…1d4`）数据已提取但未解密；② 语音消息内容未做转写，仅按文件名关联；③ 图片与文件类消息的扩展字段未解析；④ 已删除/撤回消息的残留未做空闲页扫描。
> **本结论为阴性发现，效力上限即上述范围。**
<a id="section-28"></a>

## 五、案例示例

<a id="section-29"></a>

### 5.1 WAL 未合并导致 5791 条关键消息的完整遗漏

**场景**

查获一台已 root 的 Android 12 手机，委托方要求查明嫌疑人与某人在聊天中是否提及约定交货地点与时间。检材中目标应用包名 `com.tencent.mm`，数据目录 2.3 GB。委托方已提供该应用内自行导出的**明文聊天记录文件**（2024-08-01 至 2024-08-31），并授权对设备端数据做比对分析。

委托方主动提供导出件这个安排很有价值，它给了一个独立来源做交叉验证，也让"设备端数据缺失"不至于让案件无法推进。

**处置过程**

第一步，确认用户维度，不要把数据从错误分区提出来：

```bash
$ adb shell pm list users
UserInfo{0:机主:13} running                    ← 单用户，无工作资料夹
$ PKG=com.tencent.mm
$ adb shell su -c "du -sh /data/user/0/$PKG"
2.3G
$ adb shell su -c "ls /data/user/0/$PKG/MicroMsg/"
7f3a9c2e1b8d4056a7c9e2f1b3d5a8c     ← 32 位十六进制目录（账号/设备维度）
```

第二步，整体提取，WAL 与 SHM 必须一起带上：

```bash
$ adb shell su -c "tar -cf - -C /data/user/0 $PKG" > im.tar
$ sha256sum im.tar
$ tar -xf im.tar
$ ls -l $PKG/MicroMsg/7f3a9c2e1b8d4056a7c9e2f1b3d5a8c/
412662784  2024-08-31 23:14:02  EnMicroMsg.db
  8388608  2024-08-31 23:14:02  EnMicroMsg.db-wal   ← 8 MB
    32768  2024-08-31 23:14:02  EnMicroMsg.db-shm
198402048  2024-09-01 00:02:11  MicroMsg.db
```

`EnMicroMsg.db-wal` 达 8 MB，恰好是 2 个 page_size 的整数倍量级，说明有大量事务还没回写主库。光这一个数字就已经在提示风险了。

第三步做反事实验证，把"完整提取"的价值量化出来：

```bash
# 反事实：只看主库会看到什么
$ cp EnMicroMsg.db test-mainonly.db
$ sqlite3 test-mainonly.db "PRAGMA key='<委托方提供的口令>';"
$ sqlite3 test-mainonly.db "SELECT count(*), max(CreateTime) FROM message;"
18402|1724459642000     ← 2024-08-24 08:34:02（偏早 7 天）

# 完整提取后
$ cp EnMicroMsg.db test-full.db
$ cp EnMicroMsg.db-wal test-full.db-wal
$ cp EnMicroMsg.db-shm test-full.db-shm
$ sqlite3 test-full.db "PRAGMA key='<委托方提供的口令>';"
$ sqlite3 test-full.db "SELECT count(*), max(CreateTime) FROM message;"
24193|1725118405000     ← 2024-08-31 23:33:25（正确）
```

差值 5,791 条，缺失窗口 2024-08-16 至 08-31，恰好覆盖委托方的导出区间。

第四步，确认这不是提取错误，只是 SQLite 的正常语义：

```bash
$ sqlite3 test-full.db "PRAGMA journal_mode;"
wal
$ sqlite3 test-full.db "PRAGMA wal_autocheckpoint;"
1000
# 默认 1000 页后自动 checkpoint；本案 WAL 累积到 8 MB 未触发，
# 或应用被强制终止导致 checkpoint 未完成

$ sqlite3 test-mainonly.db "PRAGMA integrity_check;"
ok
# 主库自身完好 —— 它只是不含未回写的事务
```

主库 `integrity_check = ok`。这一点使漏取难以自查：只提主库时数据库看起来完全正常，没有任何错误提示。

第五步，按实际版本读表结构，不套用旧版知识：

```bash
$ sqlite3 test-full.db ".tables"
message  ChatRoom  contact  session  MediaMSG
$ sqlite3 test-full.db ".schema message"
CREATE TABLE message (localId INTEGER PRIMARY KEY, TalkerName TEXT,
  MsgSvrID INTEGER, Type INTEGER, SubType INTEGER, IsSender INTEGER,
  CreateTime INTEGER, Status INTEGER, StrContent TEXT, BytesExtra BLOB, ...)
```

| 字段 | 含义 | 取证意义 |
|---|---|---|
| `CreateTime` | **毫秒时间戳** | 时间线主轴 |
| `IsSender` | 1=本机发出，0=收到 | **判断对话方向的关键** |
| `StrContent` | 文本内容 | 主体证据 |
| `BytesExtra` | **BLOB 扩展字段** | 语音/文件的具体信息常在这里 |
| `TalkerName` | 会话标识 | 关联通讯录名称 |
| `MsgSvrID` | 服务端消息 ID | **可用于与服务端记录对齐** |

第六步，定位关键内容：

```bash
$ sqlite3 -header -column test-full.db "
SELECT localId, datetime(CreateTime/1000,'unixepoch','+8 hours') AS 时间,
       IsSender AS 方向, substr(StrContent,1,60) AS 内容
FROM message
WHERE StrContent LIKE '%交货%' OR StrContent LIKE '%地点%'
ORDER BY CreateTime;"
```

| localId | 时间 | 方向 | 内容 |
|---|---|---|---|
| 8841201 | 2024-08-15 21:41:12 | **0（收到）** | 明天下午三点，老地方交货，别带别人 |
| 8841533 | 2024-08-15 21:42:36 | 1（发出） | 收到。老地方是哪个，我忘了 |
| 8841602 | 2024-08-15 21:43:58 | **0（收到）** | 就上回那个仓库后面的空地，路口有棵大樟树 |

`IsSender` 字段把"约定"变成了有方向的事实。第一、三条是对方提出，本机只是确认。

第七步，与委托方导出件交叉验证：

```bash
$ sha256sum 委托方提供-聊天记录导出.txt
$ grep -n '明天下午三点\|老地方\|大樟树' 委托方提供-聊天记录导出.txt
12:明天下午三点，老地方交货，别带别人
15:就上回那个仓库后面的空地，路口有棵大樟树
```

两个独立来源，内容与时间逐条一致。

第八步，解析 `BytesExtra`：

```bash
$ sqlite3 test-full.db "SELECT hex(BytesExtra) FROM message
                        WHERE Type=34 AND SubType=0 LIMIT 1;" | tr -d '\
' > extra.hex
$ xxd -r -p extra.hex > extra.bin
$ xxd -l 32 extra.bin
00000000: 12 5c 00 00 61 6d 72 00 78 78 78 2e 61 6d 72 00 ...
#        ↑总长度
$ strings -n 6 extra.bin | head -3
/data/user/0/com.tencent.mm/MicroMsg/7f3a.../voice/xxx.amr
duration: 4700ms
```

前 4 字节（`12 5c 00 00`）是总长度，偏移 0x04 起是文件路径与时长字段。语音文件本体在 `voice/` 目录，本次没提取音频内容。

第九步，三层固化。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 若只提主库将遗漏 5,791 条消息 | 反事实验证：18,402 vs 24,193 | 强（已实测） |
| 遗漏窗口为 2024-08-16 至 08-31，覆盖委托区间 | `max(CreateTime)` 差异 | 强 |
| 主库完整性检查通过，缺失不可从主库察觉 | `integrity_check = ok` | 强（说明风险隐蔽） |
| 约定内容成立且方向明确 | 三条消息的 `IsSender` 字段 | 强 |
| 关键时间窗口为 2024-08-15 21:41–21:43 | `CreateTime`（UTC+8 换算） | 强 |
| 设备端与委托方导出两个独立来源一致 | 内容与时间逐条吻合 | 强 |
| 存在时长 4700 ms 的语音消息 | `BytesExtra` 解析 | 强（仅元数据） |
| **语音内容** | — | **未提取** |
| **`MicroMsg.db` 另一库** | — | **不在本轮范围** |
| **08-31 之后的记录** | — | **不可得**（设备 09-01 扣押） |

**能证明的**：消息内容、方向、时间（精度到秒）、缺失的具体范围、以及两源一致性。

**不能证明的**：
- **不能证明约定被实际执行。** 聊天中的约定是意向，不是行为
- **不能证明"老地方"是哪里。** 描述模糊（"大樟树""仓库后面的空地"），需现场核实
- **不能证明对话双方的身份。** `TalkerName` 是账号 ID，非实名
- **不能证明消息由机主本人收发**

**误判对照**

这个案例的误判点很特殊：它不报错，只会让报告看起来一切正常。

**其一，只提取主数据库。**

常见错误之一。看的是 WAL 文件的存在与体积：

| 观察 | 含义 |
|---|---|
| `-wal` 存在且体积非 0 | 有未回写事务 |
| `-wal` 体积 = 8 MB（本案的 2×page_size 整数倍） | 累积量已达阈值，checkpoint 未触发或被中断 |
| `-shm` 存在 | 数据库当前处于 WAL 模式 |

容易误判的原因在于 `PRAGMA integrity_check` 返回 `ok`。主库自身结构完全正常，它只是不含未回写的数据。任何基于"打开库成功""结构完整"来判断提取完整性的做法，在本案里都会漏掉 5,791 条。

判据是提取后立刻做一次对比性统计：

```bash
# 主库单独
sqlite3 test-mainonly.db "SELECT count(*), max(CreateTime) FROM message;"
# 完整提取
sqlite3 test-full.db      "SELECT count(*), max(CreateTime) FROM message;"
```

两个数字必须并列记录。`max(CreateTime)` 明显早于扣押时间，就说明缺失确定存在。

本案的缺失窗口是 08-16 至 08-31，委托方的导出件恰好是 08-01 至 08-31。只用设备端主库会得出"08-24 之后无相关消息"，而 08-24 之后实际有 5,791 条，其中可能就有后续的履约沟通。

其二，把 `StrContent LIKE '%交货%'` 的命中数当作"相关消息条数"。

本案只检了 `交货` 和 `地点` 两个关键词，命中 3 条。关键词检索的系统性缺口长这样：

| 缺口类型 | 本案是否涉及 |
|---|---|
| 同义词（送货/提货/见面/接头） | ✅ 可能 |
| 拆字或拼音（jiao huo） | ✅ 可能 |
| 图片/语音中的内容 | ✅ **完全未覆盖** |
| 已删除的消息 | ✅ 可能 |
| 位置分享（经纬度） | ✅ 可能 |
| 红包/转账的 `BytesExtra` | ✅ 未检索 |

关键词表必须成组设计：同义词组、拼音组、常见误写组，并在结论里写清"本次关键词表为 X/Y/Z，未覆盖 A/B/C"。本案这 3 条命中里有"大樟树"这个具体的地点描述，只搜"交货"就会漏掉。

其三，把"两个来源一致"当作交叉验证通过，忽略来源的独立性。

本案设备端数据库与委托方导出件内容一致。但导出件是从哪来的？必须问一句它的生成方式：

| 导出方式 | 独立性 |
|---|---|
| 应用内"导出聊天记录"功能 | ✅ 独立读取路径 |
| 用本案的解密方法从同一数据库导出 | ❌ **同源，不构成交叉验证** |
| 对方自行从其他设备获得 | ✅ 独立 |

本案委托方明确说明是"应用内导出"，独立性成立。通用形式是这样：交叉验证的前提是两个来源的产出路径不同。若委托方用同一套解密方法导出，那两条证据实为一个，只算一次。

**第四个实操细节**：`PRAGMA key='<口令>'` 之后立刻执行查询是必要的，但注意 `sqlite3` 客户端的 key 设置在某些版本下需要 `PRAGMA cipher_page_size` 等参数配合。解密后先跑 `.tables` 确认表可见，再跑 `integrity_check`，两步都过才继续。跳过第一步直接查数据，遇到"表不存在"时容易误判为库损坏。

<a id="section-30"></a>

### 5.2 IsSender 字段缺失导致约定方向无法认定

**场景**

承接 5.1。委托方审阅结果时提出一个追问：报告列了三条消息，但只呈现内容没呈现方向。委托方要一个明确答案：**"这个交货约定是谁提出的？"**

谁提出约定，关系到"是否构成共同故意""是否属于被诱导"这类法律定性。方向信息恰好就在 `IsSender` 字段里。

这里要处理的是方向字段的可靠性验证，以及它在什么情况下会不可用。

**处置过程**

第一步，把方向作为显式列呈现，而不是隐含在内容里：

```bash
$ sqlite3 -header -column test-full.db "
SELECT localId,
       datetime(CreateTime/1000,'unixepoch','+8 hours') AS 时间,
       CASE IsSender WHEN 1 THEN '本机发出' WHEN 0 THEN '本机收到' END AS 方向,
       TalkerName AS 会话,
       StrContent AS 内容
FROM message
WHERE StrContent LIKE '%交货%' OR StrContent LIKE '%地点%'
ORDER BY CreateTime;"
localId  时间                   方向       会话                 内容
8841201  2024-08-15 21:41:12   本机收到   wxid_****            明天下午三点，老地方交货，别带别人
8841533  2024-08-15 21:42:36   本机发出   wxid_****            收到。老地方是哪个，我忘了
8841602  2024-08-15 21:43:58   本机收到   wxid_****            就上回那个仓库后面的空地，路口有棵樟树
```

三条里两条是"本机收到"。对方提出约定（时间、地点），本机只确认收到。

第二步，验证 `IsSender` 本身。别默认它总是对的。

```bash
# 2.1 取该会话的全部消息，检查方向与内容的自洽性
$ sqlite3 -header -column test-full.db "
SELECT CASE IsSender WHEN 1 THEN '发出' ELSE '收到' END AS 方向,
       count(*) AS 条数,
       min(datetime(CreateTime/1000,'unixepoch','+8 hours')) AS 首条,
       max(datetime(CreateTime/1000,'unixepoch','+8 hours')) AS 末条
FROM message WHERE TalkerName='wxid_****' GROUP BY IsSender;"
方向  条数    首条                    末条
发出   487    2024-08-02 09:11:03     2024-09-01 00:01:47
收到   623    2024-08-02 09:11:41     2024-08-31 23:58:12

# 2.2 用一个已知方向的系统消息做校验
$ sqlite3 -header -column test-full.db "
SELECT localId, IsSender, Type, StrContent FROM message
WHERE StrContent LIKE '%已通过朋友验证%' OR StrContent LIKE '%已成为新的联系人%' LIMIT 3;"
localId  IsSender  Type  StrContent
8820114  0         100   你已添加了<已脱敏>，现在可以开始聊天了
```

系统消息（Type=100）的 `IsSender=0`，系统生成的通知，符合预期。

第三步，看 `IsSender` 的取值域有没有异常值：

```bash
$ sqlite3 -header -column test-full.db "
SELECT IsSender, count(*) FROM message GROUP BY IsSender;"
IsSender  count(*)
0         24193
1         （本表无 1 —— 原因见下）
```

本次 `IsSender=1` 的行数是 0。不对劲。前面统计明明显示 487 条"发出"。

原因是 `IsSender` 不是 0/1 整数，而是布尔存储，`GROUP BY` 时跟整数 1 匹配不上。换一种比较方式：

```bash
$ sqlite3 -header -column test-full.db "
SELECT IsSender, typeof(IsSender) AS 类型, count(*) AS 条数
FROM message GROUP BY IsSender, typeof(IsSender);"
IsSender  类型     条数
0         integer  20418
1         integer   487
1         null     3288
```

`typeof(IsSender) = 'null'` 的有 3,288 条。这是关键发现：这些行的方向未知，不能读作"收到"也不能读作"发出"。

第四步，看这 3,288 条 NULL 到底是什么消息。

```bash
$ sqlite3 -header -column test-full.db "
SELECT Type, SubType, count(*) AS 条数,
       min(datetime(CreateTime/1000,'unixepoch','+8 hours')) AS 首条
FROM message WHERE IsSender IS NULL GROUP BY Type, SubType ORDER BY 条数 DESC LIMIT 6;"
Type  SubType  条数  首条
47    0        2871  2024-08-15 22:10:44
43    0         288  2024-08-15 22:10:50
42    0          84  2024-08-16 09:02:11
100   0          33  2024-08-02 09:11:03
49    0          12  2024-08-20 14:22:08
```

`Type=47` 占 2,871 条，`Type=43`（语音）288 条，`Type=42`（名片）84 条。全是非文本消息类型。

第五步，确认这批 NULL 里没有承载约定的内容：

```bash
$ sqlite3 -header -column test-full.db "
SELECT localId, datetime(CreateTime/1000,'unixepoch','+8 hours') AS 时间, Type,
       length(StrContent) AS 正文长度, length(BytesExtra) AS 扩展长度
FROM message WHERE IsSender IS NULL AND CreateTime BETWEEN 1723729272000 AND 1723729438000;"
localId  时间                   Type  正文长度  扩展长度
（无输出）
```

2024-08-15 21:41:12 到 21:43:58 这个关键窗口内，`IsSender IS NULL` 零命中。三条关键消息都有明确方向。

第六步，处理 NULL 的通用判据：

```bash
# 报告中呈现方向时，必须把 NULL 单列，不能归入任一侧
$ sqlite3 -header -column test-full.db "
SELECT
  sum(CASE WHEN IsSender=1 THEN 1 ELSE 0 END) AS 本机发出,
  sum(CASE WHEN IsSender=0 THEN 1 ELSE 0 END) AS 本机收到,
  sum(CASE WHEN IsSender IS NULL THEN 1 ELSE 0 END) AS 方向未知
FROM message;"
本机发出  本机收到  方向未知
487       20418     3288
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 交货约定由对方提出 | 三条消息的 `IsSender=0/1/0` | 强 |
| 本机仅确认收到，未提出具体地点 | `IsSender=1` 的那条内容为"收到。老地方是哪个，我忘了" | 强 |
| 关键窗口内无方向未知的消息 | `IsSender IS NULL` 在 21:41:12–21:43:58 区间零命中 | 强 |
| `IsSender` 字段整体可用 | 24,705 条有值（487 + 20,418），仅 3,288 条 NULL | 中 |
| 3,288 条 NULL 全部为非文本消息类型 | `Type` 分布：47/43/42/100/49 | 强 |
| 系统消息（Type=100）`IsSender=0` | 与语义预期一致 | 中（作方向字段的自洽性佐证） |

**能证明的**：三条关键消息的收发方向；约定由对方提出；关键窗口内无方向缺失。

**不能证明的**：
- **不能证明"本机收到"等于"本机同意"。** 收到 ≠ 接受，数据库无确认状态字段
- **不能证明这 3,288 条 NULL 消息的方向**，也不能推断其方向应与相邻消息一致
- **不能从 `IsSender` 推出实际操作人**

**未覆盖范围**：`Type=47`（2,871 条，缩略图/动画表情等）的内容解析、`BytesExtra` 内的媒体文件、撤回消息（`Status` 字段的撤回标记未系统检查）、以及群聊场景下 `TalkerName` 的多参与者语义。

**误判对照**

这个案例的误判点很隐蔽，因为 NULL 在 SQL 里不报错，它静静地参与运算。

其一，用 `WHERE IsSender = 0` 查"收到的消息"，把 NULL 悄悄排除。

SQL 的三值逻辑：`NULL = 0` 的结果是 `NULL`，不是 `true` 也不是 `false`，`WHERE` 子句会把 NULL 行全部过滤掉。结果看着还挺"精确"，20,418 条，一条不多。

但报告里"收到 20,418 条、发出 487 条"加起来只有 20,905，表里明明有 24,193 行。差额 3,288 就是被 `WHERE` 悄悄吃掉的 NULL。

任何分组统计都要做三值检查：

```sql
-- 正确写法
SELECT sum(CASE WHEN IsSender=1 THEN 1 ELSE 0 END) AS 发出,
       sum(CASE WHEN IsSender=0 THEN 1 ELSE 0 END) AS 收到,
       sum(CASE WHEN IsSender IS NULL THEN 1 ELSE 0 END) AS 未知
FROM message;

-- 错误写法（NULL 静默丢失）
SELECT IsSender, count(*) FROM message GROUP BY IsSender;
-- ↑ 结果里 1 只有 487，0 有 24193，看起来 NULL 并入 0 了
```

通用形式是这样：统计完成后验证三数之和等于总行数。本案 `487 + 20418 + 3288 = 24193` ✅，数字对上了才说明没有静默丢失。

**其二，把 NULL 归入"收到"。**

上面的 `GROUP BY IsSender` 会把 NULL 显示在 `IsSender=0` 那一行。SQLite 的 GROUP BY 把 NULL 视为独立分组，但很多前端工具展示时把它并到了 0。分析方据此写"收到 24,193 条、发出 487 条"，就是拿 3,288 条方向未知的消息当成了"收到"。

方向字段的三个取值必须分开呈现，发出 / 收到 / 未知，"未知"不能被并进任何一侧。法律定性上，"不知道是谁发的"与"是对方发的"差距极大。

其三，把 `IsSender=0` 读成"对方主动联系"。

`IsSender=0` 的准确语义是：这条消息在本机数据库中不是由本机账户发出的。三种可能：

| 情形 | 是否符合"对方发来" |
|---|---|
| 对方在手机上发出，同步到本机 | ✅ |
| 对方在 PC/其他设备发出，同步到本机 | ✅ |
| **本机账户在另一设备发出，漫游同步回本机** | **❌ 仍标记为 0** |

第三种是关键。多端登录场景下，本机手机上"收到"的消息，可能是自己在电脑上发的。

结合 `session` 表的设备维度来判断：

```bash
$ sqlite3 -header -column test-full.db \
  "SELECT * FROM session LIMIT 5;"
```

本次 `session` 表不含设备会话维度信息（该版本只存会话元数据）。所以正确结论只能是：

> 「三条关键消息的 `IsSender` 字段显示：两条为 0（未由本机账户在该设备发出），一条为 1。本案检材的 `session` 表不含设备会话维度，**无法排除本机账户在其他设备发出、经漫游同步至本机**的情形。方向结论的适用范围限于'本设备'。」

按错误判据走，报告写"约定由对方提出"，委托方据此认定本机是被动方。实际若是本机在另一设备提出、漫游同步过来的，这个结论会被完全推翻，而推翻它需要的证据（漫游记录）不在本次检材里。

**第四个实操细节**：`Type=47` 这类非文本消息的 `IsSender IS NULL` 是数据模型设计的结果，这类消息本来就没有"发送方"概念，不是数据损坏。看 NULL 的消息类型分布是否集中：均匀分布在各种 Type 上是数据质量问题，集中在特定 Type（本案的 47/43/42）是模型设计。集中 = 正常，分散 = 异常。

<a id="section-31"></a>

## 六、扩展阅读方向

五步法走到"解析表"就结束了。要交付一份聊天记录结论，还需要四组能力：读得更深、对得更准、跨得更远、说得清楚。

**读得更深：已删除消息与库内结构**

- [SQLite 基础与结构](../mobile-database/mobile-database-sqlite.md) —— B-tree 页结构、freelist、freelist 页中已删除记录的恢复。聊天库里"删掉了的消息"通常还在 freelist 里。
- [SQLite WAL 取证](../mobile-database/mobile-database-sqlite-wal.md) —— `-wal` 的完整机制。本篇 2.3 那一节是它的应用版展开，删库残留也靠它找回来。
- [文件雕刻与签名恢复](../../filesystem/filesystem-unix/filesystem-unix-file-carving-and-signature-recovery.md) —— 库文件本身损坏时的兜底路径，以及从整镜像里直接雕刻媒体文件。

**对得更准：时间戳与时间线**

- [时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md) —— 秒 / 毫秒 / 微秒、Cocoa 基准、时区偏移的完整判据表。陷阱 4.2 的每一个错误类型都在这篇有对应条目。
- [时间线重建](../../computer/computer-log/computer-log-linux-timeline-reconstruction.md) —— IM 消息时间 + 文件 mtime + 服务器侧时间戳的对齐方法。单一来源的时间戳不可信，本篇案例里哈希文件 mtime 与 `lastMsgID` 互证才是完整的。
- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— 应用层时间戳被改写的识别。读完之后回头看 [2.4](#section-6) 的量级判断，你会知道它只能解决"单位错"，解决不了"值被改"。

**跨得更远：同源数据的其他位置**

- [内存中的凭据与密钥](../../memory/memory-artifact/memory-artifact-memory-credentials-and-keys.md) —— 内存镜像里已解密的数据库页，以及已解密的会话令牌。**这条途径不需要在检材上执行写动作。**
- [Linux 与 Android 内存取证](../../memory/memory-artifact/memory-artifact-linux-android.md) —— Android 内存采集与分析的具体路径。
- [Frida 动态 Hook](mobile-android-frida-dynamic-hooking.md) —— 已获书面授权时的动态路径。前提是静态分析已完成，否则不知道该 hook 什么。
- [iOS 备份与沙盒提取](../mobile-ios/mobile-ios-ios-backup-and-sandbox-extraction.md) —— PC 端消息库往往**无加密**，同一案件的跨端对照常比手机端更省力。

**说得清楚：证据能力与合规边界**

- [数据库取证通用方法](../mobile-database/mobile-database-database-forensics-methods.md) —— 阴性发现的写法模板。本篇 4.4「范围覆盖与结论表述」给的是骨架，这篇给通用清单。
- [证据保管链与委托证明](../../fundamentals/fundamentals-chain/fundamentals-chain-chain-of-custody-and-authorization.md) —— 聊天记录从提取到出报告的完整链路记录要求。**这条链路是质证时容易被质疑的对象。**
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md) —— 获取 key 的授权边界与最小化要求。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 本篇三条硬规矩的出处。
<a id="section-32"></a>

## 七、命令速查

```bash
# ===== 确认包名 =====
adb shell pm list packages -f | grep -iE 'tencent|whatsapp|telegram|weibo'
adb shell pm list users
adb shell su -c "ls -d /data/user/*/<包名> 2>/dev/null"   # 查分身/多用户

# ===== 提取（★ 整个目录，db / -wal / -shm 一起）=====
PKG=com.tencent.mm
cd extracted
adb shell su -c "tar -cf - -C /data/user/0 $PKG" > im.tar && sha256sum im.tar
tar -xf im.tar && find . -type f -exec sha256sum {} \; > hashes.txt
ls -l $PKG/MicroMsg/*/EnMicroMsg.db*          # 确认三件套齐全

# ===== 判断是否加密 =====
head -c 16 EnMicroMsg.db | xxd          # 期望 "SQLite format 3"；随机字节=加密
sqlite3 EnMicroMsg.db ".tables"          # file is not a database → 加密
python3 -c "
import math,collections,sys
d=open(sys.argv[1],'rb').read(); c=collections.Counter(d); n=len(d)
print('entropy = %.3f' % (-sum((v/n)*math.log2(v/n) for v in c.values())))
" EnMicroMsg.db                          # 辅助判断，接近 8 = 加密或压缩

# ===== 解密（永远在副本上）=====
cp EnMicroMsg.db     EnMicroMsg-copy.db
cp EnMicroMsg.db-wal EnMicroMsg-copy.db-wal
cp EnMicroMsg.db-shm EnMicroMsg-copy.db-shm
sqlite3 EnMicroMsg-copy.db "PRAGMA key='<key>';"
# SQLCipher 若 key 是 hex 串，改用 PRAGMA hexkey='<hex>';
sqlite3 EnMicroMsg-copy.db ".tables" ; sqlite3 EnMicroMsg-copy.db ".schema"
sqlite3 EnMicroMsg-copy.db "PRAGMA integrity_check;"       # ok
sqlite3 EnMicroMsg-copy.db "PRAGMA wal_checkpoint(TRUNCATE);"   # ★ 让 WAL 内容生效

# ===== 记录、时间范围与安全转换 =====
sqlite3 EnMicroMsg-copy.db "SELECT count(*) FROM message;"
sqlite3 EnMicroMsg-copy.db "
SELECT datetime(min(CreateTime)/1000,'unixepoch','+8 hours'),
       datetime(max(CreateTime)/1000,'unixepoch','+8 hours') FROM message;"
# 秒/毫秒/Cocoa 混合时的安全转换：
sqlite3 EnMicroMsg-copy.db "
SELECT CASE WHEN ts > 1000000000000000 THEN datetime(ts/1000000 + 978307200,'unixepoch','+8 hours')
            WHEN ts > 1000000000000    THEN datetime(ts/1000    + 978307200,'unixepoch','+8 hours')
            WHEN ts >  1000000000       THEN datetime(ts         + 978307200,'unixepoch','+8 hours')
       END FROM message ORDER BY ts LIMIT 20;"
# 978307200 = Cocoa(2001-01-01) 的 Unix 秒数；数值 < 10 亿才考虑加

# ===== 查询、导出与扩展字段 =====
sqlite3 -header -column EnMicroMsg-copy.db "
SELECT id, datetime(CreateTime/1000,'unixepoch','+8 hours') AS 时间,
       IsSender AS 方向, StrContent FROM message
WHERE StrContent LIKE '%关键词%' ORDER BY CreateTime;"
sqlite3 -header -csv EnMicroMsg-copy.db "SELECT * FROM message;" > messages.csv
head -c 100 messages.csv | xxd | head -2        # e4bda0=UTF-8；b4f3=GBK
sqlite3 EnMicroMsg-copy.db "SELECT hex(BytesExtra) FROM message WHERE Type=34 LIMIT 1;"
xxd -r -p <<< "$HEX" > extra.bin && strings -n 4 extra.bin | head

# ===== 固化：原始包 / 解密副本 / 导出件 三层哈希 =====
sha256sum im.tar EnMicroMsg-copy.db messages.csv | tee final-hashes.txt
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 移动与数据库取证 — 即时通讯取证」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《即时通讯取证》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.vc` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
