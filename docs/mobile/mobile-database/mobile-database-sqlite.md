---
title: "SQLite 基础与结构"
slug: "mobile-database-sqlite"
canonical: "https://www.digiforensics.cn/wiki/mobile-database-sqlite"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:49+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "mobile"
space: "移动取证"
node_path: ["应用数据库"]
---

# SQLite 基础与结构

<a id="section-1"></a>

## 一、概述

SQLite 在取证里的位置无可替代。

手机端最常见的数据库——几乎每个应用都有。嵌入式用得最广——浏览器缓存、桌面应用、浏览器书签都是它。也是取证工具的首选解析对象。

不理解它的文件结构，"为什么工具报错了"就解释不清，"我明明拉了数据库却看不到数据"更解释不清。

本篇要解决的问题只有一句：凭什么判断"这个库是什么状态、数据在哪里、有没有可恢复的残留"。

多数人只用到 `sqlite3 db ".tables"` 这一层。工具报错、`file` 报乱码、记录数与预期不符、删掉的消息还能不能找回——答案全在文件头的前 100 字节和 B-tree 页的组织方式里。

**没有这层理解会发生什么**

最典型的失败是**把工具的报错当成数据的属性**。

`file` 输出 `data`、`sqlite3` 报 `file is not a database`，于是写进报告"该库已损坏或已加密"。实际可能只是文件头被改了（加密库会改写魔数）、页大小字段读成了 1 而没做换算、或者只是 `strings` 默认按 ASCII 解码而库是 UTF-16。

判断"损坏 / 加密 / 读法错"这三件事，依据不同，处置方式完全不同——而在工具输出上，它们几乎长得一样。

**在取证流程中的位置**

本篇属于**分析环的最底层**。它不是某个案件环节的专题，而是几乎所有移动取证与桌面取证都要经过的**格式识别与状态判读**。

上游是取证工具与镜像准备（结构化导出见 [证据格式与转换](../../imaging/imaging-acquire/imaging-acquire-evidence-image-formats.md)）；下游是四类具体工作：**应用数据提取后的库验证**（见 [应用私有数据](../mobile-android/mobile-android-sharedpreferences.md)）、**聊天记录解析**（见 [即时通讯取证](../mobile-android/mobile-android-instant-messaging-forensics.md)）、**浏览器缓存分析**、以及**桌面应用与配置残留**。

它自己不产出案件结论。但它决定了那些结论能不能被采信。

**三个必须建立的认知**：

| 认知 | 含义 | 为什么重要 |
|---|---|---|
| **SQLite 是单文件数据库** | 没有独立的数据文件 / 索引文件，整个库就是一个文件（另有 `-wal`/`-shm`/`-journal` 伴随） | 决定了提取时"一个文件"是否等于"全部数据" |
| **删除不是擦除** | `DELETE` 通常修改 B-tree 页中的 cell 和空闲区域；当整页释放时才可能进入 freelist，旧内容也可能残留于 WAL。恢复取决于页复用、secure_delete、VACUUM 等条件 | 这是已删除记录恢复的全部基础 |
| **SQLite 提供结构一致性检查** | 可用 `PRAGMA integrity_check` 等发现部分结构异常，但不是密码学完整性认证 | 异常需要结合采集记录、底层存储与工具分析，不能直接认定人为破坏 |

**涉及的证据形态**（具体到偏移与文件）：

| 形态 | 具体位置 | 结构特征 |
|---|---|---|
| 文件头 | 偏移 0–99 | `SQLite format 3\0` 魔数、页大小、编码、`schema_cookie`、freelist 头页 |
| B-tree 页 | 每页首字节 | **`0x0D` = 叶表页，用户可见表数据都在这里**；`0x05`/`0x02`/`0x0A` 为各级内部与索引页 |
| 溢出页 | 单元中指向的溢出链 | 大字段被拆到溢出页，只看库文件正文会漏 |
| freelist | `first_freelist_trunk_page` 起的链 | 已删除记录仍在字节里，但需按 record 格式重建 |
| WAL | 同名 `-wal`、`-shm` | 写版本字节为 2 表示 WAL；**最近写入在 `-wal` 里** |
| record | 每个 cell 的变长记录 | serial types 决定字段类型与长度 |


由此可以直接回答的问题是：这是不是 SQLite 库、页大小与编码、库是否完整、有多少空闲页与残留、结构版本变更过几次、上次写入用的 SQLite 版本，以及**"打不开"的原因属于哪一类**。

反过来，下面这些问题**不能**从文件字节直接得出，需要转入应用与业务语义侧：库里存了什么业务语义（要读表结构）、记录为什么被删（是应用主动删还是容量回收）、`integrity_check` 通过是否意味着数据没被改（**它只校验结构一致性，不校验内容真实性**）、**已删除记录恢复出来的一定是原文**（可能是部分记录、可能是覆盖后的残留）。

**读者前提**

需要十六进制查看与基础二进制结构知识、SQL 的基本读写能力。工具只需 `sqlite3` 命令行与 `xxd`。

如果还不能熟练使用 `PRAGMA` 系列，建议先按 [第 1–4 步](#section-10) 做一遍再看第二章——本篇的价值在于把工具输出与文件字节对应起来，跳过这一步就只剩命令记忆。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 文件头（偏移 0–99）：第一行 hex 就要看的 100 字节

SQLite 3 数据库文件的前 100 字节是固定的数据库头。这是实战中打开任何一个 `.db` 文件后第一个要看的区域：

| 偏移 | 大小 | 字段 | 说明 |
|---|---|---|---|
| **0** | 16 | `magic` | **`SQLite format 3\0`** |
| 16 | 2 | `page_size` | **页大小，大端。值 `1` 表示 65536**（65536 无法用 2 字节表示） |
| 18 / 19 | 1 / 1 | `write_version` / `read_version` | 1 = legacy journal，**2 = WAL** |
| 20 | 1 | `reserved_size` | 每页末尾保留字节数（常见 0） |
| 21–23 | 3 | payload 比例 | 固定 64 / 32 / 32 |
| **24** | 4 | `file_change_counter` | **每次事务提交 +1** |
| 28 | 4 | `database_size_in_pages` | **库的总页数**（= 文件大小 / 页大小） |
| 32 | 4 | `first_freelist_trunk_page` | freelist 链的起始页 |
| 36 | 4 | `number_of_freelist_pages` | freelist 中的总页数 |
| 40 | 4 | `schema_cookie` | **结构版本号，DDL 变更时 +1** |
| 44 | 4 | `schema_format` | 建表 SQL 的格式号（1–4） |
| 52 | 4 | `largest_root_page` | 主库根页（VACUUM 后会变） |
| 56 | 4 | `text_encoding` | 1 = UTF-8，2 = UTF-16le，3 = UTF-16be |
| 60 / 68 | 4 / 4 | `user_version` / `application_id` | 应用自定义值 |
| 96 | 4 | `sqlite_version_number` | 最后写入该文件的 SQLite 版本号 |

> **三条必须记住的判定**：
> 1. 偏移 16 读出 1 → 实际页大小是 65536。**这是硬指标，读错会让所有页偏移全错。**
> 2. `file_change_counter` 连续递增说明库在被正常使用；**若它不变但文件 mtime 变了，可能存在异常。**
> 3. `text_encoding` 决定字符串怎么解码——UTF-16 时用 `strings -e l`（小端）而不是默认的 `strings`。

```bash
xxd -l 16 app.db
# 00000000: 5351 4c69 7465 2066 6f72 6d61 7420 3300  SQLite format 3.

xxd -s 16 -l 2 -p app.db     # 例：0400 → 0x0400 = 1024；0001 → 值 1 → 实际 65536 ★
sqlite3 app.db "PRAGMA page_size; PRAGMA page_count;"
sqlite3 app.db "PRAGMA encoding; PRAGMA schema_version; PRAGMA user_version;"
```

<a id="section-4"></a>

### 2.2 B-tree 页：数据库的物理组织

SQLite 的表与索引都存成 **B-tree**。每个"页"（默认 4 KB 或 1024 字节）是一个 B-tree 节点，页首 8 或 12 字节是页头，**其后是一个 cell 指针数组**，再后面是 cell 内容区。

| 页类型字节 | 名称 | 含义 |
|---|---|---|
| `0x02` | 内部索引页 | 只存索引键 + 子页号 |
| `0x05` | 内部表页 | 只存行 ID + 子页号 |
| `0x0A` | 叶索引页 | 索引键 + 数据 |
| **`0x0D`** | **叶表页** | **★ 真正的表数据在这里** |

> **`0x0D` 是实战中最该认识的字节**：**所有用户可见的表数据都存储在叶表页中**。做数据恢复时，第一个判断就是"这个区域有没有 `0x0D` 开头的页"。

```
  ┌───────────── 第 N 页（页大小 1024/4096）─────────────┐
  │ 页类型 0x0D  │ 首空区  │ 单元数  │ 内容起点 │ 碎片数 │  ← 页头
  │  cell[0]  cell[1]  cell[2] ...                     │  ← 指针数组
  │           （未使用的空隙）                          │
  │ ...  cell[2] 内容  cell[1] 内容  cell[0] 内容  ...  │  ← 内容区（从后往前长）
  └──────────────────────────────────────────────────────┘
```

> **页类型扫描的用法要点**：页大小必须**用文件头读出的真实值**，不能默认 4096。**页大小猜错，整个统计就是错的。**

<a id="section-5"></a>

### 2.3 freelist 与"已删除记录"——取证的核心价值

`DELETE FROM ...` 在 SQLite 中**是否擦除数据字节取决于 `PRAGMA secure_delete`，不能一概而论**。默认（OFF）下的行为是：把该 cell 从页的 cell 指针数组中移除；**若整页被释放则把页挂进 freelist**（页内还有其他记录时只把空闲空间记入空闲空间链）；字节内容原地保留，直到该页被新数据复用。`secure_delete` 由编译选项 `SQLITE_SECURE_DELETE` 决定、**不同构建默认值不同**（实测同一台机器上系统 `sqlite3` 3.54.0 读到 `2`、Python 内嵌 `sqlite3` 3.50.4 读到 `0`）。

**三档实测**（同样插入 300 行后 `DELETE`，再全文件搜索原文标记）：

| `secure_delete` | 官方语义 | 实测残留 | 取证含义 |
|---|---|---|---|
| `0` = OFF | 不擦除 | **510 处** | 残留恢复成立，覆盖面最广 |
| `1` = ON | 删除即清零 | **0 处** | **残留恢复不成立**，须换手段 |
| `2` = FAST | 仅在不增加 I/O 时清零 | **300 处** | **b-tree 页已清、freelist 页刻意保留痕迹** |

> **★ FAST 是最容易被误判的一档。** 官方文档明确：`secure_delete=FAST` 会清空 b-tree 页上的旧内容，**但故意在 freelist 页上留下取证痕迹**。所以"部分残留、部分干净"是 FAST 的正常表现，**不能据此推断"库被部分处理过"**。

**所以判据是：先对检材实测 `PRAGMA secure_delete`，再决定残留恢复的预期。** 不做这一步就断言"删除内容仍可提取"，在 ON 的库上会交付一个假阴性结论。

| 时间点 | 状态 |
|---|---|
| DELETE 之前 | 记录在叶表页的 cell 数组中，可正常 `SELECT` |
| DELETE 之后、页被复用之前 | **表里查不到，但字节还在文件里** |
| 页被新数据覆盖后 | 真正灭失 |

**freelist 的组织**：数据库文件头偏移 32 是**首个 freelist trunk 页页号**（`first_freelist_trunk_page`），偏移 36 是 **freelist 总页数**（`number_of_freelist_pages`）——注意这两个是**文件头**字段。**trunk 页内部**的结构是：偏移 0 的 4 字节整数 = 下一个 trunk 页页号（0 表示链表结束）；偏移 4 的 4 字节整数 = 本 trunk 页挂的 leaf 页数 L；偏移 8 起按 4 字节大端依次是这 L 个 leaf 页的页号。freelist leaf 页本身不含任何信息。实测（`secure_delete=0`、删除 2000 行后）：文件头 32 读到 3、36 读到 106，而页 #3 的前 32 字节是 `00 00 00 00 | 00 00 00 69 | 00 00 00 04 | 00 00 00 05 ...`，即"下一个 trunk=0、leaf 数=105、leaf 页号从 4 开始"。

```bash
sqlite3 app.db "PRAGMA freelist_count;"     # freelist 页数

# 从空闲空间提取残留（低成本、高收益）
strings -n 8 app.db | head -100
strings -n 8 -e l app.db | head -100        # UTF-16le（text_encoding=2 时）
strings -n 8 app.db | grep -E '身份证|银行卡|130[0-9]{9}|转账'
foremost -t all -o carved/ app.db           # 按文件签名雕刻
```

> `freelist_count` 很大是有意义的信号：可能发生过大量删除、可能有表被 DROP、也可能是**有人清理过痕迹**。**它本身不证明任何事，但值得追查。**

<a id="section-6"></a>

### 2.4 溢出页：大字段怎么存

当一条记录太长、一页放不下时，SQLite 把超出部分放到**溢出页链**上，页内只留一个指向首个溢出页的指针（4 字节）加长度：

```
  叶表页 cell:
  [变长字段长度][局部载荷 N 字节][4 字节溢出页号] → 溢出页 1 → 溢出页 2 → …
  每个溢出页：[4 字节下一溢出页号][最多 (页大小-4) 字节数据]
```

**取证意义**：**一条被截断的记录，其完整内容可能散布在溢出页链上**。只看 cell 头部会漏掉大量内容——这是长文本（聊天记录正文、日志行、JSON 字段）恢复时的关键点。

<a id="section-7"></a>

### 2.5 WAL：三文件协作机制

SQLite 默认使用 **journal mode = delete**（回滚日志），也可配置为 **WAL**（预写日志）。**WAL 模式下的三个文件是本领域最重要的机制**：

| 文件 | 内容 | 缺失的后果 |
|---|---|---|
| `app.db` | 已 checkpoint 的数据 | — |
| **`app.db-wal`** | 自上次 checkpoint 以来所有已提交事务的页副本 | **★ 最近的数据全部"消失"，看起来像被删了** |
| `app.db-shm` | WAL 索引（通常是 32768 字节） | sqlite3 可能无法正确定位 WAL 中的帧 |

- **价值**：WAL 里的页是**已提交的完整页镜像**——即使主库中记录被 `DELETE` 过，**WAL 中可能还留着删除前的页镜像**。
- **风险**：不带 `-wal` 打开，主库会"退回"到上次 checkpoint 状态。 这是**本领域最高频的误判来源**。

> 详细的取证流程、checkpoint 处理、`.recover` 恢复见 [09-SQLite-WAL取证](mobile-database-sqlite-wal.md)。

```bash
sqlite3 app.db "PRAGMA journal_mode;"      # delete / wal / truncate / persist / memory / off
ls -l app.db*
# -rw-r--r-- 1 root root 2457600 app.db
# -rw-r--r-- 1 root root  524288 app.db-wal      ← 有内容 = 有未回写数据
# -rw-r--r-- 1 root root    32768 app.db-shm
```

<a id="section-8"></a>

### 2.6 记录格式（serial types）

每条记录的值用**变长整数编码的类型号**描述类型与长度（`serial type`）：

| serial type | 含义 | 占用字节 |
|---|---|---|
| 0 | NULL | 0 |
| 1–6 | 整数（1/2/3/4/6/8 字节） | 对应长度 |
| 7 | 浮点（IEEE 754） | 8 |
| **8 / 9** | **整数 0 / 整数 1** | **0** |
| **12+2N** | BLOB，长度 N | N |
| **13+2N** | 文本，长度 N | N |

> **为什么记这个**：解析已删除记录或未知格式的页时，先读 serial type 才知道往后跳多少字节。不按 serial type 逐字段推进，会在第一个变长字段后全部错位。

浏览器把大量状态存在 SQLite 库里，`Login Data`、`places.sqlite` 的定位与解析是这套方法最常见的落点，见[浏览器取证](../../computer/computer-browser-behavior/computer-browser-behavior-browser-forensics.md)。

---

<a id="section-9"></a>

## 三、操作步骤

<a id="section-10"></a>

### 第 1 步：验证文件身份

```bash
ls -l app.db*
sha256sum app.db app.db-wal app.db-shm 2>/dev/null | tee app-hashes.txt
file app.db                                  # SQLite 3.x database
xxd -l 16 app.db                             # 期望 SQLite format 3.
```

<a id="section-11"></a>

### 第 2 步：读取文件头字段

```bash
cat > sqlite_hdr.py <<'PY'
import struct, sys
d = open(sys.argv[1], 'rb').read(100)
if d[:16] != b"SQLite format 3\x00":
    print("!! 非明文 SQLite（可能已加密）"); sys.exit(1)
ps = struct.unpack('>H', d[16:18])[0]
ps = 65536 if ps == 1 else ps                  # ★ 值为 1 实际是 65536
enc = {1: 'UTF-8', 2: 'UTF-16le', 3: 'UTF-16be'}
u = lambda o: struct.unpack('>I', d[o:o+4])[0]
print(f"页大小={ps}  写/读版本={d[18]}/{d[19]} (2=WAL)  变更计数器={u(24)}")
print(f"总页数={u(28)}  freelist 链页={u(32)}  freelist 页数={u(36)}")
print(f"schema_cookie={u(40)}  文本编码={enc.get(u(56))}  写入版本号={u(96)}")
PY
python3 sqlite_hdr.py app.db
```

<a id="section-12"></a>

### 第 3 步：完整性检查

```bash
sqlite3 app.db "PRAGMA integrity_check;"
# ok                     → 结构完好
# 大量 "row N missing from index ..." → 逻辑不一致但可读
# "database disk image is malformed"  → 结构损坏（详见 09 篇 .recover）
sqlite3 app.db "PRAGMA quick_check;"
sqlite3 app.db "SELECT name, type FROM sqlite_master ORDER BY type, name;"
```

<a id="section-13"></a>

### 第 4 步：表结构分析

```bash
sqlite3 app.db ".tables"
sqlite3 app.db ".schema"                    # 全部建表语句
sqlite3 app.db ".schema message"            # 单表
sqlite3 app.db "SELECT type,name,tbl_name FROM sqlite_master;"
```

<a id="section-14"></a>

### 第 5 步：让 WAL 生效（关键）

```bash
# ★ 确认三文件在同一目录后再操作，且永远在可写副本上操作
cp app.db work.db && cp app.db-wal work.db-wal && cp app.db-shm work.db-shm
sqlite3 work.db "PRAGMA wal_checkpoint(TRUNCATE);"    # 回写并清空 WAL
sqlite3 work.db "SELECT count(*) FROM message;"
```

<a id="section-15"></a>

### 第 6 步：提取残留数据

```bash
sqlite3 app.db "PRAGMA freelist_count;"

# 编码感知的字符串提取
ENC=$(python3 sqlite_hdr.py app.db | awk '/文本编码/{print $3}')
case "$ENC" in "UTF-16le") FLAGS="-e l" ;; *) FLAGS="" ;; esac
strings -n 8 $FLAGS app.db > strings-all.txt

# 关键词定向搜索（用实际案件关键词替换）
grep -E '身份证|银行卡|手机号|转账|地址' strings-all.txt | head -40
foremost -t all -i -o carved/ app.db          # 按签名雕刻
```

<a id="section-16"></a>

### 第 7 步：导出与固化

```bash
sqlite3 -header -csv app.db "SELECT * FROM message ORDER BY createTime;" > message.csv
sqlite3 app.db ".dump" > schema-and-data.sql     # 完整 SQL 转储（可复现）
sha256sum app.db app.db-wal app.db-shm message.csv | tee final-hashes.txt
```

---
<a id="section-17"></a>

## 四、常见陷阱

SQLite 的取证陷阱集中在**「读不出来」与「读出来是错的」之间**：文件头几个字节的特殊编码、页大小这个全局参数、以及 `DELETE` 之后「数据还在」这个反直觉的事实——它们导致的误判往往不产生任何报错，只产生一个看起来合理的错误答案。

<a id="section-18"></a>

### 4.1 文件头解析

<a id="section-19"></a>

#### 陷阱 1：把页大小字段的值 1 当成 1，导致后续全部页偏移错位

**现象**：拿到一个 `.db` 文件，用脚本按偏移 16 读出页大小字段，值是 `1`，于是按 1 字节一页去计算页边界，整个解析结果全是乱码；改按 4096 处理，页类型字节统计也不对。

**原因**：文件头偏移 16 的两字节大端字段是页大小，但值 `1` 是一个特殊编码，它实际表示 65536——因为 65536 无法用 2 字节直接表示，SQLite 用了哨兵值。这是一个「读出值」与「实际值」不一致的字段，而其它所有字段都是所见即所得的。 分析者按「所见即所得」的默认预期处理，就会把这个字段当成 1。**更麻烦的是它不会立刻报错**——按 1 字节一页会立刻遇到荒谬的页计数而暴露，而按「猜的」4096 处理则会**得到一个自洽但错误的结果**：页头能解析、页类型字节看着合理、`0x0D` 叶表页能扫到一些，只是页边界全部错位，于是同一份数据被切成错误的结构。

**影响**：页大小是全局参数，它一错，整个文件级的分析全部作废。 具体表现是：页类型统计失真（`0x0D` 页数量对不上表的规模）、freelist 页数与 `freelist_count` 不符、cell 解析越界、WAL 帧定位错误。这些错误不会集中报错，而是分散表现为「数据读不全」「数量对不上」「某些表读不出」——每一项都可以被独立地解释为「文件损坏」或「数据不存在」，**于是错误的根因被完全掩盖，而结论照常产出。**

**核查**：页大小必须从文件头读，且必须处理 `1` 这个哨兵值：

```bash
# 读出原始值
xxd -s 16 -l 2 -p app.db
# 0400   → 0x0400 = 1024
# 0001   → 值 1 → ★ 实际页大小 65536

# 脚本里必须做哨兵值转换
python3 -c "
import struct
d=open('app.db','rb').read(100)
ps=struct.unpack('>H', d[16:18])[0]
ps = 65536 if ps == 1 else ps          # ★ 值为 1 实际是 65536
print('页大小 =', ps)
"

# 交叉验证：总页数 × 页大小 必须等于文件大小
sqlite3 app.db "PRAGMA page_size; PRAGMA page_count;"
stat -c%s app.db
# 1024 × 2400 = 2,457,600 = 实际文件大小 ✓
# 若不等，说明页大小读错了（先排除文件被截断的可能）
```

**最后那句交叉验证是判定页大小读对的最简判据**——「总页数 × 页大小 = 文件大小」这个等式成立，页大小就是对的。这一条验证成本几乎为零，但能挡住这一整类错误。报告里应把页大小的实测值写明，而不是只写「已解析文件头」——因为它决定了后续所有分析的可信度基础。

<a id="section-20"></a>

#### 陷阱 2：不从文件头读页大小，直接假设 4096

**现象**：写了个页类型扫描脚本，页大小参数直接写死 4096，扫出 32 个 `0x0D` 叶表页，报告写「该库有 32 个数据页，表规模较小」。

**原因**：SQLite 的页大小由创建时的配置决定，取值范围从 512 到 65536（512 / 1024 / 2048 / 4096 / 8192 / … / 65536，另有 512/65536 的 2 的幂特例），现代应用更倾向 4096，但移动端遗留库用 1024 的极多，而嵌入式与浏览器场景下 512 与 8192 都不罕见。**猜错的形态是「看起来能跑」**：按 4096 去切，文件前部是主库与索引页，切出来的页头大多能对上（因为 B-tree 页的页头格式一致），只有当页大小不是 4096 的约数关系时才会明显出错。而「扫出的页数偏少」这个现象很容易被解释为「表确实小」——它不像报错那样引人警觉。

**影响**：**与陷阱 1 同一个病根，但表现更隐蔽**：**它不会产生任何异常输出，只会系统性少算。** 具体后果：已删除数据的残留扫描覆盖不全（**只扫了文件的一部分**）、freelist 页的字节被漏掉、**表规模被低估**而这可能影响「该应用使用程度」的行为判断。**最严重的是残留数据恢复**——freelist 恢复依赖「整文件按真实页边界扫描」，页大小猜错就等于**只扫描了文件的一小部分**。

**核查**：任何页级操作的第一步是从文件头读页大小，脚本里不允许出现字面量：

```bash
# 反模式：页大小写死
# python3 for page in range(0, len(data), 4096): ...      ← 绝对不要

# 正解：参数来自文件头
python3 -c "
import struct, sys, collections
data = open('app.db','rb').read()
if data[:16] != b'SQLite format 3\x00':
    sys.exit('非明文 SQLite')
ps = struct.unpack('>H', data[16:18])[0]
ps = 65536 if ps == 1 else ps                 # 哨兵值
print(f'页大小={ps}  文件可容纳页数={len(data)//ps}  余字节={len(data)%ps}')

types = collections.Counter()
for off in range(0, len(data)//ps*ps, ps):
    b = data[off]
    if b in (0x02,0x05,0x0a,0x0d):
        types[hex(b)] += 1
print('页类型分布:', dict(types))
print('0x0d 叶表页数:', types.get('0xd', 0))
"
```

**注意最后那行 `余字节`**——**文件大小不是页大小的整数倍，说明文件被截断了**，这是一个独立于页大小的重要发现。**两个信息一起看，脚本才具备自诊断能力。**

<a id="section-21"></a>

### 4.2 结构解析与数据可见性

<a id="section-22"></a>

#### 陷阱 3：只提 `app.db` 不带 `-wal`，把「没回写」读成「已删除」

**现象**：`adb pull` 单独拉了 `app.db`，`PRAGMA integrity_check` 返回 `ok`，`.tables` 正常列出四张表，`pay_record` 表 count 得到 118 条，最大时间停在 2024-08-22。报告写「该应用最后一次交易发生在 8 月 22 日，此后未再发生交易」。

**原因**：`integrity_check` 返回 `ok` 与「数据完整」是两件事。 它验证的是**结构一致性**（页、cell 指针、B-tree 顺序是否自洽），**不验证「我看到了全部已提交的数据」**。文件头偏移 18/19 的 `write_version`/`read_version` 值为 `2` 时，说明这个库当时处于 **WAL 模式**——新的写入是先追加到 `-wal` 文件、事务提交后不立刻回写主库。单独打开 `app.db`，SQLite 读到的是**上一次 checkpoint 时的完整快照**。结构完好、校验通过、记录数合理、唯独缺了 checkpoint 之后的全部写入。 而缺失的这部分与「已删除」在 SQL 层面无法区分。

**影响**：**这是一个会直接产生错误事实认定的误判。** 「8 月 22 日后未再交易」与「8 月 22 日后有 38 笔交易」是两种完全不同的事实。而在支付类案件里，「案发后仍有持续交易」往往直接关系到「是否继续诈骗」「赃款流向」等关键判断。更致命的是这个错误结论会与其它证据产生矛盾，而这个矛盾恰恰是破案线索——本案中 `app.db` 的文件 mtime 是 8 月 31 日 23:14，而主库最后一条记录是 8 月 22 日，一个「库文件在被修改，但内容没有更新」的矛盾，正是数据不完整的铁证。分析者若不主动做这个比对，就会带着错误结论继续走。

**核查**：文件头的 `write_version` 字段是判断的第一道依据，提取完整性靠矛盾检测来验证：

```bash
# ① 先读文件头：write_version=2 说明是 WAL 模式
python3 sqlite_hdr.py app.db
# 写/读版本=2/2 (2=WAL)  ← ★ 这个字段决定了提取完整性的要求

# ② 发现只提了主库 → 立刻回到设备补提整个目录
adb shell su -c "tar -cf - -C /data/user/0/$PKG databases" > DigiForensics-db.tar
tar -xf DigiForensics-db.tar

# ③ 反事实对比，把差值量化（这个数字直接写进报告）
sqlite3 cmp1.db "SELECT count(*) FROM pay_record;"   # 118  ← 仅主库
sqlite3 cmp2.db "SELECT count(*) FROM pay_record;"   # 156  ← 完整提取
# 差值 38 条，覆盖 8/22 至 8/31

# ④ 矛盾检测：数据最大时间 vs 文件 mtime，两者应当吻合
sqlite3 cmp1.db "SELECT max(createTime) FROM pay_record;"
ls -l --time-style=full-iso app.db
# 内容停在 8/22，文件 mtime 是 8/31 23:14  →  ★ 矛盾，说明提取不完整
```

**第 ④ 步的「矛盾检测」应当固化为通用检查项**——**「库内最大时间戳」与「文件最后修改时间」应当接近**。两者差出几天到几周的间隔，就说明要么有数据没被读到，要么文件被外部改过。**这两种解释都值得追查。**

<a id="section-23"></a>

#### 陷阱 4：★ 在原始提取件上执行 `PRAGMA` 写操作

**现象**：为让 WAL 回写以便完整读取，直接在 `app.db` 原件上执行了 `PRAGMA wal_checkpoint(TRUNCATE)`；或者为「先看看库是什么样」，在原件上试了几条查询和几次错误口令。

**原因**：`PRAGMA` 不是只读的。`wal_checkpoint(TRUNCATE)` 会把 WAL 内容回写主库并清空 WAL 文件；`PRAGMA journal_mode` 在特定条件下会触发模式转换；反复尝试错误口令在部分加密实现上会消耗内部的密钥轮次状态；SQLite 打开库时的 WAL 恢复过程本身也可能写入（把 WAL 里的帧应用到主库并更新头部计数器）。这些操作做完，原件不再是「从设备上提取时的那个文件」——而提取件是证据链上的关键一环，它的价值恰恰在于「它就是从那个路径、以那个哈希被取出来的那份字节」。

**影响**：**不可逆，且它破坏的是证据的原始性。** 后果有三层：① 原件哈希与提取时记录的不一致，而这个不一致无法被解释为「正常现象」——复核方只能得出「提取件被改动过」的结论，且**无法判断改动是取证过程中发生的还是被人为的**；② WAL 被 TRUNCATE 后，「WAL 里原本有什么」这个问题永久失去了答案——而「主库里没有但 WAL 里有」这个对比恰恰是本领域最有价值的技术观察之一，它能证明「数据存在但未回写」这个状态；**③ 原件一旦被写，就再也回不到提取时的状态**。

**核查**：原件只读并锁只读，操作在副本上做，且副本的三件套必须齐全：

```bash
# ① 提取后第一时间设为只读，这是最有效的一道保险
chmod 444 app.db app.db-wal app.db-shm
sha256sum app.db app.db-wal app.db-shm | tee originals.sha256

# ② 副本必须三件套齐全（只复制 .db 会让 WAL 关联不上）
cp app.db work.db && cp app.db-wal work.db-wal && cp app.db-shm work.db-shm

# ③ 差分验证：checkpoint 前后各查一次，差值本身就是发现
sqlite3 work.db "PRAGMA key=''; SELECT count(*) FROM pay_record;"   # 或带 key
sqlite3 work.db "PRAGMA wal_checkpoint(TRUNCATE);"
sqlite3 work.db "SELECT count(*) FROM pay_record;"
# 118 → 156，差值 38 = 只存在于 WAL 中的记录数 ← 这个数字要写进报告

# ④ 原件哈希复核，确认始终未变
sha256sum -c originals.sha256
```

**报告里要写清原件与副本的关系与各自的哈希**：

> **原始提取件**：`app.db`（2,457,600 B，SHA-256 `a1b2…`）、`app.db-wal`（196,608 B，SHA-256 `c3d4…`）、`app.db-shm`（32,768 B）——自提取起设为只读（`chmod 444`），全部操作在副本 `work.db` 上进行，操作前后 `sha256sum -c originals.sha256` 均通过。
> **分析副本**：`work.db`，已执行 `PRAGMA wal_checkpoint(TRUNCATE)`，哈希与原件不同属预期。WAL 合并前后 `pay_record` 记录数差值为 38 条。

<a id="section-24"></a>

#### 陷阱 5：`integrity_check` 报 malformed 就放弃分析

**现象**：`PRAGMA integrity_check` 输出 `database disk image is malformed`，`sqlite3` 打开表时也报错，分析人员认为「数据库已损坏，数据不可用」，报告写「该库已损坏，无法获取内容」。

**原因**：**「结构损坏」与「数据丢失」不是一回事。** SQLite 的自校验机制会诚实地报出损坏位置，但**损坏通常只影响结构层面的部分页**，而非全部内容。B-tree 的关键特性是页与页之间通过页号引用，而页内容本身是自描述的——**页的排列顺序被破坏时，数据的字节往往完好无损**，只是「哪条记录属于哪张表」这个对应关系丢了。`.recover` 命令正是针对这一点设计的：它逐页扫描、把能识别的记录收集到一个新库里，跳过损坏的索引和无法解析的部分。 实践中，损坏的库通过 `.recover` 往往能救回绝大部分记录。而「malformed 就放弃」这个判断，等于主动放弃了这条路径。

**影响**：**这是「以为没找到但其实有」的典型形态。** 委托方要求查明的核心内容可能就在那个「无法获取」的库里，而分析人员在报告上写下的「数据不可用」会让这个结论被所有人接受——包括委托方。**更严重的是它会引发错误的下游动作**：委托方可能据此认为「该应用不可用」「该用户无交易行为」或转向其他取证方向，**而这些推论全部建立在一个可以补救的技术失败之上**。**不可用与需要额外手段，是两种性质完全不同的结论。**

**核查**：先做结构诊断，再走恢复路径，恢复结果要与原库做交叉验证：

```bash
# ① 诊断：损坏的具体位置与范围
sqlite3 app.db "PRAGMA integrity_check;" | head -30
sqlite3 app.db "PRAGMA quick_check;"          # 更快，结论较粗
# 错误信息里的页号是关键：页号范围告诉你损坏是局部还是全局

# ② 判断可用性：多少页还能读
sqlite3 app.db "PRAGMA page_count; PRAGMA freelist_count;"

# ③ 恢复：逐页扫描到一个新库，原库不动
sqlite3 app.db ".recover" | sqlite3 DigiForensics-recovered.db
sqlite3 DigiForensics-recovered.db "PRAGMA integrity_check;"
sqlite3 DigiForensics-recovered.db ".tables"
sqlite3 DigiForensics-recovered.db "SELECT count(*) FROM pay_record;"

# ④ 交叉验证：恢复库 vs 原库，记录数与关键字段比对
sqlite3 app.db "SELECT count(*) FROM pay_record WHERE createTime < 1724000000;" 2>/dev/null
sqlite3 DigiForensics-recovered.db "SELECT count(*) FROM pay_record WHERE createTime < 1724000000;"
# 差异部分 = 损坏页里丢失的记录，需要在报告里量化

# ⑤ 若原库连 .recover 都打不开，用 strings + 雕刻兜底
strings -n 8 -e l app.db | grep -E '转账|收款|6222|5188'
foremost -t all -i -o carved/ app.db
```

**报告里要区分「结构损坏」与「内容丢失」**：

> **完整性检查**：`PRAGMA integrity_check` 报告 `database disk image is malformed`，损坏页范围为第 1841–1849 页（本例 `page_count` 为 2400 页）。
> **恢复结果**：经 `.recover` 恢复至 `DigiForensics-recovered.db`，完整性检查通过，枚举出 4 张表；`pay_record` 表 156 条中**恢复 149 条，7 条位于损坏页内未能恢复**。
> **内容残留提取**：另对原文件执行 `strings` 定向搜索，提取到 [具体内容] 共 3 条。该内容不在任何表中（已逐表验证）。
> 本报告的「未发现」结论限于 `DigiForensics-recovered.db` 中恢复出的 149 条记录与 3 条残留内容。 损坏页内可能存在未恢复的记录，**无法排除其存在性**。

最后这句是这一类阴性发现的必要限定——「7 条记录位于损坏页内未能恢复」这个事实一旦存在，「未发现 X」就必然是有条件的。

<a id="section-25"></a>

### 4.3 残留数据与编码

<a id="section-26"></a>

#### 陷阱 6：看到 `DELETE` 就认为数据没了

**现象**：`SELECT count(*) FROM message WHERE content LIKE '%5188%'` 返回 0，报告写「聊天记录中不存在涉及该卡号的内容」。

**原因**：`DELETE` **不一定**擦除数据字节——这取决于目标库的 `PRAGMA secure_delete`（见 2.x 的三档实测）。它在默认（OFF）下的行为是：把该 cell 从页的 cell 指针数组中移除（**于是表的 B-tree 不再引用它**）、把释放的空间记入空闲空间链（若整页空了则把页挂进 freelist 链），**字节内容原地保留**，直到该页被新数据复用才被覆盖。所以在 `secure_delete=OFF` 的库里，「表里查不到」与「文件里没有」是两个完全不同的断言，前者只说明逻辑引用断了。本案的 `strings` 提取正是从空闲区里取出了完整的转账备注内容，而这些内容在任何表里都查不到——**但这个结论只在实测确认 `secure_delete` 为 OFF 或 FAST 时成立**；若为 ON，删除即被清零，本案式的恢复不成立。

**影响**：这是本领域「以为没找到但其实有」的高频形态，而且它的严重性在于证据性质的改变。 如果内容在 freelist 里而分析者没去查，报告写「未发现转账相关的聊天记录」——而实际上「有人在库被删除后做过转账备注」这个事实就在文件里。**后者是完全不同的行为性质**：表内记录说明「用户主动记录」，freelist 残留说明「内容被删除过」——后者往往更值得关注，因为它可能指向刻意清理痕迹的行为。

**核查**：freelist 残留的认定必须「物理存在 + 逻辑不存在」双重验证：

```bash
# ① freelist 规模：这是第一个信号
sqlite3 app.db "PRAGMA freelist_count;"
# 312 页（占 12.5%）← 存在较多已删除数据

# ② 物理层：内容在文件的哪些位置
strings -n 8 app.db | grep -E '转账|收款|6222|5188' | head -20
# 转账备注：先转 8800 到 5188****2277，尾号 277
# 收款确认：已收到，2024-08-23

# ③ 逻辑层：确认它确实不在任何表中（这一步不能省）
sqlite3 app.db "SELECT count(*) FROM message WHERE content LIKE '%5188%';"   # 0
sqlite3 app.db "SELECT count(*) FROM pay_record WHERE remark LIKE '%5188%';"  # 0
# 逐表验证，而不是抽查两三张

# ④ 定位到具体页，确认这些字节位于 freelist 空闲区
#    （freelist trunk 页号与空闲页号数组在文件头偏移 32/36）
python3 -c "
import struct
d=open('app.db','rb').read()
ps=struct.unpack('>H', d[16:18])[0]; ps = 65536 if ps==1 else ps
trunk=struct.unpack('>I', d[32:36])[0]
nfree=struct.unpack('>I', d[36:40])[0]
print(f'freelist 首个 trunk 页={trunk}（偏移 {trunk*ps}）  空闲页总数={nfree}')
# 目标内容若落在这些页范围内，则确证位于 freelist
"
```

第 ④ 步把「在文件里」升级为「在 freelist 里」——这个定位是「已删除」这一认定的关键一环，因为文件里出现某段文本有多种可能（它在某个未被搜到的表里、它在索引里、它是别的内容的一部分），只有定位到 freelist 范围才排除了这些。

**报告表述必须体现「存在过」的证据强度限制**：

> **已删除内容（双重验证）**：在 `app.db` 空闲区（freelist 起始页 12，共 312 空闲页）提取到以下内容：[具体内容]。**物理存在**（`strings` 于偏移 [X] 处提取，落在 freelist 页范围内）**且逻辑不存在**（已逐表验证 `message`、`pay_record`、`user_profile`、`bank_card`，相关字段 `LIKE` 查询均为 0）。据此认定该内容曾存在于本库中并已被删除，且删除后未被覆写。
> **该认定的限制**：freelist 提取所得内容**缺乏结构化上下文**（无对应 ID、无时间戳字段、无关联键），可证明「该内容曾存在过」，不能直接证明「何时由谁操作」。文件中的 `转账备注` 与 `收款确认` 两条内容之间的关联、以及它们与 `pay_record` 表中记录的对应关系，**本次未建立**。

这个限制必须写，因为它直接决定了这个发现能支撑多强的结论。

<a id="section-27"></a>

#### 陷阱 7：UTF-16 编码的库用默认 `strings`，搜不到任何内容

**现象**：`strings -n 8 app.db` 输出的中文全是乱码或空，`grep` 关键词一条都搜不到，报告写「该库中未发现中文内容，疑为内容已被清空」。

**原因**：文件头偏移 56 的 `text_encoding` 字段决定了字符串的字节编码：1 = UTF-8，2 = UTF-16le，3 = UTF-16be。而 `strings` 默认只按单字节序列扫描 ASCII 区间——UTF-16 编码的中文是 `0x4E 0x2D 0x8C 0x4E` 这样的双字节序列，中间夹着 `0x00` 字节，默认模式下每个字符都被 `0x00` 截断，扫不出任何有意义的字符串。**这不是「内容被清空」，而是「编码不匹配」**——而两者的区别在于：前者是不可逆的事实，后者是换个参数就能解决的问题。

**影响**：**这会导致「已删除内容不可恢复」的错误结论。** 分析者会合理地推断「该库确实没有相关内容」，而实际上用 `strings -e l` 能提取出大量内容。在残留数据恢复这个场景里，编码判断错了等于放弃了整条技术路径。 而「库被清空过」与「库里的内容需要用正确的编码去读」是两个天差地别的结论——**前者指向销毁证据，后者只是一个技术参数。**

**核查**：**编码从文件头读，按编码选择提取方式**：

```bash
# ① 先读编码
python3 -c "
import struct
d=open('app.db','rb').read(100)
enc={1:'UTF-8',2:'UTF-16le',3:'UTF-16be'}.get(struct.unpack('>I',d[56:60])[0],'未知')
print('文本编码 =', enc)
"

# ② 按编码选择 strings 参数
ENC=$(python3 -c "
import struct
d=open('app.db','rb').read(100)
print({1:'l',2:'l',3:'b'}.get(struct.unpack('>I',d[56:60])[0],''))")
strings -n 8 -e $ENC app.db > strings-all.txt

# ③ 兜底：两种编码都跑一遍，UTF-8 的结果通常也含有效 ASCII 串
strings -n 8 app.db > s-ascii.txt
strings -n 8 -e l app.db > s-le.txt
strings -n 8 -e b app.db > s-be.txt
cat s-ascii.txt s-le.txt s-be.txt | sort -u > strings-all.txt

# ④ 验证有效性：中文能不能正常显示
grep -E '转账|收款|身份证' strings-all.txt | head
```

**第 ③ 步的三路并出不是浪费**——UTF-8 库里的 ASCII 串（如 URL、字段名）与 UTF-16 库里的中文都需要覆盖，而混合存储的库（不同表用不同编码）也确实存在。报告里应写明本次用了哪种编码组合、提取了多少条有效内容，这决定了「未发现」这个结论的检索完整性。

<a id="section-28"></a>

#### 陷阱 8：把 `freelist_count` 很大直接读成「有人删了证据」

**现象**：`PRAGMA freelist_count` 返回 312（占全库 12.5%），报告写「该库存在大量已删除数据，判断当事人有刻意清理痕迹的行为」。

**原因**：**freelist 大是一个信号，不是一个结论。** 它的成因至少有五种，而且其中三种是完全正常的：**① 应用的正常业务逻辑产生删除**——比如应用定期清理过期日志、清理已同步的临时消息、删除超过保留期的缓存记录，这类应用里 freelist 长期维持在相当高的水位；**② 表被 DROP 或数据库被重建**——结构变更会留下大量空闲页；**③ VACUUM 未执行**——SQLite 不会自动收缩文件，删除的空间只是被标记为可用，不归还给文件系统；**④ 应用执行过全量清理**（这才是「刻意清理」的形态）；**⑤ 页大小或应用配置导致的正常波动**。**而要区分它们，需要的是业务逻辑信息**——这个应用在正常使用时是否会大量删除数据？这个问题只有从应用行为或同类样本的对比中才能回答。

**影响**：**这是「把技术现象直接归因为人的动机」的典型越界。** 「刻意清理痕迹」是一个带有主观意图的定性，**它预设了当事人的动机**。一旦这个定性被采信：① 它会作为量刑或情节认定的因素；② 若实际原因是应用正常业务逻辑，这个结论在质证时会被推翻，而推翻它会连带影响同一段落里其他基于同一提取的结论；③ **更实质的问题是它可能反向引导侦查方向**——把「技术性的大 freelist」当成「人为销毁证据」会导致侦查机关去追查「谁删的」，而不去查「那批数据本来是什么」。

**核查**：**把技术事实与动机归因分成两段，后者必须有独立证据**：

```bash
# ① 技术事实（确定，可写）
sqlite3 app.db "PRAGMA freelist_count; PRAGMA page_count;"
sqlite3 app.db "SELECT name FROM sqlite_master WHERE type='table';"   # 哪些表存在

# ② 与同类样本对比（关键判据）
#    同一应用的其它检材、其他案件中同版本应用的数据目录
#    若所有样本的 freelist 都在 10-15%，则这是应用行为特征
#    若本检材显著偏离，则值得追问

# ③ 残留内容的时间跨度分析（辅助判据）
#    若残留内容集中在某个很短的时间窗内且无日常业务内容，指向定向清理
#    若残留内容覆盖整个使用期的日常业务，指向正常业务删除
strings -n 8 -e l app.db | grep -E '转账|收款|地址|电话' | head -40
ls -l --time-style=full-iso app.db*   # 残留内容所在文件的 mtime
```

**报告表述要严格分离**：

> **技术事实**：该库 `freelist_count` 为 312 页（占 `page_count` 2400 页的 13.0%），**表明存在较大规模的删除操作或页空间未回收**。
> **成因分析**：① 该应用存在定期清理过期记录的正常业务逻辑（已通过 [具体依据] 确认）；② 库文件自最后一次 `VACUUM` 后未收缩（`PRAGMA freelist_count` 与 `page_count` 长期高位共存）；③ 上述两点可解释 freelist 偏高的主体部分。
> **不认定**：「刻意清理痕迹」需要定向删除的独立证据（如残留内容集中于特定时间段且与正常业务内容无关）。本次提取的残留内容覆盖 [时间范围] 的日常业务记录，不符合定向清理特征。 本报告不认定当事人存在清理证据痕迹的行为。

**注意最后一句——「不认定」比「不提及」更有价值**，它明确表示这个问题被考虑过并给出了理由，而不是被忽略了。

<a id="section-29"></a>

### 4.4 结论表述

<a id="section-30"></a>

#### 陷阱 9：忽略 `write_version` 字段，凭「文件看起来正常」判断 journal 模式

**现象**：用 `sqlite3 app.db "PRAGMA journal_mode;"` 查询时报错或返回与实际不符的值，分析人员据此判断「该库不是 WAL 模式」，于是认为不需要提取 `-wal` 文件。

**原因**：`PRAGMA journal_mode` 是一个查询-设置混合语句，在某些状态下（库被只读挂载、文件权限限制、库处于异常状态、或者用某些工具打开时）**它的返回值可能不可靠**——它返回的是**当前连接上的模式**，而不是「文件在设备上时的模式」。而真正记录「这个库最后一次被写入时是什么模式」的是文件头偏移 18 和 19 的两个字节（`write_version` / `read_version`，值 1 = legacy journal，**值 2 = WAL**）。**这两个字节是设备端留下的、不可变的写入痕迹**，比 `PRAGMA` 的返回值可靠得多。

**影响**：**它是陷阱 3 的前置误判**——因为这一条判错，后面「只提了主库就够了」这个决定就失去了依据，**而这个决定的代价是 38 条记录被静默遗漏**。它还有一个隐蔽的形态：在只读副本上执行 `PRAGMA journal_mode` 本身会报错，而「命令报错」很容易被解释成「工具不支持」或「库有问题」，而不是「需要换判据」。

**核查**：journal 模式以文件头字段为准，`PRAGMA` 只作参考：

```bash
# ① 权威判据：文件头偏移 18/19
python3 sqlite_hdr.py app.db
# 写/读版本=2/2 (2=WAL)  ← ★ 这个是设备写入时留下的，不可变

# ② 参考判据：PRAGMA（注意它反映的是当前连接状态）
sqlite3 app.db "PRAGMA journal_mode;"
# 在只读副本上可能报错或与文件头不一致

# ③ 辅助判据：-wal 文件是否存在且有内容
ls -l app.db*
# app.db-wal  196608  ← 存在且有内容 = 确实有未回写数据

# ④ 三者一致时结论才可靠；不一致时以文件头为准并记录不一致
```

**这个「多源一致才下结论」的方法适用于所有此类判断**——文件头的字节是设备端留下的物理事实，`PRAGMA` 是当前连接的状态推断，文件的存在性是操作系统的记录。三个独立来源一致时结论才稳固；不一致时明确写出来，不要挑一个顺眼的用。

<a id="section-31"></a>

#### 陷阱 10：把 `.recover` 的输出当作与原库等价的数据

**现象**：`PRAGMA integrity_check` 报 malformed，执行 `.recover | sqlite3 DigiForensics-recovered.db` 后，用 `DigiForensics-recovered.db` 做出了完整的数据分析，报告写「该库已恢复，内容可信」，未提及恢复过程中的损失。

**原因**：`.recover` 是「尽力而为」的逐页扫描，它产出的新库与原库之间存在结构性差异：**① 丢失的部分**（损坏页内的记录、部分索引、部分约束信息、部分触发器与视图）不会出现在结果里，**而工具不会告诉你丢了多少**；**② 索引被丢弃**（`.recover` 默认只恢复表数据，不重建索引），这意味着恢复库的 `SELECT` 性能会很差，且部分依赖索引的查询会变成全表扫描，行为上与原库不同；③ 外键约束、默认值、CHECK 约束在恢复库里可能不存在，**因此「原库会拒绝的写入」在恢复库里可能被接受**——**这对后续的分析操作是一个隐患**；**④ 主键与行号信息可能改变**，导致**记录的一一对应关系与原库不一致**。

**影响**：「内容可信」这个表述掩盖了恢复本身带来的不确定性。 最直接的问题是：**丢失了多少没人知道**——报告里说「已恢复」但没说「丢了 7 条」，读者会默认「全部拿到了」。**其次是行号变化导致的关联失效**——如果分析时用 `rowid` 或某个自增 ID 做关联，而恢复库里这些 ID 与原库不一致，**那么基于它们建立的关联关系就是错的**。**最后一点最实际：恢复库被当成原始件使用**——如果后续在恢复库上执行了任何写操作，再回头说「这是从检材中提取的」，路径就不成立了。

**核查**：恢复是「派生分析」而不是「原件替代」，损失必须量化：

```bash
# ① 记录完整性检查的全部输出（损坏页清单是量化损失的依据）
sqlite3 app.db "PRAGMA integrity_check;" | tee integrity-report.txt
sqlite3 app.db "PRAGMA integrity_check;" | grep -c 'malformed\|row .* missing'   # 损坏项数

# ② 恢复，并做完整性验证
sqlite3 app.db ".recover" | sqlite3 DigiForensics-recovered.db
sqlite3 DigiForensics-recovered.db "PRAGMA integrity_check;"

# ③ 量化损失：逐表对比记录数与时间范围
for t in $(sqlite3 DigiForensics-recovered.db "SELECT name FROM sqlite_master WHERE type='table';"); do
  echo "=== $t"
  sqlite3 DigiForensics-recovered.db "SELECT count(*), min(createTime), max(createTime) FROM $t;" 2>/dev/null
done | tee recovered-stats.txt
# 与原库能读出的部分逐表对比，差额 = 未能恢复的记录

# ④ 恢复库的性质要标明
sqlite3 DigiForensics-recovered.db "SELECT count(*) FROM sqlite_master WHERE type='index';"
# 索引数量通常为 0 → 这是「.recover 不重建索引」的证据，要写进报告

# ⑤ ★ 恢复库只读，不在它上面做任何写操作
chmod 444 DigiForensics-recovered.db
```

**报告表述**：

> **恢复方式与范围**：`app.db` 结构损坏（`integrity_check` 报告损坏页 9 处）。经 `.recover` 逐页恢复至 `DigiForensics-recovered.db`（SHA-256 `e5f6…`），完整性检查通过。
> **恢复损失**：`DigiForensics-recovered.db` 中 `pay_record` 156 条（原库可读 156，**恢复 149，7 条位于损坏页内未能恢复**）；`message` 表恢复率 100%（损失 0）。**索引未重建**（`DigiForensics-recovered.db` 中索引数为 0），故其 `SELECT` 行为与原库不完全一致。
> **性质说明**：`DigiForensics-recovered.db` 是从 `app.db` 派生的分析副本，不是原始提取件。原始提取件 `app.db`（SHA-256 `a1b2…`）保持只读未改动。本报告的数据结论基于 `DigiForensics-recovered.db`，其与原库的差异已在上表逐项列出。
> 本报告的「未发现」结论限于 `DigiForensics-recovered.db` 中恢复出的内容。损坏页内可能存在未恢复的记录，无法排除其存在性。

<a id="section-32"></a>

#### 陷阱 11：把「用某个工具能读出数据」当作「库就是明文 SQLite」

**现象**：某个 `.db` 文件，`sqlite3` 打开报 `file is not a database`，但某个第三方解析工具能列出若干条记录。分析人员据此判断「这不是 SQLite 文件，是别的格式」或「该库已被部分损坏」。

**原因**：「`sqlite3` 打不开」与「不是明文 SQLite」是两个不同的结论。 报 `file is not a database` 的最常见原因是**文件头被改写**——SQLCipher 类的加密实现在应用密钥后会把文件头部改写为随机 salt，此时前 16 字节不再是 `SQLite format 3\0`，`sqlite3` 直接拒绝。而某些专用工具能够读取，是因为**它们实现了对应的解密逻辑**（比如它内部带了一个口令、或者它会先尝试常见的派生方式）。**第二个可能性是分片或变体**——同一格式的不同实现可能有不同的头部约定。**第三个可能性是文件被截断**——尾部缺失时头部仍在，但打开会报 `malformed` 而非 `not a database`。这三种情况的处置方式完全不同，而它们在错误信息上的区分度很低。

**影响**：误判为「非 SQLite 格式」会导致整个分析方向跑偏——分析人员会去找「这是什么格式的文件」，而正确的路径是「它是被加密的 SQLite」或者「它被截断了」。**而误判为「已损坏」则会导致不必要的放弃**。更实质的问题是：如果它是被加密的，那么「用某个工具读出了数据」这个事实本身就涉及授权与手段合法性，而这个前提在报告里没有被识别和处理。

**核查**：按错误信息与头部字节分三路判定，不合并成「打不开」：

```bash
# ① 头部检查：三种情况在这里就分开了
head -c 16 app.db | xxd
# 53514c69 74652066 6f726d61 74203300  → "SQLite format 3\0" → 明文，头部完好
# 9a3f27c1 ...（随机）              → 头部被改写 → 疑似文件级加密

# ② 熵值：加密文件的熵接近 8.0
python3 -c "
import math,collections
d=open('app.db','rb').read()
c=collections.Counter(d); n=len(d)
print('熵=%.3f bits/byte  头 16 字节: %s' % (
  -sum((v/n)*math.log2(v/n) for v in c.values()), d[:16].hex()))"

# ③ 文件大小是否与页大小整除（判断截断）
python3 -c "
import struct
d=open('app.db','rb').read()
ps=struct.unpack('>H', d[16:18])[0]; ps=65536 if ps==1 else ps
print(f'页大小={ps} 文件={len(d)} 余字节={len(d)%ps}')"

# ④ 尾部检查：截断文件的最后几字节通常是乱码或半条记录
tail -c 64 app.db | xxd
```

**分路判定的结论要写清**：

> **格式判定**：`app.db` 前 16 字节为 `9a3f27c1…`（非 `SQLite format 3\0`），全文件熵 7.998 bits/byte，**符合文件级加密的形态特征**。文件大小为页大小的整数倍，**排除截断**。
> **结论**：本库为**头部被改写的 SQLite 库**，疑似使用文件级加密（头部被写入随机 salt）。「无法用标准 `sqlite3` 打开」是加密的正常表现，不是结构损坏。
> **未覆盖范围**：本报告未对加密实现做进一步判定（具体实现类型、口令来源、解密路径），**未使用任何口令尝试解密**。相关判定方法见 [02-SQLite-WAL取证](mobile-database-sqlite-wal.md) 与 [04](../mobile-android/mobile-android-frida-dynamic-hooking.md)。
<a id="section-33"></a>

## 五、案例示例

<a id="section-34"></a>

### 5.1 WAL 缺失导致 38 条交易记录遗漏与 mtime 矛盾

**场景**

查获一台 Android 手机，某应用私有目录中的 `app.db` 已被提取。委托方要求查明两件事：该应用是否存储了用户的银行卡信息，以及"已删除"记录中是否有转账信息。

关键前提：初次检材只有 `app.db` 一个文件，是 `adb pull` 单文件的结果，没有 `-wal`/`-shm`。 这个细节决定了整个案例的走向。

**处置过程**

第一步，文件头解析 —— **两个字段直接决定了后续路线**：

```bash
$ ls -l app.db*
-rw-r--r-- 1 root root 2457600 2024-08-31 23:14:02 app.db
# ★ 只有这一个文件

$ sha256sum app.db | tee app-hashes.txt
$ xxd -l 16 app.db
00000000: 5351 4c69 7465 2066 6f72 6d61 7420 3300  SQLite format 3.

$ python3 sqlite_hdr.py app.db
```

| 偏移 | 字段 | 值 | 判读 |
|---|---|---|---|
| 16–17 | 页大小 | **1024** | **★ 不是 4096** |
| 18 | 写版本 | **2** | **★ WAL 模式** |
| 19 | 读版本 | 2 | 支持 WAL 读取 |
| 28–31 | 变更计数器 | 41827 | 被正常使用过 |
| 32–35 | 总页数 | 2400 | 2400 × 1024 = 2,457,600 字节 ✅ |
| 36–39 | freelist 页数 | **312** | **★ 312/2400 = 13.0% 为空闲页** |
| 44–47 | schema cookie | 47 | 结构版本号，每次 schema 变更递增（**不等于变更次数**：`VACUUM` 会重置它，也可能跳过） |
| 56–59 | 写入版本号 | 3045001 | SQLite 3.45.1 |

`write_version = 2` 是最重要的一个字段。 它的含义是"该库当前是 WAL 模式"，而 WAL 模式下**最新的写入在 `-wal` 文件里，没回写到主库**。只提 `app.db` 等于只拿到了上一次 checkpoint 的快照。

第二步，**回到设备补提取，从根因上解决**：

```bash
$ PKG=com.digiforensics.sample
$ adb shell su -c "ls -l /data/user/0/$PKG/databases/"
-rw-r--r-- 1 u0_a123 u0_a123  2457600 2024-08-31 23:14:02 app.db
-rw-r--r-- 1 u0_a123 u0_a123   196608 2024-08-31 23:14:02 app.db-wal   ← 存在
-rw-r--r-- 1 u0_a123 u0_a123    32768 2024-08-31 23:14:02 app.db-shm   ← 存在

$ adb shell su -c "tar -cf - -C /data/user/0/$PKG databases" > db.tar
$ tar -xvf db.tar
$ sqlite3 app.db "PRAGMA integrity_check;"     # ok
$ sqlite3 app.db "PRAGMA journal_mode;"        # wal
$ sqlite3 app.db ".tables"
message  pay_record  user_profile  bank_card
```

用 `tar` 整体打包目录，而不是逐个 `adb pull` —— 后者只保证文件被取到，不保证三文件配套（配套性判据见 4.4 陷阱 9 与 [09 篇](mobile-database-sqlite-wal.md) 陷阱 2）。

第三步，**量化 WAL 缺失的影响**：

```bash
$ cp app.db cmp1.db && sqlite3 cmp1.db "SELECT count(*) FROM pay_record;"
118
$ sqlite3 cmp2.db "SELECT count(*) FROM pay_record;"
156

$ sqlite3 cmp1.db \
  "SELECT max(datetime(createTime/1000,'unixepoch','+8 hours')) FROM pay_record;"
2024-08-22 16:41:07
$ sqlite3 cmp2.db \
  "SELECT max(datetime(createTime/1000,'unixepoch','+8 hours')) FROM pay_record;"
2024-08-31 21:07:44
```

**缺失 38 条，时间窗 8/22 至 8/31。**

第四步，**这个矛盾本身就是铁证 —— 把它写出来**：

```bash
$ stat -c '%y  %n' app.db
2024-08-31 23:14:02  app.db
$ sqlite3 cmp1.db \
  "SELECT max(datetime(createTime/1000,'unixepoch','+8 hours')) FROM pay_record;"
2024-08-22 16:41:07
```

文件 mtime 是 8/31 23:14，但库里最后一条交易是 8/22 16:41。 两者相差 9 天。如果这份库真的没有 8/22 之后的交易，文件为什么在 8/31 被修改过？ 这个矛盾排除了"该时段确实无交易"的解释。

第五步，银行卡信息（委托要求 1）：

```bash
$ sqlite3 -header -column app.db ".schema bank_card"
CREATE TABLE bank_card (id INTEGER PRIMARY KEY, bank_name TEXT,
  card_no TEXT, holder TEXT, id_no TEXT, bind_time INTEGER, is_default INTEGER)

$ sqlite3 -header -column app.db "
SELECT id, bank_name,
       substr(card_no,1,4)||'****'||substr(card_no,-4) AS 卡号,
       holder, is_default,
       datetime(bind_time,'unixepoch','+8 hours') AS 绑定时间
FROM bank_card ORDER BY bind_time;"
```

| id | 银行 | 卡号 | 户名 | 默认 | 绑定时间 |
|---|---|---|---|---|---|
| 1 | 工商银行 | 6222****3801 | 王某 | 0 | 2024-03-11 10:22:04 |
| 2 | 建设银行 | 6217****9155 | 王某 | 0 | 2024-05-20 15:08:41 |
| 3 | **招商银行** | **5188****2277** | **王某** | **1** | **2024-08-19 09:31:55** |

> **脱敏**：`card_no` 与 `id_no` 属个人金融信息，按最小化原则只呈现首 4 尾 4；`id_no` 字段**已完全未提取**（值存在但不在报告中出现）。

第六步，已删除记录（委托要求 2）：

```bash
$ sqlite3 app.db "PRAGMA freelist_count;"
312
$ strings -n 8 app.db | grep -E '转账|收款|6222|5188' | head -20
转账备注：先转 8800 到 5188****2277，尾号 277
收款确认：已收到，2024-08-23
```

第七步，**双重验证 —— 这是本案例的关键方法**：

```bash
# 验证一：这些内容确实不在任何表中
$ sqlite3 app.db "SELECT count(*) FROM message WHERE content LIKE '%5188%';"
0
$ sqlite3 app.db "SELECT count(*) FROM pay_record WHERE remark LIKE '%5188%';"
0
```

物理存在（strings 在空闲区检出）+ 逻辑不存在（任何表都查不到）= 已被删除且未覆写。 两个事实必须同时成立。

第八步，时间线交叉与固化：

```bash
$ sqlite3 -header -column app.db "
SELECT datetime(createTime/1000,'unixepoch','+8 hours') AS 时间, amount, remark
FROM pay_record WHERE remark LIKE '%5188%' OR createTime > 1724109664000
ORDER BY create_time LIMIT 10;"
时间                  金额      备注
2024-08-19 09:33:12   8800.00   转账至默认卡
2024-08-22 16:41:07   5000.00   备用

$ sha256sum db.tar app.db app.db-wal app.db-shm cmp2.db | tee final-hashes.txt
$ sqlite3 cmp2.db ".dump" > recovered.sql
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 初次检材不完整，缺失 38 条交易记录 | `write_version=2` + 补提取后计数 118→156 | 强（已修正） |
| 缺失窗口 8/22–8/31 | `max(createTime)` 差异 | 强 |
| 缺失的存在由文件 mtime 矛盾证实 | mtime 8/31 23:14 vs 最大交易 8/22 16:41 | 强 |
| `bank_card` 表含 3 张卡，招商银行卡为默认卡 | 表查询 | 强 |
| 招商银行卡于 2024-08-19 09:31:55 绑定 | `bind_time` | 强 |
| 空闲区存在"转账 8800 至 5188****2277"内容 | `strings` 提取 | 强（内容存在性） |
| 该内容已被删除且未覆写 | 物理存在 + 逻辑不存在，双重验证 | 强 |
| 绑卡后 77 秒发生首笔转账 | 09:31:55 → 09:33:12 | 强 |

**能证明的**：银行信息的存在与绑定时间；已删除内容的存在与"已删除"属性；时间线的自洽性。

**不能证明的**：
- **不能证明那笔 8800 元转账实际发生。** 空闲区内容无结构化上下文，无 ID、无准确时间戳
- **不能证明删除操作的执行者与时间**
- **不能证明绑定银行卡是本人操作**
- **不能排除还有未检索到的已删除内容**（312 个空闲页只做了关键词定向搜索）

**未覆盖范围**：312 个空闲页的全面解析（非定向搜索）、`-shm` 的独立价值、`message` 表的 `BytesExtra` 媒体内容、以及 SQLite 未分配区（文件尾部超出页数的部分）。

**误判对照**

这个案例的核心误判是**用一个自相矛盾的数据源得出自洽的结论** —— 而且它看起来完全正常。

**其一，把"库里没有记录"读成"没有发生过"。**

只提 `app.db` 时，分析方看到 `max(createTime) = 2024-08-22`，会写下"该应用 8/22 后未再发生交易"。**这个结论从 SQL 角度看完全正确。**

判据是**三条互相独立的检查，任意一条矛盾就说明数据不完整**：

| 检查 | 本案结果 | 若一致说明 |
|---|---|---|
| 文件头 `write_version` | **= 2（WAL 模式）** | ❌ 矛盾：存在未回写数据 |
| 文件 mtime | 2024-08-31 23:14 | ❌ 矛盾：文件在最后交易后仍被修改 |
| 同目录是否存在 `-wal` | **存在，196 KB** | ❌ 矛盾 |

**三条全部指向同一个结论：数据不完整。** 而如果三条都通过（`write_version=1`、mtime 早于最后交易、无 `-wal`），才可以放心地做阴性结论。

按错误判据走的代价：报告写"8/22 后无交易"，而实际有 38 条。委托方据此排除嫌疑人的部分行为 —— 而那些记录里很可能就包含争议交易。  更糟的是，这个错误在报告里完全不可见。

**其二，按 4096 页大小解析。**

本案实际页大小是 **1024**。数据库文件头偏移 16–17 存的是页大小，**值 1 表示 65536**（这是编码约定），其他值为 2 的幂。

判据是**永远从文件头读，不要用默认值**：

| 值 | 实际页大小 |
|---|---|
| 1 | 65536 |
| 2 | 2 |
| 512 | 512 |
| 1024 | 1024 |
| 2048 | 2048 |
| 4096 | 4096 |
| 8192 | 8192 |
| 16384 | 16384 |
| 32768 | 32768 |
| 65536 | 65536 |

判据是自洽性检查：页数 × 页大小 必须等于文件大小。 本案 2400 × 1024 = 2,457,600 ✅。若按 4096 算，2400 × 4096 = 9,830,400 ≠ 文件大小 —— **这个不匹配会在第一步就暴露问题**，前提是你做了这个检查。

其三，把 `strings` 提取的已删除内容直接当成转账证据。

这是最需要克制的误判。判据在于**物理存在与语义完整是两件事**：

| `strings` 能证明 | `strings` 不能证明 |
|---|---|
| 文件空闲区存在这些字节 | 这些字节构成一条完整记录 |
| 内容曾存在于该文件 | 何时被写入 |
| 内容与某卡号相关 | 由谁操作 |
| — | 事务是否真正完成 |

**`strings` 提取的片段没有结构化上下文。** 它可能是被删除的一行、也可能是两个不同记录拼接的片段、还可能是某个字符串被多次修改后的残留。**判据是能否定位到完整的记录边界** —— 需要结合 `record` 头部长度字段与 `cell` 结构，本次只做到字节级提取，**未做页级 cell 解析**。

按错误判据走的代价：报告写"发现转账记录 8800 元"，委托方据此认定发生了该笔转账。而这 8800 元可能只是一条草稿、一条被取消的记录、或一条从未提交的表单。

**第四个实操细节**：`strings -n 8` 的 `-n` 参数是最小匹配长度，**它会漏掉短字符串**。本案的"转账备注：先转 8800 到 5188****2277，尾号 277"因包含数字与中文混排而超过 8 字节，得以检出。但若关键内容是短字符串（如"已确认"），需要用 `-n 4` 或更低重跑。判据是定向搜索已知关键词时用 `-n 4` 兜底，全库普查时用 `-n 8` 降噪。

<a id="section-35"></a>

### 5.2 freelist 页级 cell 解析与删除记录的结构化还原

**场景**

承接 5.1。委托方对 5.1 的结论提出具体要求：`strings` 提取到的那段"转账备注"内容，委托方想知道它属于哪条记录、什么时候产生的、是否是一次完整的操作。

这正是 5.1 明确留下的未覆盖项。`strings` 只能给出字节级的存在性证明，而委托方要的是结构化事实。

这条路径要走的是 freelist 页的 cell 解析 —— 把字节串还原成有字段、有时间戳的记录。

**处置过程**

第一步，定位空闲页的具体页号，而不是全局 `strings`：

```bash
$ sqlite3 app.db "PRAGMA page_count; PRAGMA freelist_count;"
2400
312
$ python3 - <<'PY'
import struct
d = open('/work/app.db', 'rb').read()
PS = 1024
# 页 1 是数据库头页，其偏移 32 处有 freelist 链表头
head = struct.unpack('>I', d[32:36])[0]
cnt  = struct.unpack('>I', d[36:40])[0]
print('freelist 首页: %d   总页数: %d' % (head, cnt))
pages, p = [], head
while p and len(pages) < 400:
    pages.append(p)
    nxt = struct.unpack('>I', d[(p - 1) * PS + 4: (p - 1) * PS + 8])[0]
    p = nxt
print('链上页数: %d' % len(pages))
print('前 10 页:', pages[:10])
PY
freelist 首页: 1873   总页数: 312
链上页数: 312
前 10 页: [1873, 1874, 1875, 1876, 1877, 1878, 1879, 1880, 1881, 1882]
```

**312 个页号全部取到。** 注意首尾页：从页 1873 开始，说明 1873 之前的页基本是活跃数据。

第二步，逐页解析 cell 数组 —— **这是把字节还原成记录的关键**：

```bash
$ python3 - <<'PY'
import struct
d = open('/work/app.db', 'rb').read()
PS = 1024
def varint(b, off):
    v = 0
    for i in range(9):
        x = b[off + i]
        v = (v << 7) | (x & 0x7f)
        if not (x & 0x80):
            return v, off + i + 1
    return v, off + 9

found = []
for pno in range(1873, 2401):
    base = (pno - 1) * PS
    h = base + (100 if pno == 1 else 0)
    ncell = struct.unpack('>H', d[h + 3:h + 5])[0]
    if ncell == 0:
        continue
    for i in range(ncell):
        co = h + 8 + i * 2
        cell = struct.unpack('>H', d[co:co + 2])[0]
        if cell == 0:
            continue
        c = base + cell
        payload_len, o = varint(d, c)
        rowid, o2 = varint(d, o)
        if 20 <= payload_len <= 400 and 8 <= rowid <= 99999:
            found.append((pno, i, cell, rowid, payload_len))
print('可解析的 cell 数: %d' % len(found))
for f in found[:5]:
    print('  页%d cell#%d 偏移0x%04x rowid=%d 载荷%d字节' % f)
PY
可解析的 cell 数: 6
  页1873 cell#0 偏移0x0000 rowid=0    载荷185字节
  页1918 cell#1 偏移0x0231 rowid=8842 载荷112字节
  页1955 cell#2 偏移0x04a2 rowid=8843 载荷96字节
  页2003 cell#3 偏移0x0117 rowid=8844 载荷158字节
  页2077 cell#4 偏移0x0388 rowid=8845 载荷203字节
  页2210 cell#5 偏移0x05c1 rowid=8846 载荷147字节
```

6 个可解析的 cell，`rowid` 连续（8842–8846）—— 这就是被删除的记录。

第三步，按 SQLite record 格式解析字段：

```bash
$ python3 - <<'PY'
import struct
d = open('/work/app.db', 'rb').read()
PS = 1024
def varint(b, off):
    v = 0
    for i in range(9):
        x = b[off + i]
        v = (v << 7) | (x & 0x7f)
        if not (x & 0x80):
            return v, off + i + 1
    return v, off + 9

def serial(bt, buf):
    if bt == 0: return None
    if bt in (1,2,3,4,5,6): return int.from_bytes(buf, 'big', signed=True)
    if bt == 7: return struct.unpack('>d', buf)[0]
    if bt == 8: return 0
    if bt == 9: return 1
    if bt >= 12 and bt % 2 == 0:
        n = (bt - 12) // 2
        return buf[:n].decode('utf-8', 'replace')
    if bt >= 13:
        n = (bt - 13) // 2
        return buf[:n].decode('utf-16-le', 'replace')
    return ('blob', len(buf))

for pno, ci, cell, rowid, plen in [(1918,1,0x0231,8842,112),
                                   (1955,2,0x04a2,8843,96)]:
    base = (pno - 1) * PS
    c = base + cell
    _, o = varint(d, c)
    _, o = varint(d, o)
    hstart, o = varint(d, o)          # 记录头长度
    hend = o + hstart
    types = []
    p = o
    while p < hend:
        t, p = varint(d, p)
        types.append(t)
    dp = hend
    vals = []
    for t in types:
        if t in (0,8,9): n = 0
        elif t in (1,2,3,4,5,6): n = t
        elif t == 7: n = 8
        else: n = (t - 12) // 2 if t % 2 == 0 else (t - 13) // 2
        vals.append(serial(t, d[dp:dp + n])); dp += n
    print('页%d rowid=%d' % (pno, rowid))
    names = ['id','createTime','amount','channel','remark','status','extra']
    for i, v in enumerate(vals):
        nm = names[i] if i < len(names) else 'f%d' % i
        if nm == 'createTime' and isinstance(v, int) and v > 1e12:
            import datetime
            v = '%d (%s)' % (v, datetime.datetime.utcfromtimestamp(v/1000+8*3600)
                             .strftime('%Y-%m-%d %H:%M:%S'))
        if isinstance(v, str) and len(v) > 50: v = v[:50] + '…'
        print('   %-11s %s' % (nm, v))
PY
页1918 rowid=8842
   id           8842
   createTime   1724348112000 (2024-08-23 14:55:12)
   amount       8800
   channel      wechat
   remark       先转 8800 到 5188****2277，尾号 277
   status       0
   extra
页1955 rowid=8843
   id           8843
   createTime   1724434428000 (2024-08-24 14:53:48)
   amount       8800
   channel      wechat
   remark       已确认，款到账
   status       1
   extra
```

**结构化还原成功。** 时间戳、金额、渠道、备注、状态全部可读。

第四步，把 `status` 字段与活跃记录对比 —— 这决定了删除记录的语义：

```bash
$ sqlite3 -header -column app.db \
  "SELECT status, count(*) AS 条数, min(createTime), max(createTime)
   FROM pay_record GROUP BY status;"
status  条数  最早                 最晚
0       121   1721038924000        1725109664000
1       35    1722409084000        1725085324000

$ sqlite3 -header -column app.db \
  "SELECT id, datetime(createTime/1000,'unixepoch','+8 hours') AS 时间, amount, status
   FROM pay_record WHERE status=1 LIMIT 3;"
id   时间                  金额     status
412  2024-08-01 09:38:04   200.00   1
587  2024-08-02 16:22:31   500.00   1
```

活跃记录里 `status` 也有 0 和 1 两个值。 需要确认哪个是"已完成"：

```bash
$ sqlite3 -header -column app.db ".schema pay_record"
CREATE TABLE pay_record (id INTEGER PRIMARY KEY, createTime INTEGER,
  amount REAL, channel TEXT, remark TEXT, status INTEGER)
# 无注释，看不出语义
$ sqlite3 -header -column app.db \
  "SELECT id, datetime(createTime/1000,'unixepoch','+8 hours') AS 时间, amount, remark, status
   FROM pay_record WHERE status=0 ORDER BY createTime DESC LIMIT 5;"
id    时间                  金额      remark                status
1063  2024-08-31 21:07:44   300.00   （空）                 0
1062  2024-08-31 18:22:10   150.00   备注                 0
```

`status=0` 的记录有大量 `remark` 为空、时间最近 —— 说明 0 更可能是"待处理/未完成"，1 是"已完成"。 这个推断需要更多证据：

```bash
$ sqlite3 app.db "SELECT count(*) FROM pay_record WHERE status=1 AND remark LIKE '%已%';"
35
$ sqlite3 app.db "SELECT count(*) FROM pay_record WHERE status=1;"
35
# 全部 35 条 status=1 的记录 remark 都含"已"字 → 强相关
```

`status=1` 的 35 条记录，`remark` 100% 含"已"字。 语义确认：`status=1` = 已完成。

第五步，**把删除记录与活跃记录做同类对比**：

```bash
# 删除的两条都是 status=0 → 状态为"未完成"时被删除
$ python3 -c "
print('删除记录 8842: status=0（未完成）')
print('删除记录 8843: status=1（已完成）')
"
```

其中一条已完成（8843，2024-08-24，备注"已确认，款到账"），另一条未完成（8842，2024-08-23）。

第六步，固化并与 `bank_card` 时间线对齐：

```bash
$ sha256sum db.tar app.db app.db-wal app.db-shm deleted-cells.json | tee final-hashes.txt
$ python3 -c "
import datetime
for r in [(8842,1724348112000,8800,0),(8843,1724434428000,8800,1)]:
    print('%d  %s  %.2f  status=%d' % (r[0],
        datetime.datetime.utcfromtimestamp(r[1]/1000+8*3600).strftime('%Y-%m-%d %H:%M:%S'),
        r[2], r[3]))
" > deleted-cells.txt
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| freelist 含 312 页，可定位具体页号 | freelist 链表解析，1873–2400 | 强 |
| 其中 6 个 cell 结构完整可解析 | cell 数组解析，`rowid` 连续 8842–8846 | 强 |
| 记录 8842：2024-08-23 14:55:12，8800.00，wechat，`status=0` | record 格式解析 | 强 |
| 记录 8843：2024-08-24 14:53:48，8800.00，wechat，`status=1`（已完成） | record 格式解析 | 强 |
| 两条记录已被删除且未覆写 | 存在于 freelist cell + 逻辑表中无对应 rowid | 强 |
| `status` 语义为 1=已完成 | 35 条 `status=1` 记录 remark 100% 含"已"字 | 中（语义推断） |
| 8800 元转账被标记为已到账 | 记录 8843 的 remark 与 status | 中（应用内标记，非银行侧确认） |

**能证明的**：删除记录的**完整结构**（含 rowid、时间戳、金额、渠道、备注、状态）；删除是定向的行删除而非页覆写；同一天内存在两条同金额记录（一建一确认）。

**不能证明的**：
- **不能证明资金实际到账。** `status=1` 是应用内的标记，**需银行流水或支付平台对账单才能确认**
- **不能证明删除操作者与删除时刻**
- **不能证明这两条记录已被成功提交到服务端**
- **不能证明 8844–8846 的内容**（本次仅解析出 2 条完整记录，其余 cell 结构不完整）

**未覆盖范围**：页 1873–2400 中其余 306 页的 cell 内容、`rowid` 8844–8846 对应的记录（可解析但未逐条提取）、`extra` 字段（BLOB，本次为空）、以及该表在 WAL 中的历史版本。

**误判对照**

这个案例的误判点在于**把"字节级存在"当成"记录级事实"** —— 5.1 明确留了这个缺口。

其一，用 `strings` 的输出直接当记录内容。

`strings` 的输出是**按字节序列切分的片段**，它不保证：

| `strings` 保证了 | `strings` 没保证 |
|---|---|
| 这些字节在文件里 | 它们属于同一条记录 |
| 这些字节构成可读文本 | 中间没有其他字节插入 |
| — | 前面/后面还有什么字段 |

本次 `strings` 给出的"转账备注：先转 8800 到 5188****2277，尾号 277"看起来完整，但**它无法告诉我们**：

- 前面是否还有 `createTime` 字段（实际有，1724348112000）
- 金额字段是独立列还是嵌在 remark 里（实际是独立列 `amount=8800`）
- 这条记录的 `rowid` 是多少（实际是 8842）

**判据是能否定位到 cell 边界**。`rowid` 连续（8842/8843/8844/8845/8846）这一点，**只有解析 cell 数组才能看出来** —— 它是"这是同一批被删除的连续记录"的最强证据，而 `strings` 完全给不出。

按错误判据走的代价：报告写"发现一条转账记录，金额 8800 元" —— 而实际上有**两条**（8842 的原始记录 + 8843 的确认记录），且第一条的 `status=0`（未完成）。**只报一条会掩盖"存在一次未完成的尝试"这个事实**，而后者往往是关键的。

**其二，把 `status` 字段的语义猜错。**

`status` 是 0 还是 1 表示"已完成"，从表结构上看不出来（无注释、无约束）。本次的验证方法值得写下来：

```bash
$ sqlite3 app.db "SELECT count(*) FROM pay_record WHERE status=1 AND remark LIKE '%已%';"
35
$ sqlite3 app.db "SELECT count(*) FROM pay_record WHERE status=1;"
35
```

35 条 `status=1` 的记录，100% 的 `remark` 含"已"字。 这个全称量词式的相关性，是语义推断的有力依据。

**对比错误做法**：随便看两条记录，恰好一条 `status=1` 的 remark 是"已确认，款到账"，就断定"1 = 已完成"。**样本量为 1 时的推断可能是巧合。** 判据是**至少用 10 条以上样本做全称检查**，或者找到字段名/取值有明确语义的旁证。

**本案还有一个反向的验证机会，但需要谨慎**：`status` 字段在删除记录里也出现了（8842 的 0、8843 的 1），说明这个字段在删除前就已写入，**语义与活跃记录一致**。这是自洽性检查，但不能替代独立验证。

其三，把应用内的 `status=1` 当成"资金已到账"。

这是本案例最需要克制的推断。判据是"应用记录的完成状态"与"外部事实的确认"之间的距离：

| 断言 | 所需证据 |
|---|---|
| 应用内标记该笔为已完成 | 记录 8843 的 `status=1` ✅ |
| 支付平台受理了该请求 | 平台侧对账单 ❌ |
| 资金实际到账 | **银行流水 ❌** |
| 收款方实际收到 | 收款方账户记录 ❌ |

**这三层之间没有自动的蕴含关系。** 应用可能在网络超时后误标成功，也可能在用户手动标记后并未真正转账。**判据是：应用侧状态只能证明"应用认为它完成了"。**

按错误判据走的代价：委托方据此向收款方追讨款项，或向银行申请冻结。**若款项从未到账，报告就成了责任证据。**

**第四个实操细节**：freelist 页的 cell 数组解析有一个陷阱 —— `freelist_count` 统计的是空闲页数，但空闲页上不一定有 cell。SQLite 删除行时，cell 内容通常被清除、页被加入 freelist，只有在页内空间不足、需要把不完整 cell 保留的情况才可能有残留。判据是**页头 `cell count` 是否非零**。本案 2400 页里只解析出 6 个有 cell 的页，说明大部分空闲页确实已被清空 —— 这本身也是一条结论：**删除操作伴随了页级的空间回收**。

<a id="section-36"></a>

## 六、扩展阅读方向

本篇给出的是 SQLite 的"静态解剖"能力。延伸方向分为四组。

**同一引擎的另一面：WAL 与删除残留**

- [SQLite WAL 取证](mobile-database-sqlite-wal.md) —— **本篇 2.5 那三行机制的完整展开**。`write_version=2` 之后发生了什么、checkpoint 触发条件、**删库残留如何在 `-wal` 里被找回**，以及合并前后差分那套验证动作。
- [MySQL 数据库取证](mobile-database-mysql.md) —— 对照阅读最有价值的一篇。从单文件变成多表空间，从"库即文件"变成"库依赖服务"，随之而来的是完全不同的取证路径（表空间文件、binlog、缓冲池落盘）。
- [NoSQL 与 Redis 取证](mobile-database-mongodb-and-redis-forensics.md) —— 更进一步：**没有固定 schema 意味着没有结构可解析**，取证重心落在序列化格式与内存转储上。

**把结论说得清：通用流程与报告**

- [数据库取证通用方法](mobile-database-database-forensics-methods.md) —— 引擎识别、时区归一、阴性发现的表述模板。**它是本篇的流程化版本，本篇是它的原理论证。** 遇到非 SQLite 的库时，这篇是你的入口。
- [时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md) —— 库里的时间字段通常是 Unix 秒 / 毫秒 / 文本三种形态，量级判错会让时间线整体偏移数年。
- [SQLite 基础与结构的加密对照：数据库与配置文件加密](../../crypto/crypto-app/crypto-app-database-configuration-decryption.md) —— **加密库会改写文件头魔数**，这是"打不开"最容易被误判成"损坏"的原因。识别页级加密特征、判定加密类型的方法在这一篇。

**相邻载体：SQLite 之外的同类问题**

- [浏览器取证](../../computer/computer-browser-behavior/computer-browser-behavior-browser-forensics.md) —— 浏览器的历史、书签、缓存大量使用 SQLite，**且不同浏览器版本的 schema 变化频繁**。本篇的结构知识直接适用。
- [SRUM 数据库分析](../../computer/computer-browser-behavior/computer-browser-behavior-srum.md) —— Windows 上另一个 SQLite 库，字段语义复杂而取证价值高，是本篇方法的一个深度应用。
- [iOS 备份与沙盒提取](../mobile-ios/mobile-ios-ios-backup-and-sandbox-extraction.md) —— iOS 侧大量使用 SQLite，但路径在 `Manifest.db` 里被索引过，取出入口与 Android 不同。

**方法与规范：这一层能力怎么复用到别的格式上**

- [文件雕刻与签名恢复](../../filesystem/filesystem-unix/filesystem-unix-file-carving-and-signature-recovery.md) —— 库文件损坏时的兜底：从整镜像直接按内容特征雕刻出文件。本篇的"字节级判断"思路在这里扩展到了所有格式。
- [哈希与完整性校验](../../fundamentals/fundamentals-concepts/fundamentals-concepts-hashes-and-integrity-verification.md) —— `integrity_check` 校验的是结构一致性，SHA-256 校验的才是字节同一性。**两者的差别决定了报告里能写什么话。**
- [文件签名与文件头](../../filesystem/filesystem-ntfs/filesystem-ntfs-file-headers-and-signatures.md) —— 用魔数识别格式的通用方法，与本篇 2.1 的判据逻辑一脉相承。
<a id="section-37"></a>

## 七、命令速查

```bash
# ===== 环境 =====
sudo apt install sqlite3 foremost
sqlite3 --version

# ===== 身份验证 =====
ls -l app.db*                        # ★ 确认 -wal / -shm 是否存在
sha256sum app.db app.db-wal app.db-shm 2>/dev/null | tee app-hashes.txt
file app.db
xxd -l 16 app.db                     # 期望 SQLite format 3.

# ===== 文件头（偏移是硬指标）=====
# 0   16B magic "SQLite format 3\0"
# 16   2B page_size（大端；★ 值 1 表示 65536）
# 18   1B write_version（2 = WAL）    19  1B read_version
# 24   4B file_change_counter         28  4B database_size_in_pages
# 32   4B first_freelist_trunk_page   36  4B number_of_freelist_pages
# 40   4B schema_cookie               56  4B text_encoding（1/2/3 = UTF-8/le/be）
# 96   4B sqlite_version_number
python3 - <<'PY'
import struct, sys
d = open(sys.argv[1], 'rb').read(100)
if d[:16] != b"SQLite format 3\x00":
    print("!! 非明文 SQLite（可能已加密）"); sys.exit(1)
u = lambda o: struct.unpack('>I', d[o:o+4])[0]
ps = struct.unpack('>H', d[16:18])[0]
print("页大小 =", 65536 if ps == 1 else ps, "| 版本 =", d[18], "/", d[19],
      "| 总页数 =", u(28), "| freelist =", u(36), "| schema_cookie =", u(40),
      "| 编码 =", {1:'UTF-8',2:'UTF-16le',3:'UTF-16be'}[u(56)])
PY

# ===== 完整性 =====
sqlite3 app.db "PRAGMA integrity_check;"
sqlite3 app.db "PRAGMA quick_check;"
sqlite3 app.db "PRAGMA page_size; PRAGMA page_count; PRAGMA freelist_count;"
sqlite3 app.db "PRAGMA journal_mode; PRAGMA encoding; PRAGMA schema_version;"

# ===== 表结构 =====
sqlite3 app.db ".tables"
sqlite3 app.db ".schema"
sqlite3 app.db "SELECT type,name,tbl_name FROM sqlite_master;"

# ===== ★ 让 WAL 生效（永远在可写副本上）=====
cp app.db work.db && cp app.db-wal work.db-wal && cp app.db-shm work.db-shm
sqlite3 work.db "PRAGMA wal_checkpoint(TRUNCATE);"
sqlite3 work.db "SELECT count(*) FROM message;"

# ===== 残留提取 =====
strings -n 8 app.db > strings-all.txt
strings -n 8 -e l app.db > strings-utf16.txt      # 编码为 UTF-16le 时必须
grep -E '身份证|银行卡|转账|手机号' strings-all.txt | head -40
foremost -t all -i -o carved/ app.db               # 按签名雕刻

# ===== 页类型分布（ps 必须用文件头读出的真实值）=====
python3 - <<'PY' app.db 1024
import sys, collections
fn, ps = sys.argv[1], int(sys.argv[2])
d = open(fn, 'rb').read()
types = {2: "内部索引", 5: "内部表", 10: "叶索引", 13: "叶表"}
c = collections.Counter(types[d[o]] for o in range(ps, len(d)-ps, ps) if d[o] in types)
for k, v in c.most_common(): print(f"{k:8s} {v}")
PY
# ★ 0x0D（叶表页）才是用户可见的表数据所在

# ===== 导出与固化 =====
sqlite3 -header -csv app.db "SELECT * FROM message ORDER BY createTime;" > message.csv
sqlite3 app.db ".dump" > recovered.sql
sha256sum app.db app.db-wal app.db-shm message.csv | tee final-hashes.txt
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 移动与数据库取证 — SQLite 基础与结构」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《SQLite 基础与结构》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.vc` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
