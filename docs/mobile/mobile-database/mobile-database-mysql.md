---
title: "MySQL 数据库取证"
slug: "mobile-database-mysql"
canonical: "https://www.digiforensics.cn/wiki/mobile-database-mysql"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:50+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "mobile"
space: "移动取证"
node_path: ["应用数据库"]
---

# MySQL 数据库取证

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/mobile-database-mysql)

<a id="section-1"></a>

## 一、概述

MySQL 取证的最大特征是：它不是"一个文件"，而是一整套文件协同描述数据库状态。只看 `.ibd` 或只看 `.frm`，都会得出错误结论。

更重要的是它的日志体系给取证提供了普通关系库没有的能力：

> ## ⭐ binlog 里保存着**已经执行过的删除操作**
>
> `DELETE FROM users WHERE id=42;` 之后，表里没有 42 号用户了。
> 但如果 **binlog 开启且格式为 ROW**，日志里**永久保存着 42 号用户删除前的完整行镜像**——所有列的旧值、事务 ID、执行时间、服务器 ID。
>
> 这是 MySQL 取证中一类容易被忽略的证据。 它不需要恢复物理页、不需要解析 freelist，只要 binlog 还在，删除前的事实就是可读、可校验、可复现的。

需要先建立的核心认知：

| 认知 | 含义 |
|---|---|
| **数据不在一个文件里** | 系统表空间 + 独立表空间 + undo + redo + binlog 共同构成数据库状态 |
| **版本决定文件布局** | 5.6 / 5.7 / 8.0 的文件组成**完全不同**，不先定版本就会找错文件 |
| **binlog 是逻辑日志** | 它记录"发生了什么操作"，而非"数据在哪个页"——**因此它对页损坏免疫** |
| **时间戳无时区** | MySQL 的 `datetime` 不带时区，binlog 时间戳用**服务器本地时间**（见 [12](mobile-database-database-forensics-methods.md)） |

**在取证流程中的位置**：本篇属于**分析**环节，而且路径是分叉的：binlog 在就直取 binlog，binlog 缺失或已过期才回到物理层（`ibdata1`、`.ibd`、undo 里的 MVCC 旧版本）。这个顺序不能反——binlog 存在时先啃物理页格式属于本可避免的工作量。**上游依赖**是 [数据库取证通用方法](mobile-database-database-forensics-methods.md)（时区与阴性表述纪律、`SHOW VARIABLES` 与配置文件的读取顺序）以及 [只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md)（数据库目录必须整体归档，不能只拷一个 `.ibd`）。**下游**是把行镜像与业务事实对齐，这一步靠 [系统日志深度分析](../../computer/computer-log/computer-log-system-log-analysis.md) 里的 shell 与登录痕迹、以及应用侧日志交叉。表结构或内容在磁盘上被加密时，判定与密钥材料位置走 [数据库与配置文件加密](../../crypto/crypto-app/crypto-app-database-configuration-decryption.md)。

**本篇处理的证据形态**，先按版本定文件组成，再按文件取内容：

| 文件 | 5.6 / 5.7 | 8.0 | 取证价值 |
|---|---|---|---|
| **binlog** | `binlog.000001`…、`binlog.index` | 同，**8.0 默认就是 `ROW`** | **最高**——含删除前旧值与执行时间 |
| 系统表空间 | `ibdata1`（含数据、undo、字典） | **`ibdata1` 缩为只含数据字典**，undo 独立 | 中——字典与残留数据 |
| 表数据 | `.ibd`（`innodb_file_per_table=ON`） | 同 | 高——单表独立文件 |
| 表定义元数据 | `.frm` | **已废弃移除**，改为事务数据字典（存于 `mysql.ibd`） | 5.x 用来还原列名与类型 |
| undo 表空间 | 强制在 `ibdata1` 内 | `undo_001`、`undo_002` 独立 | **中高——MVCC 未清理版本可能含旧值** |
| redo log | `ib_logfile0` / `ib_logfile1` | **`#innodb_redo/`** 目录（8.0.30+） | 低——物理页镜像，格式随版本剧变 |
| 二进制日志格式 | `binlog_format` 三选一：`STATEMENT` / `ROW` / `MIXED` | 同 | **决定删除前值能否读出**，判定入口在 `binlog.index` 与文件头 |

binlog 内部的判读字段也固定：事件类型 `Query` / `Write_rows` / `Update_rows` / `Delete_rows`，ROW 事件里带 `table_id`、`server_id`、`transaction_id`、时间戳，以及删除事件的 `before_image`（旧值整行）。**用 `mysqlbinlog` 读不动时**，可以按事件头的长度字段手工跳着扫，这是本篇第三章第 3 步的做法。

某个库有哪些表与列（5.x 靠 `.frm`，8.0 靠数据字典）、binlog 覆盖的时间窗内发生过哪些 DDL 与 DML、**被删除或被更新前的完整行镜像**、删除操作来自哪个 `server_id` 与哪个事务、undo 里尚未被清理的旧版本内容、以及配置层面 binlog 是否开启、格式是什么、有没有过期。

**binlog 里没有的东西就是没有**——binlog 通常有 `expire_logs_days` 或按容量滚动，最老的文件被自动删除，这个动作本身不留痕，**"没找到"和"已被过期清理"从盘上看不出区别**，所以阴性结论必须写成"在 `binlog.00000X`～`binlog.0000Y` 覆盖的时间窗内未发现……"，并把这个窗口写进报告。ROW 事件里的时间戳用**服务器本地时间且不带时区**，直接与应用日志比对必然出偏差；`server_id` 是实例标识，不等于操作者身份，**binlog 证明不了"是谁"**。binlog 是逻辑日志，不含页号与偏移，所以它**回答不了数据物理位置**，也无法证明某段数据当前还在表里——`UPDATE` 与随后的 `DELETE` 都会留在日志里，只能读到历史。undo 里的 MVCC 旧版本能不能读到取决于长事务是否还开着、长事务一结束就可能被 purge，**这是有时效窗口的证据，不是稳定来源**。最后，8.0 上 `.frm` 不存在，用 5.x 的方法找列名会直接扑空，而 binlog 的列名依赖当时的表定义，**表结构改过之后旧事件的列名映射会断裂**。

**读者前提**：需要先定 MySQL 大版本再动手——本篇所有偏移与文件清单都按版本给，版本判断错了后面全错（判据是 `mysql.ibd` 是否存在、`my.cnf` 的默认值、`@@version` 的残留痕迹）；需要能读十六进制并理解"页"这个单位，以及 binlog 事件头里长度字段的作用（手工跳扫时靠它定位下一个事件）；需要分清 redo（物理）与 binlog（逻辑）两类日志为什么取证价值差一个量级；还需要掌握 MySQL 配置的读取顺序（配置文件 → 环境变量 → 命令行参数，后面覆盖前面），否则改了 `binlog_format` 的场景会被漏掉。

---
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 三类日志的分工

| 日志 | 内容 | 所在 | 取证价值 |
|---|---|---|---|
| **redo log** | 物理日志：哪些页被怎么改的 | `ib_logfile*`（5.6/5.7）、`#innodb_redo/`（8.0.30+） | 低（崩溃恢复用，格式复杂） |
| **undo log** | 回滚信息与历史版本 | 系统表空间（5.6/5.7）、独立 undo 表空间（8.0 默认） | **中高**——MVCC 未清理版本可能含旧值 |
| **binlog** | **逻辑日志：DDL/DML 的语句或行事件** | `binlog.00000X`、`binlog.index` | **最高**——含删除前旧值 |

**取证应当优先攻 binlog，而不是 redo。** 原因是：redo 是物理页镜像，解析需要精确匹配 InnoDB 内部格式且随版本剧变；binlog 是行级文本/行事件，人可读、工具成熟、结论可复现。

<a id="section-4"></a>

### 2.2 版本差异：必须先定版本

| 项目 | 5.6 | 5.7 | 8.0 |
|---|---|---|---|
| 表定义元数据 | **`.frm`** | **`.frm`** | **事务数据字典（存于 `mysql.ibd`）**，`.frm` 已废弃移除 |
| 表数据 | `.ibd`（`innodb_file_per_table=ON` 时） | 同 5.6 | 同 5.6 |
| 系统表空间 | `ibdata1`（含数据、undo、字典） | `ibdata1`（含数据、undo、字典） | `ibdata1` 缩为**只含字典**，undo 独立 |
| undo 表空间 | 强制在 `ibdata1` 内 | 可用独立 undo | 默认 `undo_001`/`undo_002` 独立 |
| redo log | `ib_logfile0`、`ib_logfile1` | 同 | **`#innodb_redo/` 目录**（8.0.30+）；此前仍是 ib_logfile |
| 临时表空间 | `ibtmp1` | `ibtmp1` | `ibtmp1` |
| binlog 默认 | `binlog.0000X` | 同 | 同，且 8.0 默认 `ROW` |
| MySQL 系统库 | `mysql/*.frm` | `mysql/*.frm` | `mysql.ibd` + `mysql.ibd` 内的字典 |

> 取证第一步是先 `SELECT VERSION();` 或从文件特征判断版本，然后再决定"该去找哪些文件"。跳过这一步，5.7 上找 `mysql.ibd`、8.0 上找 `.frm` 都会走空。

**版本识别线索**（无服务可用时）：

```bash
ls data/mysql/            # 出现 mysql.ibd → 8.0；出现 *.frm → 5.6/5.7
ls data/                  # 出现 #innodb_redo/ → 8.0.30+
ls data/                  # 出现 undo_001/ → 8.0
strings data/ibdata1 | grep -m3 '5\.[67]\|8\.0'
cat data/*.cnf 2>/dev/null; cat /etc/my.cnf 2>/dev/null
```

<a id="section-5"></a>

### 2.3 InnoDB 数据页与删除行为

InnoDB 的数据以 16 KB 页为单位组织在表空间中。删除一行时：

1. 行被标记为 delete-marked，其**撤销信息写入 undo**；
2. 页进入 **purge 队列**，后台线程异步执行 purge；
3. purge 完成后，**该页被放进该表空间的 free list**，字节**通常仍然存在**。

这与 SQLite freelist 概念相似，但有两个关键差异：

| 差异 | SQLite | InnoDB |
|---|---|---|
| 旧值存放位置 | 主库文件空闲区 | **undo 表空间**（可被 purge 清理） |
| 清理时机 | 直到该页被复用 | **purge 可很快清理**，undo 也有 purge |
| 行版本 | 无 MVCC | **MVCC 保留多版本**，事务未结束前旧版可读 |

结论：InnoDB 的"已删除数据"窗口比 SQLite 更短、更不可靠。 而 binlog 不受 purge 影响——这正是 binlog 优先的原因。

<a id="section-6"></a>

### 2.4 binlog 的三种格式（决定删除前值能否读出）

| 格式 | 记录内容 | 能否还原删除前值 |
|---|---|---|
| `STATEMENT` | 原始 SQL 语句 | **不能**——只知道"删了 id=42"，不知道原值 |
| `MIXED` | 自动在两者间选择 | 视该条语句实际用的方式而定 |
| `ROW` | **每一行的变更前后镜像** | **能**——但前提是 `binlog_row_image` 不为 `MINIMAL`，见陷阱 3 |

ROW 格式下的行事件类型（重点）：

| 事件 | 含义 | 取证价值 |
|---|---|---|
| `Write_rows` | INSERT | 插入时的原始值 |
| **`Update_rows`** | UPDATE | **旧版本值 + 新版本值**（被覆盖的旧值可读） |
| **`Delete_rows`** | DELETE | **★ 删除前的完整行镜像** |
| `Table_map` | 表结构映射（列类型、NULL 位图） | 解读行事件的前提 |

**判断 binlog 格式（无需连接数据库）**：

```bash
strings binlog.000003 | grep -o 'Delete_rows\|Update_rows\|Write_rows\|Query' | sort | uniq -c
#  1200 Delete_rows     ← ROW 格式的标志
#   340 Update_rows
#  5600 Write_rows
```

若只看到 `Query`，则是 STATEMENT 格式，**删除前值不可得**，应立即转向 undo/物理页方向。

<a id="section-7"></a>

### 2.5 事务与时间

每个行事件都带：

- **事件时间戳**（`timestamp`，秒级，**使用服务器本地时区**）
- **事务 ID**（`XID`）
- 可能的 `server_id`、`GTID`

同一事务的多条事件共享 XID，恢复一条被删记录时，应把同一 XID 的所有事件一起提取，这样能同时得到该行在事务前后的完整状态。

没有事务日志的嵌入式库走的是另一条路——靠页结构与残留数据直接读，文件头与 serial type 的判读见[第 08 篇](mobile-database-sqlite.md)。

---

<a id="section-8"></a>

## 三、操作步骤

<a id="section-9"></a>

### 3.1 固定检材、版本判定与整体归档

```bash
# 1) 原始镜像哈希先行
sha256sum DigiForensics.dd | tee image.sha256

# 2) 只读挂载副本，识别数据目录与版本
mkdir -p /mnt/case
mount -o ro,loop,offset=$((2048*2048)) DigiForensics.dd /mnt/case   # 分区偏移以实际分区表为准
ls /mnt/case/var/lib/mysql/mysql/ | head -30
ls -d /mnt/case/var/lib/mysql/#innodb_redo 2>/dev/null && echo "→ 8.0.30+"
ls /mnt/case/var/lib/mysql/undo_00*       2>/dev/null && echo "→ 8.0"
ls /mnt/case/var/lib/mysql/ib_logfile*    2>/dev/null && echo "→ 5.6/5.7 或 8.0.30 之前"

# 3) 一次性打包，避免遗漏与版本不一致
cd /mnt/case/var/lib/mysql
tar -cf /work/mysql-data.tar ibdata1 ibtmp1 mysql binlog.* mysql-bin.* 2>/dev/null
find . -name '*.ibd' -o -name '*.frm' | tar -cf /work/mysql-tables.tar -T -
tar -tf /work/mysql-data.tar | sort | head -40
sha256sum /work/mysql-data.tar /work/mysql-tables.tar
```

> `binlog.index` 与 `binlog.00000X` 必须一起取。 若 `binlog.index` 中记录的最后一个 binlog **已被删除而未清理**，说明有人动过日志——这是一条独立的可疑线索。

<a id="section-10"></a>

### 3.2 配置解析：先看服务器怎么说

```bash
grep -Ei 'log[-_]?bin|binlog_format|server_id|expire_logs_days|datadir|innodb_file_per_table' my.cnf

# 若有运行中的实例，配置以实际为准
mysql -uroot -p -e "SELECT VERSION(), @@log_bin, @@binlog_format, @@server_id, @@global.time_zone, @@system_time_zone;"
```

**`@@server_id` 是取证锚点**：binlog 事件头里带 server_id，如果同一批 binlog 中出现多个 server_id，说明存在主从切换或曾被其他实例写入。这在"数据是谁写的、什么时候换了写入端"这类问题上是直接证据。

<a id="section-11"></a>

### 3.3 读取 binlog —— 本篇核心

```bash
ls -l binlog.00000*; cat binlog.index

# --base64-output=DECODE-ROWS 关键，否则行数据是 Base64 乱码
mysqlbinlog --base64-output=DECODE-ROWS -vv binlog.000003 > binlog003.txt
grep -n 'Table_map:.*app\..*users' binlog003.txt | head

# 限定表 + 只看行事件
mysqlbinlog --base64-output=DECODE-ROWS -vv \
            --tables='appdb.users' binlog.000003 | grep -A6 'Delete_rows' | head -60
```

输出形态（`### DELETE FROM` 之后即为**删除前的完整行**）：

```
### DELETE FROM `appdb`.`users`
### WHERE
###   @1=42 /*INT meta=0 nullable=0 is_null=0*/
###   @2='wangsong' /*VAR_STRING meta=0 nullable=0 is_null=0*/
###   @3=1397819423 /*INT meta=0 nullable=0 is_null=0*/
# at 4183722
#240815 10:33:19 server id 1  end_log_pos 4184120 CRC32 0x1f0e2a1b 	Query	thread_id=88
```

| 字段 | 含义 |
|---|---|
| `### WHERE` 段 | **★ 变更前的行值——删除前事实就在这里** |
| `### SET @n=…` | 仅 INSERT / UPDATE 事件的变更后行镜像；DELETE 事件只输出 `WHERE` 段 |
| `0x77616e677377` | 十六进制字符串，`wangsong`（含结尾 `\0`） |
| `1397819423` | Unix 时间戳，**无时区标记** |
| `#240815 10:33:19` | `#YYMMDD` 年月日 + **服务器本地时间** |
| `CRC32 0x…` | 事件校验，**用于证明转储未失真** |

**十六进制字段还原**（ROW 格式常见坑）：

```bash
cat > hexdec.py <<'PY'
import sys
for line in sys.stdin:
    line = line.strip()
    if not line.startswith('### SET @'):
        continue
    val = line.split('=', 2)[2].split('/*')[0].strip()
    name = line.split('= ')[0]
    try:
        if val.startswith('0x'):
            s = bytes.fromhex(val[2:]).split(b'\x00')[0].decode('utf-8', 'replace')
            print(f"{name}  hex-> str: {s!r}")
        else:
            print(f"{name}  {val}")
    except ValueError as e:
        print(f"{val}  <解析失败: {e}>")
PY

mysqlbinlog --base64-output=DECODE-ROWS -vv --tables='appdb.users' binlog.000003 \
  | grep '### SET @' | python3 hexdec.py
```

**按时间范围裁剪、跨文件按序恢复**（`binlog.index` 是权威顺序）：

```bash
mysqlbinlog --start-datetime='2024-08-01 00:00:00' \
            --stop-datetime='2024-09-01 00:00:00' \
            --base64-output=DECODE-ROWS -vv binlog.000004 | head -200

while read -r f; do
  mysqlbinlog --base64-output=DECODE-ROWS -vv "$f" >> all-binlog.txt
done < binlog.index
```

<a id="section-12"></a>

### 3.4 用 binlog 做时间线重建

```bash
# 抽取某行 id 的全部历史事件
grep -B12 -A4 '@1=1042 ' all-binlog.txt | grep -E 'SET @|WHERE|### |#24'
```

| binlog 中出现 | 可得出的结论 |
|---|---|
| `Insert` 后 `Delete` | 该记录被创建后删除，**删除前值可完整读出** |
| `Update` 多条 | **被覆盖的历次旧值全部可读**，可还原"改之前是什么样" |
| `Query: ALTER TABLE` | 表结构变更时点，**变更前的字段含义需按当时 schema 解读** |
| `Query: DROP TABLE` | 表被删除，**此后数据只能从 binlog 与备份恢复** |
| `server id` 变化 | 写入端变更，**时间点即为切换时点** |
| 序号跳变 | 有 binlog 被删除或轮转，**日志不完整，须在报告中声明** |

<a id="section-13"></a>

### 3.5 回到物理层（binlog 缺失时）与报告级导出

```bash
# 1) 找表空间
find . -name 'users.ibd' -o -name 'users.frm'

# 2) 解析表定义：5.6/5.7 可用专用工具（可用性以实际环境为准）
mysqlfrm --diagnostic users.frm 2>/dev/null | head -40
# 8.0：从 mysql.ibd 的事务数据字典中读（需同版本实例或专用解析器）

# 3) 隔离实例恢复（务必在只读副本上做）
mysqld --initialize-insecure --datadir=/work/isolated --skip-networking
mysqld_safe --datadir=/work/isolated --skip-networking &
mysql -uroot -e "SELECT VERSION();"
# 将 tables 目录复制进来，按恢复文档挂载（具体步骤以实际版本文档为准）

# 4) 报告级导出（binlog 转储与哈希一起入卷）
mysqldump --single-transaction --hex-blob --default-character-set=utf8mb4 appdb users > users.sql
sha256sum binlog.000003 binlog003.txt all-binlog.txt users.sql | tee binlog.sha256
```

> 在隔离实例中恢复 `innodb_force_recovery=1..6` 时，每升一级都会修改数据文件。 必须使用**二次副本**，且原始 `.ibd`/`.frm` 保持只读。

---
<a id="section-14"></a>

## 四、常见陷阱

<a id="section-15"></a>

### 4.1 版本与文件布局

<a id="section-16"></a>

#### 陷阱 1：未判定版本就按另一代的文件布局找证据

**现象**：接手一个 MySQL 数据目录，直接去找 `mysql.ibd`，没找到，就报告"该实例缺少系统库文件，表定义可能已丢失"；或者在另一份检材里只找 `*.frm`，找了半天一无所获。

**原因**：MySQL 的文件布局是随版本换代整体重排的，不存在"兼容两种布局"的中间态。

5.6 与 5.7 的表定义在 `.frm` 里；8.0 把表定义搬进了事务数据字典，`.frm` 被彻底移除，系统库也从散落的 `mysql/*.frm` 变成单个 `mysql.ibd`。

undo 表空间在 5.6 强制寄生于 `ibdata1`，8.0 变成默认独立的 `undo_001`/`undo_002`；redo 在 8.0.30+ 从 `ib_logfile0/1` 变成 `#innodb_redo/` 目录下的一组文件。

同一句"找表定义"，在 5.7 上要去读 `users.frm`，在 8.0 上要去解析 `mysql.ibd` 里的字典——**找错文件等于证据不存在**。

**影响**：**得出"证据缺失"的错误否定结论**。

这类误判难以自查的地方在于它看起来像一个客观事实（"目录里确实没有 `mysql.ibd`"）。一旦写进报告，后续所有依赖表结构的分析都会被这条错误前提带偏，而复核者很难看出真正的原因是版本搞错了。

**核查**：**先建立版本判定链，再谈文件清单**。最小判定集是三条独立的文件特征：

```bash
ls mysql/ | grep -c '\.frm$'        # 大量 .frm → 5.6 / 5.7
ls mysql.ibd 2>/dev/null             # 存在 → 8.0
ls -d '#innodb_redo' 2>/dev/null     # 存在 → 8.0.30+
ls undo_00* ib_logfile* 2>/dev/null  # undo_00* → 8.0；ib_logfile* → 5.6/5.7 或 8.0.30 之前
```

三条特征互相印证后再进入分析。如果服务仍可启动，`SELECT VERSION()` 是最直接的来源；不可启动时用文件特征，必要时从 `ibdata1` 中提取版本字符串作为辅助。

<a id="section-17"></a>

#### 陷阱 2：把 `ibdata1` 当成"数据文件"而忽略其内容随版本变化

**现象**：在 5.7 检材上发现 `ibdata1` 只有 12 MB，直接判定"数据量很小，说明这个库几乎是空的"。

**原因**：`ibdata1` 的体量在 8.0 上本来就与业务数据量脱钩。

8.0 把它缩减为只承载事务数据字典，字典随库表数量增长而基本不随行数增长；同时 undo 被移出到独立表空间。

也就是说，5.7 上塞满数据的 `ibdata1`，到了 8.0 可能变成几 MB 的空壳。

反过来，一个只有 12 MB 的 5.7 `ibdata1` 才是真正值得警惕的信号——它可能意味着用户表几乎全部使用 `innodb_file_per_table`，业务数据在各 `.ibd` 里；也可能意味着库确实是空的。

这两种解释的后续动作完全相反，不能靠"文件小"一句话带过。

**影响**：**用错误前提决定取证路线**。

若照着"数据很少"直接放弃深挖，可能整案的关键记录就躺在某个 `appdb/users.ibd` 里而从未被打开；反之若照着"数据都在 ibdata1"只解析系统表空间，会得出"业务表不存在"的荒谬结论。

**核查**：**按版本建立"数据在哪"的映射表，再统计体量**。

| 版本 | 业务行数据位置 | 表定义位置 |
|---|---|---|
| 5.6 / 5.7 | 各表 `.ibd`（`file_per_table=ON`）为主；`ON` 时也有部分在 `ibdata1` | `.frm` |
| 8.0 | 各表 `.ibd` 为主；`ibdata1` 只剩字典 | `mysql.ibd` 内字典 |

所以第一步是先 `find . -name '*.ibd' -o -name '*.frm' | xargs ls -lS` 把全部表空间按体量列出来，**用表空间总览而不是单个文件的大小来说明数据规模**。

<a id="section-18"></a>

### 4.2 binlog 格式与行镜像解读

<a id="section-19"></a>

#### 陷阱 3：把 `binlog_row_image=MINIMAL` 下的行镜像当成完整行

**现象**：从一个 7 行 `### WHERE` 段还原出一条"删除前记录"，报告写"该记录删除前内容为：id=1042、status=55"，并据此断言"其他字段在被删除时为空"。

**原因**：`binlog_row_image` 决定行事件里带多少列的镜像。`FULL` 记录所有列；`MINIMAL`（8.0 默认）**只记录被修改的列加上主键/唯一键**。

于是一条 DELETE 事件的 `### WHERE` 段在 MINIMAL 下往往只有主键列和少量实际数据列，其余列根本没有出现在 binlog 里——不是因为它们为空，而是因为它们没被记录。

这两种情况在输出文本里长得完全一样。

**影响**：**把"未记录"陈述成"不存在"**。

如果据此写"该账号手机号字段为空"，而真实值其实保存在主库 `.ibd` 的其他页里，报告就制造了一个可被对方直接反驳的事实错误。

更麻烦的是，MINIMAL 下的 UPDATE 事件连"变更前的旧值"都只覆盖变更列，**用它重建历史状态会得到一份残缺的行**。

**核查**：先判定 `binlog_row_image`，再决定行镜像的证据效力。

```bash
# 有运行实例时
mysql -uroot -p -e "SELECT @@binlog_format, @@binlog_row_image;"

# 无实例时：看 Update_rows 事件里 WHERE 段的列数是否明显少于 SET 段的完整列集
```

判定结果必须写进报告：若为 MINIMAL，则所有"删除前值"结论的覆盖范围仅限主键与该事务实际触及的列，其余字段须回到主库表空间或备份中补齐。

并在报告中显式标注哪些列来自 binlog、哪些来自其他来源。

<a id="section-20"></a>

#### 陷阱 4：把行事件的十六进制列值直接当 UTF-8 文本

**现象**：把 `### @2=0x77616e677377` 直接按十六进制解码成字符串，输出得到 `wangsong` 就认为"账号名是 wangsong"；遇到解码乱码时，倾向于认为"该字段被加密"或"binlog 损坏"。

**原因**：MySQL 行事件里的变长字段是带长度前缀的字节序列，前缀形式随列元数据和版本而变。

常见的是两种：一种是把整串（含结尾的 `0x00` 终止符）压在一个十六进制串里，另一种是把长度字节作为独立前导字节放在内容之前。

此外非 UTF-8 字符集（`latin1`、`gbk`）、`ENUM`/`SET` 的内部索引值、`BIT` 字段的字节序都会让"十六进制 → 文本"的直觉转换产出乱码。

乱码的成因至少有五种，落到"加密"结论上的概率极低。

**影响**：**要么错报字段值，要么错报字段性质**。

前者会直接污染证据表；后者（判成"字段被加密"）会把分析引向完全错误的分支，还会连带怀疑整个数据库遭到篡改，而实际只是字符集或长度前缀问题。

**核查**：**先取列元数据再解码**。行事件里 `/*VAR_STRING meta=…*/`、`/*STRING meta=…*/` 这类注释与前序 `Table_map` 事件共同决定了这个字段的编码方式；解码脚本应实现"识别前导长度字节 → 剥离终止符 → 按表字符集解码 → 失败时回退十六进制原样输出"四步，并把解码失败显式标记为"待人工确认"，**不允许静默替换为问号**。

```bash
# 失败时保留原值并标注，而不是替换
try:
    s = raw.split(b'\x00')[0].decode(cs, 'replace')
except Exception as e:
    print(f"{name}  <解码失败，原值: {raw.hex()}>")
```

<a id="section-21"></a>

#### 陷阱 5：把列序号 `@N` 直接对应到列名

**现象**：把 `### @3=0x77616e676775696e4068616f` 直接标注为报告中的"email 字段"，理由是"第 3 列一般是邮箱"。

**原因**：`@N` 是**行事件中的列序号，不是列名**，它只在当前 `Table_map` 事件所描述的那份 schema 里有意义。

问题在于 **schema 会变**：一旦执行过 `ALTER TABLE ... ADD COLUMN`，变更之前的历史事件仍然使用旧列序，变更之后使用新列序，而 binlog 里**不会有任何提示告诉你这个切换发生在哪个位置**。

此外 `DROP COLUMN` 会让变更后的列序号出现空洞，此时 `@5` 和 `@6` 之间的语义完全依赖于变更的确切时点。

**影响**：**整张字段对应表可能整体错位**。

这不是"某几个字段名可能不准"，而是"列名到值的映射全线偏移"，涉及每一个字段。

报告一旦发布，错误会扩散到下游所有引用该表的分析中。

**核查**：列名必须由 `Table_map` 事件 + 对应时点的表定义共同锚定，且在报告中说明锚定方式。

- 有 `.frm`（5.6/5.7）或 `mysql.ibd` 字典（8.0）时，用表定义把序号映射到列名；
- 表定义已随 `DROP TABLE` 一起消失时，只能输出"第 N 列"，并在报告的局限性一节写明"列名不可确定"；
- 存在 `ALTER TABLE` 事件时，按事件位置切分 schema 版本区间，分区间套用不同列序，并在时间线中标注 schema 变更点。

<a id="section-22"></a>

#### 陷阱 6：把 `mysqlbinlog` 输出的行号、字节位置当作原始定位

**现象**：报告里写"详见 `DigiForensics-binlog007-users.txt` 第 14203 行至 14220 行"，另附 `mysqlbinlog --start-position` 参数值 `48213000`。

**原因**：这两类坐标**都来自转储产物，而转储产物不是原始检材**。

行号是 `-vv` 输出的排版结果，会随 `mysqlbinlog` 版本、`--tables` 过滤条件、`-v` 与 `-vv` 档位、甚至终端编码而变化。

`start_position` / `end_log_pos` 则是事件在 binlog 文件中的字节位置，虽稳定但**只在指定的那一个 binlog 文件内有效**，换文件就失去意义。

把这两者混为一谈，就会写出"binlog 第 48213000 字节处"这种既非文件内偏移也非文件间序号的表述。

**影响**：**他人无法复现定位**。复核者拿着报告在另一台机器上跑同一命令，得到的行号和字节位置对不上，整份报告的可信度都会被牵连。

**核查**：**原始坐标与转储坐标分层记录**。

| 坐标类型 | 来源 | 稳定性 | 用途 |
|---|---|---|---|
| 文件名 + `binlog.index` 序号 | 原始检材 | 稳定 | 定位到具体日志文件 |
| `start_position` / `end_log_pos` | `mysqlbinlog -v` 输出头 | 稳定（需同版本工具） | 在该文件内精确定位事件 |
| 行号 | 转储文本 | **不稳定** | 仅供人工查阅 |

报告正文应使用前两种，第三种可作为辅助但必须标注"行号基于本次转储文本，仅供人工查阅"。同时把 `CRC32` 事件校验值一并记录——它是证明转储未失真的锚点。

<a id="section-23"></a>

### 4.3 事件语义与时间线

<a id="section-24"></a>

#### 陷阱 7：把同一事务内的事件时间戳当作逐行发生时间

**现象**：从 binlog 抽出三条行事件，时间戳分别是 10:20:01、10:20:01、10:20:01，报告写"该用户在 10:20:01 的三秒内连续修改了三个字段"。

**原因**：binlog 是事务日志，事件在事务提交时才被统一写入文件，同一事务内的事件共享同一个时间戳和同一个 XID。

这个时间戳标记的是"事务提交时刻"，不是"每条语句执行的时刻"。

三条时间戳相同，恰恰说明它们属于同一事务的原子提交，**既不表示同时发生，也不表示在"三秒内"发生**。

**影响**：**时间线被压缩成不可能的形态**。

如果报告据此推断"用户在三秒内先改 A 再改 B 再改 C"，实际上这三项变更可能是相隔数小时的独立操作只是碰巧在一次提交中落盘。

因果顺序与时间间隔这两个结论都建立在错误的时间语义上。

**核查**：以 XID 为事务单位重建时间线，把时间戳标注在事务层而非事件层。

- 按 XID 归组，把组内事件视为**同时提交**，只陈述"这一次提交包含哪些变更"；
- 需要更细粒度顺序时，只能引用同一事务内事件的**字节位置顺序**（`@ pos` 递增），并说明这是日志写入顺序而非用户操作顺序；
- 应用侧日志、访问日志、代理层日志若能提供更细时间粒度，应与 binlog 做交叉印证，把推断依据写明。

<a id="section-25"></a>

#### 陷阱 8：把 binlog 事件时间戳当作 UTC 或当作唯一时间基准

**现象**：报告里写"该账号于 `2024-08-23 02:33:19`（UTC）被删除"，时间轴与 Web 访问日志、应用日志直接对齐。

**原因**：binlog 事件时间戳使用服务器本地时间，不带时区标记；`DATETIME` 类型列同样不携带时区语义。

而 `@@system_time_zone` 并不是配置里写死的值，它通常跟随操作系统时区，容器部署时又常常与宿主机不同。`@@time_zone` 变量默认值为 `SYSTEM`，即"跟随 system_time_zone"，也可能在某次运维中被显式改过。

**只要有一项没查清，跨源时间对齐就是错的。**

**影响**：**整条时间线产生固定偏移**。

这类错误不会让某条记录变成错的，它让**所有**记录都整体平移。

跨源比对时表现为"8 小时对不上"，很容易被误判为"日志缺失"或"存在伪造"，进而引出完全错误的反篡改结论。

**核查**：**把时区作为必须查证项而非默认假设**。

```bash
mysql -uroot -p -e "SELECT @@global.time_zone, @@system_time_zone, @@server_id, NOW(), UTC_TIMESTAMP();"
# NOW() 与 UTC_TIMESTAMP() 的差值即为实际生效的时区偏移
grep -rEi 'default-time-zone|default_time_zone' /etc/my.cnf /etc/mysql/ 2>/dev/null
```

不可启动时，从 `my.cnf`、容器配置、系统时区文件三处交叉确认。报告里每一条来自 MySQL 的时间都必须显式标注时区假设（例：`2024-08-23 10:33:19 服务器本地时间（假定 UTC+8，未能独立确认）`），不能只写裸时间。

<a id="section-26"></a>

#### 陷阱 9：把 `Update_rows` 的输出段落当成"变更前的完整状态"

**现象**：从 `### UPDATE FROM` 事件中读出 `### WHERE` 段的值，直接填进报告的"变更前记录"表格，并据此断言"变更前该用户是代理 z-118-2240"。

**原因**：两个因素叠加。

第一，`UPDATE` 事件的 `### WHERE` 段在 `binlog_row_image=MINIMAL` 下**只含主键与被修改列**，未修改列不在其中（见陷阱 3）。

第二，即使 `FULL`，`WHERE` 段也是**该次 UPDATE 之前的行状态**，而不是该行**创建时的状态**——中间可能已经历过多次 UPDATE。

`mysqlbinlog -vv` 的输出还会在存在部分更新（partial update）事件时进一步收窄内容。

**影响**：**把"上一版"当成"最初版"**，或把"部分列"当成"全行"。

对"这个账号从注册起代理一直是哪个"这类问题，前者会给出与事实相反的答案。

**核查**：**逐 XID 串起全部事件重建行状态**。同一行主键在 binlog 中的完整事件序列（`Write_rows` 建立初始镜像 → 各次 `Update_rows` 逐次改写 → `Delete_rows` 终止）本身就是一份可回放的历史。报告中的"历史状态"表格必须由这条序列推出，而不是从任意一个事件里摘取，并注明每一行的来源事件与字节位置。

<a id="section-27"></a>

### 4.4 顺序、完整性与分析操作

<a id="section-28"></a>

#### 陷阱 10：把 binlog 序号缺口一律判定为"有人删除了日志"

**现象**：发现 `binlog.000003` 不存在而 `000001`、`000002`、`000004` 都在，报告写"日志被选择性删除，说明操作者刻意毁灭证据"。

**原因**：**缺口的位置决定性质，两者必须分开表述**。

`expire_logs_days` / `binlog_expire_logs_seconds` 会让**最老的**日志文件被自动清理，这是配置行为的正常结果；`RESET MASTER` 或 `PURGE BINARY LOGS` 会清掉**中间或末尾**的日志，这才涉及人为干预。

也就是说，缺小的通常是过期轮转，缺大的（靠近当前活跃文件）才可疑。

此外，编号跳变还可能来自 `binlog` 与 `mysql-bin` 两套命名并存、服务器重装后计数重置等情形。

**影响**：**把常规运维行为指控为蓄意毁灭证据**。

这类结论在报告里会影响后续判断。一旦写错，被委托方或嫌疑人只需出示 `expire_logs_days` 配置即可推翻，而推翻的范围往往包括整段时间线的叙述基础。

**核查**：**先取证配置，再判性质**。

```bash
grep -Ei 'expire[-_]logs|binlog_expire|log[-_]bin|server[-_]id|max[-_]binlog' /etc/my.cnf
mysql -uroot -p -e "SHOW BINARY LOGS;"        # 有实例时看实际保留窗口
```

判定规则要写进报告：序号连续性只说明"当前保留窗口内无缺口"，不等于"更早无操作"——过期清理掉的历史同样不可得。报告中应把"日志不完整"作为一个**必须声明的效力上限**来写，而不是一个可以略过的技术细节。

<a id="section-29"></a>

#### 陷阱 11：★ 直接对原始数据文件运行 `innodb_force_recovery` 启动

**现象**：为了在隔离实例上读出表数据，把检材的数据目录指向 `mysqld --innodb_force_recovery=6`，服务成功启动并导出了数据，报告直接采用导出结果。

**原因**：`innodb_force_recovery` 从 1 到 6 是**逐级放宽崩溃恢复的限制**，级别越高，服务越倾向于绕过一致性检查自行组织数据——**这个过程会直接改写数据文件、undo、redo**。

"我已经 `--skip-networking` 了、已经隔离了，所以是安全的"——但数据目录本身就是检材，改写它的后果与改写原件完全相同。

更隐蔽的是：导出的数据在级别 4 以上可能已经损失了最近的事务、也可能是从损坏页里拼凑出的不一致状态，而这两种情况在导出的 SQL 文件里没有任何标记。

**影响**：**原始检材被不可逆地改变，结论不可复现**。

一旦在原始文件上做过一次恢复尝试，第二次就无法再回到"未改动"状态；委托方若质疑检材完整性，分析师手上已经没有任何可以交付的干净副本。

而导出的数据即便看起来正常，也可能因恢复级别过高而丢掉了恰恰需要寻找的最近记录。

**核查**：原始文件全程只读，所有恢复在二次副本上进行并逐级记录。

```bash
# 1) 固定原始件哈希，之后全程不再对其操作
sha256sum DigiForensics.dd | tee image.sha256

# 2) 至少三层：只读分析副本 → 可改写工作副本 → 恢复演练副本
cp -a /work/readonly/mysql-data /work/work-mysql-data
cp -a /work/work-mysql-data   /work/recovery-mysql-data

# 3) 只在演练副本上逐级尝试，并记录每级结果
mysqld --innodb_force_recovery=1 --datadir=/work/recovery-mysql-data --skip-networking &
# 每升一级都另开一份新副本，不要在同一份数据上连续升级
```

报告必须写明：使用的恢复级别、该级别下已知会丢失的内容、原始件哈希在整个过程中未变的证明。

<a id="section-30"></a>

### 4.5 结论表述

<a id="section-31"></a>

#### 陷阱 12：在 binlog 保留窗口之外做阴性陈述

**现象**：在 binlog 保留窗口之外的时间段做阴性陈述，报告写"未发现该用户在 2020 年前的任何操作"。

**原因**：**"未发现"的说服力完全等于检索范围**，而 binlog 只覆盖其自身保留窗口。

这个窗口由 `expire_logs_days` 决定，也可能因为磁盘配额提前触发过清理，甚至被人工清理过。

窗口之外的数据不是"没有操作"，而是"操作记录已不可得"——**这一区分是取证报告的基本要求，不是措辞偏好**。

**影响**：**阴性结论被当作肯定事实**。

这类陈述在质证时最容易被推翻：委托方只要问一句"你检索的日志覆盖到什么时候"，整段结论就失去支撑。

更严重的是，用一个不可支撑的阴性结论去论证"该用户长期清白"，可能直接影响案件走向。

**核查**：**阴性发现必须写成范围受限的检索陈述**。

- 明确写出检索窗口的起止，及其依据（`binlog.index` 首末文件 + 文件时间戳）；
- 写清方法（`mysqlbinlog` 解码范围、过滤的库表、检索关键词）；
- 写清未覆盖范围（窗口之前、窗口之内被轮转掉的间隙、未纳入分析的库表、未分析的 undo/redo）；
- 写清效力上限："本结论仅在上述范围内成立，不足以推断该时段不存在相关操作"。

**范围、方法、未覆盖范围、效力上限**——四要素缺一不可，是"未发现"类结论的最低交付标准。

---
<a id="section-32"></a>

## 五、案例示例

<a id="section-33"></a>

### 5.1 binlog ROW 格式还原被删账号的完整行

**场景**

委托方提供一台涉事业务服务器的磁盘镜像 `DigiForensics.dd`（Linux 系统盘）。委托问题有两个：查明某电商平台 `users` 表中一条被删除的账号记录，以及说明该账号在 2024 年 8 月的完整状态变化。

委托方特别强调了一句："数据库已经被人清理过，日志可能没了。"

**这句话本身就是本案的第一个调查对象** —— 如果属实，所有基于日志的取证路径都要作废。而实际情况是相反的。

**处置过程**

第一步，固定与版本确认。MySQL 大版本决定了表定义存放在哪里，这个判断错了后面全错：

```bash
$ sha256sum DigiForensics.dd
$ ls mysql/ | grep -c '\.frm$'          # 大量 .frm
$ ls mysql.ibd 2>/dev/null || echo "无 mysql.ibd → 非 8.0"
```

| 判据 | 结果 | 结论 |
|---|---|---|
| `mysql/` 下有 `*.frm` | 有 | 5.7 特征 |
| `mysql.ibd` 是否存在 | **不存在** | 排除 8.0 |
| `ib_logfile0/1` | 存在 | 5.7 特征 |
| `#innodb_redo/` | **不存在** | 8.0 才有 |

**确认为 MySQL 5.7** → 表定义在 `.frm`，数据在 `.ibd`，undo 与数据字典在 `ibdata1`。

第二步，**核查"日志可能没了"这个前提**：

```bash
$ cat binlog.index
./binlog.000001
./binlog.000002
...
./binlog.000007
$ ls -l binlog.00000*
-rw-r----- 1 mysql mysql  1.1G  2024-01-02 00:00:11  binlog.000001
...
-rw-r----- 1 mysql mysql  1.1G  2024-08-31 23:41:07  binlog.000007
```

序号 000001–000007 连续无跳变，`.index` 与实际文件一一对应。

**"日志没了"不成立。** 若清理行为发生过，会在 `.index` 或序号上留下缺口 —— 除非清理者同时编辑了 `.index`，而那样做需要停服且极易出错。**这是一条必须写进报告的否证结论**：它不仅恢复了取证路径，还纠正了委托方的前提假设。

第三步，确认 binlog 格式 —— **这决定删除前值是否可读**：

```bash
$ strings binlog.000007 | grep -o 'Delete_rows\|Update_rows\|Write_rows\|Query' \
    | sort | uniq -c
  214  Delete_rows
   96  Update_rows
 1820  Write_rows
   31  Query
```

`Delete_rows`/`Update_rows` 占主导，`Query` 只有 31 条 → `binlog_format=ROW`。 在 ROW 格式下，每行变更都记录了完整的前后镜像。如果这是 STATEMENT 格式，本次就无法还原删除前值 —— 只能看到 `DELETE FROM users WHERE id=1042` 这条语句。

第四步，抽取删除前值：

```bash
$ mysqlbinlog --base64-output=DECODE-ROWS -vv --tables='appdb.users' \
    binlog.000007 > binlog007-users.txt
$ sed -n '14203,14220p' binlog007-users.txt
```

```text
### DELETE FROM `appdb`.`users`
### WHERE
###   @1=1042 /*INT meta=0 nullable=0 is_null=0*/
###   @2=0x77616e677377 /*VAR_STRING meta=0 nullable=0 is_null=0*/
###   @3=0x77616e676775696e4068616f /*VAR_STRING meta=0 nullable=0 is_null=0*/
###   @4=1397819423 /*INT meta=0 nullable=0 is_null=0*/
###   @5=0x31663365623735313030 /*VAR_STRING meta=0 nullable=0 is_null=0*/
###   @6=0x6b696e672e636f6d /*VAR_STRING meta=0 nullable=0 is_null=0*/
###   @7=0x6b696e672e636f6d /*VAR_STRING meta=0 nullable=0 is_null=0*/
###   @8=0x7a2d3436372d38303936 /*VAR_STRING meta=0 nullable=0 is_null=0*/
###   @9=55 /*TINY meta=0 nullable=0 is_null=0*/
# at 48213902
#240823 10:33:19 server id 1  end_log_pos 48214118 CRC32 0x1f0e2a1b  Query  thread_id=88
```

第五步，解码 hex 并与 `.frm` 的列序对齐：

```bash
$ sed -n '14203,14220p' binlog007-users.txt | grep '### ' | python3 hexdec.py
@2 'wangsong'  @3 'wangxin@hao'  @5 '1f3eb75100'
@6 'king.com'  @7 'king.com'     @8 'z-467-8096'
```

| `@` 号 | 列名 | 删除前值 |
|---|---|---|
| @1 | `id` | 1042 |
| @2 | `username` | wangsong |
| @3 | `email` | `wangxin@hao` |
| @4 | `created_at` | 1397819423 |
| @5 | `mobile` | `1f3eb75100` |
| @6 | `domain` | king.com |
| @7 | `mail_domain` | king.com |
| @8 | `proxy_id` | z-467-8096 |
| @9 | `status` | 55 |

> **`@` 号到列名的映射依赖 `.frm`**：`Table_map` 事件只给出"第 N 列"，列名必须从 `.frm` 的列序表读取。若 `.frm` 已被 `DROP TABLE` 删除，就只能给出"第 N 列"，无法确定列名。本案 `.frm` 存在，故列名可靠。

> **脱敏**：`email` 与 `mobile` 属个人信息，按最小化原则只保留可用于与委托方核对的部分形态；完整值存受控存储。

第六步，核对完整状态历史：

```bash
$ grep -B14 -A6 '@1=1042 ' all-binlog.txt \
    | grep -E '^#24|### (INSERT|UPDATE|DELETE|WHERE)'
```

| 时间（服务器本地 UTC+8） | 事件 | 关键值 |
|---|---|---|
| 2015-04-20 14:07:03 | INSERT | status=1，proxy_id=`z-118-2240` |
| 2019-11-08 09:41:22 | UPDATE | proxy_id: `z-118-2240` → `z-203-7711` |
| 2023-05-30 16:22:58 | UPDATE | status: 1 → **55** |
| 2024-06-14 11:07:03 | UPDATE | mail_domain 不变 |
| **2024-08-23 10:33:19** | **DELETE** | 整行移除 |

2019 年那次 UPDATE 的旧代理 ID `z-118-2240` 只在 binlog 里存在，当前表内已无迹可寻。

第七步，**三重印证**：

```bash
# 逻辑层
$ mysql -uroot -D appdb -e "SELECT * FROM users WHERE id=1042;"
Empty set

# 物理层
$ strings -n 8 appdb/users.ibd | grep -A2 -B2 'wangsong'
wangsong
1f3eb75100
z-467-8096          ← 旧值仍在页空闲区
```

第八步，时间基准确认：

```bash
$ strings ibdata1 | grep -m2 -i 'system_time_zone\|CST\|+08:00'
+08:00
$ grep -r 'default-time-zone' /etc/my.cnf /etc/mysql/ 2>/dev/null
default-time-zone='+08:00'
```

`240823 10:33:19` 是服务器本地时间，即北京时间。 而 `created_at=1397819423` 是 Unix 秒，必须换算后才能并入同一时间轴：

```bash
$ python3 -c "
import datetime
print(datetime.datetime.utcfromtimestamp(1397819423+8*3600).strftime('%Y-%m-%d %H:%M:%S'))
"
2014-04-18 15:10:23
```

第九步，固化与精确截取：

```bash
$ sha256sum binlog.000007 binlog007-users.txt all-binlog.txt appdb/users.ibd \
    | tee final.sha256
$ mysqlbinlog --start-position=48213000 --stop-position=48214500 \
    --base64-output=DECODE-ROWS -vv binlog.000007 > excerpt-240823.txt
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 委托方"日志已丢失"的前提不成立 | `binlog.000001`–`000007` 连续，`.index` 与文件一一对应 | 强（否证结论） |
| binlog 格式为 ROW | `Delete_rows` 214 / `Query` 仅 31 | 强 |
| `users` 表中无 `id=1042` | `SELECT` 返回 Empty set | 强 |
| 该账号于 2024-08-23 10:33:19（UTC+8）被删除 | binlog `DELETE` 事件 + `end_log_pos` + CRC32 | 强 |
| 删除前 9 个字段值可完整读出 | `mysqlbinlog -vv` 的 `### @N` 段 + hex 解码 | 强 |
| 账号历史可完整重建（5 个时点） | binlog 全量检索 | 强 |
| 2019 年的旧代理 ID 仅存在于 binlog | `UPDATE` 的前值镜像 | 强 |
| `.ibd` 空闲区仍残留该账号字节 | `strings` 命中 | 弱（依赖 purge 未覆写） |

**能证明的**：删除行为的事实、精确时间（到秒）、删除前的完整行内容、以及 9 年的完整状态变迁。

**不能证明的**：
- **不能证明删除操作者。** `thread_id=88` 是一个连接 ID，需结合 `general_log` 或连接表才能关联到用户
- **不能证明 `status=55` 的业务含义**（需委托方提供字段字典）
- **不能证明 2015 年之前的状态**（binlog 从 2015-01-02 起）
- **不能把 `.ibd` 空闲区命中作为主要依据**（见下节误判对照）

**未覆盖范围**：undo/redo（`ibdata1` 内）、`general_log`（连接来源）、binlog 有效期之外的历史、以及 8/23 之后是否有对该账号的重建记录。

**误判对照**

这个案例的误判点集中在**"前提假设"上**——委托方那句"日志可能没了"如果被直接接受，整个取证路径就废了。

**其一，把委托方的前置判断当作事实前提。**

委托方说"数据库被清理过，日志可能没了"。若分析方直接以此为出发点，结论会写成"因日志已丢失，无法还原删除记录" —— 而实际 binlog 完整覆盖 2015 至 2024。

判据是**对任何"证据可能不存在"的判断做独立核查**，核查项是**序列连续性**：

| 检查 | 本案结果 | 含义 |
|---|---|---|
| `binlog.index` 列出 | `./binlog.000001` … `./binlog.000007` | 7 个连续序号 |
| 实际文件是否都在 | 都在，大小 1.1 G | 无缺失 |
| 序号有无跳变 | **无** | 无删除痕迹 |
| 文件 mtime 是否连续 | 2024-01-02 → 2024-08-31 | 顺序正常 |

若清理者删除了某个 binlog 文件，序号会出现缺口；若他同时改了 `.index`，则 `.index` 的 mtime 会晚于其他文件 —— 两者本次都未出现。

按错误判据走的代价：委托方基于"日志没了"这个结论调整了调查方向（比如转向物理层碰运气），而正确的路径（binlog）完好无损却没被使用。更严重的是，报告里写"因日志缺失无法取证"会让委托方误以为数据真的不可恢复。

**其二，把 `@1`/`@2` 直接当作列名对应。**

`mysqlbinlog` 输出的 `@1`–`@9` 是**位置序号**，不是列名。映射必须经过：

```bash
# 从 .frm 提取列序
$ python3 frm_parse.py appdb/users.frm
CREATE TABLE users (
  id, username, email, created_at, mobile,
  domain, mail_domain, proxy_id, status
)
# @1→id, @2→username, ... @9→status
```

`.frm` 不存在时（表被 `DROP` 过），映射链断裂，只能给出"第 N 列"。 判据是**先确认 `.frm` 存在，再做映射**，并在报告中写明映射依据。若跳过这一步直接按常见字段顺序猜测，**一个字段错位会让后面所有值都归错列** —— 比如把 `mobile` 的值当作 `proxy_id` 报告出去。

其三，把 `.ibd` 空闲区的 `strings` 命中当作主要证据。

`users.ibd` 的空闲区命中 `wangsong`/`1f3eb75100`/`z-467-8096`，看起来是极有力的"物理证据"。判据是**InnoDB 的 purge 机制**：

| 机制 | 说明 | 后果 |
|---|---|---|
| purge 线程 | 后台删除 undo 中的旧版本 | 会覆写 `.ibd` 内的旧字节 |
| purge 滞后 | purge 在后台异步进行 | **窗口期内旧字节保留** |
| 何时覆写 | delete 后约 10 分钟到数小时 | 取决于 undo 空间压力 |

**本次命中纯属运气** —— purge 尚未跑到该区域。若数据库负载高、undo 空间紧张，purge 可能在删除后几分钟内就完成覆写。

判据是物理层证据的定位：它是"加分项"而非"依据"。 正确的报告表述：

> 「结论主要依据 binlog（服务器自身写入、CRC32 可校验、不受 purge 影响）。`users.ibd` 空闲区检出该账号的残留字节，与 binlog 记录一致，构成补充印证；但该印证依赖 purge 尚未覆写该区域，属不可控因素，不作为主要依据。」

按错误判据走的代价：委托方据此认为"物理证据 + 日志证据"双保险。实际上未来的同类案件中，若照搬"从 `.ibd` 空闲区找已删数据"这个方法，会大面积落空。

其四，把 binlog 时间戳当作 UTC 解读。

`#240823 10:33:19` 是**服务器本地时间**，不是 UTC。本案服务器时区为 `+08:00`（从 `ibdata1` 与 `my.cnf` 双重确认），所以它就是北京时间。

判据是**跨源比对前必须锁定三个时间基准**：

| 时间源 | 类型 | 本案处理 |
|---|---|---|
| binlog 事件时间 | 服务器本地时区字符串 | 换算为 UTC+8 标注 |
| `created_at` 等列值 | Unix 秒（UTC 基准） | 加 8 小时后并入本地时间轴 |
| `users.ibd` / `ibdata1` | 无内嵌时间 | — |

**不换算的后果**：把 `created_at=1397819423` 按 UTC 解读得 `2014-04-18 07:10:23`，与 binlog 的 `2015-04-20 14:07:03`（INSERT 事件）**相差 11 个月**——一个明显不合理的时间线。

判据是：换算后的 `created_at` 必须早于或接近 INSERT 事件时间。

本案换算后为 `2014-04-18 15:10:23`，早于 INSERT 7 个月，合理。

**第五个实操细节**：`mysqlbinlog` 需要在**正确的时区与字符集环境**下运行，否则 `VAR_STRING` 类型的解码可能出错。

判据是解码后 `@2` 应为可读的 `wangsong` 而不是乱码。

若出现乱码，说明字符集不匹配，应指定 `--default-character-set=utf8mb4` 重跑。

<a id="section-34"></a>

### 5.2 general_log 反查 thread_id 定位删除操作的来源连接

**场景**

承接 5.1。5.1 已经证明 `id=1042 / wangsong` 在 2024-08-23 10:33:19 被删除，binlog 事件行末给出 `thread_id=88`。

委托方追问第二个问题：这条 DELETE 是谁发的？是从哪台机器连上来的？

这一步的意义在于：`thread_id` 是 MySQL 的**连接 ID**，不是用户身份。它只在连接存活期间有意义，单看 binlog 无法回答"谁"。

必须另找能把连接 ID 与来源地址、账号绑定的记录。

**处置过程**

第一步，先确认 `general_log` 是否开启 —— **这是本路径成立的前提，不确认就往下走会白做**：

```bash
$ grep -rn 'general_log\|general_log_file' /etc/my.cnf /etc/mysql/
general_log=1
general_log_file=/var/log/mysql/general.log

$ ls -l /var/log/mysql/general.log*
-rw-r----- 1 mysql mysql  4.2G  2024-09-01 00:00:04  general.log
```

`general_log=1` 且文件存在 → 可用。若为 `0` 或文件已轮转丢失，本节结论只能写成"来源不可考"。

第二步，把 binlog 事件的 `end_log_pos` 与 `thread_id` 精确定位到具体事务上下文：

```bash
$ mysqlbinlog --start-position=48213500 --stop-position=48214500 \
    --base64-output=DECODE-ROWS -vv binlog.000007 > excerpt-240823.txt
$ grep -n 'thread_id' excerpt-240823.txt
# at 48213902
#240823 10:33:19 server id 1  end_log_pos 48214118 CRC32 0x1f0e2a1b   Query   thread_id=88
```

`end_log_pos 48214118` 是这条事件在该 binlog 文件中的字节位置。

这个值是把 general_log 与 binlog 对齐的锚点，不是可省略的细节。

第三步，在 `general_log` 中按连接 ID 与时间双条件检索：

```bash
$ grep -n 'Connect' /var/log/mysql/general.log | awk '$0 ~ /Id: *88\b/'
```

```text
2024-08-23 10:28:51  Id:    88 	User: app_rw	@ host-7-14 [10.62.8.14]  Query: connect
```

关键字段逐个对上：

| 字段 | 值 | 作用 |
|---|---|---|
| `Id` | 88 | 与 binlog `thread_id=88` 精确对应 |
| `User` | `app_rw` | 数据库账号名 |
| `@ host-7-14` | 反向解析主机名 | **仅有 IP 时的辅助信息，非权威** |
| `[10.62.8.14]` | 来源 IP | 有效的来源定位依据 |
| `Query: connect` | 连接建立 | 确定连接起始时间 |

第四步，取该连接的完整语句序列，确认这条连接在删除前后做了什么：

```bash
$ awk '/Id: *88\b/{f=1} f' /var/log/mysql/general.log \
    | grep -E '2024-08-23 10:2[0-9]:|2024-08-23 10:3[0-9]:' | head -40
```

```text
2024-08-23 10:28:51  Id:    88 	User: app_rw	@ host-7-14 [10.62.8.14]  Query: connect
2024-08-23 10:29:14  Id:    88 	User: app_rw	@ host-7-14 [10.62.8.14]  Query: SELECT id,status FROM appdb.users WHERE username='wangsong'
2024-08-23 10:33:19  Id:    88 	User: app_rw	@ host-7-14 [10.62.8.14]  Query: DELETE FROM appdb.users WHERE id=1042
```

三点互相咬合：

- `10:33:19` 与 binlog 事件时间**逐秒一致**
- `Id: 88` 与 binlog `thread_id=88` 一致
- 删除前的 `SELECT ... WHERE username='wangsong'` 说明操作者**先查后删**，不是批量清理

第五步，界定这条连接的账号权限与后续复用情况：

```bash
$ grep -c 'Id: *88\b' /var/log/mysql/general.log
# 该连接在日志中出现的语句总数

# 确认 88 号连接是否在删除后仍被复用（连接 ID 会被复用，这是关键陷阱）
$ awk '/Id: *88\b/{print $1,$2,$3,$8,$9}' /var/log/mysql/general.log \
    | awk '$1=="2024-08-23"'
```

若 `88` 在 2024-08-24 之后再次出现 `Connect`，则说明连接 ID 被新连接复用过，前面的对应关系只对 10:28:51–10:33:19 这一段有效。

第六步，交叉核验来源 IP 的主机侧证据：

```bash
$ grep -rn '10.62.8.14' /var/log/mysql/slow.log /var/log/secure 2>/dev/null | head
$ python3 -c "print(int('0xC3A6E7E9',16))"
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 删除操作由 MySQL 账号 `app_rw` 发起 | `general_log` 的 `User: app_rw` 与 `Id: 88` 对应 | 强 |
| 来源地址为 `10.62.8.14` | `general_log` 的 `@ host-7-14 [10.62.8.14]` | 强（限于该日志） |
| 操作者为"先查后删"而非批量清理 | 删除前 65 秒的定向 `SELECT` | 中（行为特征，非直接证据） |
| 该删除发生在 10:28:51 建立的连接上 | `Connect` 与 `DELETE` 同为 `Id: 88` | 强 |

**能证明的**：执行删除的数据库账号名、来源 IP、连接的建立时刻，以及操作前存在一次针对 `username='wangsong'` 的定向查询。

**不能证明的**：
- **不能证明操作者是人还是自动化脚本。** `app_rw` 是服务型账号，通常由应用使用；`User` 字段给出的是数据库账号，不是登录用户
- **不能证明 `10.62.8.14` 上坐着谁。** 反向解析出的 `host-7-14` 只是内网 DNS 记录，可能早已变更
- **不能证明这条连接是否经过跳板或代理。** 需结合防火墙/netflow 才能判断
- **不能证明该账号是否专用于此操作。** `app_rw` 的读权限是否被其他功能共用，本案未覆盖

**未覆盖范围**：`mysql.user` 表的历史授权变更（无审计）、`performance_schema` 的历史事件缓冲（重启即失）、`10.62.8.14` 这台主机自身的登录日志与命令历史、以及 10:33:19 之后是否有其他连接对同一账号做了重建。

**误判对照**

其一，把 `thread_id=88` 直接当成"用户 88 号"或"第 88 个登录"。

`thread_id` 是**连接 ID**，由 MySQL 在连接建立时分配，与业务用户、登录次数、用户 ID 都无对应关系。本案如果不做 general_log 关联，报告里写"thread_id=88 执行了删除"，读者很容易理解成"编号 88 的账号"。

判据是**连接 ID 的三个特征**：

| 特征 | 本案表现 | 后果 |
|---|---|---|
| 生命周期 | 连接存活期间有效 | 连接断开后该 ID 可被复用 |
| 作用域 | 仅在单个 MySQL 实例内唯一 | 迁移或重启后编号可能重新分配 |
| 与身份无关 | 由计数器分配 | 与业务账号无映射 |

**必须做的关联**：`general_log` 的 `Id` 字段 与 binlog 事件尾部的 `thread_id`，按"同一天同一时刻 + 同一 Id"双向锁定。只报 `thread_id` 不报 `User` 和来源 IP，等于什么都没查。

按错误判据走的代价：报告把一个连接编号当成身份凭据，委托方拿 `thread_id=88` 去数据库里找"88 号用户"，找不到，结论被整体质疑。

**其二，把反向解析出的主机名当作可信的身份线索。**

`@ host-7-14 [10.62.8.14]` 中，`host-7-14` 来自 `skip_name_resolve=OFF` 下的反向 DNS 查询。这个值**在日志写入时就已经是一次可能失败的解析**，且内网 DNS 记录随时会变。

判据是**反向解析结果只作辅助**：

```bash
# 判据1：确认是否开启了名称解析
$ grep -rn 'skip_name_resolve' /etc/my.cnf
skip_name_resolve=OFF          # 开启 → 日志里可能有主机名

# 判据2：反向解析结果若为 localhost 或泛化名，直接丢弃
$ getent hosts 10.62.8.14
10.62.8.14   app-bastion-7.internal    ← 与日志中的 host-7-14 不一致
```

本次 DNS 记录与日志中的 `host-7-14` 不一致，说明**该名称记录已变更**。正确表述是"来源 IP 为 `10.62.8.14`，日志中记录的名称为 `host-7-14`，该名称当前已无法解析到同一记录"。

**其三，把 `app_rw` 认定为人为操作。**

`User: app_rw` 是数据库账号命名规范中的典型**读写分离服务账号**（`app_` 前缀、`rw` 后缀）。这类账号通常由应用代码池持有，一个应用实例会共用它。

判据是**账号命名形态与语句特征的双重检查**：

| 检查项 | 批量清理的预期 | 本案实际 |
|---|---|---|
| 语句序列 | 连续多条 `DELETE ... WHERE id BETWEEN` 或无 WHERE | 单条 `WHERE id=1042` |
| 前置语句 | 无 SELECT，或有但为 `SHOW` | 有定向 `SELECT ... WHERE username='wangsong'` |
| 会话长度 | 极短 | 4 分 28 秒，中间有间隔 |
| 账号类型 | 运维型账号（`dba_`、`root`） | 服务型账号（`app_rw`） |

"先按用户名查、再按主键删"这一序列更符合**有目标的单条处置**，与批量清理的模式不符。但**这只是行为特征推断，不是身份证明** —— 报告里必须写成"与单条定向处置的行为特征一致"，不能写成"系人为操作"。

按错误判据走的代价：把自动化任务误报为人工操作，委托方对嫌疑人范围做出错误判断，方向性错误比技术性错误更难挽回。

其四，忽略连接 ID 复用，把整个日志期的 `Id: 88` 都算作同一连接。

第五步中"确认 88 号连接是否在删除后仍被复用"不是可选动作。MySQL 的连接 ID 在连接断开后会被重新分配给新连接。

判据是**用 `Connect` 行切分连接生命周期**：

```bash
$ awk '/Id: *88\b/&&/Query: connect/{print NR": "$0}' /var/log/mysql/general.log
1452031: 2024-08-22 02:11:07  Id: 88  User: cron_job  @ localhost  Query: connect
2890477: 2024-08-23 10:28:51  Id: 88  User: app_rw   @ host-7-14  Query: connect
5503912: 2024-09-05 19:44:20  Id: 88  User: app_ro   @ host-2-03   Query: connect
```

同一个 `Id: 88` 在 8/22 是 `cron_job`、8/23 是 `app_rw`、9/5 是 `app_ro`。只有 8/23 10:28:51–10:33:19 这一段能归到 `app_rw`。 若按 `Id` 全量检索并直接汇总，会把三个不同账号的行为混在一起。

按错误判据走的代价：报告把 `cron_job` 或 `app_ro` 的操作也算到 `app_rw` 头上，行为画像整体失真。

其五，把 `end_log_pos` 当成可省略的调试字段。

`end_log_pos 48214118` 是 binlog 事件在该文件中的字节边界，第二步的 `--start-position=48213500 --stop-position=48214500` 就依赖它。它同时也是**校验定位是否正确的自检项**：如果按该区间截取出的内容不是这条 `DELETE`，说明字节位置理解有误或文件有分片。

判据是每次定位都记录 `end_log_pos` 并回验：

```bash
$ mysqlbinlog --start-position=48213902 --stop-position=48214118 \
    --base64-output=DECODE-ROWS -vv binlog.000007 \
  | grep -c 'DELETE FROM `appdb`.`users`'
1        # 恰好一条 → 区间正确
```

**区间不对时会出现两种典型错误**：区间过大，截进相邻事务，把别人的 `DELETE` 一并输出（`grep -c` 返回大于 1）；区间过小，事件头被切掉，只剩 `### @N` 行而无 `thread_id`。两种情况都必须回退重定边界。

<a id="section-35"></a>

### 5.3 binlog 已过期时的范围限定结论与列名映射断裂

**场景**

另一起委托。委托方提供同一业务线的历史备份 `DigiForensics-old.vc`（同一台服务器 2024 年 3 月的数据目录归档），要求查明表 `appdb.orders` 在 2023 年 12 月的一次批量状态变更涉及哪些订单号。

委托方称该表在 2024 年 5 月被 `DROP TABLE` 后重建过。这带来两个问题：binlog 是否覆盖到 2023 年 12 月，以及列名还能不能确定。

这一案的价值不在"又一次提取"，而在两处边界：一份阴性结论应该怎么写，以及映射链断裂时结论应该退到什么程度。

**处置过程**

第一步，先查证"清理"这一前提，与 5.1 同法但结论相反：

```bash
$ cat binlog.index
./binlog.000001
./binlog.000002
./binlog.000003
./binlog.000004
./binlog.000005

$ ls -l binlog.00000*
-rw-r----- 1 mysql mysql  1.1G  2024-02-01 00:00:09  binlog.000001
-rw-r----- 1 mysql mysql  1.1G  2024-02-20 00:00:11  binlog.000002
-rw-r----- 1 mysql mysql  1.1G  2024-03-15 00:00:07  binlog.000003
-rw-r----- 1 mysql mysql  1.1G  2024-04-01 00:00:09  binlog.000004
-rw-r----- 1 mysql mysql  1.1G  2024-04-25 00:00:12  binlog.000005

$ grep -rn 'expire_logs_days\|max_binlog_size' /etc/my.cnf
expire_logs_days=30
max_binlog_size=1073741824
```

序号仍连续，但**最早的文件起点是 2024-02-01**。`expire_logs_days=30` 与文件跨度吻合：这是**自动过期清理**，不是人工删除 —— 人工删除通常留下序号缺口，而这里没有任何缺口。

关键结论：`binlog.000001` 的事件时间决定了本次取证的时间下界。

第二步，精确确定时间下界，不靠文件名推测：

```bash
$ mysqlbinlog --base64-output=DECODE-ROWS binlog.000001 2>/dev/null \
    | grep -m2 -E '^#[0-9]{6} '
#240201  0:14:52 server id 1  end_log_pos 4  CRC32 0x...  Start: binlog v 4, server v 5.7.44 created 240201  0:14:52
```

最早事件为 **2024-02-01 00:14:52**。委托问题指向 2023 年 12 月，**落在有效期之外**。

第三步，确认 binlog 格式仍为 ROW（决定"如果有的话能不能读到旧值"）：

```bash
$ for f in binlog.00000*; do
    printf '%s  ' "$f"
    strings "$f" | grep -c 'Delete_rows'
  done
# binlog.000001  214
# binlog.000002  198
```

格式没有问题，**缺的是时间跨度，不是可读性**。这两件事必须分开表述。

第四步，`DROP TABLE` 之后列名映射链的断裂验证：

```bash
$ ls -l appdb/orders*
-rw-r----- 1 mysql mysql 12.4M 2024-05-14 16:22:08  orders.ibd
-rw-r----- 1 mysql mysql  9.8K 2024-05-14 16:22:08  orders.frm

$ mysqlbinlog --base64-output=DECODE-ROWS -vv --tables='appdb.orders' binlog.000005 \
    | grep -A3 'DROP TABLE'
```

```text
### DROP TABLE `appdb`.`orders`
# at 133047711
#240514 16:22:08 server id 1  end_log_pos 133048903 CRC32 0xb31e9a77  Query  thread_id=141
```

第五步，此时列名必须来自当前 `.frm`，而当前 `.frm` 是重建后的结构：

```bash
$ python3 frm_parse.py appdb/orders.frm
CREATE TABLE orders (
  id, order_no, user_id, status, amount, paid_at, updated_at
)
```

第六步，比对重建前后的列数与列名，以确认是否发生结构变更：

```bash
# 从 DROP 之前最后一次 ALTER 事件取旧结构
$ mysqlbinlog --base64-output=DECODE-ROWS -vv binlog.000004 \
    | grep -B2 -A12 'ALTER TABLE `appdb`.`orders`' | head -40
```

```text
### ALTER TABLE `appdb`.`orders`
###   ADD COLUMN `channel` VARCHAR(16) NOT NULL DEFAULT '',
###   ADD COLUMN `remark` VARCHAR(255) DEFAULT NULL
```

旧结构 7 列，新结构 9 列，且新增列位于末尾。 对本案而言位置关系是有利的 —— 末尾追加列不会移动既有列的前后顺序，因此 `@1`–`@7` 的列名映射在两个版本间保持一致。

但这个"有利"必须**逐列验证后得出**，不能假定。

第七步，把阴性结论的范围钉死 —— 这一步是本案的核心：

```bash
# 明确"查过什么、在什么范围内查的、结果是什么"
$ for f in binlog.00000*; do
    printf '%s  first=%s  last=%s\
' "$f" \
      "$(mysqlbinlog "$f" 2>/dev/null | grep -m1 -E '^#[0-9]{6}' | cut -c2-15)" \
      "$(mysqlbinlog "$f" 2>/dev/null | grep -E '^#[0-9]{6}' | tail -1 | cut -c2-15)"
  done
```

| binlog | 事件起始 | 事件结束 |
|---|---|---|
| `binlog.000001` | 2024-02-01 00:14:52 | 2024-02-19 23:59:48 |
| `binlog.000002` | 2024-02-20 00:00:11 | 2024-03-14 23:59:52 |
| `binlog.000003` | 2024-03-15 00:00:07 | 2024-03-31 23:59:41 |
| `binlog.000004` | 2024-04-01 00:00:09 | 2024-04-24 23:59:55 |
| `binlog.000005` | 2024-04-25 00:00:12 | 2024-05-14 16:22:08 |

第八步，列出未覆盖范围：

```text
未覆盖：
- 2024-02-01 00:14:52 之前的全部变更（含委托问题所指的 2023-12）
- ibdata1 内 undo 段（未解析）
- ib_logfile0/1 的 redo 物理记录（未解析）
- orders.ibd 重建前的旧表空间是否仍存在于文件系统空闲区（未 carve）
- DROP 之后的重建操作是否覆盖了原始数据（未验证）
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| binlog 文件序列连续无缺口 | `binlog.index` 与 5 个文件一一对应 | 强 |
| 清理是 `expire_logs_days=30` 自动过期，非人工删除 | 文件时间跨度与配置吻合，无序号缺口 | 强 |
| binlog 最早事件为 2024-02-01 00:14:52 | `mysqlbinlog` 输出首个事件头 | 强 |
| 2023 年 12 月的变更不在 binlog 覆盖范围内 | 事件时间早于最早文件 | 强（阴性） |
| binlog 格式为 ROW，删除前值具备可读性 | `Delete_rows` 计数 214 / 198 | 强 |
| `orders` 表于 2024-05-14 16:22:08 被 DROP | binlog `DROP TABLE` 事件 + `end_log_pos` | 强 |
| 重建后 9 列，旧结构 7 列，新增列位于末尾 | `.frm` 与 `ALTER TABLE` 事件 | 强 |
| `@1`–`@7` 列名映射在两个版本间一致 | 末尾追加列不移位，逐列验证 | 中（限于已验证的 7 列） |

**阴性结论（严格限定）**：

> 在 `binlog.000001` 至 `binlog.000005` 共 5 个文件、覆盖 2024-02-01 00:14:52 至 2024-05-14 16:22:08 的范围内，**未发现** `appdb.orders` 在 2023 年 12 月的状态变更记录。
>
> 该阴性结论**仅对上述文件与时间窗口成立**。窗口之外的历史变更因 `expire_logs_days=30` 自动过期已不可得，本案未通过 `ibdata1` 的 undo 段、`ib_logfile0/1` 的 redo 记录、以及文件系统空闲区 carve 三条路径做补充检索，这三条均为未覆盖范围。

**能证明的**：`orders` 表被 DROP 的确切时刻、重建后的结构、以及 binlog 覆盖窗口的确切边界。

**不能证明的**：
- **不能证明 2023 年 12 月没有发生过变更。** 只能说在该窗口内未发现
- **不能证明 binlog 之外没有其他副本。** 从库、备份系统、外部 binlog 归档目录均未检查
- 不能证明 `@1`–`@9` 在 DROP 前的行事件中都对应同名列。 本次只验证了新增列在末尾这一条；若当时存在 `DROP COLUMN` 或 `CHANGE COLUMN`，映射会断裂
- **不能证明重建后的表数据与原表有继承关系。** 重建过程未做数据迁移的证据分析

**误判对照**

**其一，把"文件连续"当成"历史完整"。**

本案五个 binlog 文件序号连续、无缺口，极容易得出"binlog 完整"的结论。但完整性有两个维度：**序列连续性**（有没有被删文件）与**时间跨度**（覆盖到多早）。本案前者成立、后者不成立。

判据是**必须先确定时间下界再谈完整性**：

| 维度 | 检查方法 | 本案结果 |
|---|---|---|
| 序列连续性 | `binlog.index` 列出序号与实际文件比对 | 连续，无缺口 |
| 时间下界 | 首个文件的 `Start: binlog v 4 ... created` 行 | 2024-02-01 00:14:52 |
| 时间上界 | 末个文件的最后事件时间 | 2024-05-14 16:22:08 |
| 清理机制 | `expire_logs_days` 配置 vs 文件跨度 | 30 天，吻合 |

**"无缺口"只排除了人工删除，不能排除自动过期。** 自动过期删掉的是**最早的一段**，序号是接着往下写的，天然不留缺口 —— 这是容易忽略的一点。

按错误判据走的代价：报告写"binlog 完整，日志可信"，委托方据此认为历史变更可查，进而调整调查方向并放弃其他路径，而实际上 2023 年 12 月这一整段历史根本不在检材内。

**其二，阴性结论写成无限定陈述。**

错误写法：

> 未发现 `orders` 表在 2023 年 12 月的批量状态变更，说明该表当时未被修改过。

正确写法（限定范围 + 列出未覆盖）：

> 在 `binlog.000001`–`000005`、覆盖 2024-02-01 00:14:52 至 2024-05-14 16:22:08 的范围内，未发现该记录。2023 年 12 月早于该窗口，**不构成"未发生"的证据**。未覆盖路径：`ibdata1` undo 段、`ib_logfile` redo 记录、文件系统空闲区 carve、从库与外部 binlog 归档。

**判据是三要素缺一不可**：检查范围、检查方法、未覆盖项。**"未发现"这三个字后面必须跟着范围。** 少了范围，读者无法判断这条结论能用来否定什么。

按错误判据走的代价：委托方把"未发现"读成"未发生"，据此排除嫌疑对象。这是一个会让调查方向彻底走偏的错误，且报告中找不到任何提示。

其三，用重建后的 `.frm` 给 DROP 前的行事件标列名。

`Table_map` 事件只给"第 N 列"。列名的唯一来源是 `.frm` 的列序表。而本案 `orders.frm` 的 mtime 是 2024-05-14 16:22:08，与 `DROP TABLE` 事件**同一秒** —— 它是重建后的文件，不是事件发生时的文件。

判据是**`.frm` 的可用性必须逐事件判定**：

```bash
# 该 .frm 是否在事件时刻就存在？
$ stat -c '%n  mtime=%y' appdb/orders.frm appdb/orders.ibd
appdb/orders.frm  mtime=2024-05-14 16:22:08
appdb/orders.ibd  mtime=2024-05-14 16:22:08
# → 与 DROP 同时刻 → 是重建产物，不能用于标注 DROP 前的行事件

# 结构是否在期间变更过？
$ mysqlbinlog -vv binlog.00000* | grep -E 'ALTER TABLE|ADD COLUMN|DROP COLUMN|CHANGE COLUMN'
```

| `.frm` 状态 | 能否确定列名 | 结论表述 |
|---|---|---|
| 事件时刻 `.frm` 存在且期间无 `ALTER` | 能 | 可给出字段名，强 |
| `.frm` 已重建，但新增列仅在末尾 | 部分能 | 逐列验证后给出，中等强度 |
| `.frm` 已重建且有 `DROP COLUMN`/`CHANGE` | **不能** | 只能给出"第 N 列" |
| `.frm` 缺失 | **不能** | 只能给出"第 N 列" |

本案落在第二行，且额外做了第六步的 `ADD COLUMN` 位置验证。验证的依据是"新增列在末尾则前序列不移位"，这是一个结构推断，必须在报告中写明这个推断及其前提 —— 若日后发现存在 `CHANGE COLUMN`，这条推断即失效。

按错误判据走的代价：列序错位会让后面所有值归错列。比如误以为 `@5` 是 `amount`，实际它是 `channel`，那么把字符串 `"app"` 报告成金额，会直接影响责任认定与金额核算。

其四，把 binlog 格式可读当成"数据可恢复"。

`Delete_rows` 计数为 214，说明 ROW 格式、删除前值可读。这个事实与"本次能恢复 2023 年 12 月的数据"毫无关系 —— 缺的是文件，不是格式。

判据是**把可读性与可得性分开表述**：

| 性质 | 由什么决定 | 本案状态 |
|---|---|---|
| 格式可读性 | `binlog_format` 是否为 ROW | 可读 |
| 时间可得性 | binlog 保留窗口 vs 事件时间 | **不可得** |

**"格式是对的"永远不能替代"文件在不在"。** 报告中出现"ROW 格式，删除前值可读"这句时，必须紧跟时间窗口说明，否则读起来就像在说数据能拿回来。

按错误判据走的代价：委托方看到"删除前值可完整读出"的表述，投入人力去准备还原环境，结果发现根本没有对应的 binlog 文件。这类表述造成的预期落差，比直接说"无法恢复"危害更大。

其五，`.frm` 与 `DROP TABLE` mtime 相同却当作"未变更"。

常见推理是"`.frm` 还在，所以列名可靠"。但 `.frm` 存在不代表是**事件发生时的那一份**。本案 `.frm` mtime 与 `DROP` 事件同一秒，恰恰证明它是重建产物。

判据是**时间戳比对**：`stat` 出的 `.frm` mtime 必须**早于**待标注的事件时间才可直接使用；晚于或等于就必须先解决版本对应问题。

按错误判据走的代价：把重建后的结构套用到重建前的数据上，字段含义可能整体错位，且这种错误在报告里完全看不出来 —— 因为列名看起来都"像那么回事"。

---

<a id="section-36"></a>

## 六、扩展阅读方向

**前置与基础。** binlog 的格式选择决定了后面能读到多少。
ROW 格式的完整行事件带着列元数据与 NULL 位图，
部分更新事件（partial update）则是另一套语义——
这三种形态不区分开，看到的「SQL」可能根本不完整。
GTID 体系要一并立住：`GTID_NEXT` 的赋值方式、
主从 binlog 依据 GTID 拼接的规则、
`WAIT_FOR_EXECUTED_GTID_SET` 的等待语义，
半同步复制下这些字段是判断事务是否落地的主线索。

**同层深入。** 事务与原子性的边界体现在两阶段提交如何落到 binlog 里，
崩溃时留下的半提交痕迹该怎么解释，需要单独推演。
InnoDB 侧则要下到页级：聚簇索引与二级索引的组织方式、
purge 行为对旧版本行的清理节奏、und 页的格式，
共同决定了「删掉的数据还能不能被翻出来」。

**相邻议题。** 8.0 的变化值得单列：事务数据字典的结构、
`mysql.ibd` 的解析、以及双写缓冲的引入，
都让老版本的经验不能直接套用。网站装在宝塔面板上时，
业务库口令与加密配置有固定路径，解密思路见
[《宝塔新版加密数据解密》](../../server/server-panel/server-panel-bt-panel-encrypted-data.md)。

**工具与判据。** 时间一致性是这一层的核心难题：
`system_time_zone` 变更过几次、GTID 与时间戳表达的是不是同一件事、
跨源数据怎么对齐，都需要逐项确认。binlog 中的 SQL 要与 Web 日志、
应用日志、代理层日志交叉印证，单一来源的结论不足以支撑因果。

**判据与反例。** 「binlog 里没找到」不等于「操作没发生」：
binlog 有过期时间（覆盖窗口之外不可得，见陷阱 12），
能否读出旧值取决于 `binlog_format` 与 `binlog_row_image`（STATEMENT 格式与 MINIMAL 行镜像都不提供完整旧值，见 2.4 与陷阱 3），
而 purge 之后的 undo 信息也可能已被覆盖。
每条否定结论都要附上 binlog 的时间范围与格式类型。

---

<a id="section-37"></a>

## 七、命令速查

```bash
# ===== 版本与布局判定 =====
ls mysql/ | grep -c '\.frm$'                 # 大量 .frm → 5.6/5.7
ls mysql.ibd 2>/dev/null                      # 存在 → 8.0
ls -d '#innodb_redo' 2>/dev/null              # 存在 → 8.0.30+
ls ib_logfile* undo_00* ibtmp1 2>/dev/null
grep -Ei 'log[-_]?bin|binlog_format|server_id' /etc/my.cnf

# ===== 归档（只读，顺序完整）=====
cd /mnt/case/var/lib/mysql
tar -cf mysql-data.tar ibdata1 ibtmp1 mysql binlog.* mysql-bin.*
find . -name '*.ibd' -o -name '*.frm' | tar -cf mysql-tables.tar -T -
sha256sum mysql-data.tar mysql-tables.tar

# ===== binlog 判定与转储 =====
ls -l binlog.00000*; cat binlog.index
strings binlog.000007 | grep -o 'Delete_rows\|Write_rows\|Query' | sort | uniq -c
mysqlbinlog --base64-output=DECODE-ROWS -vv binlog.000007 > binlog007.txt
mysqlbinlog --base64-output=DECODE-ROWS -vv --tables='appdb.users' binlog.000007
mysqlbinlog --start-datetime='2024-08-01 00:00:00' --stop-datetime='2024-09-01 00:00:00' \
            --base64-output=DECODE-ROWS -vv binlog.000004
while read -r f; do mysqlbinlog --base64-output=DECODE-ROWS -vv "$f" >> all-binlog.txt; done < binlog.index

# ===== 物理层 =====
mysqlfrm --diagnostic appdb/users.frm
strings -n 8 appdb/users.ibd | grep -B2 -A2 '目标关键字'

# ===== 时间与固化 =====
mysql -uroot -p -e "SELECT @@system_time_zone, @@time_zone, @@server_id;"
sha256sum binlog.000007 all-binlog.txt appdb/users.ibd | tee final.sha256
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 移动与数据库取证 — MySQL 数据库取证」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《MySQL 数据库取证》（CC BY-SA 4.0）`

文中 `DigiForensics.dd` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
