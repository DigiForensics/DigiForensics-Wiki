---
title: "数据库取证通用方法"
slug: "mobile-database-database-forensics-methods"
canonical: "https://www.digiforensics.cn/wiki/mobile-database-database-forensics-methods"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:51+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "mobile"
space: "移动取证"
node_path: ["应用数据库"]
---

# 数据库取证通用方法

<a id="section-1"></a>

## 一、概述

前面几篇都是具体引擎的具体做法，本篇讲与引擎无关的骨架：拿到 `.db`、`ibdata1` 还是 `dump.rdb`，第一小时该怎么走、每一步产出什么、结论在什么情况下才算成立。

有三个问题最容易漏，而且漏了会一路错到结论。

> ## ⭐ 1. 时间线陷阱：`datetime` 没有时区
>
> MySQL 的 `DATETIME`、PostgreSQL 的 `timestamp without time zone`、MongoDB 的 BSON Date、JSON 里的字符串时间——**它们存储时都不带时区信息**。
> 它们的含义完全依赖服务器/数据库当时的 `time_zone` 设置，而这个设置**可以被随时改、且不记录在数据里**。
> 一旦跨系统比对（应用日志、Nginx 访问日志、Syslog、内网其他服务器），**8 小时甚至更大的时差错位很容易发生**。

> ## ⭐ 2. 容器里的 `TZ=UTC` 陷阱
>
> 越来越多的服务跑在容器里。容器镜像**默认时区就是 UTC**，且**经常与宿主机时区不一致**。
> 运维看到的日志时间是 UTC，取证人员按本地时区解读，**同一行日志会有两种"正确"读法**。
> 必须确认数据库所在运行环境（宿主 or 容器）的实际时区，不能看"服务器在哪"来判断。

> ## ⭐ 3. 缺失 ≠ 未发生
>
> 数据库层面的"查不到"至少有六种完全不同的原因，任何一种都不能写成"没有这个行为"：
> 已删除 / 未落盘 / 已过期清理 / 从未同步到该节点 / 归档窗口已过 / 检材提取不完整。

**在取证流程中的位置**：本篇是本板块**所有具体引擎文章的前置方法论**，读它应该在读 SQLite WAL 或 MySQL 之前。它给出一条固定的六个阶段：检材固定与环境记录 → 引擎识别 → 整体归档 → 时间基准归一 → 一致性与完整性校验 → 报告输出。**每个阶段都有明确产出**，跳过任何一个都会在后面某个环节以更贵的形式还回来——尤其是时间基准归一，它必须在**任何查询执行之前**完成，因为 `mysqldump` 一次就足以在检材副本上留下访问痕迹。**上游依赖**是 [只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md)（归档动作必须只读、哈希先于分析）与 [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md)（证据链与结论标准）。**下游**是本板块的四个具体篇目：[SQLite 基础与结构](mobile-database-sqlite.md)、[SQLite WAL 取证](mobile-database-sqlite-wal.md)、[MySQL 数据库取证](mobile-database-mysql.md)、[NoSQL 与 Redis 取证](mobile-database-mongodb-and-redis-forensics.md)——**它们各自的具体做法都建立在本篇的阶段划分之上**，尤其时间基准这一段，四篇共用同一套纪律。

**本篇处理的证据形态**，横跨三类对象，判据各不相同：

| 类别 | 具体对象 | 判据 |
|---|---|---|
| **数据库文件** | `app.db`、`app.db-wal`、`app.db-shm`（SQLite 三件套）；`ibdata1`、各 `.ibd`、`binlog.00000X`、`undo_001`（InnoDB 家族）；WiredTiger 的 `collection-*.wt` 与 `WiredTiger.turtle`；`dump.rdb` 与 AOF 分片 | **看目录构成与文件头，不看扩展名**；三件套必须整体哈希，单独哈希主库没有意义 |
| **配置** | `my.cnf` 与 `~/.my.cnf`、`postgresql.conf`、`redis.conf`、`/etc/mongod.conf`；容器的 Dockerfile / compose / K8s manifest | 读取顺序是**配置文件 → 环境变量 → 命令行参数**，后者覆盖前者，所以只看配置文件会得出错误配置 |
| **时区证据** | 三处独立来源：进程环境变量 `TZ`、数据库参数 `@@time_zone` / `@@system_time_zone`、日志里已渲染出来的时间；物证是 `/etc/localtime` 的符号链接指向与 `/usr/share/zoneinfo/` 下的文件 | `/etc/localtime → Etc/UTC` 是容器 UTC 时区最直接的物证；环境变量在内存镜像里也能捞到 |
| **完整性证据** | 归档包的 SHA-256、页级校验（如 SQLite 的 WAL 帧滚动校验和）、解析时的 `PRAGMA integrity_check` 一类只读校验 | **哈希要在分析前、分析后各算一次**，两次一致才说明分析过程没有写坏副本 |

检材在什么状态下被接收、它包含哪些引擎的文件、时间基准是什么（依据哪三处证据得出）、文件与归档包是否完整一致、每个结论的覆盖范围到哪里。

**"数据库里没有记录"永远不等于"这件事没有发生"**——`time_zone` 一旦被改过且无记录，你根本判断不出那条时间戳当初是按哪个时区写的，这时**任何时间换算都是猜测**，报告里必须把不确定性写出来而不是给一个看似精确的时间。查不到记录的六种成因彼此无法区分，需要靠同批次的其他工件（日志、备份、binlog 过期窗口）缩小范围，而不能靠数据库本身下结论。归档完整**不等于内容完整**：整体哈希一致只能证明文件没变，证明不了提取时就没漏。阴性结果必须限定到具体范围与时间窗，并列出未覆盖对象（未提取的应用目录、未纳入归档的日志、已过期的 binlog）；而且"查不到"永远无法排除它从未被写入数据库这个可能之外的路径——比如数据只存在于客户端缓存或另一个副本库里。

**读者前提**：需要已经能识别检材属于哪种引擎（否则"阶段二：引擎识别"就是天书），至少读过本板块的 SQLite 或 MySQL 两篇之一；需要能读十六进制并理解偏移、页、大小端这类基本概念，因为完整性校验和时区物证的判断都要落到具体字节上；需要接受"证据链记录"本身就是交付物的一部分，而不是事后补写；还要理解 `mysqldump` 这类工具是**有副作用**的——它能触发 checkpoint、能写查询历史、能在文件系统上留下访问痕迹，所以任何导出动作必须在副本上做，并在采集记录里写明执行时间。

---
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 数据库状态是文件集合，不是文件

任何数据库在某个时刻的状态，都是好几个文件一起定下来的。少一个，那个时刻的状态就不完整。

| 组成 | 作用 | 缺失后果 |
|---|---|---|
| **数据文件** | 表/集合/键的实际内容 | 无法读取 |
| **结构元数据** | 表定义、列类型、集合映射 | 读得出字节，读不出含义 |
| 日志（WAL / journal / binlog） | 未落盘增量、历史值 | 丢失最新数据与删除前值 |
| **索引文件** | 加速与完整性辅助 | 部分查询退化，索引存在性无法验证 |
| **内存状态** | 未刷盘缓冲、活跃会话 | 关键数据完全不可见 |
| **配置** | 引擎、时区、字符集、加密 | 解释错误、时区错位、解密失败 |

通用规则就一条：**能整体打包就整体打包，别做"选择性拷贝"。**

选择性拷贝的错误是静默的。命令成功，包也出来了，一个警告都没有——只是内容少了。

<a id="section-4"></a>

### 2.2 时间的三种存储形态

| 形态 | 示例 | 带时区？ | 判读要求 |
|---|---|---|---|
| **Unix 时间戳** | `1724297599`、MySQL `INT`、Redis AOF 中的 `SETEX` | **是**（UTC 基准） | 转成 UTC 后再按目标时区呈现 |
| **带时区时间** | `2024-08-22T11:33:19+08:00`、Java `Instant` | **是** | 直接换算，但**注意可能是客户端伪造的** |
| **无时区时间** | MySQL `DATETIME`、MySQL binlog 事件时间、PostgreSQL `timestamp without time zone`、本地文件 mtime 呈现 | **否** | **必须声明所采用的时区假设** |

> 出错最多的就是第三类。`DATETIME '2024-08-22 11:33:19'` 写进去的时候按哪个时区理解，取决于连接会话的 `time_zone`；写完之后这个信息就永久没了。
> 取证能做的有限：把当时的配置和系统时区找出来当证据，**声明假设**，再在报告里标清这个假设影响到哪些结论。

<a id="section-5"></a>

### 2.3 容器化环境的时间链路

服务跑在容器里，时间基准得一层层往回追：

| 层级 | 可能的状态 | 后果 |
|---|---|---|
| 应用代码 | 可能显式设置 `TZ`、`time.Local`、`X-TIMEZONE` | 应用层时间已被转换 |
| 运行时镜像 | **基础镜像几乎都是 UTC** | 容器内 `date` 是 UTC |
| 编排平台 | K8s Pod 可注入 `TZ` 环境变量；未注入则继承镜像设置 | **多数集群不设** |
| 数据库连接 | JDBC/驱动可能把会话时区设为服务器时区 | 决定 `DATETIME` 如何解释 |
| 宿主机 | 可能为 UTC+8 | **宿主机时区≠容器时区** |

**判读规则**：

> 别看"服务器物理位置在哪"，看"数据库进程实际读到的是什么"。
> 这个值有三个地方能拿到：进程环境变量 `TZ`、数据库参数 `@@time_zone` / `@@system_time_zone`、日志里已经渲染出来的时间。

```bash
# 宿主机时区
timedatectl 2>/dev/null | grep -E 'Time zone|RTC in'
cat /etc/timezone 2>/dev/null

# 进程环境（内存镜像中）
strings -n 4 DigiForensics-mem.raw | grep -E '^TZ=|^TZ=' | sort | uniq -c

# 容器内（若有 shell 权限）
cat /etc/timezone 2>/dev/null
readlink -f /etc/localtime
# 常见容器值：/usr/share/zoneinfo/Etc/UTC   ← 关键线索

# 数据库参数
mysql -uroot -p -e "SELECT @@global.time_zone, @@session.time_zone, @@system_time_zone;"
```

`/usr/share/zoneinfo/Etc/UTC` 或 `/etc/localtime → Etc/UTC` 这种指向，就是容器 `TZ=UTC` 最直接的物证。

<a id="section-6"></a>

### 2.4 "查不到"的六种成因

| 成因 | 判据 | 报告应写 |
|---|---|---|
| **已删除** | 主库无记录，但 binlog/undo/空闲区有痕迹 | "已被删除，删除前值可从 X 恢复" |
| **未落盘** | WAL/AOF/内存中有，磁盘文件中无 | "存在于 X，尚未持久化" |
| **已过期清理** | 日志窗口外，无任何痕迹 | "**在已获取的日志窗口（A 至 B）内未见**，窗口外无法判断" |
| **未同步到该节点** | 从库/副本缺少主库有的事件 | "本节点未同步，不代表未发生" |
| **已归档轮转** | 文件序号跳变、目录被压缩移走 | "**存在日志缺口，该时段不可判断**" |
| **检材提取不完整** | 只提了主库、漏了伴随文件 | "**检材不完整，已回源补提**" |

> **这一张表应当直接印在报告模板里。** 每一条"未发现"的结论旁边，必须标注它属于上表哪一类。**不标注的"未发现"在质证环节无法成立。**

<a id="section-7"></a>

### 2.5 完整性的三个层级

委托方嘴里的"数据库已恢复"，可能是三件完全不同的事。

| 层级 | 含义 | 验证方式 |
|---|---|---|
| **设备已解锁** | 手机/主机已能正常进入系统 | 能否开机、能否登录 |
| **存储已解密** | 全盘/FBE/BitLocker 已解开，文件可读 | 文件系统能否挂载、目录能否列出 |
| **数据库已解密** | 数据库自身的表空间加密/字段加密已解开 | **能否 `SELECT` 出明文** |

> 报告里这三层必须分开说。
> "手机已解锁、磁盘镜像已解密，但目标数据库为 SQLCipher 加密且密钥未获取"——**这是一个完整、准确、对委托方有实质价值的结论**，不能写成"数据无法获取"。

归档副本的哈希怎么算、用 MD5 还是 SHA-256、要不要登记进哈希数据库，见[哈希与完整性校验](../../fundamentals/fundamentals-concepts/fundamentals-concepts-hashes-and-integrity-verification.md)。

这几个数字后面的每一处时间、每一个结论，都要靠上面的记录兜底。

---

<a id="section-8"></a>

## 三、操作步骤

<a id="section-9"></a>

### 3.1 阶段一：检材固定、环境与时区链路记录

```bash
# 1) 哈希先行，之后一切修改只在副本上
sha256sum DigiForensics.dd DigiForensics-mem.raw | tee hashes.txt

# 2) 记录时区链路（★ 这一步的产出必须写进报告）
timedatectl 2>/dev/null | grep -E 'Time zone'
readlink -f /etc/localtime                          # 常见容器值：/usr/share/zoneinfo/Etc/UTC
cat /etc/timezone 2>/dev/null
strings -n 4 DigiForensics-mem.raw | grep -x 'TZ=[A-Za-z/_+-]*' | sort -u

# 3) 判断是否容器
ls /.dockerenv 2>/dev/null && echo "容器"
cat /proc/1/cgroup 2>/dev/null | head -3
systemd-detect-virt --container 2>/dev/null

# 4) 数据库进程与配置
ps aux | grep -E '[m]ysqld|[m]ongod|[r]edis-server|[p]ostgres'
ls /etc/my.cnf /etc/mysql/ /etc/mongod.conf /etc/redis/redis.conf 2>/dev/null
mysql -uroot -p -e "SELECT @@global.time_zone, @@session.time_zone, @@system_time_zone;"
```

**时区链路的结论格式**（写入报告）：

> 宿主机时区：`Asia/Shanghai (UTC+8)`；容器内 `/etc/localtime → Etc/UTC`；数据库 `@@system_time_zone = UTC`。据此判断：本机数据库写入的 `DATETIME` 与 binlog 事件时间均按 UTC 解释。

`/usr/share/zoneinfo/Etc/UTC` 或 `/etc/localtime → Etc/UTC` 这类指向，**是容器 `TZ=UTC` 最直接的物证**。

<a id="section-10"></a>

### 3.2 阶段二：引擎识别

```bash
# 通用特征扫描
find /mnt/case -maxdepth 4 \( -name '*.db' -o -name '*.ibd' -o -name 'ibdata*' \
  -o -name '*.frm' -o -name '*.wt' -o -name 'dump.rdb' -o -name 'appendonly*' \
  -o -name 'PG_VERSION' -o -name 'ib_logfile*' -o -name '*-journal' -o -name '*-wal' \) \
  2>/dev/null | head -40

# 魔术字节
xxd -l 16 app.db | grep -q '5351 4c69 7465' && echo "SQLite 明文"
# 若首字节不是 'S' → 可能是加密库，判定加密扩展（以实际库为准）
xxd -l 9 dump.rdb        # 5245 4449 5300 0006 02   → REDIS + 版本号
cat base/PG_VERSION      # PostgreSQL 纯文本版本号
```

| 命中 | 引擎 | 首要动作 |
|---|---|---|
| `SQLite format 3` 文件头 | SQLite | **确认并提取 `-wal`/`-shm`**（见 [09](mobile-database-sqlite-wal.md)） |
| `ibdata1` / `*.ibd` | MySQL InnoDB | **先定版本**（见 [10](mobile-database-mysql.md)） |
| `binlog.0000*` | MySQL | **优先攻 binlog** |
| `WiredTiger` / `collection-*.wt` | MongoDB | **必须取 catalog 文件**（见 [11](mobile-database-mongodb-and-redis-forensics.md)） |
| `dump.rdb` / `appendonly*` | Redis | **必须做内存取证** |
| `PG_VERSION` / `pg_wal/` | PostgreSQL | 取 `pg_wal` 与 `pg_xact` |

<a id="section-11"></a>

### 3.3 阶段三：整体归档

```bash
# 原则：宁可多不可少；不要跨时间点分别拷贝
cd /mnt/case/var/lib/mysql
tar -cf mysql.tar ibdata1 ibtmp1 mysql binlog.* mysql-bin.* 2>/dev/null
find . -name '*.ibd' -o -name '*.frm' | tar -cf mysql-tables.tar -T -

cd /mnt/case/var/lib/mongodb
tar -cf mongo.tar WiredTiger WiredTiger.turtle WiredTigerLog.* collection-*.wt index-*.wt

cd /mnt/case/data/redis
tar -cf redis.tar dump.rdb appendonlydir/ 2>/dev/null

# Android 侧：整目录而非单文件（保证三文件同刻）
adb shell su -c "tar -cf - -C /data/user/0/com.digiforensics.sample/databases ." > dbset.tar

sha256sum *.tar | tee archive.sha256
chmod -R a-w /mnt/case   # 原始挂载点立刻只读
```

**归档后的验收清单**（逐项打勾，缺项必须在报告中说明）：

- [ ] 数据文件（主库 / 表空间 / 集合文件）
- [ ] 结构元数据（`.frm` / catalog / `mysql.ibd` / `PG_VERSION`）
- [ ] 日志（WAL / journal / binlog / AOF / `pg_wal`）
- [ ] 索引文件
- [ ] 配置文件（`my.cnf`、`mongod.conf`、`redis.conf`、`postgresql.conf`）
- [ ] 内存镜像（若涉及进程驻留数据）

<a id="section-12"></a>

### 3.4 阶段四：时间基准归一

```bash
cat > tzfix.py <<'PY'
import sys, datetime

def naive_to_utc(s, offset_hours):
    """无时区时间 → 必须显式传入所假设的时区"""
    return datetime.datetime.strptime(s, "%Y-%m-%d %H:%M:%S") \
        - datetime.timedelta(hours=offset_hours)

s = sys.argv[1]
if s.isdigit():                                    # Unix 时间戳
    utc = datetime.datetime.utcfromtimestamp(int(s))
    print(f"UTC   : {utc:%Y-%m-%d %H:%M:%S}")
    print(f"UTC+8 : {utc + datetime.timedelta(hours=8):%Y-%m-%d %H:%M:%S}   ← 若原系统为 UTC+8")
else:
    print(f"按 UTC+8 假设解释为 UTC : {naive_to_utc(s, 8):%Y-%m-%d %H:%M:%S}")
PY

python3 tzfix.py 1724297599
python3 tzfix.py '2024-08-22 11:33:19'
```

> **每一条时间进入报告前必须过一遍这个换算**，并**在报告的每一处时间旁边标注所用时区**。跨来源比对时先全部转成 UTC 对齐，再各自按阅读者习惯呈现。

<a id="section-13"></a>

### 3.5 阶段五：一致性与完整性校验

```bash
# SQLite（immutable=1 只读观察，不会触发 checkpoint）
sqlite3 "file:app.db?immutable=1" "PRAGMA integrity_check; PRAGMA journal_mode; PRAGMA freelist_count;"
mysql -uroot -e "CHECK TABLE appdb.users EXTENDED;"     # MySQL：隔离实例、只读副本
redis-check-rdb dump.rdb

# 通用：数据内容时间 vs 文件 mtime（★ 极其有效的矛盾检测）
stat -c '%n mtime=%y' app.db
sqlite3 app.db "SELECT max(datetime(createTime/1000,'unixepoch','localtime')) FROM pay_record;"
# 文件 8/31 被写过、内容却停在 8/22 → 存在未落盘数据，检材不完整
```

**矛盾检测表**（把每一对都查一遍，不一致即写进报告）：

| 配对 | 一致则 | 不一致则 |
|---|---|---|
| 文件 mtime vs 内容最大时间 | 一致，正常 | **未落盘数据 / 提取不完整** |
| 主库行数 vs binlog 事件累加 | 接近 | 中间有未落盘或被删的操作 |
| AOF 最后命令时间 vs RDB mtime | 接近 | AOF 更新 → RDB 快照滞后 |
| binlog 序号 vs 实际文件 | 连续 | **日志缺口，部分时段不可判断** |
| oplog `ts` 范围 vs 委托描述时间 | 覆盖 | 超出窗口 → 需补日志来源 |

<a id="section-14"></a>

### 3.6 阶段六：报告输出规范

**每一条数据类结论必须携带四要素**：① **来源**（哪个文件、哪条命令、哪段偏移）；② **可复现命令**（委托方或同行能原样重跑）；③ **完整性状态**（是否加密、是否完整提取、是否仅内存可见）；④ **限制**（这条结论不能证明什么）。

**固定表述模板**：

> **结论**：订单 `SO20240822000931` 于 2024-08-22 11:33:19（UTC+8）支付成功，金额 8800.00 元。
> **来源**：`/var/lib/redis/appendonlydir/appendonly.aof.1.incr.aof` 第 41182 行（`SET` 命令）。
> **复现**：`python3 resp.py appendonlydir/*.incr.aof | grep -n 'SO20240822000931'`
> **完整性**：Redis 6.2.7，AOF 与 RDB 均已完整提取；该键在 RDB 中不存在，说明 AOF 为最新来源。
> **限制**：本条**不证明**订单当前仍在库中；订单已于同日被 `DEL` 删除。

---
<a id="section-15"></a>

## 四、常见陷阱

<a id="section-16"></a>

### 4.1 检材固定与归档

<a id="section-17"></a>

#### 陷阱 1：以"减小体积"为由做选择性拷贝

**现象**：数据目录 40 GB。分析师判断"大部分是索引和临时文件，拷数据文件就够了"，于是只打包 `*.ibd` / `collection-*.wt` / `*.db`，元数据、索引、日志、配置全跳过。到分析阶段才发现：文件对应哪个集合定不了，列名读不出来，最近的操作也看不见。

**原因**：因为**数据库的"状态"是文件集合，不是文件**。而选择性拷贝的错误是**静默的**——命令执行成功，归档包正常生成，不产生任何警告，只是内容少了。

分析师的判断依据通常是文件大小和名字，这两样都不反映必要性。一个 8 KB 的 `.frm` 决定整个表怎么解读，一个没有扩展名的 `WiredTiger` 文件是整库的映射入口。反过来，几百 MB 的 `ibtmp1`（临时表空间）可能完全无关。

**影响**：**得到一份无法解释的残缺件，而且往往补不回来。** 等发现缺失，服务器可能已停机、磁盘已回收、委托方已失去访问权。

更隐蔽的是它会直接污染后续结论——"没有找到"到底是"不存在"还是"没拷"，从材料本身分辨不出来。

**核查**：**整体打包 + 逐项验收**，验收清单缺项必须在报告中说明。

```bash
# 原则：宁可多不可少；不要跨时间点分别拷贝
cd /mnt/case/var/lib/mysql
tar -cf mysql.tar ibdata1 ibtmp1 mysql binlog.* mysql-bin.* 2>/dev/null
tar -cf mongo.tar WiredTiger WiredTiger.turtle WiredTigerLog.* collection-*.wt index-*.wt
tar -cf redis.tar dump.rdb appendonlydir/ 2>/dev/null

sha256sum *.tar | tee archive.sha256
chmod -R a-w /mnt/case          # 原始挂载点立刻置只读
```

验收清单（逐项打勾，**缺项必须在报告中说明**）：数据文件 / 结构元数据 / 日志（WAL、journal、binlog、AOF、`pg_wal`）/ 索引文件 / 配置文件 / 内存镜像。判断标准很简单：**只要你不确定某个文件是否影响解读，就一定要带上**。

<a id="section-18"></a>

#### 陷阱 2：跨时间点分别拷贝，破坏"同一时刻状态"

**现象**：为了赶进度，先拷数据文件。过了两天再拷日志文件，归档包到第三次拷贝后才合并。分析时发现主库有记录、日志里却没有对应操作，报告就写成"该操作未被记录"。

**原因**：**数据库的多个文件必须来自同一时刻才有意义。** 间隔拷贝那两天数据库还在跑，主库在记操作，日志也在涨。两次拷贝拼起来的"状态"，物理上从来没存在过。

SQLite 的 `-wal` 尤其敏感。主库和 `-wal` 不是"主文件 + 附属文件"的关系，是同一个状态的两半。跨时刻拼接会得到一个既不是旧版本、也不是新版本的自造状态，而且不报错。

**影响**：**制造出"日志缺失"的假象。** 这类假象方向性很强——它会被读成"有人清除了操作记录"，进而引出错误的反篡改结论。

**核查**：**同一目录、同一时刻、一次性打包**。

```bash
# Android 侧：整目录而非单文件（保证三件套同刻）
adb shell su -c "tar -cf - -C /data/user/0/com.digiforensics.sample/databases ." > dbset.tar

# 打包后立即记录成员清单与时间戳，作为"同刻性"的证据
tar -tvf dbset.tar | head -20
```

归档包内所有文件的 mtime 应该彼此接近。哪几件明显早于或晚于其余，就是发生了跨时刻拷贝——写进报告里。

<a id="section-19"></a>

#### 陷阱 3：★ 用读写方式打开原始文件

**现象**：为了查询方便，直接在检材的原始路径上跑 `sqlite3 app.db "SELECT ..."`，或者以读写方式挂载数据目录运行 `mysqld`，甚至在原始 `dump.rdb` 旁边执行一次 `redis-check-rdb` 之外的工具。

**原因**：因为**"打开"这个动作本身就可能改写字节**。

SQLite 打开一个 WAL 模式库时会尝试 checkpoint，把 `-wal` 的内容回写主库，还可能截断 `-wal`。InnoDB 启动时会执行崩溃恢复、改写 redo 和表空间。连"以只读方式打开"都有例外——`immutable=1` 和 `ro` 挂载是两套机制，没加 `immutable=1` 的 `file:...?mode=ro` 仍然可能触发写行为。

分析师的直觉是"我只是读"。但引擎层面，读和写的界限远没有想象中清楚。

**影响**：**原始检材被不可逆地改变，后续无法复现。** 委托方质疑检材完整性时，手上已经没有干净副本了。

更糟的是：改写发生了但事后才察觉。那之后所有分析都建在一个"已经不是原始状态"的材料上，结论效力无法自证。

**核查**：原始件全程只读，所有可能写行为的操作在副本上做，且分层明确。

```bash
# 1) 固定哈希，之后只校验不操作
sha256sum DigiForensics.dd DigiForensics-mem.raw | tee hashes.txt

# 2) 原始挂载点立刻置只读
chmod -R a-w /mnt/case

# 3) SQLite：immutable=1 才是"纯观察"，并且在副本上做
cp app.db /work/DigiForensics-analysis.db
sqlite3 "file:/work/DigiForensics-analysis.db?immutable=1" "PRAGMA integrity_check; PRAGMA journal_mode; PRAGMA freelist_count;"

# 4) MySQL：隔离实例 + 只读副本
mysqld --datadir=/work/isolated --skip-networking
mysql -uroot -e "CHECK TABLE appdb.users EXTENDED;"
```

报告里要写明两件事：哪些操作在原件上做过（应为无）、原件哈希在分析前后是否一致。

<a id="section-20"></a>

### 4.2 引擎识别与时间基准

<a id="section-21"></a>

#### 陷阱 4：只凭文件扩展名或文件名判断引擎

**现象**：看到 `users.db` 就按 SQLite 解析，输出一片乱码，于是判定"文件已加密或损坏"。看到 `data.db` 就套用 mmapv1 的解析脚本。

**原因**：**扩展名不构成引擎证据。** 应用可以给自己的数据库文件起任何名字。同一个 `.db` 可能是 SQLite，可能是 SQLCipher 加密的 SQLite，也可能是完全自定义的格式。

**魔术字节才是可靠判据。** SQLite 明文库以 `SQLite format 3\0` 开头；Redis RDB 以 `REDIS` + 版本号开头；PostgreSQL 的 `PG_VERSION` 是纯文本版本号。首字节不是 `S`，那就不是明文 SQLite——该转向判断加密扩展，而不是继续按明文解析。

**影响**：**在错误的引擎假设上投入大量时间**，并可能得出"数据已损坏"这个错误且严重的结论。加密和损坏在字节层面根本无法区分（见[第 11 篇](mobile-database-mongodb-and-redis-forensics.md)）。

**核查**：先做通用特征扫描与魔术字节判定，再确定引擎与解析路径。

```bash
# 通用特征扫描
find /mnt/case -maxdepth 4 \( -name '*.db' -o -name '*.ibd' -o -name 'ibdata*' \
  -o -name '*.frm' -o -name '*.wt' -o -name 'dump.rdb' -o -name 'appendonly*' \
  -o -name 'PG_VERSION' -o -name '*-journal' -o -name '*-wal' \) 2>/dev/null | head -40

# 魔术字节
xxd -l 16 app.db | grep -q '5351 4c69 7465' && echo "SQLite 明文"
xxd -l 9 dump.rdb        # 5245 4449 5300 0006 02   → REDIS + 版本号
cat base/PG_VERSION
```

| 命中 | 引擎 | 首要动作 |
|---|---|---|
| `SQLite format 3` 头 | SQLite | **确认并提取 `-wal`/`-shm`** |
| `ibdata1` / `*.ibd` | MySQL InnoDB | **先定版本** |
| `WiredTiger` / `collection-*.wt` | MongoDB | **必须取 catalog 文件** |
| `dump.rdb` / `appendonly*` | Redis | **必须做内存取证** |
| `PG_VERSION` / `pg_wal/` | PostgreSQL | 取 `pg_wal` 与 `pg_xact` |

**判定结果与版本号必须一并写进报告**——后面所有的解析选择都建立在它之上。

<a id="section-22"></a>

#### 陷阱 5：只看宿主机时区就确定时间基准

**现象**：`timedatectl` 显示 `Asia/Shanghai (UTC+8)`，报告据此写"本机数据库时间均为北京时间"，全案时间线按 UTC+8 解读。

**原因**：服务跑在容器里时，宿主机时区跟数据库进程实际时区可以完全不同。 容器基础镜像几乎都是 UTC；K8s Pod 可以注入 `TZ` 变量，不注入就继承镜像设置；`/etc/localtime` 指向 `/usr/share/zoneinfo/Etc/UTC` 就是最直接的物证。

关键在于：决定 `DATETIME` 语义的是数据库进程读到的时区值，不是服务器物理位置在哪。

**影响**：**整条时间线产生固定偏移。**

这类错误的阴险之处在于：它不会让单条记录变成错的，它让所有记录整体平移。跨源比对时表现为"8 小时对不上"，很容易被进一步误判成"日志缺失"或"时间被篡改"，引出完全错误的结论。

**核查**：**沿容器链路逐层取证，输出可写入报告的时区结论句**。

```bash
timedatectl 2>/dev/null | grep -E 'Time zone|RTC in'
readlink -f /etc/localtime                          # 常见容器值：/usr/share/zoneinfo/Etc/UTC
cat /etc/timezone 2>/dev/null

# 是否容器
ls /.dockerenv 2>/dev/null && echo "容器"
cat /proc/1/cgroup 2>/dev/null | head -3
systemd-detect-virt --container 2>/dev/null

# 进程环境（内存镜像中）
strings -n 4 DigiForensics-mem.raw | grep -x 'TZ=[A-Za-z/_+-]*' | sort -u

# 数据库参数（最权威）
mysql -uroot -p -e "SELECT @@global.time_zone, @@session.time_zone, @@system_time_zone;"
```

结论句式："宿主机时区 `<X>`；容器内 `/etc/localtime → <Y>`；数据库 `@@system_time_zone = <Z>`。据此判断：本机数据库写入的 `DATETIME` 与 binlog 事件时间按 `<Z>` 解释。"

<a id="section-23"></a>

#### 陷阱 6：把无时区时间当作 UTC，或把它当作已知的本地时间

**现象**：从表里读出 `created_at = 2024-08-22 11:33:19`，报告直接写"该记录创建于北京时间 11:33:19"。或者反过来，写"该时间为 UTC，对应北京时间 19:33:19"。

**原因**：MySQL 的 `DATETIME`、PostgreSQL 的 `timestamp without time zone`、MongoDB 的 BSON Date、JSON 里的时间字符串，存的时候都不带时区信息。 `DATETIME` 写入时按什么时区解释，完全取决于**连接会话的 `time_zone`**，写完这个信息就永久丢了——**数据本身回答不了这个问题**。

分析师往往按自己所在地的习惯直接补上时区。这一步没有任何证据支撑。

**影响**：**用一句没有依据的假设，撑起了整条时间线。**

而且这类错误在报告内部往往是自洽的——所有时间统一偏移了，看着很整齐。只有跨源比对时才暴露，那时已经很难定位是哪一步引入的偏差。

**核查**：**把时区处理变成显式的、可追溯的两步**。

```bash
# ① 换算（显式传入假设，绝不隐式默认）
python3 tzfix.py 1724297599                    # Unix 秒 → 同时给出 UTC 与 UTC+8
python3 tzfix.py '2024-08-22 11:33:19'        # 无时区时间 → 按指定假设换算

# ② 把假设升级为证据：查时区是否被改过
mysqlbinlog --base64-output=DECODE-ROWS -vv binlog.000003 \
  | grep -iE "SET (time_zone|timestamp)|@@(session|global)\.time_zone" | head
# 出现 SET @@session.time_zone='+00:00' 且无 '+08:00' → 该时段按 UTC 写入
```

**每一处时间旁边必须标注所用时区。** 证据不足时，无时区时间写成 `2024-08-22 11:33:19（假定 UTC+8，未独立确认）`。跨来源比对先全部转成 UTC 对齐，再按阅读者习惯分别呈现。

<a id="section-24"></a>

### 4.3 完整性与覆盖度

<a id="section-25"></a>

#### 陷阱 7：把"未找到"写成"未发生"

**现象**：在 binlog 里检索某个用户的操作，一无所获。报告结论一节写"该用户在涉案时段没有进行任何相关操作"。

**原因**：因为**"查不到"至少有六种成因**——已删除但主库无痕、未落盘（只在 WAL/AOF/内存中）、已过期清理（超出日志窗口）、未同步到该节点（从库缺少主库有的事件）、已归档轮转（文件序号跳变）、检材提取不完整。

**这六种成因对应的结论强度完全不同**，但"未找到"这个现象对它们是等价的。误判就出在这儿——把"检索无结果"直接等同于"事实不存在"。

**影响**：**用检索能力的边界，冒充事实层面的否定。**

这类结论在质证中只需一句"你检索的日志覆盖到什么时候"就被推翻。要是被拿去论证"该用户长期清白"，影响远超单条记录。

**核查**：每条"未发现"都必须标注它属于哪一类成因（成因—判据对照表见 2.4），并写明四要素。

**范围、方法、未覆盖范围、效力上限**——这四要素是"未发现"类结论的最低交付标准。不满足，质证环节立不住。

<a id="section-26"></a>

#### 陷阱 8：只报"查到多少条"，不报覆盖范围

**现象**：报告写"共检索到 1,204 条相关操作"。这些操作覆盖多长时间、该范围内是否完整，一个字没提。

**原因**：**条数是绝对量，覆盖率才是判断依据。** 1,204 条可能覆盖 3 小时，也可能覆盖 3 个月——要是前者，说明绝大部分时段根本没被检材覆盖，1,204 这个数字反而掩盖了覆盖不足的事实。

更麻烦的是条数多会给人"证据充分"的错觉。实际可能是 1,200 条无关操作，只有 4 条相关。

**影响**：**把数据量误读为证据强度**，让委托方基于错误的印象做决策。

**核查**：**条数与覆盖率必须成对出现**。

```bash
# 窗口实测，不估算
const a = db.getSiblingDB("local").oplog.rs.find().sort({$natural:1}).limit(1).toArray()[0];
const b = db.getSiblingDB("local").oplog.rs.find().sort({$natural:-1}).limit(1).toArray()[0];
print("覆盖跨度（秒）：" + (b.ts.t - a.ts.t));

# 报告句式
"在 <起> 至 <止> 的 binlog 窗口内（跨度 N 天，基于首末文件时间戳实测），
 共检索到 N 条相关操作，其中与委托事项直接相关的 M 条。
 未覆盖：窗口之前、轮转间隙、其他库表、未分析的 undo/redo。"
```

<a id="section-27"></a>

#### 陷阱 9：跳过矛盾检测，把不一致当作正常现象

**现象**：文件 mtime 是 8/31，表内最大时间却是 8/22。分析师判断"可能这台机器那段时间没业务"，跳过不查，继续往下做。

**原因**：mtime 与内容时间的矛盾是极其有效的异常信号。 文件在 8/31 被写过、内容却停在 8/22，至少有三种解释：未落盘数据（WAL/内存里还有）、提取不完整（漏了 `-wal`）、文件被写坏或被清空。

三者对结论的影响完全不同。而"应该只是没业务"恰恰是**最不该优先采信**的那个——**因为它是其中唯一不需要任何证据就能说出口的解释**。

**影响**：**放过一个本可发现检材缺陷的机会**，还把一个可核查的信号降级成了噪音。

**核查**：把矛盾检测做成固定配对表，逐对检查，不一致即写进报告（配对表见 3.5 阶段五）。

```bash
stat -c '%n mtime=%y' app.db
sqlite3 full.db "SELECT max(datetime(createTime/1000,'unixepoch','localtime')) FROM pay_record;"
```

**每一处不一致，要么解释清楚，要么列入局限性。** "未作进一步检查"这种含糊处理不允许。

<a id="section-28"></a>

#### 陷阱 10：忽略"三层完整性"被混为一谈

**现象**：委托方问"数据恢复了吗"，报告答"该设备已解锁，数据库数据可正常读取"。而实际目标是 SQLCipher 加密库，解密根本没成功。

**原因**：**"数据库已恢复"在实践中指三件完全不同的事**：设备已解锁（能开机登录）、存储已解密（FBE/BitLocker 已解，文件可读）、数据库已解密（表空间或字段级加密已解，能 `SELECT` 出明文）。

**前两层通过，不代表第三层通过。** 混为一谈的根源，是把这三层当成一个状态看。而实际案件中，三层状态各种组合都可能出现。

**影响**：**给出方向性错误的结论**，并让委托方以为工作已经完成。而且"数据无法获取"这个笼统说法，会掩盖"已解密到什么程度"这个有实际价值的信息。

**核查**：**报告中三个层级必须分别陈述**。

| 层级 | 状态表述 | 证据 |
|---|---|---|
| 设备已解锁 | 已解锁 / 未解锁 / 需口令 | 开机与登录结果 |
| 存储已解密 | 全盘 / FBE / BitLocker 已解或未解 | 文件系统能否挂载、目录能否列出 |
| 数据库已解密 | 表空间或字段加密已解 / 未解 | **能否 `SELECT` 出明文** |

规范句式："手机已解锁、磁盘镜像已解密，但目标数据库为 SQLCipher 加密且密钥未获取。"

这句话本身就是完整、准确、对委托方有实质价值的结论。别压缩成"数据无法获取"。

<a id="section-29"></a>

### 4.4 分析操作与结论表述

<a id="section-30"></a>

#### 陷阱 11：为了"能查"而在原库上执行修复

**现象**：数据库打不开。分析师在原始数据目录上执行修复操作（`REPAIR TABLE`、`innodb_force_recovery`、`sqlite3 .recover` 覆盖导出），成功打开后就基于结果下结论。

**原因**：**修复操作的定义就是改写。** `innodb_force_recovery` 逐级放宽一致性检查，直接改写数据文件；`.recover` 会重新构造一个库文件。

"不修就查不了"——这个动机是合理的。但**修复后的库已经不是事故时刻的状态了**。恢复级别过高时可能丢掉最近的事务，也可能拼出不一致的结果，而这些在导出的产物里没有任何标记。

**影响**：**破坏现场且无法复现。** 修复一旦执行，原始状态永久丢失；委托方质疑时，你拿不出"未改动的原始件"。

更麻烦的是，**从修复库导出的行数与字段分布会被当成现场状态陈述**，而它们可能早就偏离真实了。

**核查**：**修复只在副本上做，并逐级记录，产物不参与事实认定**。

```bash
# 原始件只读
sha256sum DigiForensics.dd | tee image.sha256
chmod -R a-w /mnt/case

# 分层副本：只读分析 → 可改写工作 → 恢复演练
cp -a /mnt/case/var/lib/mysql /work/work-mysql
cp -a /work/work-mysql            /work/recovery-mysql
# 每升一级恢复强度都另开一份新副本，不在同一份数据上连续升级
```

报告须写明三件事：使用的恢复级别、该级别下已知会丢失的内容、原始件哈希在全程中未变的证明。

<a id="section-31"></a>

#### 陷阱 12：不同来源的时间直接并列成表

**现象**：报告时间线表格里，Redis 字段写 `2024-08-22 11:33:19`、MySQL 写 `#240822 03:33:19`、手机库写 `1724297599`。三个值裸并列，读者判断不出它们是不是同一时刻。

**原因**：三个值可能确实指向同一时刻，但表格形式否定了这一点。 Unix 时间戳不显示时区，无时区时间不标注假设，已带偏移的时间自带时区。裸并列的结果是：读者要么以为它们不一致（去做无谓的矛盾排查），要么以为它们一致（直接采信）。

真正的信息——各自的基准与换算关系——恰恰被省略了。

**影响**：**时间线的可读性丧失，埋下误读隐患。** 更实际的是，这份表格交到不熟悉取证细节的读者手里，会成为质证时的攻击点。

**核查**：表头逐列标注时区，或统一转为 UTC 后再呈现换算值。

| 来源 | 原始呈现 | 实际含义（UTC） | 换算为 UTC+8（委托方习惯） |
|---|---|---|---|
| Redis AOF `paidAt` | `2024-08-22T11:33:19+08:00` | 2024-08-22 03:33:19Z | 2024-08-22 11:33:19 |
| MySQL `pay_record.createTime` | `1724297599`（Unix） | 同上 | 同上 |
| MySQL binlog 事件时间 | `#240822 03:33:19`（UTC） | 同上 | 同上 |
| 手机 `app.db` 内 `createTime` | `1724297599000`（Unix 毫秒） | 同上 | 同上 |

```bash
# 统一换算入口，绝不隐式默认时区
python3 tzfix.py 1724297599
python3 tzfix.py '2024-08-22 11:33:19'
```

四源收敛于同一 UTC 时刻——这本身就是时间基准正确的最强验证。 报告里要显式说出来，别让读者自己发现。

<a id="section-32"></a>

#### 陷阱 13：结论只写事实，不写这条结论不能证明什么

**现象**：报告结论写"订单 `SO20240822000931` 于 2024-08-22 11:33:19（UTC+8）支付成功，金额 8800.00 元"，没有限制条款。委托方据此认为"资金已追回"。

**原因**：**业务系统的记账方向不等于实际资金流向。** `settlement` 表里的 `-8800.00` 是业务系统侧的记账结果，**实际是否到账必须以银行或支付通道流水为准**。

这条界限在分析者看来是常识。但交付给非技术读者时极易被忽略——报告只写"是什么"而不写"不能证明什么"，限制信息就在传递过程中丢了。

**影响**：**结论被过度解读，进而影响案件走向。** 这类误解一旦发生，通常很难收回。

**核查**：**每条数据类结论强制携带四要素**——来源、可复现命令、完整性状态、限制。

> **结论**：订单 `SO20240822000931` 于 2024-08-22 11:33:19（UTC+8）支付成功，金额 8800.00 元。
> **来源**：`/var/lib/redis/appendonlydir/appendonly.aof.1.incr.aof` 第 41182 行（`SET` 命令）。
> **复现**：`python3 resp.py appendonlydir/*.incr.aof | grep -n 'SO20240822000931'`
> **完整性**：Redis 6.2.7，AOF 与 RDB 均已完整提取；该键在 RDB 中不存在，说明 AOF 为最新来源。
> **限制**：本条**不证明**订单当前仍在库中；订单已于同日被 `DEL` 删除；**亦不证明资金已实际到账**。

同时保留一个独立的"局限性"小节，汇总覆盖度不足、依赖假设、来源可信度不足等条目。"未纳入分析的部分"要明确写出来，而不是让它从报告里消失。

**范围、方法、未覆盖范围、效力上限**——这四项是本篇全部阴性结论与边界性陈述的统一交付标准。

---
<a id="section-33"></a>

## 五、案例示例

<a id="section-34"></a>

### 5.1 委托事项

> 委托方提供一套业务系统的服务器镜像 `DigiForensics.dd`、内存镜像 `DigiForensics-mem.raw`，以及从手机提取的应用数据库 `app.db`（含 `-wal`/`-shm`）。要求：还原 2024-08-22 一笔 8800.00 元订单的完整时间线，并说明该笔订单的资金去向。委托方提供的书面说明中，时间均按"北京时间"给出。

<a id="section-35"></a>

### 5.2 检材状态

| 项 | 值 |
|---|---|
| 磁盘检材 | `DigiForensics.dd`，SHA-256 已固定 |
| 内存检材 | `DigiForensics-mem.raw`，SHA-256 已固定 |
| 移动端检材 | `app.db` + `app.db-wal` + `app.db-shm`（**三件套齐备**，见 [09](mobile-database-sqlite-wal.md)） |
| 主机环境 | K8s 集群节点；`.dockerenv` 存在；应用与 MySQL 均在容器内 |
| 宿主机时区 | `Asia/Shanghai (UTC+8)` |
| 容器时区 | `/etc/localtime → /usr/share/zoneinfo/Etc/UTC`，进程环境 `TZ` 未设置 |
| MySQL | 8.0，`binlog_format=ROW`，`server_id=1` |
| Redis | 6.2.7，`appendonly yes`，`appendfsync everysec` |

<a id="section-36"></a>

### 5.3 发现与验证

**第 1 步 · 时区链路取证（本案第一个关键）**

```bash
timedatectl | grep 'Time zone'                    # Time zone: Asia/Shanghai (CST, +0800)
readlink -f /etc/localtime                         # /usr/share/zoneinfo/Etc/UTC  ← ★ 容器内是 UTC
ls /.dockerenv && cat /proc/1/cgroup | head -2     # 12:pids:/docker/3f9a2b1c8d7e
strings -n 4 DigiForensics-mem.raw | grep -x 'TZ=[A-Za-z/_+-]*' | sort -u   # TZ=（空值，继承镜像的 Etc/UTC）

mysql -uroot -p -e "SELECT @@global.time_zone, @@session.time_zone, @@system_time_zone;"
# @@global.time_zone  @@session.time_zone  @@system_time_zone
# SYSTEM              SYSTEM                 UTC             ← ★ 关键
```

> **发现 1（决定全案时间基准）**：MySQL 进程报告 `@@system_time_zone = UTC`。虽然宿主机是 UTC+8，但**数据库进程运行在时区为 UTC 的容器内**，因此 MySQL 中的 `DATETIME`、binlog 事件时间戳**均按 UTC 写入与渲染**。
> **这与委托方"按北京时间给出"的说明直接冲突。** 若沿用委托方的时区假设，全案时间线将整体偏移 8 小时。

第 2 步 · 把假设升级为证据：查时区是否被改过

```bash
mysqlbinlog --base64-output=DECODE-ROWS -vv binlog.000004 > binlog004.txt
grep -inE "SET (time_zone|timestamp)|@@(session|global)\.time_zone" binlog004.txt | head
# 118:SET @@session.time_zone='+00:00'     90231:  同上
# 338104: 同上                              442210: 同上
# （全部为 SYSTEM 时区下的显式 +00:00 设定，未出现 +08:00）
```

> **发现 2**：日志中出现的时区设定**全部是 `+00:00`** 且均为**会话级**（`@@session`），**从未出现把全局时区改为 `+08:00` 的语句**。这把"该时段按 UTC 写入"从**假设**升级为**有日志支撑的结论**。

**第 3 步 · 时间换算与基准对齐**

```bash
python3 tzfix.py 1724297599
# UTC   : 2024-08-22 03:33:19
# UTC+8 : 2024-08-22 11:33:19   ← 若原系统为 UTC+8
```

| 来源 | 原始呈现 | 实际含义（UTC） | 换算为 UTC+8（委托方习惯） |
|---|---|---|---|
| Redis AOF `paidAt` 字段 | `2024-08-22T11:33:19+08:00` | 2024-08-22 03:33:19Z | 2024-08-22 11:33:19 |
| MySQL `pay_record.createTime` | `1724297599`（Unix） | 同上 | 同上 |
| MySQL binlog 事件时间 | `#240822 03:33:19`（UTC） | 同上 | 同上 |
| 手机 `app.db` 内 `createTime` | `1724297599000`（毫秒） | 同上 | 同上 |

> **发现 3**：**四个独立来源在换算后完全一致**，收敛到 `2024-08-22 03:33:19Z = 11:33:19 UTC+8`。
> 注意 binlog 原始输出是 `03:33:19` 而**不是** `11:33:19`——**这个差异就是本案时区陷阱的直接体现**：若不查 `@@system_time_zone` 而按"服务器在北京"直觉解读，会得出 8 小时偏差的时间线。

第 4 步 · 订单数据的完整链条与资金去向（委托要求 2）

```bash
# Redis AOF（最新来源）
python3 resp.py appendonlydir/*.incr.aof > aof-cmds.txt
grep -n 'SO20240822000931\|U100245' aof-cmds.txt | head -20

# MySQL binlog（删除前值）
mysqlbinlog --base64-output=DECODE-ROWS -vv --tables='shopdb.settlement' binlog.000004 \
  | grep -A10 '### DELETE FROM' | grep -E '@[0-9]+=' | head -12
# @1=88231  @2=0x313732343239393939392e303030   (= '1724297599.000')
# @3=0x534f3230323430383232303030393331       (= 'SO20240822000931')
# @4=0x2d383830302e3030                       (= '-8800.00')
# @5=0x726566756e646564                       (= 'refunded')
```

| 序 | 命令（节选） | 时间 |
|---|---|---|
| 41182 | `SET order:SO20240822000931 {...,"amount":8800.00,"status":"paid","userId":"U100245"}` | 03:33:19Z |
| 41203 | `SET session:9f3a2b7c41e5 U100245 ...` | 03:33:20Z |
| 41547 | `SET order:SO20240822000931 {...,"status":"charged_back"}` | 08-31 15:09:44Z |
| 41557 | `DEL order:SO20240822000931` | 08-31 15:09:44Z |
| 41559 | `SET audit:chargeback:SO20240822000931 {...}` | 08-31 15:09:45Z |
| — | `SET pending_refund:SO20240822000931 {...,"amount":8800.00,"state":"PENDING"}` | **仅内存**（见 [11](mobile-database-mongodb-and-redis-forensics.md)） |

> **发现 4（资金去向成立）**：`settlement` 表中该笔记录于同日被删除，删除前值为 -8800.00、状态 `refunded`，记录号 `88231`，时间戳与订单支付时间一致。结合 Redis 侧 `audit:chargeback` 与 `pending_refund`，三处独立来源共同指向：该笔 8800.00 已进入退款流程。
> **注意方向性**：`settlement` 的 `-8800.00` 是在**业务系统侧**的记账方向，实际资金是否到账需以银行流水为准，本检材中不含银行数据。

**第 5 步 · 移动端侧交叉验证**

```bash
cp app.db full.db && cp app.db-wal full.db-wal && cp app.db-shm full.db-shm
sqlite3 full.db "PRAGMA journal_mode;"       # wal
sqlite3 full.db "
SELECT datetime(createTime/1000,'unixepoch','+8 hours') AS 时间, amount, remark
FROM pay_record WHERE createTime BETWEEN 1724297400000 AND 1724297700000;"
# 2024-08-22 11:33:19  8800.00  扫码支付-尾号2277
```

> **发现 5**：手机侧 `pay_record` 中存在时间、金额、尾号完全对应的记录，**为服务端时间线提供了独立佐证**。手机本地时间戳（Unix，与时区无关）换算后与服务端一致，**这是本次时间基准正确的最强验证**。

**第 6 步 · 矛盾检测与固化**

```bash
stat -c '%n mtime=%y' app.db                 # app.db mtime=2024-08-31 23:14:02
sqlite3 full.db "SELECT max(datetime(createTime/1000,'unixepoch','+8 hours')) FROM pay_record;"
# 2024-08-31 21:07:44      ← 内容到 21:07，文件写到 23:14

python3 - <<'PY'
from datetime import date
first, last, target = date(2024, 1, 2), date(2024, 8, 31), date(2024, 8, 22)
print(f"binlog 覆盖：{first} 至 {last}（共 {(last-first).days} 天）")
print(f"委托关注时段 {target} 是否在窗口内：{first <= target <= last} → 可判断")
PY

sha256sum app.db app.db-wal app.db-shm binlog.000004 \
          appendonlydir/* aof-cmds.txt DigiForensics-mem.raw | tee final.sha256
```

| 配对 | 结果 | 处置 |
|---|---|---|
| 手机 `app.db` mtime vs 内容最大时间 | 差 2 小时 | 预期（WAL 补回后自洽），已在 [09](mobile-database-sqlite-wal.md) 说明 |
| binlog 序号 vs 实际文件 | 连续无缺口 | 日志完整 |
| `pending_refund` 键 RDB/AOF/内存 | 仅内存 | 已在 [11](mobile-database-mongodb-and-redis-forensics.md) 单独报告 |
| 结算表删除前值 binlog | 可读 | ROW 格式生效 |

<a id="section-37"></a>

### 5.4 结论

1. **★ 时间基准已确定并有证据支撑**：MySQL 进程 `@@system_time_zone = UTC`，容器 `/etc/localtime → Etc/UTC`，binlog 中从未出现 `+08:00` 的时区设定。因此本报告全部服务端时间以 UTC 记录，并同时给出 UTC+8 呈现值。
2. 委托方"按北京时间给出"的表述会引入 8 小时偏差。原始 binlog 输出为 `03:33:19`，**这才是该事件的真实 UTC 时刻**，对应北京时间 11:33:19。
3. **时间线经四源交叉验证一致**：Redis AOF 字段（带 `+08:00` 显式偏移）、MySQL binlog 事件（UTC）、MySQL 业务表（Unix 秒）、手机 SQLite（Unix 毫秒），换算后收敛于 `2024-08-22 03:33:19Z`。
4. **订单事实完整**：`SO20240822000931`，8800.00 元，用户 `U100245`，招商银行卡尾号 2277，支付成功。
5. **资金去向成立（业务系统侧）**：订单于 8/31 转为 `charged_back` 并被删除，对应审计键写入；`settlement` 表中该笔以 `-8800.00`、`refunded` 状态被删除，**删除前值从 binlog 完整读出**；Redis 内存中另有 `pending_refund` 键（`PENDING`，8800.00）。
6. **局限性**：
   - （1）**本检材不含银行侧流水**。`settlement` 中的 `-8800.00` 是**业务系统的记账方向**，**不能据此认定资金已实际到账或已实际扣除**。资金闭环需以银行或支付通道流水为准。
   - （2）时区结论基于配置与 binlog 证据，无法排除"个别客户端在会话级设置为 `+08:00` 后写入"的情况。本案已检查到的 `SET time_zone` 均为 `+00:00`，但日志保留窗口外（2024-01-02 之前）的写入时区无从验证。
   - （3）**部分时间字段来自不可信来源**。Redis 中的 `paidAt` 为应用写入的字符串，若客户端时间被伪造或时区标注错误，会与 binlog 冲突。本案因四源一致而采信，但这一致性本身不能排除"所有来源同时错误"的极端情形。
   - （4）**未做跨时区夏令时影响分析**。本时段不涉及采用夏令时的时区，若检材涉及跨夏令时区间（如欧洲服务器），偏移量会随时间变化，不能用固定偏移换算。
   - （5）**MongoDB 实例数据未纳入本报告**（该机另有一实例，按独立流程处理），**本报告不对其数据作任何陈述**。

---

<a id="section-38"></a>

## 六、扩展阅读方向

**前置与基础。** 一切跨源比对都建立在统一时间模型上。
TAI、UTC 与原子钟的关系、闰秒的处理，
以及单调时钟与墙上时钟的区别——后两者混用会直接产出错误的时间线。
单机的时钟看着准，多机就不一定了：NTP 偏移检测、跨主机的时钟漂移，
以及 GTID 与时间戳各自的适用边界，都要先测出来再谈对齐。

**同层深入。** 数据库审计是可靠的时间来源之一，
审计插件的表结构、日志的独立性以及可信度评估需要逐项确认——
写在同一台机器、同一块盘上的审计日志，证明力天然弱于异机记录。
归档与冷数据则是另一片常被忽略的区域：
日志归档、对象存储里的备份、WORM 存储，
它们决定了一次删除动作是否真的不可撤回。

**相邻议题。** 容器化部署把数据库搬进了新的结构里：
镜像层文件系统、overlay2 的合并视图、卷挂载的落点，
以及 K8s 元数据与 Secret 的存放位置，
都要求在传统路径之外再查一遍。供应链视角同样不可省略——
第三方 SDK 的埋点与数据外传是常见通道，
而 SDK 层记录的时间戳往往来自远端服务器，可信度需要单独评估。

**工具与判据。** 报告规范是这一层的收口：
多源证据链怎么表述、矛盾点如何规范记录、复核建议怎么写，
决定了结论能不能被别人接手。
以嵌入式库为例走完整个流程（含文件头校验与残留数据处理）
见 [《SQLite基础与结构》](mobile-database-sqlite.md)；
遇到加密字段要先判断是真加密还是编码，再决定能否直接读明文，
见 [《数据库与配置文件加密》](../../crypto/crypto-app/crypto-app-database-configuration-decryption.md)。

**判据与反例。** 几台机器的时间戳对不上时，
默认假设不是「某台机器时间错了」，而是「存在未量化的时钟漂移」。
报告里每条时间线结论都要标注它依赖哪几台机器的时钟假设，
否则误差会在多次转述中被放大成完全错误的因果顺序。

---

<a id="section-39"></a>

## 七、命令速查

```bash
# ===== 阶段一：固定与环境 =====
sha256sum DigiForensics.dd DigiForensics-mem.raw | tee hashes.txt
timedatectl | grep 'Time zone'; readlink -f /etc/localtime
ls /.dockerenv; cat /proc/1/cgroup | head -2
strings -n 4 DigiForensics-mem.raw | grep -x 'TZ=[A-Za-z/_+-]*' | sort -u
ps aux | grep -E '[m]ysqld|[m]ongod|[r]edis-server|[p]ostgres'

# ===== 阶段二：引擎识别 =====
find /mnt/case -maxdepth 4 \( -name '*.db' -o -name '*.ibd' -o -name 'ibdata*' \
  -o -name '*.wt' -o -name 'dump.rdb' -o -name 'PG_VERSION' \) 2>/dev/null
xxd -l 16 app.db | grep -q '5351 4c69 7465' && echo "SQLite"
xxd -l 9 dump.rdb                     # REDIS + 版本
cat base/PG_VERSION

# ===== 阶段三：整体归档 + 验收 =====
tar -cf mysql.tar ibdata1 ibtmp1 mysql binlog.*
find . -name '*.ibd' -o -name '*.frm' | tar -cf mysql-tables.tar -T -
tar -cf mongo.tar WiredTiger WiredTiger.turtle WiredTigerLog.* collection-*.wt index-*.wt
tar -cf redis.tar dump.rdb appendonlydir/
sha256sum *.tar; chmod -R a-w /mnt/case

# ===== 阶段四：时区判定与换算 =====
mysql -uroot -p -e "SELECT @@global.time_zone, @@session.time_zone, @@system_time_zone;"
mysqlbinlog --base64-output=DECODE-ROWS -vv binlog.000004 \
  | grep -iE "SET (time_zone|timestamp)|@@(session|global)\.time_zone"
python3 tzfix.py 1724297599

# ===== 阶段五：一致性与矛盾检测 =====
sqlite3 "file:app.db?immutable=1" "PRAGMA integrity_check; PRAGMA journal_mode;"
redis-check-rdb dump.rdb
stat -c '%n mtime=%y' app.db
sqlite3 full.db "SELECT max(datetime(createTime/1000,'unixepoch','localtime')) FROM pay_record;"

# ===== 报告用：缺失成因判定 =====

# 已删除？      → binlog 有 Delete_rows / oplog 有 op=d / 空闲区有残留
# 未落盘？      → WAL/AOF/内存中有，磁盘文件中无
# 已过期清理？  → 超出日志窗口 → 只能写"窗口内未见"
# 检材不完整？  → write_version=2 但缺 -wal → 回源补提
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 移动与数据库取证 — 数据库取证通用方法」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《数据库取证通用方法》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-mem.raw` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
