---
title: "MongoDB 与 Redis 取证"
slug: "mobile-database-mongodb-and-redis-forensics"
canonical: "https://www.digiforensics.cn/wiki/mobile-database-mongodb-and-redis-forensics"
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

# MongoDB 与 Redis 取证

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/mobile-database-mongodb-and-redis-forensics)

<a id="section-1"></a>

## 一、概述

这两类存储放在同一篇，不是凑数——它们共享一个取证特征：大量有价值的数据可能不在磁盘文件里。

| 存储 | 磁盘上的主要证据 | 不在磁盘上的部分 | 核心风险 |
|---|---|---|---|
| **MongoDB** | WiredTiger 数据文件、oplog（逻辑集合）、journal | 未刷盘的内存缓冲、事务快照 | 按 `data.db`（旧引擎）去找，会完全找错文件 |
| **Redis** | RDB 快照、AOF 日志 | **★ 未落盘的内存数据集**——可能占全部数据的大部分 | 只查 RDB 会漏掉"最后快照之后"的关键操作 |

需要刻进认知的两条：

> ### ⭐ Redis 的主要证据很可能根本不在磁盘上
>
> RDB 是**周期快照**，AOF 是**写命令追加**但可被重写裁剪。两次快照之间、以及尚未落盘的全部操作，只存在于 Redis 进程的内存里。 因此 Redis 取证**必须把内存镜像作为一等检材**，不能只拷 `dump.rdb`。

> ### ⭐ MongoDB 的 oplog 是逻辑集合，物理上是 WiredTiger 文件
>
> oplog 存在 `local` 库的 `oplog.rs` 集合中，但它**不是独立文件**，而是通过 catalog 映射到 `collection-*.wt` 上的普通集合。**"去找一个叫 oplog 的文件"是错误路径。**

**在取证流程中的位置**：本篇属于**分析**环节，但它的第一个动作发生在采集规划时——服务器类案件的检材清单里必须提前写明 Redis 的内存镜像，只申请磁盘文件就来不及了。**上游依赖**是[只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md)：为读 oplog 而启动一个隔离的 `mongod` 实例是本领域少见的写风险动作，必须在副本上做，原件目录挂 `chmod -R a-w`。时间线对齐按 [数据库取证通用方法](mobile-database-database-forensics-methods.md) 的时区纪律走；Redis 的会话键要与内存里的连接态互相印证时，用 [内存中的凭据与密钥](../../memory/memory-artifact/memory-artifact-memory-credentials-and-keys.md) 那条路径。

**本篇处理的证据形态**，MongoDB 侧落在 `/var/lib/mongodb/` 下：

| 证据 | 文件或字段 | 取证价值 |
|---|---|---|
| 引擎配置 | `WiredTiger` | 决定用哪套工具、能否整体归档 |
| 数据块文件 | `collection-0--<oid>.wt`、`index-*.wt` | 实际数据与索引所在 |
| **catalog** | `WiredTiger.turtle` | 集合名到文件名的映射表，解不出它就只能看到一堆无名块文件 |
| journal | `WiredTigerLog/log-0000000001.wt` | 未 checkpoint 的写入、未提交事务 |
| oplog | `local` 库的 `oplog.rs` 集合 | 逻辑变更流水，`op` 字段区分 `i`/`u`/`d`，`ts` 是时间戳 |
| 旧引擎 | `data.db` | 见于 3.x 时代，按它去找会完全找错文件 |
| 启动参数 | `/etc/mongod.conf` 的 `security`、`keyFile` 段 | 是否启用加密与认证 |

Redis 侧分配置与数据两处。配置里要看 `dir` 与 `dbfilename`（默认组合 `/var/lib/redis/dump.rdb`，**别默认路径，实例可能改过**）、`save` 策略行（它决定 RDB 快照周期，也就是两次快照之间的空窗有多大）、`appendonly yes` 时 `appendonlydir/` 里的 AOF 分片、以及 `appendfsync` 的取值——`everysec` 意味着最多丢一秒的写入，丢的是一个时间窗口而不是一个文件。`rename-command` 被改过、`masterauth` 出现、`bind` 暴露到 `0.0.0.0`，都是现成的攻击痕迹，不必等分析阶段再去挖。

MongoDB 有哪些集合、每集合的物理文件在哪、oplog 里最近发生过哪些写删改（尤其是已删除文档的旧值）、journal 里有没有未提交或已回滚的事务；Redis 当前有哪些键、键的类型与 TTL、`INFO` 层面的运行时统计、AOF 或 RDB 覆盖到的最后一个时间点，以及配置层面有没有被削弱的安全项。

**磁盘文件给不出"当前"状态**——Redis 的写入若未落盘，只有内存镜像能补；MongoDB 的 checkpoint 间隔也会让磁盘落后于实际。两者都证明不了**"某个键或某个文档从未存在过"**：Redis 的 LRU 淘汰会主动删键，AOF 重写会把旧命令裁掉，MongoDB 的集合被 drop 后旧数据块可能还留在文件里但元数据已失联。oplog 里的记录只证明**某条命令被执行过**，不证明它属于哪次业务请求；`$natural` 是存储序不是时间序。跨系统比对时间时，BSON Date 与 AOF 时间戳都要按 [数据库取证通用方法](mobile-database-database-forensics-methods.md) 的规则处理时区。

**读者前提**：需要能区分「事务日志」与「数据文件」这类概念——WiredTiger 的 journal 是预写日志，AOF 是命令追加，两者都不是备份，没开它们也不等于数据不安全，只是取证路径变了；需要知道集合与文件的映射关系不是靠文件名直读出来的，`WiredTiger.turtle` 是绕不开的一步；需要理解内存镜像取证的前提条件（见 [内存证据的可采性与报告](../../memory/memory-artifact/memory-artifact-memory-evidence-and-reporting.md)），否则很容易把「Redis 里没找到」写成「Redis 里没有」。没接触过这两种存储的读者，先看本章的目录构成判定引擎，再回来看后面的工具链。

---
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 MongoDB 的实际文件布局

现代 MongoDB（3.2 起默认 WiredTiger 引擎）的数据目录长这样：

```
/var/lib/mongodb/
├── WiredTiger           # ★ 引擎主元数据文件（catalog 映射在这里）
├── WiredTiger.turtle     # 统计与元信息日志
├── WiredTigerLog.*       # 引擎 journal（= 引擎自己的 redo）
├── journal/              # 早期版本（mmapv1 时代）的 journal 目录
├── collection-0.wt       # 集合数据
├── index-1.wt            # 索引
└── diagnostic.data       # FTDC 诊断快照（可能含慢查询、连接信息）
```

| 事实 | 取证含义 |
|---|---|
| 集合数据与索引**分文件存放** | `collection-N.wt` 与 `index-N.wt` 必须配套取，**单取 collection 得不到索引字段** |
| 文件名数字 N **不代表集合名** | 必须解析 `WiredTiger` catalog 文件才能建立"N → 集合名"映射 |
| `WiredTiger`（无扩展名）是元数据主文件 | **它是打开数据库的入口**，缺它整库不可映射 |
| 实际数据是 **BSON 文档** | 一个文档可能跨多个 extent（4 KB 块），不是行式结构 |

**关于 `data.db`**：这是 **mmapv1 引擎时代（≤3.0）**的布局。不能把「读 `data.db` 前若干字节之后即为 BSON」当作所有版本的通则——WiredTiger 的块结构、压缩（Snappy/Zstd）与加密都与之完全不同。**先判引擎，再谈解析。**

<a id="section-4"></a>

### 2.2 oplog：逻辑集合，不是文件

oplog 记录每个写操作的 BSON 形式，是**逻辑序列而非物理页**。

**① 恢复删除前值。** `op: "d"` 的条目含被删文档的**完整原始 BSON**，与 MySQL binlog 的价值完全对应。

**② 重建时间线。** 每条含 `ts`（秒 + 递增计数）、`wall`（客户端时间）、`op`、`ns`（库.集合）。

**③ 证明时间基准。** 可用于校准本机时间与其他来源的偏差。

> **关键提醒**：oplog 位于 `local` 库，其保留策略由**大小上限**而非时间决定，是一个可被 truncate 的滚动窗口。因此「oplog 里没有」绝不能等同于「没发生过」。

未加密的 WiredTiger `.wt` 也可用专用工具直接解析，**但版本匹配要求高，结论必须以工具实际输出为准**。

<a id="section-5"></a>

### 2.3 Redis 的持久化三形态

| 形态 | 文件 | 内容 | 缺失时的影响 |
|---|---|---|---|
| **RDB** | `dump.rdb` | 某一时刻的**完整数据集快照**（二进制紧凑格式，头部为 `REDIS<版本号>`） | **回到最近一次快照，之后全部操作不可见** |
| **AOF** | `appendonlydir/appendonly.aof.manifest` + `*.incr.aof` + `*.base.rdb`（6.x 为单文件 `appendonly.aof`） | **写命令追加日志** | 丢失 AOF → 无增量可补 |
| **无持久化** | 无 | 全部数据只在内存 | **重启即全部丢失，取证只能靠内存镜像** |

```bash
redis-check-rdb dump.rdb              # 校验与统计（不加载数据）
rdbtools --dump dump.rdb > rdbdump.json
```

**AOF 的两种形态**（版本不同，文件名与结构完全不同，**必须先确定版本再选工具**）：

| 版本 | 形态 | 文件 | 取证要点 |
|---|---|---|---|
| **6.x 及更早** | 单文件 AOF | `appendonly.aof` | RESP 文本命令流，**`SET` 追加写入，被删除键的旧值仍留在更早的命令行里** |
| **7.0 起默认** | 多部分 AOF | `appendonlydir/` 下的 `appendonly.aof.manifest` + `*.base.rdb` + `*.incr.aof` | manifest 列出每个文件的 seq 与角色；`*.base.rdb` 是某时刻基线，`*.incr.aof` 是其后的**增量命令** |

版本判据有三处可互证：目录中是否存在 `appendonlydir/` 与 `.manifest`、内存中的 `redis_version` 字段、镜像内 `redis.conf` 文本。

看错版本会导致整个 AOF 段解析为空，且不会报错。

文件内 `SELECT` 指示数据库切换，`MULTI/EXEC` 指示事务块。

> **★ 一条必须记住的局限**：`DEL key` 命令本身**只含 key 名，不含旧值**。Redis 的删除前值只能从 RDB 快照、更早的 AOF 或内存镜像中取得，这与 MySQL ROW 格式 binlog 直接给出 `Delete_rows` 旧值镜像有本质差别。这是 Redis 取证必须依赖内存镜像的根本原因之一。

<a id="section-6"></a>

### 2.4 内存取证：Redis 的核心战场

`DigiForensics-mem.raw` 中要拿的东西：

| 目标 | 取证价值 |
|---|---|
| **键空间与键清单** | 完整键列表，是「存在哪些数据」的直接证明 |
| **键类型标记** | `$`(string) `*`(list) `-`(set) `~`(hash)，决定如何解释后续字节 |
| **键名中的业务标识** | 订单号、用户 ID、会话 ID、token |
| **嵌入的 JSON / protobuf** | 可能直接包含业务内容 |
| **过期时间字段** | 区分「已过期未删除」与「仍有效」 |
| **AOF 缓冲区 `aof_buf`** | **尚未写入磁盘的写命令——关键增量** |

> ★ `aof_buf` 往往是有价值、也容易被忽视的目标。 它是"已经执行但还没落盘"的命令序列。若关键行为发生在最后一次 AOF 重写之后、且进程尚未刷盘，那么这些行为在磁盘上完全不存在，只有内存里有。

```bash
# 先确认 Redis 是否在内存中，避免在错误的镜像上做无效工作
strings -n 8 DigiForensics-mem.raw | grep -E '^redis_version|^run_id' | head
```

<a id="section-7"></a>

### 2.5 主动导出的边界与风险

若服务端可达，`redis-cli` 提供了几条取证友好的路径：

| 命令 | 性质 | 取证适用性 |
|---|---|---|
| `INFO` / `CONFIG GET` | 只读 | **优先使用** |
| `--rdb <file>` | 客户端拉取**当前数据集快照** | 可用；但它是快照，**不是进程内存镜像** |
| `DUMP key` | 序列化单个键 | 需 RDB 格式；可与 RDB 交叉验证 |
| `BGSAVE` | 服务端写 RDB | **会修改文件系统**，取证中应先评估 |
| **`DEBUG RELOAD`** | **清空并从 RDB 重新加载** | **⚠️ 高危：内存中未落盘的数据将被永久销毁** |

> `DEBUG RELOAD` 在取证中应当被视为禁止操作。 它的作用是"丢掉当前内存、用磁盘快照重载"——如果内存里有未落盘的关键数据，执行它等于主动销毁证据。 该命令在部分版本中已被禁用或需特殊编译选项，行为**以实际版本为准**。
> 取证纪律：只读优先；任何可能改变状态的命令，必须先书面说明影响并取得委托方确认。

库跑在容器里时，RDB 文件与 dump 出来的副本都在卷内，需要先确定它挂在哪个卷上再动手，见[第 03 篇](../../server/server-docker/server-docker-docker-volumes-and-bind-mounts.md)。

---

<a id="section-8"></a>

## 三、操作步骤

<a id="section-9"></a>

### 3.1 MongoDB：确定引擎、归档与文件映射

```bash
# 1) 固定检材
sha256sum DigiForensics.dd DigiForensics-mem.raw | tee hashes.txt

# 2) 引擎判定
ls /mnt/case/var/lib/mongodb/WiredTiger 2>/dev/null && echo "→ WiredTiger"
ls /mnt/case/var/lib/mongodb/data.db     2>/dev/null && echo "→ mmapv1（老版本）"

# 3) 整体归档（catalog + collection + index + journal 一个都不能少）
cd /mnt/case/var/lib/mongodb
tar -cf mongo-db.tar WiredTiger WiredTiger.turtle WiredTigerLog.* \
        collection-*.wt index-*.wt diagnostic.data 2>/dev/null
sha256sum mongo-db.tar

# 4) 建立 N → 集合名映射（复制后启动，禁止在原始路径上启动）
cp -a /mnt/case/var/lib/mongodb /work/mongo-copy
chmod -R a-w /mnt/case/var/lib/mongodb      # 原始目录立刻置只读
mongod --dbpath /work/mongo-copy --port 27018 --bind_ip 127.0.0.1 --fork
mongosh --port 27018 --quiet --eval \
  'db.adminCommand({listDatabases:1}).databases.forEach(d=>print(d.name))'
```

> **常见的错误**：只拷 `collection-*.wt` 而漏掉 `WiredTiger`。没有 catalog 文件就无法知道哪个文件对应哪个集合，此时拿到的文件只是一堆无法解释的块。

<a id="section-10"></a>

### 3.2 MongoDB：oplog 时间线重建

```bash
mongosh --port 27018 --quiet --eval '
const s = db.getSiblingDB("local");
s.oplog.rs.find({op:{$in:["d","u","i"]}}).sort({$natural:-1}).limit(20)
 .forEach(e => printjson({ts: e.ts.toString(), op: e.op, ns: e.ns, o: e.o}));
// 顺带核算 oplog 窗口（必须写进报告）
const a = s.oplog.rs.find().sort({$natural:1}).limit(1).toArray()[0];
const b = s.oplog.rs.find().sort({$natural:-1}).limit(1).toArray()[0];
print("oplog 覆盖跨度（秒）：" + (b.ts.t - a.ts.t));'
```

| `op` | 含义 | 旧值可读？ |
|---|---|---|
| `i` | insert | — |
| `u` | update | **★ 含变更前后的字段** |
| `d` | **delete** | **★ 含被删文档完整 BSON** |
| `c` | command（如 `drop`） | 视命令而定 |

**oplog 中的删除事件形态**：

```
{ ts: Timestamp({ t: 1724371999, i: 1 }),
  wall: ISODate('2024-08-22T11:33:19.000+08:00'),
  op: 'd',
  ns: 'shopdb.orders',
  o: { _id: ObjectId('66a4c2f1e3b2a10012ab34cd'),
       orderNo: 'SO20240822000931',
       amount: Decimal128('8800.00'),
       userId: 'U100245',
       status: 'paid' } }
```

> 这条 oplog 条目独立证明：2024-08-22 该订单存在，金额 8800.00，状态 paid，随后被删除。
> 即使集合中已无此文档，oplog 只要还在窗口内，事实就可复原。

<a id="section-11"></a>

### 3.3 MongoDB：加密实例的处理

若启用了 WiredTiger 加密，`.wt` 内容不可解析。

**处理顺序**：① 找配置中 `encryption.keyFile` 指向的密钥文件、配置中心凭据、运维交接材料；② 在**内存镜像中搜索 master key**（配置加载时会将其放入进程内存）；③ 两者皆无 → **明确记录"无法解密"，说明影响范围，不得推测内容**。

```bash
grep -Ei 'encryption|keyFile|enableEncryption' /etc/mongod.conf
xxd /etc/mongo-keyfile | head -6      # 密钥文件本身是 96 字节原始密钥
```

<a id="section-12"></a>

### 3.4 Redis：定位、归档与离线解析

```bash
# 1) 定位配置与数据目录
ps aux | grep '[r]edis-server'
grep -E '^\s*(dir|dbfilename|appendonly|appendfsync|save|rename-command)' /etc/redis/redis.conf

# 2) 归档（AOF 目录整体取走，manifest 不能缺）—— 两种版本二选一
cd /mnt/case/var/lib/redis
tar -cf redis-data.tar dump.rdb appendonlydir/ 2>/dev/null   # 7.0+ 多部分 AOF
tar -cf redis-data.tar dump.rdb appendonly.aof  2>/dev/null  # 6.x 单文件 AOF
sha256sum redis-data.tar

# 3) 离线解析（manifest 列出 base/incr 两部分）
redis-check-rdb dump.rdb
rdbtools --dump dump.rdb > rdbdump.json 2>/dev/null
cat appendonlydir/appendonly.aof.manifest
```

| 配置项 | 取证意义 |
|---|---|
| `dir` + `dbfilename` | **数据文件实际路径**——常被改到非默认目录，容易漏掉 |
| `appendfsync` | `always`（每条落盘）/ `everysec`（**最多丢 1 秒**）/ `no`（**由 OS 决定，可能丢很多**） |
| `save` | RDB 快照策略；`save 900 1` = 900 秒内 1 次修改就存 |
| `rename-command` | 是否禁用了危险命令；被禁用的 `DEBUG` 印证 2.5 的风险提示 |

**AOF 命令解码器**（RESP 协议，可直接运行）：

```bash
cat > resp.py <<'PY'
import sys
d = open(sys.argv[1], 'rb').read()
# 第三个参数为输出上限，仅用于抽样预览；不传则完整解码全文件
cap = int(sys.argv[2]) if len(sys.argv) > 2 else None
i = n = 0
while i < len(d) and (cap is None or n < cap):
    if d[i:i+1] != b'*':                # 跳过非数组头（SELECT、\
、注释等）
        i += 1; continue
    j = d.find(b'\r\
', i)
    if j < 0: break
    argc, args, i = int(d[i+1:j]), [], j + 2
    for _ in range(argc):
        if d[i:i+1] != b'$': args = []; break
        j = d.find(b'\r\
', i); ln = int(d[i+1:j]); i = j + 2
        args.append(d[i:i+ln].decode('utf-8', 'replace')); i += ln + 2
    if args:
        n += 1; print(f"[{n}] {' '.join(args)}")
print(f"# 共解码 {n} 条命令", file=sys.stderr)
PY

python3 resp.py appendonlydir/appendonly.aof.1.incr.aof > aof-cmds.txt   # 完整解码
python3 resp.py appendonlydir/appendonly.aof.1.incr.aof 20                 # 仅抽样看格式
grep -an 'DEL\|UNLINK\|FLUSHALL\|FLUSHDB\|CONFIG SET' aof-cmds.txt | head -40
```

> **统计口径**：`aof-cmds.txt` 的行数是**命令条数**（一条 AOF 命令一行，`MULTI/EXEC` 块内命令同样逐条计数）。取证报告中引用"解码出 N 条命令"时必须说明这个口径，**不要把它与"数据条数"或"键数量"混用**。

<a id="section-13"></a>

### 3.5 Redis：内存镜像分析（重点）

```bash
# 1) 确认 Redis 驻留痕迹与配置
strings -n 6 DigiForensics-mem.raw | grep -E 'redis_version|redis_mode|run_id' | sort -u

# 2) 键空间清单（★ 最重要的一步）
# 典型形态：order:SO20240822000931 / session:9f3a2b7c41e5 / cart:8d2f1a
strings -n 4 DigiForensics-mem.raw | grep -E '^[a-zA-Z][a-zA-Z0-9_]*:[A-Za-z0-9_.:-]+$' \
  | sort -u > keys.txt
wc -l keys.txt && head -20 keys.txt

# 3) 业务内容：嵌入 JSON 的值
strings -n 12 DigiForensics-mem.raw | grep -E '^\{"(orderId|userId|amount|token)' | head -20

# 4) 未落盘的 AOF 缓冲区（aof_buf）
strings -n 8 DigiForensics-mem.raw | grep -aE '^\*(3|4)$' -A3 | grep -aE 'SET|DEL|EXPIRE' | head -30

# 5) 三处差分（内存 vs RDB vs AOF，★ 论证结构的核心，见案例第 3 步脚本）
```

> **★ 关键发现判据**：`keys.txt` 中的键如果在 dump.rdb 中不存在、在 AOF 中也查不到，那么它们的**唯一证据就在内存镜像里**。这一"三处皆无、仅存于内存"的对比，是 Redis 取证中论证力较强的结构。

**报告级固化**：

```bash
sha256sum dump.rdb appendonlydir/* redis-data.tar | tee redis.sha256
redis-check-rdb dump.rdb 2>&1 | tee rdb-check.txt
sha256sum keys.txt | tee -a redis.sha256     # 内存侧提取结果也固定哈希
```

---
<a id="section-14"></a>

## 四、常见陷阱

<a id="section-15"></a>

### 4.1 MongoDB：文件布局与引擎

<a id="section-16"></a>

#### 陷阱 1：只找名为 `oplog` 的文件，判定"无操作日志"

**现象**：在数据目录里搜索 `oplog`、`oplog.rs` 之类的文件名，一个都没找到，报告写"该实例未启用 oplog，无操作日志可用"。

**原因**：oplog 从来不是文件，它是 `local` 库中的一个普通集合。

它在逻辑上叫 `oplog.rs`，物理上和其他集合一样通过 catalog 映射到 `collection-N.wt` 上，文件名里不会有任何 "oplog" 字样。

`op: "d"` 的删除条目因此完全藏在某个编号不透明的 `collection-*.wt` 里。

分析师在文件系统层面搜索的行为，等于在一个"字段名"里找"文件"。

**影响**：**丢掉了本引擎证据价值最高的一类材料**。

oplog 的 `d` 条目含被删文档的完整 BSON，与 MySQL ROW binlog 的 `Delete_rows` 处于同一价值层级；一旦认定它不存在，整条"删除前值恢复"路线就被自己封死。

而报告里"无操作日志"这个结论本身还是错的。

**核查**：先解析 `WiredTiger` catalog 建立"文件编号 → 集合名"映射，再问"oplog 在哪个文件里"。

```bash
# 优先：隔离实例上直接问（务必在副本上启动）
mongosh --port 27018 --quiet --eval 'db.getSiblingDB("local").oplog.rs.countDocuments()'

# 无实例时：解析 catalog 找 oplog.rs 对应的 collection-N.wt
# 顺序不能颠倒——没有 catalog 就没有映射，没有映射就只是块
tar -cf mongo-db.tar WiredTiger WiredTiger.turtle WiredTigerLog.* \
        collection-*.wt index-*.wt diagnostic.data
```

同时**必须核算 oplog 窗口**：取 `local.oplog.rs` 首末条目的 `ts`，写出实际覆盖的秒数。这是后面所有"未发现"结论的效力边界。

<a id="section-17"></a>

#### 陷阱 2：只拷 `collection-*.wt`，漏掉 catalog 与索引文件

**现象**：为了省空间，只把 `collection-*.wt` 打包带走，解析出一堆 BSON 块，却发现无法确定每个文件对应哪个集合，也无法确定某个索引是否存在。

**原因**：`WiredTiger`（无扩展名）这个"看起来不像数据文件"的文件才是整个库的入口——它保存 catalog，记录着"哪个 collection 编号对应哪个命名空间、哪个表是索引表"。

缺了它，`collection-*.wt` 就只是一堆无法解释的块。

同理 `index-*.wt` 是索引文件，单取 collection 只能读到文档内容，读不到索引字段，也就无法验证索引的存在性与其中的时间字段——而索引字段在争议中往往正是关键。

**影响**：**得到"有数据但无法归属"的结果**。

更麻烦的是这种残缺件往往在很久以后才被发现，届时期望早已落空，也无法回头补取（服务器可能已停机、卷已释放）。

**核查**：**整个数据目录整体打包，不做选择性拷贝**。

```bash
cd /mnt/case/var/lib/mongodb
tar -cf mongo-db.tar WiredTiger WiredTiger.turtle WiredTigerLog.* \
        collection-*.wt index-*.wt diagnostic.data
sha256sum mongo-db.tar
```

选择性拷贝的判断标准很简单：**只要你不确定某个文件是否影响解读，就一定要带上**。

`WiredTigerLog.*`（引擎 journal，即引擎自己的 redo）同理——它决定最后一个事务的状态，漏掉它就无法说明"崩溃前最后写了什么"。

<a id="section-18"></a>

#### 陷阱 3：把 `data.db` 解析方式套用到 WiredTiger 上

**现象**：从另一个案例里抄来"读取 `data.db` 文件头若干字节后即为连续 BSON"的脚本，套到本案数据上，解出一堆错位字节，判定"文件已损坏"。

**原因**：`data.db` 是 mmapv1 引擎时代（3.0 及更早）的布局，其页面结构接近 BSON 连续排布。

WiredTiger 采用完全不同的分块结构，且页面内容可能经 **Snappy 或 Zstd 压缩**、可能**页级加密**。

同一个文件在两种引擎下，字节层含义没有任何交集。

"文件大小看起来正常、开头几字节像是类型字节"，于是沿用了旧经验——误判就是这么来的。

**影响**：**把结构差异误报为数据损坏**。

这个结论一旦写进报告，会引导委托方认为"数据库文件已不可用"，进而放弃本可恢复的数据；而实际上文件完全健康，只是需要正确的解析器。

**核查**：**先判引擎，再选解析路径**。

```bash
ls /mnt/case/var/lib/mongodb/WiredTiger 2>/dev/null && echo "→ WiredTiger（3.2+ 默认）"
ls /mnt/case/var/lib/mongodb/data.db     2>/dev/null && echo "→ mmapv1（≤3.0）"
```

判定结果与版本号一并写进报告。若为 WiredTiger，解析工具的**版本匹配要求很高，结论必须以工具实际输出为准**，不能因为某个工具输出为空就断言"数据不存在"。

<a id="section-19"></a>

### 4.2 Redis：持久化形态与删除前值

<a id="section-20"></a>

#### 陷阱 4：只取 `dump.rdb` 就当作全部数据

**现象**：在 `/data/redis` 下找到 `dump.rdb`，`rdbtools --dump` 导出键空间，发现目标订单键不存在，报告写"该订单在缓存中不存在，删除前状态不可得"。

**原因**：**RDB 是周期快照，不是日志**。它的内容是"某一次 `BGSAVE` 时刻的数据集"，该时刻之后的所有写入都不在其中。

本案配置为 `save 900 1 300 10` + `appendfsync everysec`，RDB 反映的状态可能滞后最后一刻几十分钟。

而且如果发生过 AOF 重写，内存里存在而 RDB 未包含的键完全正常。

更关键的是，若 `appendonly yes`，**AOF 里很可能完整保留了 `SET` 命令**——那份记录直接含有订单金额、状态、用户、支付时间。

**影响**：把"快照里没有"当成"历史上没有"，并主动放弃可得的证据。

这不是判断偏弱的问题，而是把可获取的删除前值直接判为不可得。

**核查**：**三处逐一核对，任何一处不得替代另一处**。

| 来源 | 覆盖范围 | 关键作用 |
|---|---|---|
| RDB | 最近一次快照时刻 | 基线状态 |
| AOF | 基线之后的写命令序列 | **删除前值的主要来源** |
| 内存镜像 | 进程当前全部键空间 | **快照之后的增量** |

```bash
redis-check-rdb dump.rdb
rdbtools --dump dump.rdb > rdbdump.json
cat appendonlydir/appendonly.aof.manifest
```

差分结果本身就是最有价值的论证结构：在 RDB 中不存在、在 AOF 中也查不到的键，其唯一证据位置就是内存镜像。

<a id="section-21"></a>

#### 陷阱 5：AOF 版本判错，整个 AOF 段解析为空

**现象**：在 Redis 7.x 的实例上按 6.x 的方式去找 `appendonly.aof` 单文件，发现文件不存在；或者反过来，把 7.x 的 `appendonlydir/` 目录当单文件解析，得到空输出，报告写"AOF 不可用，无增量日志"。

**原因**：**7.0 起 AOF 默认改为多部分结构**，目录下有 `appendonly.aof.manifest`（列出每个文件的 seq 与角色）、`*.base.rdb`（某时刻基线）、`*.incr.aof`（其后增量命令）。6.x 及更早则是单个 `appendonly.aof` 的 RESP 文本命令流。

两种结构互不兼容，而最恶劣的一点是：按错误结构解析不会报错，只会静默返回空。

于是"工具没输出"就被直接写成了"日志是空的"。

**影响**：把解析失败当成事实缺失，报告里出现"无增量日志"这个编造出来的结论。而且这个错误在流程上难以自查，因为命令确实成功执行了。

**核查**：**用三个独立来源互证版本，再选工具**。

```bash
# 1) 目录结构
ls -d appendonlydir 2>/dev/null && ls appendonlydir/     # 7.0+
ls -l appendonly.aof 2>/dev/null                          # 6.x 及更早

# 2) manifest 内容（存在即 7.x 风格）
cat appendonlydir/appendonly.aof.manifest

# 3) 内存中的版本字段（最强判据）
strings -n 6 DigiForensics-mem.raw | grep -E '^redis_version' | sort -u
```

三者一致后再选择解析路径。**并且"解析结果为空"必须先自证工具与版本匹配**，不能直接当作数据不存在的依据——空输出本身是需要解释的异常，而不是结论。

<a id="section-22"></a>

#### 陷阱 6：把 AOF 中的 `DEL` 当作删除前值的来源

**现象**：在 AOF 中找到 `DEL order:SO20240822000931`，报告写"binlog 等价物确认订单被删除，删除前金额 8800.00"，把金额直接挂在 `DEL` 命令上。

**原因**：**`DEL` 命令只携带键名，不携带任何旧值**。

这是 Redis 与 MySQL 在删除前值能力上的本质差别：ROW 格式 binlog 的 `Delete_rows` 事件里带完整行镜像，而 `DEL` 就是 `DEL <key>` 这么几个字节。

删除前值只能来自**更早的 `SET` 命令**（AOF 中）或**更早的 RDB 快照**（内存中）。

"AOF 是命令流，看到 `DEL` 就认为上下文里应该也有值"——这个推理在这里不成立。

**影响**：**把不存在的证据关联到具体的日志条目上**。

一旦在质证中被指出"`DEL` 行里根本没有金额"，整条删除前值的证据链都要重新论证。

**核查**：删除前值必须锚定到具体的 `SET` 命令，并说明锚定方式。

```bash
# 找出该键的全部历史命令，按顺序看状态演变
grep -an 'order:SO20240822000931' aof-cmds.txt
# 41182 [n] SET order:... {"orderId":...,"amount":8800.00,"status":"paid",...}   ← 旧值来源
# 41547 [n] SET order:... {...,"status":"charged_back",...}                       ← 覆盖前状态
# 41557 [n] DEL order:...                                                        ← 只含键名
```

报告中的"删除前内容"必须注明**来自第几条命令**，而不是来自 `DEL` 本身。数值型字段若只在业务 JSON 里出现过一次，还要在报告里说明该 JSON 是由谁写入、何时写入，避免与服务器自身字段混为一谈。

<a id="section-23"></a>

#### 陷阱 7：把 `redis-cli --rdb` 拉下来的快照当作"内存镜像"

**现象**：为了"拿到内存里的数据"，在运行中的实例上执行 `redis-cli --rdb DigiForensics-rdb.rdb`，把得到的数据集当作"进程内存的内容"写进报告。

**原因**：`--rdb` 触发的是**一致性快照导出**，导出的是 Redis 持有的数据集，**不等于进程内存镜像**。

差异至少有三重：内存里存在但已被 `UNLINK`（惰性删除，尚在异步释放队列）的键、不在 keyspace 表中但仍在 `aof_buf` 里的**待落盘命令**、以及各类分配器中的空闲块与残留字节。

把这三者都排除之后，`--rdb` 得到的只是"此刻数据集"，**恰恰丢掉了 AOF 缓冲区这个最关键的增量来源**。

**影响**：**得出"三处皆无"的错误判断**。

真实情况可能是"三处皆无、仅存于 `aof_buf`"，而这个差别正是本篇最有价值的那个发现。

**核查**：**严格区分三类证据并分别标注**。

| 证据 | 来源 | 能证明什么 |
|---|---|---|
| 数据集快照 | `redis-cli --rdb` / `BGSAVE` | 该时刻的 keyspace |
| **进程内存** | **内存镜像** | **含 `aof_buf`、惰性未释放键、残留字节** |
| 磁盘持久件 | `dump.rdb` / AOF | 已落盘内容 |

只有第三类能作为"某时刻已持久化的状态"，只有第二类能触及未落盘增量。报告中凡引用 `--rdb` 结果，必须标注"（客户端一致性快照，非内存镜像）"。

<a id="section-24"></a>

### 4.3 内存取证的解释力边界

<a id="section-25"></a>

#### 陷阱 8：把 `strings` 提取结果当作完整键空间

**现象**：在内存镜像中提取到 23,417 个疑似键名，报告写"内存中共 23,417 个键"，并以此支撑"仅存于内存的键有 1,483 个"的统计。

**原因**：`strings` 只能提取可打印且连续的部分字节，这个集合天然偏小。

具体会漏掉：值被分片存放在非连续内存区的键、被 ziplist/listpack 等紧凑编码分摊存储的哈希与大键、含非打印字符因而跨越提取长度限制的键、以及已被覆盖但尚未复用的旧值残留。

更关键的是，**提取出的候选里还混有大量与键空间无关的字符串**——业务日志、配置文本、其他进程的数据。

"漏"与"误"同时存在，方向相反。

**影响**：**把下限当成全集**。

若某键恰好因编码方式而未被提取，"内存中也不存在"的结论就会把整个关键发现推翻。反过来，误提取的候选若被计入统计，会虚增"仅存于内存"的键数，稀释结论的说服力。

**核查**：**统计口径必须写明是下限，并做交叉验证**。

```bash
# 提取（输出为候选集，不是全集）
strings -n 4 DigiForensics-mem.raw \
  | grep -E '^[a-zA-Z][a-zA-Z0-9_]*:[A-Za-z0-9_.:-]+$' | sort -u > keys.txt

# 交叉验证：与 RDB / AOF 做差分，剔除可在磁盘侧解释的键
python3 - <<'PY'
import json
mem = set(open('keys.txt').read().split())
rdb = {json.loads(l)['keyname'] for l in open('rdbdump.json') if 'keyname' in l}
aof = set()
for l in open('aof-cmds.txt'):
    p = l.split(' ', 1)[-1].split()
    if p: aof.add(p[0])
print("仅存于内存的候选键：", len(mem - rdb - aof))
PY
```

报告中**必须**写明："键空间清单为下限，内存键空间完整性未经验证"。

而对某个具体键的存在性判断，要靠该键值在内存中的上下文（相邻字节、`aof_buf` 中的命令）来支撑，不能只靠键名正则命中。

<a id="section-26"></a>

#### 陷阱 9：★ 在运行中的实例上执行 `BGSAVE` 或 `DEBUG RELOAD`

**现象**：为了"让数据落盘便于分析"，在运行中的实例上执行 `BGSAVE`；或为"刷新一下状态"执行 `DEBUG RELOAD`，然后基于结果继续分析。

**原因**：`BGSAVE` 会在数据目录写入新的 `dump.rdb`、触发 RDB 重写，**改变文件系统状态**——原始 RDB 被新快照替换，文件 mtime 变化，日志窗口被切断。

`DEBUG RELOAD` 性质更严重：它的定义就是**丢弃当前内存、从磁盘 RDB 重新加载**，因此**内存中一切未落盘的数据会被永久销毁**，其中包括 `aof_buf` 里那些"已执行但未持久化"的命令。

"我只是让它更一致一点"——这两条命令的作用方向恰恰相反于取证需要。

**影响**：**不可逆地销毁了本案最有价值的一类证据**。

若 `pending_refund:SO20240822000931` 这类键此时还只存在于内存中，一次 `DEBUG RELOAD` 就让整份报告的核心发现彻底消失，且**没有任何补救途径**。

同时 `BGSAVE` 覆盖 RDB 会破坏"最后一次快照时刻"这个时间基准，使 `appendfsync` 落盘窗口的分析失去参照。

**核查**：取证环境只允许只读命令，写操作须书面确认并在报告中声明。

| 命令 | 性质 | 取证处置 |
|---|---|---|
| `INFO` / `CONFIG GET` / `SCAN` / `TYPE` / `TTL` | 只读 | 可直接使用 |
| `DUMP key` | 只读 | 可用，RDB 格式，可与 RDB 交叉验证 |
| `--rdb <file>` | 写客户端文件，触发一致性快照 | 先说明影响，取得委托方确认 |
| `BGSAVE` | **写服务端 RDB，覆盖原快照** | 默认禁止；必须先书面确认 |
| **`DEBUG RELOAD`** | **丢弃未落盘内存数据** | **禁止** |

```bash
# 只读基线采集
redis-cli INFO server keyspace
redis-cli CONFIG GET dir dbfilename appendonly appendfsync save
redis-cli --scan --count 200 | head -200
```

禁用危险命令的配置（`rename-command DEBUG ""`、`rename-command FLUSHALL ""`）本身就是一条值得记录的部署特征，应在报告的检材状态一节中列出。

<a id="section-27"></a>

### 4.4 加密、范围与结论表述

<a id="section-28"></a>

#### 陷阱 10：加密实例按明文解析 `.wt`，判定文件损坏

**现象**：对启用了 WiredTiger 加密的实例，直接用通用解析工具处理 `collection-*.wt`，输出全是不可读字节，报告写"集合文件已加密或损坏，数据不可读"。

**原因**：**加密后的输出与损坏后的输出在字节层面无法区分**——两者都是"读不出有意义的结构"。

而 WiredTiger 加密是**页级**的（不是整文件），因此同一文件里可能既有能看出结构的元数据页，也有完全不可读的加密页，这更容易被误判为"部分损坏"。

真正的排查方向是配置与密钥，而不是文件本身。

**影响**：**在"文件损坏"这个错误方向上继续投入**，把可解密的数据当作不可用证据，同时错过了密钥线索的排查。

**核查**：**按固定顺序排查，穷尽后才下"不可读"结论**。

```bash
# ① 配置
grep -Ei 'encryption|keyFile|enableEncryption' /etc/mongod.conf
ls -l /etc/mongo-keyfile 2>/dev/null

# ② 密钥文件本身是 96 字节原始密钥
xxd /etc/mongo-keyfile | head -6

# ③ 内存镜像中搜索 master key（配置加载时会进入进程内存）
strings -n 32 DigiForensics-mem.raw | grep -A2 -B2 'encryption.key' | head
```

三者皆无时，报告应写**"在现有检材与授权下无法解密"**，同时列出已排查的三条路径与各自结果。

**严禁推测内容。** "无法解密"与"数据不存在"是完全不同的结论，把前者写成后者会造成不可挽回的报告缺陷。

<a id="section-29"></a>

#### 陷阱 11：把 `appendfsync no` 直接断言为"数据已丢失"

**现象**：读到配置里 `appendfsync no`，报告直接写"由于未开启同步落盘，Redis 崩溃时数据会全部丢失，AOF 中记录的操作不可作为完整证据"。

**原因**：`appendfsync` 控制的是"何时交给操作系统"，不是"是否落盘"。

`no` 意味着写入时机由 OS 决定，OS 自身的页缓存通常仍会在几十秒内刷盘，因此**绝大部分数据其实落了盘**。`everysec` 相对 `no` 提升的可靠性同样有限，只有 `always` 才接近"每条命令同步落盘"。

把这个配置项当作"数据不可信"的判据，是把**风险窗口**当成了**既成事实**。

**影响**：**要么过度贬低 AOF 的证据价值**（把可用的日志整体排除），**要么在真正需要时才发现应该看内存**。

更实际的风险是反向错误：把 `everysec` 理解成"绝不丢数据"，于是在只取到 AOF 的情况下就宣布"最后一次落盘之后的操作不存在"。

**核查**：把配置转成风险窗口表述，并以 AOF 实际内容为准。

| `appendfsync` | 语义 | 报告应写 |
|---|---|---|
| `always` | 每条命令同步落盘 | 落盘延迟最低 |
| `everysec` | 约每秒刷盘 | **存在约 1 秒的丢失窗口** |
| `no` | 交由 OS 决定 | **存在由 OS 调度决定的丢失窗口，长度不可预估** |

结论句式应为："配置为 `no`，**存在**未落盘数据的可能；**AOF 实际内容显示**，最后一次写入为 `<时间>`，此后至镜像获取时点的行为无法从磁盘侧确认。"——用"存在可能"而不是"已经丢失"，并把判断落到 AOF 实际内容上。

<a id="section-30"></a>

#### 陷阱 12：在 oplog 窗口之外做阴性结论

**现象**：报告写"oplog 中未发现该订单被删除的操作"，随后在结论一节写"该订单从未被删除"。

**原因**：oplog 是可被 truncate 的滚动窗口，保留策略由大小上限而非时间决定。

窗口之外的操作不是"没发生"，而是"记录已被覆盖"。

更隐蔽的情形是：oplog 窗口按大小滚动，在低流量时段它可能覆盖很长时间，在高峰时段可能只覆盖几小时。

所以"窗口跨度"必须实测核算，不能凭配置估算。

**影响**：**把检索能力的边界陈述成事实层面的否定**。

这类结论在质证中极易被推翻，且若被用于论证"该订单一直存在"或"该用户从未删除过数据"，影响会远超单条记录。

**核查**：阴性发现必须写成范围、方法、未覆盖范围、效力上限四要素齐备的检索陈述。

```bash
# 实测窗口跨度（不估算）
const a = db.getSiblingDB("local").oplog.rs.find().sort({$natural:1}).limit(1).toArray()[0];
const b = db.getSiblingDB("local").oplog.rs.find().sort({$natural:-1}).limit(1).toArray()[0];
print("oplog 覆盖跨度（秒）：" + (b.ts.t - a.ts.t));
```

报告句式规范：

"在 `<起>` 至 `<止>` 的 oplog 窗口内（跨度 N 小时，基于首末条目 `ts` 实测），以 `op ∈ {d, u, i}` 检索 `<库.集合>`，**未发现**订单 `<编号>` 的删除条目。**未覆盖**：窗口之前的操作、已 truncate 的历史、其他命名空间、undo/WiredTiger 未刷盘缓冲。**效力上限**：本结论仅表明该操作记录已不可得，**不足以推断该操作未曾发生**。"

<a id="section-31"></a>

### 4.5 结论表述

<a id="section-32"></a>

#### 陷阱 13：把"内存中仅存于候选提取"表述为"内存中存在"

**现象**：报告写"`pending_refund:SO20240822000931` 存在于 Redis 进程内存中，是本案的直接证据"，而该键的确认依据仅为 `strings` 正则命中一次，报告中未提及其他印证。

**原因**："键名在内存镜像中出现"与"该键当前存在于键空间"是两个不同强度的命题。

前者只说明"这些字节在某处存在过"——它可能是当前键、可能是已过期未释放的旧值、可能是 `aof_buf` 里的待写命令、也可能是 jemalloc 复用后的残留。

区分它们需要看值内容、类型标记、过期时间字段，以及与 RDB / AOF 的差分结果。

**影响**：**把弱证据包装成直接证据**。

这是本篇最需要警惕的一类误判，因为内存取证的结论往往最抢眼，也最容易被质证方逐条追问："你怎么证明它在键空间里，而不是一块残留内存？"

**核查**：为"内存中存在"这一断言建立三级证据链，并在报告中逐级标注。

| 级别 | 判据 | 可支撑的表述 |
|---|---|---|
| L1 | 键名正则命中 | "内存镜像中出现该键名字节" |
| L2 | 键名 + 类型标记 + 值内容在内存中相邻出现 | "内存中存在该键的完整键值对" |
| L3 | L2 + 与 RDB/AOF 差分确认 + `aof_buf` 中存在对应待写命令 | "**该键当前存在于键空间，且其写入尚未持久化**" |

报告中的断言强度必须与已取得的级别一致，并明确写出判据。

**同时必须声明内存提取的不完整性**："键空间清单为下限，完整性未经验证"——这一句不能省，它是所有内存侧结论的共同前提。

**范围、方法、未覆盖范围、效力上限**——四要素是"未发现"与"仅存于某单一来源"两类结论的最低交付标准。

---
<a id="section-33"></a>

## 五、案例示例

<a id="section-34"></a>

### 5.1 DEL 删除的订单与仅存于内存的待退款键

**场景**

委托方提供涉事缓存服务器磁盘镜像 `DigiForensics.dd` 与其内存镜像 `DigiForensics-mem.raw`。委托问题：某电商系统 2024-08-22 一笔 8800.00 订单在"支付成功后被删除"，要求查明删除原因，并说明该订单对应的用户会话数据是否仍可恢复。

委托方的隐含假设是"订单被支付后就没了"，即认为这笔钱没有后续动作。这个假设会把调查方向引向"用户是否欺诈"，而实际答案在另一个方向：有一笔待退款记录，只存在于内存里。

**处置过程**

第一步，固定检材并确认配置基线 —— `appendonly` 与 `save` 的组合决定了"磁盘上的数据代表哪个时刻"：

```bash
$ sha256sum DigiForensics.dd DigiForensics-mem.raw
$ cd /mnt/case/data/redis && ls -l
-rw-r--r-- 1 redis redis  4128768 2024-08-31 23:30:11  dump.rdb
-rw-r--r-- 1 redis redis  4194304 2024-08-31 22:10:03  appendonly.aof.1.base.rdb
-rw-r--r-- 1 redis redis   918273 2024-08-31 23:29:58  appendonly.aof.1.incr.aof
$ grep -E '^(dir|dbfilename|appendonly|appendfsync|save)' /etc/redis/redis.conf
appendonly yes
appendfsync everysec
save 900 1 300 10
```

第二步，解析 RDB 并建立"键存在性"基线：

```bash
$ redis-check-rdb dump.rdb
[info] 21841 keys, 4128768 bytes
$ rdbtools --dump dump.rdb > rdbdump.json
$ grep -c 'order:SO20240822000931' rdbdump.json
0
$ grep -c 'session:9f3a2b7c41e5'     rdbdump.json
0
```

**目标订单键与会话键在 RDB 中都不存在。**

这两条 `0` 只说明"最近一次快照里没有"，**不是"订单不存在"**。RDB 最后修改于 23:30:11，而订单事件发生在 2024-08-22，快照晚于事件却查不到，说明订单在快照前已被删。这两件事必须分开表述。

第三步，解析 AOF。Redis 7.x 的多部分 AOF 先读 `MANIFEST`，再按 base/incr 分别处理：

```bash
$ cat appendonlydir/appendonly.aof.manifest
file appendonly.aof.1.base.rdb seq 1 type b
file appendonly.aof.1.incr.aof seq 1 type i
$ python3 resp.py appendonlydir/appendonly.aof.1.incr.aof > aof-cmds.txt
$ wc -l aof-cmds.txt
41571 aof-cmds.txt
$ awk '{print $2}' aof-cmds.txt | sort -u | wc -l
21902
```

41,571 条命令、涉及 21,902 个不同键名。这是"目标键在 AOF 中不存在"这一判断的**可信度基础** —— 只有解码覆盖足够全，"查无此键"才是有意义的阴性。

第四步，按目标订单号定位完整命令序列：

```bash
$ grep -n 'order:SO20240822000931' aof-cmds.txt
41182:SET order:SO20240822000931 {"orderId":"SO20240822000931","amount":8800.00,"status":"paid","userId":"U100245","paidAt":"2024-08-22T11:33:19+08:00"}
41203:SET session:9f3a2b7c41e5 U100245 127.0.0.1 1724298391 ...
41547:SET order:SO20240822000931 {"orderId":"SO20240822000931","amount":8800.00,"status":"charged_back",...}
41557:DEL order:SO20240822000931
41559:SET audit:chargeback:SO20240822000931 {"orderNo":"SO20240822000931","by":"system","ts":"2024-08-22T12:07:44+08:00"}
```

| 序 | 命令 | 能证明什么 |
|---|---|---|
| 41182 | `SET order:... {"amount":8800.00,"status":"paid","userId":"U100245"}` | 删除前的完整内容 |
| 41203 | `SET session:9f3a2b7c41e5 U100245 127.0.0.1 ...` | 会话与订单同属 U100245 |
| 41547 | `SET order:... "status":"charged_back"` | 状态先改为拒付 |
| **41557** | `DEL order:SO20240822000931` | **删除事实，且只含键名** |
| 41559 | `SET audit:chargeback:...` | 拒付审计记录 |

删除前的内容必须来自 41182 那条 `SET`，不能来自 41557 的 `DEL`。 `DEL` 只记录键名，不含值 —— 这是本案最关键的一个技术判据。

第五步，三处差分找出未落盘的键：

```bash
$ strings -n 4 DigiForensics-mem.raw \
    | grep -E '^[a-zA-Z][a-zA-Z0-9_]*:[A-Za-z0-9_.:-]+$' | sort -u > keys.txt
$ python3 diff_keys.py keys.txt rdbdump.json aof-cmds.txt
内存 23417 / AOF 涉及键 21902 / RDB 21841
★ 三处皆无、仅存于内存的键：1483
    order:SO20240831220144
    session:7b41e5c9d2a8
    lock:invoice:2024-08
    pending_refund:SO20240822000931      ★★★
```

`pending_refund:SO20240822000931` 在 RDB 与 AOF 中都不存在，只存在于内存。

它指向订单 `SO20240822000931` —— 正是被删除的那一笔。**若本次未做内存取证，这个事实完全不可见。**

第六步，取该键的值，并用内存中的 AOF 命令缓冲交叉印证：

```bash
$ strings -n 8 DigiForensics-mem.raw \
    | grep -a -A3 -B3 'pending_refund:SO20240822000931'
```

```text
pending_refund:SO20240822000931
{"orderNo":"SO20240822000931","amount":8800.00,"reason":"customer_complaint",
 "operator":"ops-118","state":"PENDING","created":"2024-08-31T23:12:07+08:00",
 "note":"refund after chargeback"}
```

```bash
# 内存中的 AOF 命令缓冲：证明该 SET 已进入内存但尚未落盘
$ strings -n 8 DigiForensics-mem.raw \
    | grep -aE '^\*[3-5]$' -A3 | grep -aE 'pending_refund|ops-118' | head -20
*4
$6
SELECT
$1
0
*3
$3
SET
$31
pending_refund:SO20240822000931
```

"值在内存中"与"AOF 缓冲里有对应命令"是两个独立证据：前者说明键存在，后者说明这个写入还没落盘。两者同现，才能定性为"未持久化"，而非"解析失败导致漏读"。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 订单键于 2024-08-22 被 `DEL` 删除且此后无写回 | AOF 序 41557，之后无 `SET` | 强 |
| 删除前内容完整可重建 | AOF 序 41182 的 `SET` | 强 |
| 删除紧接在状态改为 `charged_back` 之后 | 序 41547 → 41557，相隔 10 条 | 强 |
| 拒付后清理订单并留审计，与处理流程一致 | 序 41559 `audit:chargeback:` | 中（流程吻合，非流程文档比对） |
| 存在一笔仅存于内存的待退款记录 | 三处差分 + 内存 AOF 缓冲 | 强 |
| 该退款记录要素完整 | 内存 JSON：`ops-118`、`PENDING`、2024-08-31 23:12:07 | 强（限于内存镜像时刻） |

**能证明的**：删除动作、删除前完整内容、删除前后的状态顺序，以及一笔未持久化的待退款记录及其操作账号。

**不能证明的**：
- **不能证明 `ops-118` 是自然人操作者。** 该值是业务系统写入 JSON 里的字段，需与人员台账核对
- **不能证明该退款最终是否执行。** 键状态为 `PENDING`，已获取检材中无后续记录
- **不能证明删除操作的执行者。** AOF 记录的是 Redis 命令，不含客户端身份
- 不能证明 RDB 中查无此键就代表订单从未存在过。 只能代表快照时刻不存在

**未覆盖范围**：客户端连接来源（`CLIENT LIST` 属瞬时状态，内存镜像中不完整）、其他 Redis 实例、本机 MongoDB 实例、以及 AOF 缓冲区在镜像获取后的变化。

**误判对照**

其一，从 `DEL` 命令里"读出"删除前的订单内容。

`DEL order:SO20240822000931` 只有键名，没有任何字段。这是 AOF 与 RDB 的根本差别之一，也是最容易被想当然的一步。

判据是**"删除类命令的值来源"必须逐条指定**：

| 命令 | 是否含旧值 | 内容来源 |
|---|---|---|
| `DEL k` | **否** | 只能给出"该键被删" |
| `SET k v` | **是**（v 即全量） | 直接取 v |
| `EXPIRE k 60` | 否 | 只能给出续期事实 |
| `HGETALL` 类 | 否（只读命令不入 AOF） | 不可得 |

**核查**：先按键名全文检索 AOF，取该键**最后一次 `SET`** 的值作为删除前状态。判据是**"最后一次 SET"而非"第一条 SET"** —— 本案 41182 的 `status:paid` 与 41547 的 `status:charged_back` 是同一键的两次写入，取错一条会导致状态结论完全相反。

按错误判据走的代价：报告写"该订单金额为 8800.00"，但把 `charged_back` 状态误当作支付后状态，委托方据此认定"用户拒付后平台删除订单"，而实际时序是平台先改状态再删。

其二，把"键在 RDB 中不存在"写成"订单不存在"。

`grep -c 'order:...' rdbdump.json` 返回 0，这是一个极易被直接引用为结论的数字。但 RDB 是**某一时点的快照**，不是全量历史。

判据是**RDB、AOF、内存各自的时间代表性与语义**：

| 来源 | 时间代表性 | "查无此键"能推出什么 |
|---|---|---|
| `dump.rdb` | 单个快照时刻（23:30:11 前后） | 快照时刻不存在 |
| AOF incr | 上次重写后至最近的命令流 | 该区间内无相关命令 |
| AOF base.rdb | 重写时刻的快照 | 同 RDB |
| 内存镜像 | 获取时刻 | 镜像时刻不存在 |

本案 RDB 快照时间（8-31）**晚于**订单事件（8-22），所以"RDB 中没有"确实支持"订单已被删除"。但这个推论成立的前提是**快照晚于事件**，必须先确认两个时间。若快照早于事件，"查无此键"就完全不能说明任何问题。

按错误判据走的代价：委托方据此认为"这笔订单从来不存在"，进而排除用户投诉的基础事实，后续争议解决方向完全偏离。

**其三，把内存中的键清单当作完整键空间。**

`strings -n 4` 提取出 23,417 个键，看起来是全集。但 `strings` 的工作方式决定了它必然漏读。

判据是**`strings` 的三项已知漏读来源**：

| 漏读来源 | 机制 | 后果 |
|---|---|---|
| 值中含非可打印字节 | `\x00` 等中断连续串 | 键或值被截断 |
| 键名长度超阈值 | `-n` 与对象分配对齐 | 短键被并入长串 |
| 值被压缩（`lz4`/`zstd`） | 字符串不可直接打印 | 整个键值不可见 |

另外还有一层：`keys.txt` 是按**正则形状**筛出来的（`^[a-zA-Z][a-zA-Z0-9_]*:[...]$`），不含该形状的键（无冒号、大写前缀、含空格）根本不会进入统计。

正确表述是"23,417 个可解析键，应视为下限"，而不是"Redis 内共 23,417 个键"。这个限定必须写进报告，否则委托方会拿它做容量或业务量核算。

按错误判据走的代价：用"内存中键总数"与 RDB 的 21,841 做差值去推算"24 小时内新增业务量"，而实际差值里混着大量漏读与形状不符的键，数字没有意义。

其四，把内存中存在 AOF 命令缓冲误读为"已经写入 AOF 文件"。

内存里搜到 `*4 / $6 / SELECT / $1 / 0 / *3 / $3 / SET / $31 / pending_refund:...`，非常像"AOF 里已经有这条命令了"。但 AOF 文件（`.incr.aof`，最后修改 23:29:58）中查无此键。

判据是**AOF 的写入路径**：命令先进内存的输出缓冲区 → 由 fsync 策略（本案 `everysec`）每秒刷盘。**缓冲区里有 ≠ 磁盘上有**，两者之间最多差一秒。

| 位置 | 语义 | 本案状态 |
|---|---|---|
| 内存键空间 | 键的当前值 | 有 |
| 内存 AOF 缓冲 | 待刷盘的命令 | 有 |
| `.incr.aof` 文件 | 已刷盘的命令 | **无** |

**这三条同现，才能得出"该写入尚未持久化"。** 只看到缓冲区就下"已落盘"的结论，会把一条随时可能丢失的数据当成有持久副本的证据，报告的可信度会随之崩塌。

按错误判据走的代价：报告称"该记录在 AOF 中有副本"，委托方据此认为即使镜像损坏也能恢复，实际上唯一的副本就是这块内存。

其五，把 `pending_refund` 的存在直接解读为"钱已退给用户"。

键名含 `refund`，值里有 `state: PENDING`，非常容易被读成"退款已完成待打款"或"退款流程已启动"。

判据是**状态枚举值必须按字面理解**：

| `state` 值 | 语义 |
|---|---|
| `PENDING` | **已创建、尚未执行** |
| `PROCESSING` | 执行中 |
| `SUCCESS` / `DONE` | 已完成 |
| `FAILED` / `CANCELLED` | 已终止 |

`PENDING` 意味着**只有一条待处理记录，不是一笔已发生的退款**。报告应写"存在一笔待处理的退款请求"，不能写"已发起退款"。

按错误判据走的代价：委托方向用户或支付渠道主张已退款并据此下架争议，实际该请求从未执行，反而掩盖了"钱既未退也未到账"的真实问题。

<a id="section-35"></a>

### 5.2 EXPIRE 续期与会话键的跨源恢复

**场景**

承接 5.1。委托方在得知订单被删后追问第二个问题：`session:9f3a2b7c41e5` 这个会话键，RDB 里没有、AOF 里也查不到 8-22 之后的内容，**还能不能证明该会话在事发后仍被使用？**

这个问题看似简单，实际是本案最容易出错的地方：会话键通常设了 TTL，RDB 不保存过期键，AOF 里 `EXPIRE` 只留续期动作不留值，两个来源同时"查不到"很容易被写成"会话已失效"。

**处置过程**

第一步，先把该键在三个来源中的原始状态分别列清，不做推断：

```bash
# RDB
$ grep -c 'session:9f3a2b7c41e5' rdbdump.json
0

# AOF：只看该键的全部命令
$ grep -n 'session:9f3a2b7c41e5' aof-cmds.txt
41203:SET session:9f3a2b7c41e5 U100245 127.0.0.1 1724298391
41204:EXPIRE session:9f3a2b7c41e5 7200
41877:EXPIRE session:9f3a2b7c41e5 7200
43011:SET session:9f3a2b7c41e5 U100245 127.0.0.1 1724298391
43012:EXPIRE session:9f3a2b7c41e5 7200

# 内存
$ strings -n 8 DigiForensics-mem.raw | grep -a 'session:9f3a2b7c41e5'
session:9f3a2b7c41e5
```

第二步，理解为什么 RDB 里没有这个键 —— **这是 TTL 的正常语义，不是删除**：

| 机制 | RDB 行为 | AOF 行为 |
|---|---|---|
| `SET k v` | 记录键值与过期时间戳 | 记录 `SET` |
| `EXPIRE k 7200` | 并入该键的过期字段 | 记录 `EXPIRE` |
| 键已过期 | **不写入 RDB** | 不产生任何命令 |
| 内存中已淘汰 | 无 | 无 |

`rdbtools --dump` 的输出中，过期键是被跳过的。因此"RDB 里没有 `session:` 键"只说明**快照时刻它已过期或尚未创建**，与"被删除"是两回事。

**判据是 RDB 中同前缀键的存在情况**：

```bash
$ grep -c '"keyname": "session:' rdbdump.json
1642
# 同类 session 键有 1642 个，只缺这一条 → 是过期，不是整类缺失
```

第三步，用 AOF 的 `EXPIRE` 续期记录定位"最后一次使用时间"：

```bash
$ awk '/session:9f3a2b7c41e5/ && /^EXPIRE/ {print NR": "$0}' aof-cmds.txt
41204:EXPIRE session:9f3a2b7c41e5 7200
41877:EXPIRE session:9f3a2b7c41e5 7200
43012:EXPIRE session:9f3a2b7c41e5 7200
```

续期动作共 3 条，最后一次是序 43012。`EXPIRE` 出现在 AOF 中说明**该键在那个时刻确实存在**（对不存在的键执行 `EXPIRE` 返回 0，不写入有效续期）。

第四步，把续期时间点与订单事件对齐，确定"事发后是否仍被使用"：

| 序 | 动作 | 相对订单删除（41557） |
|---|---|---|
| 41203–41204 | `SET` + `EXPIRE 7200` | 之前，会话建立 |
| 41557 | `DEL order:...` | — |
| 41877 | `EXPIRE session:... 7200` | **之后**，续期 |
| 43011–43012 | `SET` + `EXPIRE 7200` | **之后**，重新写入并续期 |

序 41877 与 43011 都在订单删除之后，**该会话在订单被删后仍被使用**。

第五步，取会话值并做跨源一致性核对：

```bash
$ strings -n 8 DigiForensics-mem.raw | grep -a -A2 'session:9f3a2b7c41e5'
session:9f3a2b7c41e5
U100245 127.0.0.1 1724298391
```

```bash
# 与订单的 userId 比对
$ grep -o '"userId":"[^"]*"' aof-cmds.txt | sort -u | grep U100245
"userId":"U100245"
$ sed -n '41203p;43011p' aof-cmds.txt | awk '{print $3}'
U100245
U100245
```

会话的 `userId` 与订单的 `userId` 均为 `U100245`，归属同一用户。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 该会话键在 RDB 快照时刻已过期 | 同前缀 1642 个键中独缺此条 | 强 |
| 会话键在事发后仍被使用 | `EXPIRE` 续期序 41877、43011 晚于序 41557 | 强 |
| 会话最后一次写入值可读 | AOF 序 43011 + 内存值一致 | 强 |
| 会话与订单属同一用户 `U100245` | AOF 两侧 `userId` 一致 | 强 |
| RDB 无此键的原因是 TTL 过期而非删除 | 同类键大量存在 + AOF 有续期无 `DEL` | 强 |

**能证明的**：会话键的存在时间跨度、事发后仍被使用、以及会话与订单的用户归属关系。

**不能证明的**：
- **不能证明会话被使用的是谁。** 会话值里的 `U100245` 是业务用户标识，与实际操作人无关
- **不能证明会话的具体操作内容。** 会话值只记录身份与来源 IP，业务动作需查应用日志
- **不能证明该会话未被复制或盗用。** 本案未查会话绑定机制与异地登录策略
- 不能证明 RDB 中缺失的其他 1641 个会话键都已过期。 未逐键核对 TTL

**未覆盖范围**：应用层访问日志、`lastseen` 缓存结构、Redis 之外的会话存储、以及 8-31 快照时刻之后的会话活动。

**误判对照**

**其一，把"RDB 里没有"当成"键已被删除"。**

这是本案最容易犯的错。RDB 对带 TTL 的键有一套特殊规则：**已过期的键不会被写入快照**。

判据是**"RDB 缺失"的两种成因与区分方法**：

| 成因 | AOF 中是否有对应命令 | 同前缀键是否齐全 |
|---|---|---|
| **TTL 过期** | 有 `SET`/`EXPIRE`，**无 `DEL`** | 齐全（1642 个） |
| 被 `DEL` | 有 `DEL` | 不受 TTL 影响 |

判据的关键在 AOF：有过期或续期记录而无 `DEL` → TTL 过期；有 `DEL` → 显式删除。 本案 AOF 中该键有 3 条 `EXPIRE`、零条 `DEL`，TTL 过期成立。

按错误判据走的代价：报告写"会话键被删除，说明攻击者清理了痕迹"，凭空引入一个攻击假设，委托方据此排查服务器管理员，而真正的会话续期记录完整躺在 AOF 里没被读。

其二，把 `EXPIRE` 的存在当作"键当前仍然存在"。

看到 AOF 里有 `EXPIRE session:... 7200` 就断定会话活跃。但 `EXPIRE` 只记录"某个时刻发生过续期"，不记录结果。

判据是**`EXPIRE` 的返回值语义**：对不存在的键执行 `EXPIRE` 返回 `0`，且**不产生有效的续期效果**。因此 AOF 中的 `EXPIRE` 记录只能证明"那一刻键在"。

**要证明"现在还在"，必须再看一个来源**：

| 来源 | 能否证明镜像时刻键存在 |
|---|---|
| AOF `EXPIRE` | 只能证明该时刻存在 |
| RDB | 只能证明快照时刻存在 |
| **内存镜像** | **能证明镜像获取时刻存在** |

本案内存中检出了该键，因此"会话在镜像时刻仍存在"成立。只有这条结论是直接观察得来的，其余都是时间点的推断。

按错误判据走的代价：把 8-22 的续期记录当成 8-31 的活跃证明，报告的时间陈述错误；若委托方据此认定"事发时用户在操作"，实际时间点差了 9 天。

其三，用 `EXPIRE` 的 TTL 值推断会话时长。

`EXPIRE k 7200` 容易被读成"会话有效期 2 小时"。但本案至少有三种可能，TTL 值无法区分：

| 可能 | 判定依据 |
|---|---|
| 会话 TTL 固定 7200 秒 | 配置侧 `session_ttl=7200` 可佐证 |
| 定期续期维持长会话 | 同一键出现多条 `EXPIRE` |
| 业务代码显式续期 | 应用代码调用 `expire` 接口 |

本案 3 条 `EXPIRE` 中夹着一条 `SET`（序 43011），说明存在"重新写入并续期"的动作，**与"空闲超时即失效"的模型不符**。

**判据是必须在配置或代码侧确认 TTL 语义**：

```bash
$ grep -rn 'session_ttl\|EXPIRE\|expire(' /etc/app/config.yml
session_ttl: 7200
$ grep -rn 'SETEX\|EXPIRE' /opt/app/session.py
session.expire(ttl)      # 每次请求都续期
```

按错误判据走的代价：委托方据此认为"会话 2 小时必然过期，用户不可能在事发后继续操作"，从而否定了"事发后仍被使用"这一有 AOF 支撑的事实。

其四，把会话值里的 `userId` 直接当成操作人。

会话值形如 `U100245 127.0.0.1 1724298391`，其中 `127.0.0.1` 看起来像"没有来源地址"，容易连带地把 `U100245` 也当成一个无意义的占位符。

判据是**会话值的字段构成必须逐段解释**：

| 字段 | 值 | 含义 |
|---|---|---|
| 第 1 段 | `U100245` | 业务用户标识，与订单 `userId` 同源 |
| 第 2 段 | `127.0.0.1` | **来源 IP，回环地址** |
| 第 3 段 | `1724298391` | 会话创建时间戳 |

`127.0.0.1` 说明**会话是由本机上的服务创建或代理的**，来源 IP 在应用层就已经被折叠了。**这意味着本键无法用于定位来源主机。**

正确表述是"该会话由本机服务签发，来源 IP 字段为回环地址，实际客户端地址需查应用日志或上游代理日志"。

不能因为 IP 是 `127.0.0.1` 就说"该会话无来源信息"，也不能因为有 `U100245` 就说"已知操作人"。

按错误判据走的代价：把 `U100245` 当成操作人姓名写进报告，而它其实只是一个数据库里的用户编号；委托方按这个编号去找人不果，怀疑整份报告的严谨性。

<a id="section-36"></a>

### 5.3 单快照检材的阴性结论限定与前缀缺口核验

**场景**

另一起委托。委托方提供一份较老的 Redis 服务器镜像 `DigiForensics-old.vc`，要求查明 2023 年 11 月一批约 6000 个键被集中 `DEL` 的时间与执行者。

检材里 `dump.rdb` 存在，`appendonlydir/` 目录不存在。委托方据此认为"AOF 已关闭，只能看 RDB"。

这一案的价值在于两处阴性结论的边界：AOF 目录不存在与 AOF 文件被清空，含义完全不同；而单份快照的时间下界必须独立确定。

**处置过程**

第一步，先判定 AOF 是"关闭"还是"被移除"，而不是接受检材表面状态：

```bash
$ ls -l /mnt/case/data/redis/
-rw-r--r-- 1 redis redis  3980032 2023-12-31 23:55:02  dump.rdb
$ ls -ld appendonlydir 2>/dev/null || echo "appendonlydir 不存在"
appendonlydir 不存在

$ grep -E '^appendonly|^dir|^dbfilename' /etc/redis/redis.conf
appendonly no
dbfilename dump.rdb
```

配置为 `appendonly no`，且目录不存在。**"从未启用"与"启用后被删目录"在磁盘上表现相同**，需用旁证区分。

第二步，查找启用过 AOF 的旁证：

```bash
$ strings -n 6 dump.rdb | grep -iE 'aof|appendfsync' | head
# 无命中

# 检查 RDB 头部的 aux 字段（Redis 6.0+ 记录 redis_version 与 ctime）
$ rdb_info.py dump.rdb | head
redis_version: 6.2.14
ctime: 1704035702
```

RDB 头部 `ctime` 是快照创建时刻，aux 字段中无 AOF 相关痕迹。结合配置 `appendonly no`，判定该实例在检材所示时期未启用 AOF。

第三步，用 RDB 内的键计数确定数据规模，与委托方的"6000 个键"对账：

```bash
$ redis-check-rdb dump.rdb
[info] 18204 keys, 3980032 bytes
$ rdbtools --dump dump.rdb > rdbdump.json
$ wc -l rdbdump.json
18204
```

**快照时刻共 18,204 个键**，远大于 6,000。这个数字本身不说明删除是否发生，但确立了"被删的那批"应当体现为快照内不存在。

第四步，确定 RDB 的时间下界 —— **这是本次能否回答委托问题的前提**：

```bash
$ stat -c '%n  size=%s  mtime=%y' dump.rdb
dump.rdb  size=3980032  mtime=2023-12-31 23:55:02
$ rdb_info.py dump.rdb | grep -iE 'ctime|aof_base_size'
ctime: 1704035702
$ python3 -c "
import datetime
print(datetime.datetime.utcfromtimestamp(1704035702+8*3600))
"
2023-12-31 23:55:02
```

RDB 快照时刻为 2023-12-31 23:55:02（UTC+8）。

第五步，按删除模式做定向检索，并对"6000 个键"逐类验证：

```bash
# 检查四类候选键在快照中是否仍在
$ grep -c '"keyname": "cart:'        rdbdump.json
2241
$ grep -c '"keyname": "session:'    rdbdump.json
11098
$ grep -c '"keyname": "cache:'      rdbdump.json
3387
$ grep -c '"keyname": "temp:'      rdbdump.json
1478
```

四类候选键全部大量存在，合计 18,204，与快照总键数一致。若存在一次针对这四类前缀的集中 `DEL`，快照里至少有一类应出现异常缺口。 本案无缺口。

第六步，查 Redis 运行日志确认是否有 AOF 相关动作：

```bash
$ ls -l /var/log/redis/
-rw-r----- 1 redis redis  202301 2023-12-31  redis-server.log
$ grep -c 'appendonly' /var/log/redis/redis-server.log
0
$ grep -E 'DB saved|Background saving' /var/log/redis/redis-server.log | tail -2
1337:M 31 Dec 2023 23:55:02.088 * Background saving started by pid 2145
1337:M 31 Dec 2023 23:55:02.114 * Background saving terminated with success
```

日志中 `appendonly` 相关记录 0 条，与 `appendonly no` 一致。日志与配置、文件状态三者互相印证，可作为"从未启用 AOF"的判定依据。

第七步，把阴性结论的范围钉死：

```bash
$ grep -cE 'DEL|UNLINK|FLUSHALL|FLUSHDB' /var/log/redis/redis-server.log
0
```

```text
未覆盖：
- 2023-12-31 23:55:02 之前的全部变更（无 AOF，无其他变更日志）
- save 900 1 300 10 决定的快照之间的状态
- Redis 之外的上游应用日志与数据库审计
- 该实例是否有从库或持久化归档
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 该实例未启用 AOF | 配置 `appendonly no` + 目录不存在 + 日志零命中 | 强（三源印证） |
| RDB 快照时刻为 2023-12-31 23:55:02（UTC+8） | 文件 mtime + RDB aux `ctime` | 强 |
| 快照时刻共 18,204 个键 | `redis-check-rdb` + `rdbdump.json` 行数一致 | 强 |
| 四类候选键在快照中均无异常缺口 | `cart:`2241 / `session:`11098 / `cache:`3387 / `temp:`1478 | 中（限于这四类前缀） |
| 日志中无删除类命令 | `grep -cE 'DEL\|UNLINK\|FLUSHALL\|FLUSHDB'` 返回 0 | 中（日志级别未验证） |

**阴性结论（严格限定）**：

> 在 `dump.rdb` 单一来源、覆盖 2023-12-31 23:55:02 快照时刻的范围内，对 `cart:`、`session:`、`cache:`、`temp:` 四类键前缀**未发现**集中删除导致的数量缺口（四类合计 18,204 条，与快照总键数一致）。
>
> 该阴性结论**不能推广到 2023 年 11 月的删除事件**：委托问题所指时间早于本检材中唯一的时间锚点，而该实例未启用 AOF，快照之间无任何变更记录可查。
>
> 未覆盖路径：`save` 策略决定的快照间隔内的全部变更、Redis 之外的应用日志与数据库审计、该实例的上游/从库副本、以及 `redis-server.log` 自身的完整性。

**能证明的**：该实例未启用 AOF、RDB 快照的精确时刻与键规模、以及四类前缀在快照时刻的分布。

**不能证明的**：
- **不能证明 2023 年 11 月未发生集中删除。** 该时间早于检材中唯一的时间锚点，本次无任何证据可覆盖
- 不能证明 `redis-server.log` 完整。 未检查是否有轮转、截断或清空
- **不能证明该实例没有从库或外部备份。** 均未检查
- **不能证明那 6,000 个键的编号范围。** 委托方未提供具体键名，本次无法逐键核对

**误判对照**

其一，把 `appendonlydir` 不存在直接说成"AOF 从未启用"。

磁盘上"从未启用"与"启用后目录被删"的表现完全相同 —— 都是路径不存在。仅凭这一点作结论，等于把一种可能当成了唯一可能。

判据是**旁证三件套**：

| 旁证 | 指向"从未启用" | 指向"启用后被移除" |
|---|---|---|
| 配置文件 | `appendonly no` | `appendonly yes` |
| 运行日志 | 启动行无 `appendonly yes` | 启动行含 `appendonly yes` |
| 日志中的启停记录 | 零条 | 有 enable/disable 记录 |
| RDB aux 字段 | 无 AOF base size | 有 `aof_base_size` |

本案配置为 `no`、日志零命中、RDB aux 无相关字段，**三件套一致指向"从未启用"**，结论才成立。若配置是 `yes` 而目录缺失，正确表述就是"目录缺失，原因未确定，需检查文件删除痕迹"。

按错误判据走的代价：把"目录不存在"当成确定结论，委托方据此排除"AOF 曾启用后被清理"这一可能，而后者若成立，含义完全不同 —— 那意味着有人刻意清理过。

**其二，用 RDB 快照证明删除发生。**

委托方说"约 6000 个键被集中 DEL"。最顺手的验证是"查快照里有没有这些键，没有就说明被删了"。这个推理在时间方向上成立时有效，方向反了就会出错。

判据是**快照时刻与事件时刻的先后关系**：

| 情形 | 快照 vs 事件 | "查无此键"能推出 |
|---|---|---|
| 快照**晚于**事件 | 8-31 快照 vs 11 月事件 | 支持"已被删除" |
| 快照**早于**事件 | 11 月快照 vs 8 月事件 | **什么都不能推出** |
| 无时间锚点 | — | **什么都不能推出** |

本次事件是 2023 年 11 月，唯一快照是 2023-12-31 23:55:02，**快照晚于事件**。

这个方向确认之后，"四类前缀无缺口"才有意义 —— 而恰恰因为无缺口，所以对照委托方的 6,000 之说**不支持"该实例上发生过这次集中删除"**。

"没有缺口"这个阴性结果，必须紧跟"快照时刻晚于事件"这个前提才有意义，否则读者无法判断它否定了什么。

按错误判据走的代价：把"快照中未发现缺口"写成"删除发生在别处"，委托方据此怀疑另一台服务器，而真实答案可能是这批键的删除发生在快照之前、且已被后续写入掩盖。

其三，把"快照里键总数 18,204"当成历史峰值。

`redis-check-rdb` 报出的键数是**快照时刻的瞬时值**，不是历史最大值。

判据是**带 TTL 的键对计数的影响**：

| 键类型 | 过期行为 | 对计数的影响 |
|---|---|---|
| 带 TTL（如 `session:`） | 到期不写入 RDB | 快照计数偏低 |
| 不带 TTL（如 `config:`） | 永久存在 | 稳定计入 |
| 已被删除 | 不存在 | 不计入 |

本案 `session:` 占 11,098 个（约占快照 18,204 个键的 61%），这类键多数设 TTL。若事发当时活跃会话数高于快照时刻，快照计数就会低于历史峰值 —— 这与"键被删了"是两种不同的解释，但单看总数无法区分。

要证明"某批键被删"，必须按前缀逐类对比，并说明该前缀是否带 TTL：

```bash
# 该前缀下带 TTL 的键有多少
$ python3 ttl_ratio.py dump.rdb session:
# 带 TTL 11402 / 11098
```

按错误判据走的代价：委托方拿 18,204 与业务侧峰值（比如 24,000）对比，得出"服务器上少了近 6,000 个键"的结论，而差额其实是会话过期。

其四，把"日志中无删除命令"当作删除不存在的证据。

`grep -cE 'DEL|UNLINK|FLUSHALL|FLUSHDB'` 返回 0，看起来是直接证据。但要先确认日志本身的覆盖范围与完整性。

判据是**日志作为证据的三个前提**：

| 前提 | 检查方法 | 本案状态 |
|---|---|---|
| 日志未轮转丢失 | `ls -l` 看是否有 `.1`、`.gz` 等 | 只有单文件，**未验证历史是否被删** |
| 日志级别包含命令内容 | 启动参数含 `loglevel debug` 或 `loglevel verbose` | **未检查** |
| 日志周期覆盖事件时间 | 首行时间 vs 事件时间 | 未核对首行时间 |

Redis 默认 `loglevel notice`，**默认不记录客户端执行的每条命令**。因此"日志里没有 DEL"很可能只是因为日志级别不够，而非命令没执行过。

正确表述是"在该日志级别与覆盖范围内未检出删除类命令记录"，而不是"未发生删除"。

按错误判据走的代价：报告用日志阴性结论否定删除事件，委托方据此放弃追查，而真正的原因只是采集方没把 `loglevel` 调到 `debug` —— 一个本可补的采集疏漏被写成了不可逆的结论。

**其五，把阴性结论写成"未发现异常"。**

错误写法：

> 经分析，该 Redis 实例未发现异常删除行为。

正确写法（限定范围 + 列出未覆盖）：

> 在 `dump.rdb` 单一来源、2023-12-31 23:55:02 快照时刻的范围内，对 `cart:`、`session:`、`cache:`、`temp:` 四类前缀未发现数量缺口（四类合计 18,204，与快照总键数一致）。事件时间 2023-11 早于该唯一时间锚点，本检材无证据可覆盖该时段。未覆盖路径：快照间隔内的变更、`redis-server.log` 完整性（未验证轮转与日志级别）、Redis 之外的应用与数据库审计、上游与从库副本。

**判据是三要素缺一不可**：检查范围、检查方法、未覆盖项。"未发现异常"这种笼统表述，在数据库与缓存取证中基本等于无效结论 —— 它既不能让读者判断可信度，也不能说明下一步该往哪查。

按错误判据走的代价：委托方把"未发现异常"理解为"这条线索到此为止"，而报告中实际已列出四条未覆盖路径，其中任意一条都可能给出答案。**阴性结论的价值在于指路，不在于结案。**

---

<a id="section-37"></a>

## 六、扩展阅读方向

**前置与基础。** 没有 schema 的库，第一步是引擎识别——
先确认它到底是 WiredTiger、Redis 还是别的存储引擎，再谈解析。
WiredTiger 内部要立住块结构、checkpoint 机制，
以及 Snappy/Zstd 压缩和加密在页级留下的影响：
压缩会改变字节布局，不先搞清压缩状态就无从下手。

**同层深入。** BSON 的二进制布局是 MongoDB 侧的基本功，
元素类型、Binary/Decimal128/时间戳各自的编码方式，
以及跨块文档的重组规则，三者缺一项就会解析出错误的结果。
MongoDB 事务与快照要弄清多文档事务在 oplog 中的表示方式，
以及读隔离级别如何决定一条记录在某个时间点是否可见。

**相邻议题。** `changeStream` 的用途和它在取证中的合规边界需要单独说清：
它是给在线业务用的接口，落到取证场景里既有价值也有风险。
Redis 的内部结构则完全是另一套逻辑，dict/skiplist/listpack 等编码、
jemalloc 造成的碎片、AOF 重写机制，
决定了 dump 文件里看到的字节和内存里活着的对象并不对应。

**工具与判据。** 大镜像的分块扫描、符号与堆识别、跨页重组
是内存态分析需要的工程能力。
无 schema 的库如何做引擎识别、时间线重建与完整性校验，
见 [《数据库取证通用方法》](mobile-database-database-forensics-methods.md)；
有事务日志的库怎么用 redo 与 binlog 证明操作，
可以在 [《MySQL数据库取证》](mobile-database-mysql.md) 里对照着理解——
一条有日志可依，另一条只能靠结构推断，证据强度差着量级。

**判据与反例。** 缓存与持久层不一致时，最容易犯的错是拿缓存内容当定案依据。
缓存里的值可能过期、可能来自另一次请求，它的证据价值恰恰在于
「与数据库矛盾」这件事本身。
同理，Redis 的 AOF 重写会截断历史，重写之前的写入可能不在增量段里，
报告里必须交代时间范围。

---

<a id="section-38"></a>

## 七、命令速查

```bash
# ===== MongoDB：引擎判定与整体归档 =====
ls /var/lib/mongodb/WiredTiger 2>/dev/null && echo "→ WiredTiger"
ls /var/lib/mongodb/data.db     2>/dev/null && echo "→ mmapv1"
cd /var/lib/mongodb
tar -cf mongo.tar WiredTiger WiredTiger.turtle WiredTigerLog.* collection-*.wt \
        index-*.wt diagnostic.data && sha256sum mongo.tar

# ===== MongoDB：隔离实例（仅在副本上）+ oplog =====
cp -a /var/lib/mongodb /work/mongo-copy && chmod -R a-w /var/lib/mongodb
mongod --dbpath /work/mongo-copy --port 27018 --bind_ip 127.0.0.1 --fork
mongosh --port 27018 --quiet --eval 'db.getSiblingDB("local").oplog.rs.find({op:"d"}).sort({$natural:-1}).limit(20).toArray()'
grep -Ei 'encryption|keyFile' /etc/mongod.conf && xxd /etc/mongo-keyfile

# ===== Redis：配置与归档 =====
ps aux | grep '[r]edis-server'
grep -E '^\s*(dir|dbfilename|appendonly|appendfsync|save|rename-command)' /etc/redis/redis.conf
cd /data/redis && tar -cf redis-data.tar dump.rdb appendonlydir/ && sha256sum redis-data.tar

# ===== Redis：离线解析 =====
redis-check-rdb dump.rdb
rdbtools --dump dump.rdb > rdbdump.json
cat appendonlydir/appendonly.aof.manifest
python3 resp.py appendonlydir/*.incr.aof > aof-cmds.txt
grep -aE 'DEL|SET order:' aof-cmds.txt

# ===== Redis：内存（★ 不可省略）=====
strings -n 6 DigiForensics-mem.raw | grep -E 'redis_version|dir|dbfilename|appendonly'
strings -n 4 DigiForensics-mem.raw | grep -E '^[a-zA-Z][a-zA-Z0-9_]*:[A-Za-z0-9_.:-]+$' \
  | sort -u > keys.txt
strings -n 8 DigiForensics-mem.raw | grep -aE '^\*[3-5]$' -A3 | grep -aE 'SET|DEL'

# ===== Redis：在线只读（写操作须委托方确认）=====
redis-cli INFO server keyspace
redis-cli CONFIG GET dir dbfilename appendonly appendfsync save
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 移动与数据库取证 — MongoDB 与 Redis 取证」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《MongoDB 与 Redis 取证》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-mem.raw` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
