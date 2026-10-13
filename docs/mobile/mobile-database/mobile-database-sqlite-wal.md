---
title: "SQLite WAL 取证"
slug: "mobile-database-sqlite-wal"
canonical: "https://www.digiforensics.cn/wiki/mobile-database-sqlite-wal"
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

# SQLite WAL 取证

<a id="section-1"></a>

## 一、概述

移动端几乎所有主流应用都把 SQLite 配成 **WAL 模式**。

这不是可选项，是事实默认值：Android 侧 `SQLiteOpenHelper` 的 `enableWriteAheadLogging()`、iOS 侧 Core Data 与大量第三方库、桌面与服务端库，几乎都开了 WAL。

由此产生一个实战中后果很重的事实：应用正在使用的数据，绝大多数不在 `.db` 主库里，而在同目录的 `-wal` 伴随文件里。

| 现象 | 真实原因 |
|---|---|
| 刚导出的库里查不到"最新"记录 | 最新提交在 `-wal` 中，尚未 checkpoint |
| 记录数比委托方描述的少一截 | 同上，缺的是 WAL 尾部 |
| 换个工具解析结果就不一样 | 有的工具读 WAL、有的只读主库 |
| 同一份检材两次 `SELECT` 结果不同 | 第一次查询触发了 checkpoint，副本被改写 |

本篇要建立的核心认知只有一条：

> ## ⚠️ `app.db`、`app.db-wal`、`app.db-shm` 三个文件必须一起提取
>
> 只提主库 = 拿到的是上一次 checkpoint 的时间切片，不是应用当前状态。
> 漏提 `-wal` 是本领域出现频率最高、后果最严重的提取失误。

`-shm` 不含业务数据（它是共享内存索引），但它记录了 WAL 的读取状态，**保留它可保证 wal-index 的一致性判断**。三者应作为**一个不可分割的整体**归档、哈希、传输、存储。

**在取证流程中的位置**：本篇是**提取之后、解析之前**的必经一步，位置很窄但漏不起。它有两个动作：提取阶段确保三件套一起走（含从应用私有目录与 `/data/data/<pkg>/databases/`、`Library/Application Support/` 等不同落点定位），分析阶段**先用只读副本建立基线，不碰原始文件**。**上游依赖**是 [SQLite 基础与结构](mobile-database-sqlite.md)（页、B-tree、`sqlite_master` 与页大小这些概念要先有），时间戳处理按 [数据库取证通用方法](mobile-database-database-forensics-methods.md) 的时区纪律走。**"分析即破坏"这条纪律在本领域没有例外**：用 `sqlite3` 直接打开原始 `-wal` 副本或原始 `.db` 都可能触发 checkpoint，把要取证的状态改掉，所以流程是"哈希 → 复制 → 只对副本操作"。

**本篇处理的证据形态**，是三件套加两个关键字段：

| 证据 | 关键位置或字段 | 判读要点 |
|---|---|---|
| `app.db` | 文件头 `SQLite format 3`、偏移 18/19 的 `write_version` / `read_version`，**值为 2 即 WAL 模式**；页大小在偏移 16（`0x1000` 表示 4096） | 主库头里的**变更计数器**要与 `-wal` 头对照，它决定哪些 WAL 页有效 |
| `app.db-wal` | **32 字节文件头** + 若干 **24 字节帧头 + 页数据**；文件头 `magic` 为 `0x377f0682`（校验和按小端）或 `0x377f0683`（大端），偏移 16/20 是 `salt1`/`salt2` | 每次 checkpoint 后 salt 会随机重生成，旧帧因 salt 不匹配失效；帧头的 salt 必须与文件头一致，不一致的帧属于上一个 WAL 周期，必须丢弃 |
| `app.db-shm` | wal-index 共享内存映像 | 无业务数据，但**它的读取状态决定 WAL 会被怎么消费**，保留它是为了判断一致性 |
| 表结构 | `sqlite_master`（3.33 之后重命名为 `sqlite_schema`，两者内容一致） | **只有它能回答"某张表是否存在"**——只提主库时它可能不含被 WAL 覆盖后的最新结构 |
| 帧内字段 | 帧头的页号、提交点、`checksum`（滚动校验和） | 校验和用于发现被静默篡改或比特翻转的帧 |

应用在关机或提取那一刻真正持有的数据（不只是上次 checkpoint 的快照）、`-wal` 里最近发生过哪些事务与页面覆盖、被 checkpoint 覆盖掉的历史页内容、只提了主库时"缺失"这一事实本身能说明什么。

**解析不出一段内容不等于那段数据没被写过**——帧的 salt 不匹配只能说明它属于已失效的 WAL 周期，说明不了写它的是谁；校验和不通过只能说明字节被改过或损坏，**不能直接定性为人为篡改**，也可能是正常的比特翻转或采集传输截断。`sqlite_master` 里没有的表**不能断言它从未被创建**——drop 掉再 checkpoint 之后元数据就没了。提取时机造成的损失不可弥补：应用在被提取前就已经 checkpoint 或主动删掉 WAL，检材里就不存在那批数据，这时任何分析都给不出结论。阴性结果的表述必须落到范围上："在 `/data/data/<pkg>/databases/` 与 `/data/user/0/<pkg>/` 下未发现该应用 SQLite 三件套"，未覆盖的是已卸载应用残留、系统级数据库与云备份。**本篇给不出"谁做的"**——SQLite 里没有用户身份、没有来源 IP、没有执行轨迹，把聊天记录里的内容对上嫌疑人，需要 [即时通讯取证](../mobile-android/mobile-android-instant-messaging-forensics.md) 与应用侧日志来补。

**读者前提**：需要先理解 SQLite 的页与 B-tree 概念、以及 `sqlite_master` 存的是模式而非数据（[SQLite 基础与结构](mobile-database-sqlite.md) 是硬前置）；需要能读十六进制并手工走一遍 32 字节 WAL 文件头与 24 字节帧头，**这一步是本篇的核心技能**——不手工校验过一轮，salt 与校验和的判断就只能靠工具报成功；需要分清"字节序"这件事在 WAL 里有两层含义（`magic` 最低位决定整体字节序，而**帧头字段固定按大端读取**，混用会算出看似合理的错误值）；还需要接受不可在原始文件上操作这条纪律，并知道文件系统层复制 SQLite 文件时必须走 `cp` 保留大小与时间、不能靠"打开另存"。

---
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 为什么会有 WAL：先写日志再写库

传统 rollback journal 的写入顺序是"**先改数据页 → 再写日志说明改了什么 → 提交**"，代价是写放大严重、并发读能力弱。WAL 反过来：

1. 所有修改以「帧（frame）」为单位追加写入 `-wal` 文件尾部；
2. **数据页在被覆盖前，事务已完整记录在 WAL 中**，崩溃后只需重放 WAL 即可把主库推进到一致状态；
3. **主库文件在 checkpoint 时才被批量改写**，checkpoint 是分批的（默认满 1000 页触发一次），**所以主库长期处于"落后"状态**。

结论：`-wal` 的大小反映的是"距上次 checkpoint 以来累积的写入量"。

一个 20 MB 的库配一个 200 MB 的 `-wal`，说明该库高频写入且长期未 checkpoint——这在取证中是重要信号。

<a id="section-4"></a>

### 2.2 三个文件的分工

| 文件 | 内容 | 含业务数据 | 缺失/损坏后果 |
|---|---|---|---|
| `app.db` | 主库，含 B-tree 页、schema、freelist | 是 | 无法解析 |
| `app.db-wal` | 预写日志，含**尚未落盘的完整页镜像**与部分已落盘页的新版本 | **是（最新）** | **丢失最新数据**；主库仍可解析但内容陈旧 |
| `app.db-shm` | wal-index 共享内存索引，含各事务的读取标记 | 否（纯索引） | SQLite 会**尝试重建**；极端情况下会忽略整个 WAL |

`-shm` 是**共享内存映射文件**，内容通常保留在磁盘（未 unlink 时），但**它的存在与内容在不同提取路径下差异极大**。

有的 `tar` 打包会带上它，有的按 `*.db` 通配符只取主库，有的同步工具因为它是「内存文件」而直接跳过。

这正是「三文件一起提取」容易被简化为「两个文件」的原因。
<a id="section-5"></a>

### 2.3 WAL 文件的字节结构

`-wal` 由 **32 字节文件头** + **若干 24 字节帧头 + 页数据**组成。

**WAL 文件头（32 字节）**：

| 偏移 | 字段 | 说明 |
|---|---|---|
| 0 | `magic` | `0x377f0682` 校验和按小端计算，`0x377f0683` 大端 |
| 4 | `format_version` | 目前为 `3007000` |
| 8 | `page_size` | 4 字节，页大小原值（含 65536 本身，不做 1→65536 转换） |
| 12 | `checkpoint_seq` | **主库与 WAL 不一致时 WAL 会被整体忽略** |
| 16/20 | `salt1`/`salt2` | 每次 checkpoint 后随机重生成 |
| 24 | `checksum` | **前 24 字节**的校验和（起始状态 0,0） |

**帧头（24 字节）**：

| 偏移 | 字段 | 说明 |
|---|---|---|
| 0 | `page_number` | 该帧承载的页号 |
| 4 | `db_size_after_commit` | 非 0 表示该帧所属事务的提交点，同时给出提交后库的总页数 |
| 8 | `salt1`/`salt2` | 必须与文件头一致，否则该帧属于上一个 WAL 周期，必须丢弃 |
| 16 | `checksum` | **帧头前 8 字节 + 整页数据**的滚动校验和 |

**salt 与校验和是 WAL 取证的两道核心判据**：WAL 被 checkpoint 重置后，文件头会被填入新的随机 salt，旧帧因 salt 不匹配而失效；而校验和用于**发现被静默篡改或比特翻转的帧**。

> "WAL 里有很多数据"不等于"这些数据都有效"，更不等于"这些数据没被改过"。必须逐帧校验 salt 与校验和。 只查 salt 会漏掉页数据被改写的情形；只查长度与帧边界则两种都查不出来。

**校验和算法的两个易错点**：

- **字节序由 `magic` 最低位决定**，但**帧头字段本身固定按大端读取**——这是两个独立的字节序，不要混用。
- 帧校验和的输入范围是「帧头前 8 字节 + 页数据」，不含 salt 与校验和字段本身。写错范围会算出看似合理的错误值。

<a id="section-6"></a>

### 2.4 checkpoint 的四种模式与"分析即破坏"

| 模式 | 行为 | 风险 |
|---|---|---|
| `PASSIVE` | 尽力而为地搬运，**遇到读事务就停** | 低；但**它仍然会改写主库** |
| `FULL` | 阻塞等待所有读者，之后搬运 | 会改写主库 |
| `RESTART` | 搬运 + 重置 WAL 起始点 | 改写主库与 WAL |
| `TRUNCATE` | 搬运并把 `-wal` 截断为 0 字节 | **不可逆地销毁 WAL 残留** |

> 取证要求：`sqlite3 app.db "SELECT ..."` 是一次读写操作。
> 只要同目录存在有效的 `-wal`，SQLite 打开数据库时就会自动执行隐式 checkpoint，把 WAL 内容写回主库并**改写主库文件的字节**。
> 这意味着：你分析"只提主库"的那份副本，查询一次后主库就变了，原始哈希不再可复现。

正确做法有两条：

**① 归档副本永远只读**（`chmod 444` 或只读挂载）；
② 需要保留 WAL 原始状态时用 immutable 模式 `sqlite3 'file:app.db?immutable=1'`——此时 SQLite 明确声明「该文件不变」，**不会写、也不会 checkpoint**（代价是不读 WAL）。

<a id="section-7"></a>

### 2.5 "-wal 里有数据但查询不出来"的三种原因

| 原因 | 判据 | 处置 |
|---|---|---|
| **WAL 被忽略**：checkpoint 序列或 salt 不匹配 | 主库头 `write_version=2`，但读取后行数不变 | 检查 `-wal` 头 12 字节与主库头变更计数器 |
| **WAL 已损坏**：帧校验和断裂 | 越靠后的帧越不可用 | 用 3.3 节脚本逐帧判定可用边界 |
| **本来就只有这些数据**：应用最后一次写入就在更早时间 | 有效帧的 `db_size_after_commit` 均不晚于主库状态 | 属正常情况，需回到时间线交叉验证 |

若库文件本身是 SQLCipher 之类加密的，三文件联合提取这套流程要先过密钥这一关，判定与获取路径见[数据库与配置文件加密](../../crypto/crypto-app/crypto-app-database-configuration-decryption.md)。

---

<a id="section-8"></a>

## 三、操作步骤

<a id="section-9"></a>

### 3.1 提取：三文件作为一个整体

**首选方案：整目录 tar（一次传输，避免逐文件漏取伴随文件）**

```bash
PKG=com.digiforensics.sample
DEV=/data/user/0/$PKG/databases

# ① 设备端先看全貌 —— 先 ls，确认哪些文件真实存在
adb shell su -c "ls -la $DEV"
# app.db 2457600 / app.db-wal 196608 ★必须 / app.db-shm 32768 ★必须 / app.db-journal 8192

# ② 流式复制示例：可减少设备落盘，但运行中的数据库不保证取得一致性快照
adb shell su -c "tar -cf - -C $DEV ." > dbset.tar
sha256sum dbset.tar | tee dbset.sha256      # tar 落盘即证据载体

# ③ 只在副本上工作
mkdir -p work && tar -xf dbset.tar -C work && chmod -R a-w work
```

**无法 root 时的降级路径**（`run-as` 仅适用于 debuggable 应用）：

```bash
adb shell run-as com.digiforensics.sample ls -la databases/
adb exec-out run-as com.digiforensics.sample tar -cf - -C databases . > dbset-runas.tar
```

> **采集一致性限制**：将多个文件依次加入同一 `tar` 并不能保证它们处于同一事务时刻。采集运行中的数据库，应优先考虑经授权的应用停写/系统一致性快照机制；SQLite Online Backup API 可生成逻辑一致性备份，但不能替代保留原始 `-wal` 等取证工件。记录采集开始与结束时间、进程状态及文件哈希；可能不一致时仅报告原始观察值。

<a id="section-10"></a>

### 3.2 建立基线：不触碰地观察

```bash
sqlite3 "file:work/app.db?immutable=1" "PRAGMA integrity_check;"
sqlite3 "file:work/app.db?immutable=1" "PRAGMA page_size;"
sqlite3 "file:work/app.db?immutable=1" "PRAGMA freelist_count;"
xxd -s 18 -l 2 work/app.db          # 0202 = WAL 模式；0101 = legacy journal
```

<a id="section-11"></a>

### 3.3 逐帧校验 WAL 的有效性

`wal_scan.py` —— 校验文件头与每一帧的 **salt 与滚动校验和**，输出**有效帧的提交点与页覆盖情况**：

```bash
cat > wal_scan.py <<'PY'
import struct, sys
d = open(sys.argv[1], 'rb').read()
if len(d) < 32:
    print("!! 文件过小，不是合法 WAL"); sys.exit(1)
# 文件头字段固定大端；magic 最低位单独决定校验和的字节序
magic, fmt, ps, cseq, s1, s2, ck1, ck2 = struct.unpack('>IIIIIIII', d[0:32])
CE = '<' if not (magic & 1) else '>'
M = 0xFFFFFFFF
def ck(data, s0, s1_):
    """SQLite 32 位滚动校验和：按 CE 字节序取 32 位字，成对迭代"""
    n = len(data) // 8
    v = struct.unpack(CE + 'I' * (n * 2), data[:n * 8])
    for i in range(0, len(v), 2):
        s0 = (s0 + v[i] + s1_) & M
        s1_ = (s1_ + v[i + 1] + s0) & M
    return s0, s1_
h0, h1 = ck(d[0:24], 0, 0)                 # 头校验和覆盖前 24 字节，起始状态 0,0
print(f"magic=0x{magic:08x} ({'大端' if magic&1 else '小端'}校验和)  format={fmt}")
print(f"page_size={ps}  checkpoint_seq={cseq}  salt=0x{s1:08x}/0x{s2:08x}")
print(f"头校验和 计算=0x{h0:08x}/0x{h1:08x} 存储=0x{ck1:08x}/0x{ck2:08x} "
      f"{'OK' if (h0,h1)==(ck1,ck2) else '!! 不一致'}")
off, valid, bad, pages = 32, 0, 0, set()
while off + 24 + ps <= len(d):
    pno, dbsz, fs1, fs2, f1, f2 = struct.unpack('>IIIIII', d[off:off+24])
    if fs1 != s1 or fs2 != s2:             # salt 不匹配 → 上个周期的残留帧
        print(f"帧@{off}: salt 不匹配 → 该帧及之后失效，停止"); break
    # 校验和输入 = 帧头前 8 字节 + 整页数据（不含 salt 与校验和字段）
    c1, c2 = ck(d[off:off+8], h0, h1)
    c1, c2 = ck(d[off+24:off+24+ps], c1, c2)
    if (c1, c2) != (f1, f2):
        bad += 1
        print(f"帧@{off} page={pno}: 校验和不符 计算=0x{c1:08x}/0x{c2:08x} "
              f"存储=0x{f1:08x}/0x{f2:08x} → 该帧及之后不可用，停止"); break
    valid += 1; pages.add(pno); h0, h1 = c1, c2
    if dbsz:
        print(f"  提交帧@{off}: page={pno} 提交后总页数={dbsz} → "
              f"累计 {valid} 有效帧，覆盖 {len(pages)} 个页号")
    off += 24 + ps

print(f"\
有效帧={valid} 校验失败={bad} 覆盖页号={len(pages)}")
print("结论:", "存在校验通过的 WAL 帧；须进一步识别提交边界" if valid else "未识别有效帧；不能据此断言主库为最新状态")
PY

python3 wal_scan.py work/app.db-wal
```

> **验证范围**：仓库未附可核验的“158 帧”测试样本和执行日志，故该数字暂不作为实测结论。本脚本能辅助检查部分 WAL 帧的结构与校验和，但未完整实现事务提交边界、salt、重置及 WAL 历史版本判读。实际应用须使用受控样本复现，并在分析副本上与 SQLite 引擎和页面结构交叉核对。

<a id="section-12"></a>

### 3.4 联合解析：让 SQLite 自己合并

```bash
# 在分析副本上让 SQLite 识别 WAL；普通连接是否触发 checkpoint 取决于状态和操作，不可一概而论
cp work/app.db analysis.db && cp work/app.db-wal analysis.db-wal && cp work/app.db-shm analysis.db-shm
sqlite3 analysis.db "PRAGMA journal_mode;"
sqlite3 analysis.db "SELECT count(*) FROM pay_record;"
sqlite3 analysis.db "PRAGMA wal_checkpoint(PASSIVE);"     # 0 | 38 | 0 ← (busy, 已搬运, 仍留在 WAL)
sha256sum work/app.db                                      # 归档副本哈希此时必须不变
```

<a id="section-13"></a>

### 3.5 只保留主库的情况：把"缺失"变成证据

若确实只有主库，**不要沉默地继续分析**，而要把缺失转化为可陈述的事实：

```bash
xxd -s 18 -l 2 app.db                 # 0202 → 表明数据库头声明 WAL 模式；无 -wal 可能已经正常 checkpoint，不能直接判缺失
ls app.db-wal 2>/dev/null || echo "未发现 -wal：需结合采集状态与 checkpoint 历史判断"
stat -c '%n  mtime=%y  size=%s' app.db
sqlite3 app.db "SELECT max(datetime(createTime/1000,'unixepoch','localtime')) FROM pay_record;"
```

若"内容最大时间"显著早于"文件 mtime"，只能作为进一步排查的线索，不能单独证明 WAL 事务未落入主库，应写入报告限制条款。

<a id="section-14"></a>

### 3.6 单独挖掘 WAL 内的历史页

WAL 帧中可能保留页面的多个版本或历史页片段，但不能将其未经提交状态、salt 与校验和核对就认作"覆盖前的上一版本"。这在删除类案件中有独立价值：

```bash
cat > wal_dump.py <<'PY'
import struct, sys
wal, want, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
d = open(wal, 'rb').read()
ps = struct.unpack('>I', d[8:12])[0]
off = n = 32
while off + 24 + ps <= len(d):
    pno = struct.unpack('>I', d[off:off + 4])[0]
    if pno == want:
        open(f"{out}-f{n}-p{pno}.page", 'wb').write(d[off + 24:off + 24 + ps])
        print(f"帧 {n}: page {pno} → {out}-f{n}-p{pno}.page"); n += 1
    off += 24 + ps
PY

python3 wal_dump.py work/app.db-wal 3 page3
strings -n 6 page3-*-p3.page | head -30
```

若 WAL 已 checkpoint 完成，**旧页镜像通常已被主库覆盖，不再存在**；因此上述手段对"尚未 checkpoint 的近期操作"最有效。

---
<a id="section-15"></a>

## 四、常见陷阱

WAL 是移动取证里**唯一一个「数据存在但常规手段看不到」的机制**。

它带来的误判有三个特征：**不报错**（结构完好、校验通过、行数合理）、**不可自愈**（一次错误的 checkpoint 会让残留永久灭失）、**难以发现**（所有错误产出的都是一个看起来正常的答案）。


<a id="section-16"></a>

### 4.1 提取完整性

<a id="section-17"></a>

#### 陷阱 1：只提取 `app.db`，主库长期「落后」于应用实际状态

**现象**：`adb pull` 单独拉了 `app.db`，`PRAGMA integrity_check` 返回 `ok`，`.tables` 正常列出，查询得到 118 条交易记录，最大时间停在 2024-08-22。报告写「该应用最后一次交易为 8 月 22 日，此后未再发生交易」。

**原因**：**WAL 模式下主库文件长期处于「落后」状态。**

写入顺序是：所有修改以「帧」为单位追加到 `-wal` 尾部 → 事务提交时数据已完整在 WAL 中 → **主库要等 checkpoint 才被批量改写**，而 checkpoint 是分批触发的（默认累积 1000 页）。

这意味着在两次 checkpoint 之间，主库里根本没有最近这段时间的写入。

单独打开 `app.db` 时，SQLite 读到的就是上一次 checkpoint 时的完整快照——**结构完好、校验通过、记录数合理**，只是缺了尾部这一段。

而「缺的那段」与「没有发生」在 SQL 层面完全无法区分。

**影响**：本领域出现频率最高、后果最重的误判，因为它会直接产生一个与事实相反的行为认定。

本案完整提取后是 156 条、到 8 月 31 日；只提主库是 118 条、到 8 月 22 日。**38 条交易被静默遗漏**。

在支付类案件里，「案发后仍有持续交易」直接关系到「是否继续诈骗」「赃款是否仍在流转」等定性，**而这个错误结论会让案件在关键事实上走反方向**。

更隐蔽的是它与其它证据的矛盾——主库 mtime 是 8 月 31 日而内容停在 8 月 22 日，「文件被改过但内容没更新」本身就是不完整的确证。分析者若不主动做这个比对，就会带着错误结论继续走。

**核查**：**三文件作为一个不可分割的整体提取，一次打包完成**（同刻一致性见 3.1 的采集一致性限制）：

```bash
PKG=com.digiforensics.sample
DEV=/data/user/0/$PKG/databases

# ① 先 ls 确认哪些文件真实存在（这是提取范围的依据，要入卷）
adb shell su -c "ls -la $DEV"
# app.db 2457600 / app.db-wal 196608 ★ / app.db-shm 32768 ★ / app.db-journal 8192

# ② 整目录一次性流式导出（不落地到设备，不受 /data 空间限制）
adb shell su -c "tar -cf - -C $DEV ." > dbset.tar
sha256sum dbset.tar | tee dbset.sha256

# ③ 归档副本立刻锁只读
mkdir -p work && tar -xf dbset.tar -C work && chmod -R a-w work

# ④ 反事实对比，把差值量化（这个数字直接写进报告）
cp work/app.db DigiForensics-a1.db && cp work/app.db-wal DigiForensics-a1.db-wal && cp work/app.db-shm DigiForensics-a1.db-shm
sqlite3 DigiForensics-a1.db "SELECT count(*) FROM pay_record;"   # 156
# 只提主库的情形：sqlite3 app.db "SELECT count(*) FROM pay_record;"   # 118
# 差值 38 条 = 只存在于 WAL 中的记录数
```

**第 ④ 步的反事实验证值得固化为习惯**：它用两条命令把「漏了多少」变成一个具体数字，这个数字同时是覆盖范围的客观依据和「检材曾经不完整」这个事实的记录。

<a id="section-18"></a>

#### 陷阱 2：三个文件不是同一次打包取得的，SQLite 静默忽略整个 WAL

**现象**：三文件都在，`.db`、`.db-wal`、`.db-shm` 都能 `ls` 到，`sqlite3` 打开不报错，`PRAGMA journal_mode` 返回 `wal`，但**查询结果与只提主库时完全相同**——WAL 里的数据一条都没进来。

**原因**：这是本领域最隐蔽的一类错误，因为它没有任何报错信号。

三个文件的导出时间若不一致（主库来自 23:14、WAL 来自 23:12），SQLite 会把它们判定为**不匹配**：WAL 帧头里的 `salt1`/`salt2` 与文件头不一致的帧被丢弃。

而主库头部的 `write_version=2` 只说明「曾经是 WAL 模式」，**不保证当前 WAL 可用**。

SQLite 在这种情况下**静默降级**——它不提示「WAL 被忽略」，只是返回主库的状态。

分析者会认为「WAL 里本来就没数据」，而实际上是三文件不配套。

**影响**：它会让人得出「WAL 为空」的错误技术判断，而这个判断会进一步导向「该应用最近没有写入」的行为结论。

也就是说，一次提取工艺上的不一致，最终变成了一个关于用户行为的事实断言。

**而且这个错误极难自查**：在分析阶段，所有可见的证据（三个文件都在、模式是 wal、库可读）都指向「WAL 已被正常处理」。只有「为什么行数没变」这个疑点能提示问题，而这一疑点很容易被归因为「这段时间确实没有写入」。

**核查**：一次 `tar` 完成，且验证时用 WAL 自己的头字段做判据：

```bash
# ① 一次打包，保证同刻
adb shell su -c "tar -cf - -C $DEV ." > dbset.tar
tar -tvf dbset.tar | grep -E '\.db'        # 确认三文件都在且时间一致

# ② 验证 WAL 有效性：逐帧校验 salt 与滚动校验和（wal_scan.py，见 3.3）
python3 wal_scan.py work/app.db-wal
# magic=0x377f0683  page_size=4096  checkpoint_seq=12  salt=0x1a2b3c4d/0x5e6f7a8b
# 头校验和 OK
# 帧@56: salt 不匹配 → 该帧及之后失效，停止        ← ★ 这种情况说明三文件不配套
# 有效帧=0  → 结论: WAL 无有效帧

# ③ 与主库头对照
xxd -s 18 -l 2 work/app.db                    # 0202 → WAL 模式
python3 -c "
import struct
d=open('work/app.db-wal','rb').read(32)
m,f,ps,cseq,s1,s2,ck1,ck2=struct.unpack('>IIIIIIII',d)
print(f'WAL: magic=0x{m:08x} checkpoint_seq={cseq} salt=0x{s1:08x}/0x{s2:08x}')"
sqlite3 "file:work/app.db?immutable=1" "PRAGMA schema_version;"   # 不写文件的查询

# ④ 判据：checkpoint_seq 与主库的实际状态是否吻合
#    若 WAL 的 checkpoint_seq 明显落后，且有效帧为 0 → 判定为「三文件不配套」
```

注意 `wal_scan.py` 的输出里「有效帧=0」这个结论的含义——它不区分「WAL 本来就是空的」与「WAL 因为 salt 不匹配被丢弃」。

所以必须看它的中间输出（是否打印了 `salt 不匹配`）。

这个区分是本条陷阱的核心：前者是正常情况，后者是提取失败。

<a id="section-19"></a>

#### 陷阱 3：用 `*.db` 通配符批量拷贝，扩展名不符的伴随文件全被漏掉

**现象**：写了个批量脚本 `adb pull /data/user/0/$PKG/databases/*.db ./out/`，跑完之后每个库都只有一个 `.db` 文件，`-wal`/`-shm`/`-journal` 一个都没有，而脚本本身「执行成功」。

**原因**：通配符 `*.db` 只匹配以 `.db` 结尾的文件，而伴随文件的命名是 `app.db-wal`（结尾是 `-wal`）、`app.db-shm`、`app.db-journal`——**它们都不以 `.db` 结尾**。

同时还有两个叠加因素：

**① 很多提取工具按「已知文件类型」过滤**，把 `*.db` 视为主库而忽略其余；
② 同步/备份工具常把 `-shm` 当作「内存文件」而跳过，理由是「它是共享内存映射，不落盘」。

**这些行为都不会报错**——`adb pull` 对不存在的文件会报错，但对「通配符匹配到的文件全部成功拉取」是完全正常的。

**批量的成功掩盖了筛选的错。**

**影响**：**它与陷阱 1 的后果相同，但发生在更隐蔽的位置**。

单次提取时人会去 `ls` 确认，而**批量脚本跑几百个应用时没有人会逐个确认**。

结果是一批数据里大部分是残缺的，而报告里写的是「已批量提取 N 个应用的数据目录」。

更糟的是：如果这些数据被用来做「哪些应用使用了某功能」这类统计，**残缺的数据会系统性偏向「较早的使用行为」**——因为最近的使用记录都在被漏掉的 WAL 里。

**核查**：**永远用目录级打包，不用文件通配符**：

```bash
# ✗ 绝对不要：通配符会漏掉所有伴随文件
# adb pull /data/user/0/$PKG/databases/*.db ./out/

# ✓ 正确：整目录 tar，三文件与其它伴随文件天然齐全
PKG=com.digiforensics.sample
adb shell su -c "tar -cf - -C /data/user/0/$PKG databases" > DigiForensics-db.tar
tar -tf db.tar | grep -E '\.db'         # 逐个确认

# ✓ 批量场景：整目录打包 + 逐个核对文件数
: > extraction-log.txt
for d in $(adb shell su -c "ls /data/user/0/" | tr -d '\r'); do
  adb shell su -c "tar -cf - -C /data/user/0 $d/databases 2>/dev/null" \
    | tar -xf - -C out/$d 2>/dev/null \
    && echo "OK $d: $(ls out/$d/databases/ 2>/dev/null | wc -l) 个文件" >> extraction-log.txt \
    || echo "FAIL $d" >> extraction-log.txt
done < <(adb shell su -c "ls /data/user/0/" | tr -d '\r')

# ✓ 事后审计：多少个库带了 -wal，带了的体量分布
find out -name '*.db-wal' -printf '%s %p\
' | sort -rn | head -20
echo "带 -wal 的库数: $(find out -name '*.db-wal' | wc -l)"
echo "主库总数:      $(find out -name '*.db' ! -name '*-wal' ! -name '*-shm' | wc -l)"
```

**最后那三行的审计是必需的**——它给出「有多少个库处于 WAL 模式但 WAL 被漏掉」的规模估计，这个数字直接决定了报告里「数据完整性」的表述强度。

<a id="section-20"></a>

### 4.2 分析即破坏

<a id="section-21"></a>

#### 陷阱 4：★ 在归档副本上直接 `SELECT`，触发隐式 checkpoint 改写原始字节

**现象**：为了「先看一眼库里有什么」，直接在 `work/app.db` 上执行了 `sqlite3 app.db ".tables"` 和几条查询。查询结果正常，此后 `sha256sum` 发现文件哈希与提取时记录的不一致。

**原因**：`sqlite3 app.db "SELECT ..."` 不是只读操作。

只要同目录存在有效的 `-wal`，SQLite 打开数据库时就会自动执行隐式 checkpoint，把 WAL 内容写回主库并改写主库文件的字节（同时更新文件头部的变更计数器）。

这个行为对使用者是完全透明的——**查询结果完全正常，没有任何提示**。

而它的后果是：归档副本的哈希变了，而它是证据链上「从设备上提取时的那份字节」的唯一记录。

**更隐蔽的是它会连锁影响后续判断**：checkpoint 之后，`-wal` 里的内容被搬进主库，**「哪些数据只存在于 WAL 里」这个状态就消失了**——而这恰恰是本领域最有价值的一个技术观察。

**影响**：**不可逆，且破坏的正是「原始性」这个属性。**

三重后果：**① 原件哈希无法复现**，复核时无法证明分析对象就是检材；**② 「数据未回写」这个状态永久丢失**——而这个状态本身能证明「应用在检材时刻仍在活跃使用」；③ 若在设备侧或归档副本上做过，后续所有关于「提取完整性」的技术判断都失去了可验证的依据。

**核查**：归档副本只读，查询走 immutable 模式，分析另开可写副本：

```bash
# ① 归档副本从一开始就锁只读（最有效的保险）
chmod -R a-w work/

# ② 需要「只看不改」时用 immutable 模式：不写、不 checkpoint（代价是不读 WAL）
sqlite3 "file:work/app.db?immutable=1" "PRAGMA integrity_check;"
sqlite3 "file:work/app.db?immutable=1" "PRAGMA page_size;"
xxd -s 18 -l 2 work/app.db                     # 直接读字节，不经过 sqlite3

# ③ 要读 WAL 内容 → 另开可写副本，让它自动合并
cp work/app.db DigiForensics-analysis.db && cp work/app.db-wal DigiForensics-analysis.db-wal && cp work/app.db-shm DigiForensics-analysis.db-shm
sqlite3 DigiForensics-analysis.db "PRAGMA journal_mode;"
sqlite3 DigiForensics-analysis.db "SELECT count(*) FROM pay_record;"     # 156（WAL 已并入）
sqlite3 DigiForensics-analysis.db "PRAGMA wal_checkpoint(PASSIVE);"     # 0 | 38 | 0 ← (busy, 已搬运, 仍留在 WAL)

# ④ 验证归档副本确实未变
sha256sum -c originals.sha256
# 每次对 DigiForensics-analysis.db 做操作后都跑一次，作为纪律
```

`immutable=1` 这个参数是本领域最被低估的工具，它解决的问题是「我想看主库的原始状态但不想让它被改」。

它的代价是不读 WAL——这恰恰是它在「建立基线」这一步的价值：你需要一个不受 WAL 影响的、纯粹的、未被改写的主库视图。

在做逐帧分析、算差值、判断「哪些数据在 WAL 里」之前，**都应该先在 immutable 模式下取一份基线**。

<a id="section-22"></a>

#### 陷阱 5：先 checkpoint 再想看 WAL 残留，已删除内容永久灭失

**现象**：按教程执行了 `PRAGMA wal_checkpoint(TRUNCATE)` 让主库「干净」，然后开始找已删除内容，`strings` 扫了半天什么都没找到，报告写「未发现已删除的交易记录」。

**原因**：WAL 帧里保存的是「页的完整镜像」，而这个镜像可能是该页被覆盖前的上一版本。

主库里的记录被 `DELETE` 之后，如果这个页在 checkpoint 之后、再次被修改（比如有更新操作又写了一次，或者 checkpoint 把它覆盖了），那么它当前版本就已经不含那段内容了——但 **WAL 里的历史页镜像可能还在**。

而 `TRUNCATE` 模式做的事是：把 WAL 内容搬进主库，然后把 `-wal` 文件截断为 0 字节。这意味着**所有这些历史页镜像被一次性销毁**。

这是一个不可逆操作，而且它的作用对象恰恰是取证价值最高的那部分数据。

**影响**：**不可逆的证据灭失，而且灭失得毫无提示。**

`TRUNCATE` 执行后一切正常，文件列表正常，查询正常，**没有任何迹象表明刚才销毁了一批历史页镜像**。

「未发现已删除记录」这个结论因此建立在一个已经被破坏的检材状态上——而更糟的是，**复核时无法发现这一点**，因为 checkpoint 后的状态本身是完全合法的、无法与「正常分析后的状态」区分。

在删除类案件中，这直接导致「未能发现已删除的交易」这个错误结论。

**核查**：挖掘 WAL 残留必须在任何 checkpoint 之前完成，顺序不能颠倒：

```bash
# ★ 顺序：① strings 扫主库 ② wal_scan 逐帧验证 ③ 挖掘 WAL 内的历史页 ④ 最后才 checkpoint
# ① 先在主库里找已删除残留（freelist）
sqlite3 "file:work/app.db?immutable=1" "PRAGMA freelist_count;"
strings -n 8 -e l work/app.db | grep -E '转账|收款|6222|5188' | head -20
# 转账备注：先转 8800 到 5188****2277，尾号 277

# ② 逐帧验证 WAL 有效性（必须在 checkpoint 前）
python3 wal_scan.py work/app.db-wal
# 有效帧=158（含 2 个提交帧）→ 覆盖 96 个页号

# ③ 挖掘 WAL 里的历史页镜像
python3 wal_dump.py work/app.db-wal 3 page3
strings -n 6 page3-*-p3.page | head -30
# ★ 可能在主库里看不到的内容在这里

# ④ 记录完整之后，才在副本上做 checkpoint
cp work/app.db DigiForensics-analysis.db && cp work/app.db-wal DigiForensics-analysis.db-wal
sqlite3 DigiForensics-analysis.db "PRAGMA wal_checkpoint(TRUNCATE);"

# ⑤ 原始副本校验：确认始终未变
sha256sum -c originals.sha256
```

**这个顺序本身就是一条需要写进报告的方法论**——「WAL 残留挖掘是一次性的、不可重来的机会，必须在数据库操作之前完成」。

而 §3.6 里那句「WAL 已 checkpoint 完成后，旧页镜像通常已被主库覆盖，不再存在」正是这个顺序约束的理由。

<a id="section-23"></a>

#### 陷阱 6：把失效 salt 的帧当作有效数据，引入上一周期的陈旧内容

**现象**：写了个简单的脚本遍历 `-wal` 提取所有页数据，`strings` 扫出来一堆「看起来像交易记录」的文本，写进报告当作已恢复数据。

**原因**：WAL 被 checkpoint 重置后，文件头会被填入新的随机 salt，而旧帧的 salt 仍是上一周期的值。

SQLite 靠这个机制判断「哪些帧属于当前周期」——salt 不匹配的帧属于上一个 WAL 周期的残留，必须丢弃。

而手工解析时若不做这个检查，**旧帧会被当成有效数据混入结果**。

这批陈旧内容的危害在于它是「上一个周期的真实数据」——它不是垃圾，它曾经是有效的库内容。

因此它会呈现出高度可信的形态：内容完整、格式正确、时间戳合理。

**而它实际上已经在主库里被后续操作替换掉了。**

**影响**：把「曾经存在过的内容」当成「当前状态下的内容」，这是时间维度的错误。

具体后果有三条：① 已删除的内容可能以「被覆盖前的旧页镜像」的形式重新出现，分析者据此得出「内容未被删除」的结论，而事实上它已经被覆盖；② 反过来，checkpoint 之后的新状态可能被旧页覆盖掉，导致「未发现」的错误结论；**③ 最严重的是不可分辨**——旧页镜像与有效页在字节层面结构完全相同，混进去之后无法事后区分。

报告里引用的「已恢复数据」可能有一部分来自错误的周期。

**核查**：逐帧校验 salt 与滚动校验和，两道都查，且在中途失败时立即停止：

```python
# 校验逻辑要点（完整实现见 3.3 的 wal_scan.py）
# ① 文件头字段固定大端读取；magic 最低位单独决定校验和算法的字节序
magic, fmt, ps, cseq, s1, s2, ck1, ck2 = struct.unpack('>IIIIIIII', d[0:32])
CE = '<' if not (magic & 1) else '>'

# ② 头校验和覆盖前 24 字节，起始状态 (0,0)
h0, h1 = ck(d[0:24], 0, 0)
assert (h0, h1) == (ck1, ck2), "WAL 头校验和不符"

# ③ 逐帧：先查 salt，不匹配立即停止（该帧及之后都失效）
if fs1 != s1 or fs2 != s2:
    print(f"帧@{off}: salt 不匹配 → 属上一周期，该帧及之后失效，停止"); break

# ④ 再查滚动校验和：输入范围 = 帧头前 8 字节 + 整页数据（不含 salt 与校验和字段）
c1, c2 = ck(d[off:off+8], h0, h1)
c1, c2 = ck(d[off+24:off+24+ps], c1, c2)
if (c1, c2) != (f1, f2):
    print(f"帧@{off}: 校验和不符 → 该帧及之后不可用，停止"); break

# ⑤ 只有通过两道的帧才计入有效集合并更新滚动状态
valid += 1; pages.add(pno); h0, h1 = c1, c2
```

**两道检查各查一类问题，缺一不可**：只查 salt → 页数据被改写或比特翻转查不出来；只查长度与帧边界 → salt 不匹配的旧帧会被当成有效数据。

而在两种情况下都「立即停止」而不是「跳过继续」——因为校验和是滚动计算的，一帧失败之后的所有帧的校验起点都已错位，**继续解析只会产生更多看似合理的错误值**。

**报告里要写明有效帧的范围**：

> **WAL 有效性**：`-wal` 文件头 `magic=0x377f0683`（大端校验和）、`page_size=4096`、`checkpoint_seq=12`、`salt=0x1a2b3c4d/0x5e6f7a8b`，头校验和通过。逐帧校验结果：**有效帧 158 个**（其中提交帧 2 个，最后一次提交后总页数 96），覆盖 96 个页号，**校验失败帧 0 个，无 salt 不匹配**。
> 据此判定：该 WAL 全部有效帧均属当前周期且未被改写，应与主库联合解析。
> **补充**：另将 `page=3` 的全部历史页镜像导出为独立文件并做字符串提取（见附件 `page3-f*.page`），提取到 [具体内容]。该内容在主库当前状态下不可见，属 checkpoint 前的历史版本。

<a id="section-24"></a>

### 4.3 WAL 解析细节

<a id="section-25"></a>

#### 陷阱 7：校验和的输入范围写错，算出「看似合理」的错误值

**现象**：脚本算出的 WAL 头校验和与文件里存的不一致，于是判定「WAL 已被篡改」；或者反过来，算出来「一致」就认为数据完好，而实际检查的是页数据。

**原因**：SQLite 的滚动校验和有三个独立的易错点，任何一个写错都会产出一个「看起来像校验和」的四字节值。

**① 字节序有两个来源**——WAL 文件头的 `magic` 最低位决定校验和算法的字节序（`0x377f0682` 为小端，`0x377f0683` 为大端），**而帧头与文件头的所有字段本身固定按大端读取**。这是两个独立的字节序，混用会得到完全错误的结果。

**② 输入范围各不相同**——**文件头校验和覆盖前 24 字节**（不含它自己的 checksum 字段，起始状态为 0,0）；而帧校验和的输入是「帧头前 8 字节 + 整页数据」，不含 salt 与校验和字段本身，且起始状态是上一帧的校验结果。

**③ 滚动方式**——按校验和字节序取 32 位字**成对迭代**，不是逐字累加。

**影响**：**两个方向的错误都很严重。**

判「已篡改」而实际未篡改：**这是对一个检材的完整性问题做了虚假指控**。在报告里写下「WAL 校验和不符，疑似被篡改」是一个严重的结论性主张，**而它是分析工具的 bug**。

**反向的错误更隐蔽**——如果检查范围写错导致计算出的值恰好与存储值一致，**「校验通过」这个结论就是虚假的**，而基于它得出的「WAL 未被改写，可以采信」直接把一批未经验证的数据当成了可靠数据。

**核查**：**用三段式验证法，任何一段不过就停下核对实现**：

```bash
# ① 先看头校验和（范围：前 24 字节，起始 0,0）
python3 wal_scan.py work/app.db-wal | head -3
# magic=0x377f0683 (大端校验和)
# 头校验和 计算=0x... 存储=0x... OK

# ② 人为破坏验证：复制一份 WAL，翻转页数据里的 1 个 bit，必须立即报出校验和不符
cp work/app.db-wal test-wal
python3 -c "
d=bytearray(open('test-wal','rb').read())
d[40] ^= 0x01                     # 翻转第 1 帧页数据的 1 个 bit
open('test-wal','wb').write(d)"
python3 wal_scan.py test-wal | tail -5
# 帧@36 page=1: 校验和不符 → 该帧及之后不可用，停止
# ★ 这一步是自我验证：工具能报出人为破坏，才说明它能发现真实破坏

# ③ 交叉验证：让 SQLite 自己读一遍
cp work/app.db DigiForensics-x.db && cp work/app.db-wal DigiForensics-x.db-wal && cp work/app.db-shm DigiForensics-x.db-shm
sqlite3 DigiForensics-x.db "PRAGMA integrity_check;"
sqlite3 DigiForensics-x.db "SELECT count(*) FROM pay_record;"
# SQLite 读出的结果应与 wal_scan.py 的有效帧结论一致
```

第 ② 步的「人为破坏验证」是这一类校验代码的必做动作。

理由很简单：一个从不报错的校验工具和一个正确的校验工具，在没有阳性样本时无法区分。

造一个已知损坏的样本，确认工具能报出来——这是唯一能证明「校验通过」这个阴性结果有意义的方法。

**报告里要写明这项自我验证做过**：

> **校验实现的自检**：在 `test-wal`（本副本，人为翻转第 1 帧页数据的 1 个 bit）上运行同一脚本，脚本在第 1 帧即报出校验和不符并停止。**据此确认该脚本具备检出单比特篡改的能力**，因此本报告中「WAL 有效帧 158 个、校验失败 0 个」的结果可作为「未检出篡改」的依据。**该结论为「未检出」而非「证明未篡改」。**

<a id="section-26"></a>

#### 陷阱 8：把 WAL 头偏移 8 的页大小直接当主库页大小用

**现象**：从 `-wal` 文件头偏移 8 读出 `page_size` 字段值 `1`，按 1 处理；或者反过来，主库页大小 1024 而 WAL 头显示 65536，分析时统一用了其中一个，解析结果整体错位。

**原因**：这两个字段的编码规则不同，而这个差异没有任何提示。

主库文件头偏移 16 的 `page_size` 是 2 字节，**值 1 是哨兵、实际表示 65536**；而 WAL 文件头偏移 8 的 `page_size` 是 4 字节，它直接存 65536 本身，不做 1→65536 的转换。

**同一个物理概念（页大小）在两个文件里用了两套编码**，而解析脚本通常只写一次转换逻辑，套用到两个文件上就必然错一个。

**更麻烦的是错位后的表现**——按错误页大小切页，会得到「页头看着合理但内容乱码」的结果，**它不像明确的报错，而像是数据本身有问题**。

**影响**：**它是整条 WAL 解析链的基础，错了后面全错。**

具体表现：帧边界定位偏移 24 字节，页数据起始位置错位，**于是每个提取出来的「页」都是前后错开的片段**。

`strings` 提取时可能仍然能捞到一些文本（因为文本在字节流里），但结果是内容碎片化、时间戳错乱、`wal_dump.py` 导出的「页」无法被 B-tree 解析。

**而这些错误的页仍能提供「看起来像证据」的字符串**——这就是它危险的地方。

**核查**：**两个页大小分别读，并交叉验证一致性**：

```bash
# ① 主库页大小（2 字节，含哨兵值处理）
python3 -c "
import struct
d=open('work/app.db','rb').read(100)
ps=struct.unpack('>H', d[16:18])[0]
print('主库页大小 =', 65536 if ps==1 else ps)     # ★ 1 → 65536"

# ② WAL 页大小（4 字节，不做转换）
python3 -c "
import struct
d=open('work/app.db-wal','rb').read(12)
ps=struct.unpack('>I', d[4:8])[0]
print('WAL 页大小 =', ps)                          # ★ 直接就是 65536，不转换"

# ③ ★ 两者必须相等 —— 这是 WAL 与主库配套的一个强判据
#    不相等 → 三文件不配套，WAL 不可用

# ④ 帧边界用真实页大小计算
python3 -c "
import struct
d=open('work/app.db-wal','rb').read()
ps=struct.unpack('>I', d[8:12])[0]
n=(len(d)-32)//(24+ps)          # 可容纳的帧数
print(f'文件 {len(d)}B，页大小 {ps}B，理论帧数 {n}，余字节 {(len(d)-32)%(24+ps)}')
# 余字节非 0 → 末帧不完整（传输截断或文件本身如此），要写进报告"
```

**第 ③ 步的两值相等是一个免费的配套性判据**——它比「行数没变」这类间接观察更直接，成本也只有一行代码。

<a id="section-27"></a>

### 4.4 结论表述

<a id="section-28"></a>

#### 陷阱 9：把「WAL 有效帧中未见」写成「设备上没有该行为」

**现象**：`wal_scan.py` 报告有效帧 0（因为三文件不配套被忽略），`strings` 也没搜到相关内容。报告结论写「该设备上未发现该笔交易的相关记录」。

**原因**：这是一个把「在我拿到的数据里没看到」当成「事实不存在」的问题，而在 WAL 语境下尤其突出。

因为这个领域里「数据存在但我没拿到」的形态太多了：数据可能在失效 salt 的旧帧里、可能在被忽略的 WAL 中、可能在 `PRAGMA wal_checkpoint(TRUNCATE)` 之后的灭失里、可能在从未被提取的 `-journal` 文件里、也可能在设备的另一个用户（work profile）下。

**这六种形态在「我搜不到」这个现象上是完全一样的。**

而「未发现」的表述把这一堆可能性全部压掉了。

**影响**：这是阴性发现的表述层失真，代价与错误阳性发现同量级。

「未发现该笔交易」会被委托方读作「该交易未发生」或「该设备与此无关」，**而这两者都可能是错的**。

委托方据此做的判断（排除某嫌疑人、终止侦查）**无法挽回**。

在需要证明「不具备作案条件」的案件里，一个基于不完整检材的「未发现」会直接制造出错误的不在场证明。

**核查**：**阴性发现写成三段式，并逐条列出未覆盖范围**：

> **关于「未发现该笔交易」的说明**
>
> **检索范围**：本检材 `com.digiforensics.sample` 在 `/data/user/0/`（`pm list users` 确认本机为单用户，无 work profile）下的 `databases/` 目录，经整目录 `tar` 提取，共 4 个库文件及全部伴随文件。
>
> **检索方法**：① 4 个库的主库 freelist 空闲区 `strings` 提取（UTF-8 与 UTF-16le 两种编码）；② `-wal` 逐帧校验后对全部有效帧做页数据提取；③ `-journal` 文件字符串提取；④ 对主库全部 4 张业务表做字段级 `LIKE` 查询。
>
> **检材完整性**：4 个库中 **1 个为 WAL 模式**（`pay_record` 所在库），其 `-wal` 经逐帧校验有效帧 158 个已全部解析；`app.db-journal`（8,192 B）已提取并检索。三文件配套性经页大小一致性与 salt 校验双重确认。
>
> **结论**：**在上述检索范围内未发现**交易金额 8800.00、备注含「5188」的记录。
>
> **未覆盖范围**：① 已卸载应用的数据残留未恢复（`packages.xml` 存在卸载记录但内容不可取）；② 设备云端/服务端数据不在本次范围；③ freelist 中与本关键词无关的 312 页内容未做逐页语义分析，仅做关键词检索；④ `MediaMSG` 等扩展字段未解析。
>
> **本结论为阴性发现，效力上限即上述范围。**

**注意 ③ 里的 `app.db-journal`**——它经常被完全忽略，而这个文件记录的是「崩溃瞬间的事务状态」，在时间线分析里是关键的锚点。整目录 tar 已经把它带上了，但分析时容易忘了看。

<a id="section-29"></a>

### 4.4 结论表述

<a id="section-30"></a>

#### 陷阱 10：把「WAL 文件很大」直接读成「该应用高频写入」

**现象**：`-wal` 文件 200 MB，主库 20 MB。报告写「该应用属于高频写入型应用，行为活跃」。

**原因**：`-wal` 的体量反映的是「距上次 checkpoint 以来累积的写入量」，而 checkpoint 的触发条件不只看累积量。

它还看**时间**（多数实现在无写入后一段时间也会 checkpoint）、**读者状态**（`PASSIVE` 模式下遇到活跃读事务就停）、**配置参数**（`wal_autocheckpoint` 的页数阈值、journal_size_limit）。

所以一个 200 MB 的 WAL 可能意味着高频写入，也可能意味着：写入了 200 MB 之后应用被杀/崩溃，checkpoint 从未被触发；或者存在一个长事务一直持有读锁，阻止了 checkpoint 反复尝试。

这三种情形的性质完全不同——最后一种甚至可能指向某个长时间运行的后台操作或卡住的查询。

**影响**：**这是「技术现象被直接归因为行为特征」的越界。**

「高频写入」在案件里是一个行为画像的结论，它可能被用于支持「该设备被用于自动化操作」「该应用被持续用于某活动」这类判断。**而支撑它的证据只是一个文件大小。**

更实际的问题是：分析人员会因此跳过追问「为什么没有 checkpoint」这个更有价值的问题。

而答案可能是「有东西卡住了」——这个线索比「写入频繁」有用得多。

**核查**：**体量只是一个待解释的观察，需要三个数据才能定性**：

```bash
# ① 体量与比值
ls -l work/app.db work/app.db-wal
python3 -c "
import os
db=os.path.getsize('work/app.db'); wal=os.path.getsize('work/app.db-wal')
print(f'WAL/主库 = {wal/db:.2f}')"

# ② 逐帧统计：有效帧数、覆盖页数、提交次数 —— 这比体量有信息量得多
python3 wal_scan.py work/app.db-wal | grep -E '提交帧|有效帧'
# 累计 158 有效帧，覆盖 96 个页号
# ★ 158 帧 × (24+4096)B ≈ 650 KB —— 与 200 MB 的文件体量严重不符

# ③ 关键判据：有效帧数 × 帧大小 vs 文件实际大小
python3 -c "
import struct
d=open('work/app.db-wal','rb').read()
ps=struct.unpack('>I',d[8:12])[0]
print(f'文件 {len(d)}B  帧大小 {24+ps}B  理论最多 {(len(d)-32)//(24+ps)} 帧')
# 若「有效帧数 << 理论最多帧数」→ 文件里有大量无效/旧周期的数据
# 若两者接近 → 确实是持续写入累积"

# ④ 时间维度：帧里能读出时间戳吗（WAL 不含业务时间戳，需从页内容解析）
#    改为看 checkpoint_seq 与主库的关系
python3 -c "
import struct
d=open('work/app.db-wal','rb').read(32)
m,f,ps,cseq,s1,s2,ck1,ck2=struct.unpack('>IIIIIIII',d)
print(f'checkpoint_seq={cseq}  salt=0x{s1:08x}/0x{s2:08x}')"
```

**第 ③ 步是这个陷阱的核心判据**——「有效帧数 × 帧大小」与「文件实际大小」的差距，能区分「真的写了这么多」与「文件里大部分是无效残留」。

前者说明确实有大量未 checkpoint 的写入；后者说明这个文件大部分内容是上一周期的残留，**与「应用活跃」无关**。

**报告表述模板**：

> **WAL 体量说明**：`-wal` 文件 200,704,512 B，为主库（20,971,520 B）的 9.6 倍。逐帧校验后，**有效帧 158 个**（累计 650 KB，覆盖 96 个页号），**与文件体量相差约 300 倍**。
> **据此判定**：该 `-wal` 文件的绝大部分内容为**无效残留**（上一 WAL 周期的帧或校验不通过的数据），实际未 checkpoint 的写入量为 650 KB 量级。**不将该文件的体量作为「应用高频写入」的依据。**
> **未解释项**：`checkpoint_seq=12`，有效帧的两次提交对应的提交后总页数均为 96。为何该库累积了 9.6 倍于主库体积的 WAL 而几乎未 checkpoint，本次未查明（可能原因包括存在长读事务、应用异常终止、或 checkpoint 机制未触发）。

**最后那句「未查明」是这一类分析的诚实终点**——把「我不知道」写出来，好过用一个错误的技术解释把它填掉。
<a id="section-31"></a>

## 五、案例示例

<a id="section-32"></a>

### 5.1 WAL 有效帧校验与 38 条记录的补回

**场景**

委托方提供一台 Android 设备的镜像 `DigiForensics.dd`（userdata 分区，FBE 已在实验室解密），要求恢复某支付类应用（包名 `com.digiforensics.sample`）在 2024 年 8 月的交易记录，并核查是否存在已删除的交易。

初检时只复制到了 `app.db` 一个文件。这个操作细节是本案的起点，也是本篇要解决的核心问题。

**处置过程**

第一步，固定检材并只读解包。**归档副本与工作副本必须分离**：

```bash
$ sha256sum DigiForensics.dd | tee image.sha256
$ mkdir -p work && cd work
$ tar -cf dbset.tar -C /mnt/case/data/user/0/com.digiforensics.sample/databases .
$ tar -xf dbset.tar
$ cp app.db archived-app.db && chmod a-w archived-app.db
$ chmod -R a-w app.db app.db-wal app.db-shm
$ ls -l app.db*
-rw-r--r-- 2457600  2024-08-31 23:14:02  app.db
-rw-r--r--  196608  2024-08-31 23:14:02  app.db-wal
-rw-r--r--   32768  2024-08-31 23:14:02  app.db-shm
-rw-r--r--    8192  2024-08-31 22:50:11  app.db-journal
```

第二步，文件头判定 WAL 模式：

```bash
$ xxd -s 16 -l 4 app.db
00000010: 0400 0202                                   # 页大小 1024，写=2 读=2
```

**`write_version = 2`** —— 主库声明自己运行在 WAL 模式，**未 checkpoint 的写入不在主库里**。初检只复制 `app.db`，等于只拿到了上一次 checkpoint 的快照。

第三步，**校验 WAL 自身的有效性 —— 这一步不能跳**。WAL 文件存在不等于它有效：

```bash
$ python3 wal_scan.py app.db-wal
magic=0x377f0682  format=3007000
page_size=1024  checkpoint_seq=7  salt=0xa3f21c84/0x5b7e0d31
头校验和: 计算=0x8dcebdf8/0xb8dca111  存储=0x8dcebdf8/0xb8dca111  OK
  提交帧@32:     page=5     提交后总页数=2400  → 累计 1 有效帧，覆盖 1 个页号
  提交帧@1080:   page=12    提交后总页数=2402  → 累计 6 有效帧，覆盖 6 个页号
  提交帧@196296: page=1204  提交后总页数=2450  → 累计 38 有效帧，覆盖 34 个页号
有效帧=38  校验失败=0  覆盖页号=34
```

**四个判据全部通过**：magic 正确、头校验和匹配、38 个帧的滚动校验和全部通过、**全部帧的 salt 与 WAL 头一致**（salt 一致意味着这些帧属于同一个写入序列，不含被覆盖的旧序列残留）。

34 个页号 —— 有 34 个页的"新版本"只存在于 WAL 中。

第四步，反事实对比，把缺失量量化：

```bash
$ cp app.db only-main.db
$ sqlite3 only-main.db "SELECT count(*) FROM pay_record;"
118
$ cp app.db full.db && cp app.db-wal full.db-wal && cp app.db-shm full.db-shm
$ sqlite3 full.db "SELECT count(*) FROM pay_record;"
156

$ sqlite3 only-main.db \
  "SELECT max(datetime(createTime/1000,'unixepoch','localtime')) FROM pay_record;"
2024-08-22 16:41:07
$ sqlite3 full.db \
  "SELECT max(datetime(createTime/1000,'unixepoch','localtime')) FROM pay_record;"
2024-08-31 21:07:44
```

**缺失 38 条，时间窗 8/22 至 8/31。**

第五步，把"文件新、内容旧"这个矛盾写清楚 —— 它是最有效的单一指标：

```bash
$ stat -c '%y  %n' app.db
2024-08-31 23:14:02  app.db
$ sqlite3 only-main.db \
  "SELECT max(datetime(createTime/1000,'unixepoch','localtime')) FROM pay_record;"
2024-08-22 16:41:07
```

文件在 8/31 23:14 被写过，主库内最大交易却停在 8/22 16:41。 若不查 WAL，分析方会写下"该账户 8/22 之后再无交易"。

第六步，在分析副本上做 checkpoint —— 并观察它改写了什么：

```bash
$ sqlite3 full.db "PRAGMA wal_checkpoint(PASSIVE);"
0 | 38 | 0          # 0=忙，38=已搬运帧数，0=剩余待处理
$ sha256sum full.db archived-app.db
a1c4e8...  full.db           ← 哈希已变
7a3f...    archived-app.db   ← 哈希不变 ✓
```

**这是"分析即破坏"的直接实证。** 一次只读查询触发了 checkpoint，数据从 WAL 落进主库，工作副本的哈希随之改变。**归档副本哈希不变，是全部结论可复现的基础。**

第七步，取回补回的 38 条明细：

```bash
$ sqlite3 -header -column full.db "
SELECT datetime(createTime/1000,'unixepoch','localtime') AS 时间,
       amount, channel, remark
  FROM pay_record WHERE createTime >= 1724256000000
  ORDER BY createTime LIMIT 12;"
```

| 时间 | 金额 | 通道 | 备注 |
|---|---|---|---|
| 2024-08-22 16:41:07 | 5000.00 | 网银 | 备用 |
| **2024-08-23 10:02:55** | **8800.00** | **转账** | **先转 8800 到 5188****2277** |
| 2024-08-24 19:33:10 | 1200.00 | 余额 | — |
| … | … | … | （WAL 补回共 38 条） |

8/23 的 8800.00 转账在主库中完全不存在，只存在于 WAL。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| WAL 文件有效 | magic + 头校验和 + 38 帧滚动校验和全通过 | 强 |
| WAL 含 38 个有效帧、覆盖 34 个页号 | `wal_scan.py` 输出 | 强 |
| 帧属于同一写入序列 | 全部帧 salt 与 WAL 头一致 | 强 |
| 缺失 38 条交易记录，覆盖 8/22–8/31 | `count(*)` 118 vs 156；`max(createTime)` 差异 | 强 |
| 数据不完整的确证 | 文件 mtime 8/31 23:14 vs 主库最大时间 8/22 16:41 | 强 |
| 2024-08-23 10:02:55 的 8800.00 转账成立 | `pay_record` 明细（WAL 补回） | 强 |
| "分析即破坏"已实证 | checkpoint 后 `full.db` 哈希改变，归档副本不变 | 强 |

**能证明的**：WAL 的完整性与自洽性；缺失记录的具体数量与时间窗；补回数据的完整内容；归档与工作分离的必要性。

**不能证明的**：
- **不能证明这 38 帧之前的全部历史。** WAL 只保存"自上次 checkpoint 起"的写入
- **不能证明 8800.00 转账实际到账**（需银行流水）
- **不能证明帧内容未被一致重算后的替换**（校验和只保证字节自洽，不保证原始性）

**未覆盖范围**：WAL 覆盖窗口之外的历史版本、`app.db-journal`（8/31 22:50:11 的一次事务）、`-shm` 的索引内容、以及早于 8/22 的交易全貌。

**误判对照**

这个案例的误判点在于"WAL 文件存在"与"WAL 内容可用"之间有距离，以及**校验和的作用被高估**。

**其一，WAL 校验和通过就等于内容未被改动。**

这是最需要纠正的认知。SQLite WAL 的滚动校验和**只保证"帧内的字节与该帧头部记录的校验和自洽"**。判据在于它无法排除的情形：

| 校验和能证明 | 校验和不能证明 |
|---|---|
| 帧字节未被随机损坏 | 帧未被整帧替换 |
| 帧属于同一 salt 序列 | 帧内容与采集时一致 |
| 传输过程中未出错 | 采集时写入的就是这些内容 |

**整帧替换后重算校验和是完全可行的。** 判据是**校验和属于"完整性检查"而非"真实性证明"**。若要证明真实性，需要外部基线：云端备份、第三方账单、应用的服务端记录。

按错误判据走的代价：报告写"WAL 校验和全部通过，数据完整可靠"，委托方据此认为不需要其他来源交叉。**而"可靠"这个词在报告里承担了它不该承担的责任。**

其二，把 `checkpoint_seq=7` 读成"这是第 7 次 checkpoint"或"数据不会丢"。

`checkpoint_seq` 是事务提交的序列号，作用是区分"属于本次事务序列的帧"与"上一次 checkpoint 遗留的旧帧"。读法有两层：

| 错误读法 | 正确读法 |
|---|---|
| checkpoint_seq=7 → 已 checkpoint 过 7 次 | 本次 WAL 序列的提交序号为 7 |
| checkpoint_seq 越大数据越新 | 无此含义 |
| 有 checkpoint_seq 就说明数据已落盘 | ❌ 恰恰相反：**WAL 存在即说明有未落盘数据** |

**第二个读法尤其危险。** `checkpoint_seq` 存在的前提就是"还有未 checkpoint 的帧"。若真的全部落盘了，WAL 会被清空或重置。

其三，用 `PRAGMA wal_checkpoint` 在唯一的检材副本上直接跑。

`sqlite3` 的任何连接（哪怕只是 `SELECT`）都可能触发自动 checkpoint。这会让**分析动作本身改变检材状态**，而检材的原始哈希就此失效。

判据是归档与工作副本必须分离，且分离要在任何 SQLite 操作之前完成：

```bash
# 正确顺序
tar -cf dbset.tar ...        # ① 原始三文件打包
cp app.db archived-app.db    # ② 立即留一份只读归档
sha256sum app.db* | tee before.txt
sqlite3 full.db "SELECT ..." # ③ 只在工作副本上操作
sha256sum full.db before_hashes.txt   # ④ 对比可见已改变
```

判据是：`sqlite3` 操作的目录里必须存在至少两个 `app.db` 副本，其中一个从未被 sqlite3 打开过。 本案第 6 步的哈希对比就是这个纪律的验证 —— 归档副本哈希不变，说明它确实没被碰过。

**第四个实操细节**：`PASSIVE` / `FULL` / `RESTART` / `TRUNCATE` 四种 checkpoint 模式的副作用递增：

| 模式 | 行为 | 阻塞写者 |
|---|---|---|
| `PASSIVE` | 尽力而为，不阻塞 | 否 |
| `FULL` | 等待所有读者 | 是 |
| `RESTART` | 阻止新读者 | 是 |
| `TRUNCATE` | 完成后清空 WAL 文件 | 是 |

**取证分析应始终用 `PASSIVE`**，其余三种会改变检材的更多状态（如 `TRUNCATE` 会把 WAL 清零，销毁证据）。

本次 `PRAGMA wal_checkpoint(PASSIVE)` 返回 `0|38|0` 表示 38 帧全部搬运完成、无剩余——这个返回值本身是"数据已成功补回"的验证。

<a id="section-33"></a>

### 5.2 WAL 旧页镜像与 freelist 的双位置删除证据

**场景**

承接 5.1。委托方的第二个要求是"核查是否存在已删除的交易"。5.1 的 `PRAGMA wal_checkpoint(PASSIVE)` 已经把 38 帧搬进主库 —— **但 checkpoint 会不会销毁删除痕迹？**

这个疑问必须回答，因为它决定了下一步的取证路径是否还有效。

**处置过程**

第一步，关键认识：checkpoint 只搬运当前有效帧，不清除旧页镜像。

WAL 中同一页号可以出现多个版本 —— 每次该页被修改就追加一个新帧，旧帧字节**不被覆盖**（WAL 只在 checkpoint 后才可能被复用）。因此：

```bash
$ python3 wal_scan.py app.db-wal --list-frames
frame   page   salt        type    状态
32      5      a3f21c84    commit  有效（seq 7）
1080    12     a3f21c84    commit  有效（seq 7）
196296  1204   a3f21c84    commit  有效（seq 7）
...
300184  5      a3f21c84    frame   旧版本（seq 5）
300648  12     a3f21c84    frame   旧版本（seq 5）
```

**page 5 与 page 12 各有两个版本** —— seq 5 是旧版本，seq 7 是当前有效版本。**seq 5 的字节仍在 WAL 文件里。**

第二步，dump 出旧版本页，与主库 freelist 做对比：

```bash
$ python3 wal_dump.py archived-app.db-wal 5 seq5 page5-seq5.page
$ python3 wal_dump.py archived-app.db-wal 12 seq5 page12-seq5.page

$ strings -n 6 page5-seq5.page page12-seq5.page | grep -E '转账|5188|收款|备注'
转账备注：先转 8800 到 5188****2277，尾号 277
收款确认：已收到，2024-08-23
```

**同一段已删除内容出现在 WAL 旧页镜像里。**

第三步，主库 freelist 侧的独立提取：

```bash
$ sqlite3 app.db "PRAGMA freelist_count;"
312
$ strings -n 8 archived-app.db | grep -E '5188|收款确认'
转账备注：先转 8800 到 5188****2277，尾号 277
收款确认：已收到，2024-08-23
```

**两个独立的物理位置，提取出完全相同的两句内容。**

第四步，**逻辑验证 —— 确认内容确实不在任何表中**：

```bash
$ sqlite3 full.db "SELECT count(*) FROM pay_record WHERE remark LIKE '%5188%';"
0
$ sqlite3 full.db "SELECT count(*) FROM message WHERE content LIKE '%5188%';"
0
$ sqlite3 full.db "SELECT count(*) FROM pay_record WHERE amount = 8800;"
1
```

注意最后一条：`amount = 8800` 有 1 条命中。 这是 5.1 补回的那条活跃记录（8/23 10:02:55，备注"先转 8800 到 5188****2277"）。**而 freelist 里的那句是另一条内容** —— 这一点必须在报告里说清楚，否则读者会以为二者矛盾：

```bash
$ sqlite3 -header -column full.db "
SELECT id, datetime(createTime/1000,'unixepoch','localtime') AS 时间, amount, remark
  FROM pay_record WHERE amount = 8800;"
id   时间                  金额     remark
1063  2024-08-23 10:02:55   8800.00  先转 8800 到 5188****2277
```

活跃记录 `id=1063` 的 `remark` 是"先转 8800 到 5188****2277"（无"尾号 277"），freelist 里的是"…尾号 277"。两者措辞不同，是两条不同的记录。

第五步，把三条事实合成一条证据链：

| # | 事实 | 类型 | 验证方式 |
|---|---|---|---|
| 1 | 内容存在于 WAL 旧页镜像（seq 5） | 物理 | `wal_dump` + `strings` |
| 2 | 内容存在于主库 freelist 空闲区 | 物理 | `strings` on 主库 |
| 3 | 内容不存在于任何表 | 逻辑 | `SELECT count(*)` = 0 |

事实 1+2 证明"内容曾被写入"（两个独立位置），事实 3 证明"已被删除"，两者相加得出"删除后字节未被覆写"。

第六步，时间线合并：

```bash
$ sqlite3 full.db "
SELECT 'bank_bind' AS 事件,
       datetime(bind_time,'unixepoch','localtime') AS 时间
  FROM bank_card WHERE card_no LIKE '5188%'
UNION ALL
SELECT 'transfer',
       datetime(createTime/1000,'unixepoch','localtime')
  FROM pay_record WHERE amount = 8800.00
ORDER BY 时间;"
事件        时间
bank_bind   2024-08-19 09:31:55
transfer    2024-08-23 10:02:55

$ sha256sum dbset.tar archived-app.db app.db app.db-wal app.db-shm | tee final-hashes.txt
$ sqlite3 full.db ".dump" > recovered.sql
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| WAL 同一页号存在多个版本，旧版本字节未被覆盖 | `--list-frames` 显示 page 5/12 各有 seq 5 与 seq 7 | 强 |
| 已删除内容存在于 WAL 旧页镜像 | `wal_dump` seq5 + `strings` 命中 | 强 |
| 同一内容亦存在于主库 freelist | `strings` on 主库命中 | 强（第二物理位置） |
| 该内容已从所有表中删除 | `pay_record`/`message` 的 `count(*)` 均为 0 | 强（逻辑验证） |
| freelist 里的内容与活跃记录 1063 是**两条不同记录** | 措辞差异（"尾号 277"）+ 独立 rowid | 强 |
| 交易时间线自洽 | 8/19 09:31:55 绑卡 → 8/23 10:02:55 转账 | 强 |

**能证明的**：已删除内容的存在性；删除事实的逻辑确认；删除内容的**两个独立物理副本**；完整交易时间线。

**不能证明的**：
- **不能证明删除操作者与删除时刻**（两处内容均无结构化时间戳）
- **不能证明被删除的记录对应哪次具体交易**（无 rowid 与 ID 字段）
- 不能排除 freelist 中还有其他未定向搜索到的删除内容（312 页）
- 不能证明 checkpoint 之前的历史已完整覆盖

**未覆盖范围**：WAL 中 seq 5 之前的历史版本、`app.db-journal`（8/31 22:50:11 事务）、`-shm` 内容、freelist 312 页的全面 cell 解析、以及已删除记录的服务端状态。

**误判对照**

这个案例的误判点在于**checkpoint 与痕迹销毁的边界**，以及**"多位置"这个概念的严格性**。

其一，认为 checkpoint 会清空 WAL 内的旧数据。

`PRAGMA wal_checkpoint` 把**当前有效帧**的数据写入主库，但 WAL 文件内**历史版本的字节不被擦除**。原因是 WAL 的设计：

| 机制 | 说明 |
|---|---|
| WAL 是追加式的 | 新帧追加在文件尾部，不覆盖旧字节 |
| 页版本并存 | 同一页号的多个版本顺序排列 |
| checkpoint 只做搬运 | 把有效帧的数据写进主库对应页 |
| 旧帧的清除 | 发生在**后续 checkpoint 之后**的 WAL 复用（`WRAP` 模式） |

判据是：WAL 里的旧页版本是"物理存在但逻辑无效"的数据。 它们不参与任何查询（SQLite 只读 salt 与 seq 匹配当前事务序列的帧），但**字节可以被提取**。这正是取证价值所在。

关键操作纪律：必须在 checkpoint 之前 dump 旧页版本。 本案第 1 步的 dump 用的就是 `archived-app.db-wal`（归档副本），**不是** `app.db-wal` —— 虽然 5.1 的 checkpoint 只改了主库，但两者的分离是纪律的体现：**任何提取动作都不在归档上进行。**

按错误判据走的代价：分析方在 5.1 跑完 checkpoint 后，紧接着在同一个目录里用 `app.db-wal` 做 dump。虽然本次数据还在（`PRAGMA wal_checkpoint(PASSIVE)` 不清空 WAL 文件），但若此时又有新的写入触发 WAL 复用，这批旧页字节就会被覆盖。这是一个时序赌注。

其二，把"同一个 IP/内容在两处出现"当作两个独立证据，实际是同一个来源。

判据是**"两个物理位置"与"两个独立来源"的区别**：

| 概念 | 含义 | 本案是否满足 |
|---|---|---|
| 两个物理位置 | 内容存在于文件的不同区域 | ✅ WAL 旧页 + 主库 freelist |
| 两个独立来源 | 内容由不同的写入路径产生 | **❌ 不满足** |

**实际的数据流是单源的**：应用执行 `DELETE` → SQLite 写 WAL（新版本页）→ checkpoint 把新页写入主库 → 旧版本页进入主库 freelist。

WAL 旧页与主库 freelist 里的内容，源头是同一次 DELETE。

按错误判据走的代价：报告写"该内容在两个独立位置得到印证，可靠性高"。

**这在方法论上是错的**——双位置提高的是"存在性"的可信度（不是误读、不是提取假象），**不提高"来源独立性"**。

真正独立的来源是应用服务端记录或银行流水。

**正确的表述**：「该内容在 WAL 旧页镜像与主库 freelist 两个物理位置均检出，且逻辑上已不存在于任何表。三条事实互相印证：内容曾被写入 → 内容已被删除 → 删除后字节未被覆写。两个位置同源于同一次删除操作，不构成来源独立性印证，但其对"内容确实存在于该文件"的证明力高于单位置。」

其三，把已删除内容与活跃记录 1063 混为一谈。

本次 `SELECT count(*) FROM pay_record WHERE amount = 8800` 返回 1，很容易让人以为"删除的内容就是这条活跃记录"。判据是**逐字符比对**：

| 位置 | `remark` 完整文本 |
|---|---|
| 活跃记录 1063 | `先转 8800 到 5188****2277` |
| freelist / WAL | `转账备注：先转 8800 到 5188****2277，尾号 277` |

**三处差异**：freelist 版本多了前缀"转账备注："、多了后缀"尾号 277"、且 `pay_record` 表的 schema 里根本没有"转账备注："这个前缀格式（remark 列的活跃记录都不带该前缀）。**这是两条不同的记录，措辞不同。**

按错误判据走的代价：报告把两者当作同一条，得出"该转账已被删除" —— 而它实际上还活着。委托方据此认为交易记录被清除，实际数据完整存在。这是一个把证据反向解读的误判，危害比漏报更大。

**第四个实操细节**：提取 WAL 页时要**指定 seq 号**。同一页号有多个版本，dump 哪一个决定了拿到什么内容。

判据是先 `--list-frames` 看清版本分布，再决定 dump 目标。

本次 dump 的是 seq 5（旧版本），因为要找的是被覆盖前的历史内容；若要的是当前有效内容，dump seq 7 即可——那个内容在主库里已经有了。

<a id="section-34"></a>

## 六、扩展阅读方向

**前置与基础。** WAL 格式本身要先读透。校验和算法的字节序细节、
salt 与 checkpoint 序列的精确语义、以及跨进程读取时共享内存的可见性，
这三点是后面所有判断的地基。wal-index 的结构同样属于必读：
`-shm` 的内存布局、读事务标记，以及里面可恢复的访问时间信息，
往往是判断「最后访问时间」的唯一来源。

**同层深入。** 崩溃一致性是这一章的分水岭。断电时刻的 WAL 尾部
可能停在任意位置，此时 hot journal 的判定与 `.recover` 的配合方式
决定了能捞回多少。加密库与 WAL 的交互是另一处深水区：
以 SQLCipher 及商业变体为例，WAL 页的加密范围与密钥交互顺序
需要单独确认，日志里出现明文不代表没加密。

**相邻议题。** 并发写入场景下，多进程共享同一库时的写入交错、
锁与重试痕迹会互相覆盖，必要时要靠帧头的 salt 值判断页的新旧。
跨库关联则要求把同一业务在主库、WAL、缓存库、SharedPreferences
之间的时间线合并起来，单看一个库很容易得出过时的结论。

**工具与判据。** `sqlite_dissect`、`sqlite3_analyzer` 这类工具
在 WAL 场景下各有能力边界，读它的输出之前得先知道它默认忽略了什么；
工具之间互相印证的结果才值得采信。

**判据与反例。** 「主库里没有这条记录」更可能是它还在 WAL 里没被 checkpoint，
而不是数据不存在——这一误判的现象、影响与核查见陷阱 1 与陷阱 9。
三文件联合提取之后如何做时区归一与完整性校验并写进报告，
见 [《数据库取证通用方法》](mobile-database-database-forensics-methods.md)。

---

<a id="section-35"></a>

## 七、命令速查

```bash
# ===== 提取：三文件必须一起 =====
PKG=com.digiforensics.sample
DEV=/data/user/0/$PKG/databases
adb shell su -c "ls -la $DEV"                          # ① 先看清有哪些文件
adb shell su -c "tar -cf - -C $DEV ." > dbset.tar      # ② 整目录一次性导出
sha256sum dbset.tar | tee dbset.sha256                 # ③ 立刻固定哈希
tar -xf dbset.tar -C work && chmod -R a-w work/app.db* # ④ 归档副本只读

# ===== 判定：是不是 WAL 模式 =====
xxd -s 18 -l 2 app.db                                  # 0202=WAL  0101=journal

# ===== 校验：WAL 是否真的有效 =====
python3 wal_scan.py app.db-wal                        # 头校验和 + 逐帧 salt/校验和
python3 wal_dump.py app.db-wal 3 page3                # 抽取指定页的旧镜像

# ===== 解析：三件套齐备时自动合并 =====
cp app.db full.db && cp app.db-wal full.db-wal && cp app.db-shm full.db-shm
sqlite3 full.db "PRAGMA journal_mode;"
sqlite3 full.db "PRAGMA wal_checkpoint(PASSIVE);"
sqlite3 full.db "SELECT count(*) FROM pay_record;"

# ===== 只读观察：不触碰原件 =====
sqlite3 "file:app.db?immutable=1" "PRAGMA integrity_check;"
sqlite3 "file:app.db?immutable=1" "PRAGMA freelist_count;"

# ===== 损坏库应急 =====
sqlite3 damaged.db ".recover" > recovered.sql          # 以实际版本支持情况为准
sqlite3 recovered.db "PRAGMA integrity_check;"
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 移动与数据库取证 — SQLite WAL 取证」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《SQLite WAL 取证》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-mem.raw` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
