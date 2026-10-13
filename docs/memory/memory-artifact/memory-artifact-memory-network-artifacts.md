---
title: "网络连接与流量痕迹"
slug: "memory-artifact-memory-network-artifacts"
canonical: "https://www.digiforensics.cn/wiki/memory-artifact-memory-network-artifacts"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:51+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "memory"
space: "内存与专项取证"
node_path: ["内存工件"]
---

# 网络连接与流量痕迹

<a id="section-1"></a>

## 一、概述

内存中的连接结构可用于分析"这台机器当时在和谁通信"，并与日志记录交叉核对。

原因是它记录的是**协议栈的实际状态**，而不是"被记录下来的行为"。代理、防火墙、IDS 日志都要配置，可能丢包，可能只记一部分；内存里的 `TCB` 结构是当时连接的真实快照。

但这里有一条必须先知道的路：**内核池里的网络结构会残留已释放的数据。**

内核的分页池分配器不会主动清零已释放的内存。一个连接关闭后 `TCB` 被释放回池，字段里仍保留着旧的 IP、端口和 PID。后果很具体：`netscan` 显示一条 `ESTABLISHED` 到境外 IP 的连接，看起来足以定案——**但它可能几小时前就关闭了**。单凭 `netscan` 输出认定"该机当时与某 IP 建立了连接"，在方法论上站不住。

这一步落在**关联环节**，上游是内存镜像与已完成的进程定位，下游是外传类结论的定性。它提供的是"方向"，不是"结论"——要认定数据外传，流量侧必须独立支撑。

与采集环节的耦合点在于时间：内存里的连接是**采集区间内**的状态，与 PCAP 的时间线对齐方式决定了能不能做因果论证。

可用的对象与判据如下：

| 对象 | 具体形态 | 关键字段/判据 |
|---|---|---|
| 内核网络结构 | `TCB`、`UDP_ENDPOINT`、`TCP_ENDPOINT` | 状态字段、索引项、PID |
| 枚举方式 | `netscan`（扫池，**含残留**）vs `netstat`（遍历结构，**仅当前活动**） | 两者结果是否一致 |
| 连接归属 | 本地端口 → PID → 进程映像路径 | 归属链条是否闭合 |
| 明文残留 | 内存中的域名、URL、HTTP 头、请求体 | 是否有上下文可判定方向 |
| 抓包侧 | `DigiForensics.pcap`、NetFlow 导出、防火墙日志 | 与内存侧的时间对齐 |

第二行是核心：`netscan` 与 `netstat` 的差异不是工具选择问题，而是方法论问题。两者的一致性本身就是一项判据。

据此能回答的是这些：采集区间内存在哪些连接、它们归属哪个进程、连的是哪个 IP 与端口、内存里是否残留了明文通信内容（域名、URL、请求体）、某个 IP 是否与已知的可疑基础设施吻合。

回答不了的是这些。它不能单侧认定"发生了数据外传"——连接存在与内容外传是两件事，后者需要流量侧或落盘侧独立支撑。它也给出不了精确到秒的行为顺序，内存证据的时序精度受采集耗时限制。

往下读之前，先确认你已经掌握：TCP 状态机与端口的基本概念、内存镜像的基本可用性、以及至少一种把 PID 与进程对应起来的方法。镜像还没有，先看[内存采集方法](../memory-acquire/memory-acquire-memory-acquisition-methods.md)；要跟抓包做时序对齐，先看[PCAP 网络流量取证](../memory-network/memory-network-pcap.md)里的结论强度分级口径。

连接指向远控软件时，去[远程工具凭据解密](../../crypto/crypto-app/crypto-app-remote-tool-credential-preservation.md)看同一批凭据在磁盘侧的固定方法。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 `netscan` 与 `netstat` 的原理差异

两者输出看起来相似，原理却完全不同。

**`netstat` —— 遍历内核维护的活动链表**

```
内核全局变量：TcpCompartmentSet / UdpCompartmentSet
        ↓
遍历活动连接链表（每个 TCP 端点一个 TCB）
        ↓
只包含【当前处于活动状态】的连接
```

> 这与 `tasklist`、`netstat -ano` 看到的是同一份数据——因为它们都走内核的活动链表。

`netscan` —— 扫描内核池，搜索结构特征

```
遍历物理内存的每一个页
        ↓
搜索符合 TCB / UDP_ENDPOINT 特征模式的字节
        ↓
对每个候选做有效性校验
        ↓
输出【所有能找到的】结构，包括已释放后残留的
```

| 维度 | `netscan` | `netstat` |
|---|---|---|
| 方法 | **扫描**内核池 | **遍历**活动链表 |
| 已关闭的连接 | **能发现**（可能） | **看不到** |
| 已释放的残留 | **会误报** | **不会** |
| 证据强度 | 线索，需验证 | **较强**（内核视角的当前态） |

**`netscan` 能发现已关闭连接的价值是真的**：一次短暂的 beacon 通信可能只持续几秒，抓包抓不到，日志可能没开，**但内核池里还留着结构**。

这让它成为发现"短暂外联"的独门工具。

代价就是 stale data 误报。

<a id="section-4"></a>

### 2.2 stale data（陈旧数据）的成因

```
T1 连接建立，分配 TCB，写入 remote IP/port/PID/状态
T2 连接关闭，内核释放 TCB
   ↑ 释放 ≠ 清零！分页池只把这段内存标记为"可复用"
T3 该内存块被其他对象部分复用（覆盖了部分字段）
T4 采集内存
T5 netscan 扫描 → 若 TCB 特征字段仍"看起来合法"，就被报出
```

**为什么残留字段"看起来合法"**：

- IP 是 4 字节固定值，**被复用后可能恰好又是合法 IP**
- 端口是 2 字节，几乎任何值都合法
- 状态字段（`TcpState`）在固定偏移，**释放时没被改**，所以仍是 `ESTABLISHED`
- **PID 字段可能被新对象覆盖成别的进程 PID**——最危险，会**错误归因到无辜进程**

> **必须记住**：stale data 影响的不只是"连接是否存在"，还包括"**是哪个进程**"。这是误伤无辜进程的高发点。

<a id="section-5"></a>

### 2.3 TCP 状态的语义区分

| 状态 | 含义 | 取证意义 |
|---|---|---|
| `ESTABLISHED` | 连接已建立且活动 | **最需关注，但注意 stale 误报** |
| `SYN_SENT` / `SYN_RECV` | 握手进行中 | 外连尝试 |
| `LISTENING` | 监听端口 | **后门驻留的直接信号** |
| `TIME_WAIT` | 主动关闭方等待 | 证明此前的连接**确实发生过** |
| `CLOSE_WAIT` | 对端已关闭，本地未释放 | 应用层异常，程序未正确关闭 |

> `TIME_WAIT` 与 `CLOSED` 的区别很关键：`TIME_WAIT` 残留**本身就是有效证据**——它表明连接**确实建立过**且是本机主动关闭的。孤立的 `ESTABLISHED` 残留**不能证明任何事**。**这是判读 netscan 的实用过滤器。**

<a id="section-6"></a>

### 2.4 端口与 IP 的解读

| 端口 | 用途 | 说明 |
|---|---|---|
| **4444** | Metasploit 默认 payload 端口 | 经典后门端口 |
| **1337** | 常见于各类工具默认 | 需结合进程判断 |
| **8080 / 8443** | 代理 / 备用 HTTPS | 本身正常，但常被滥用 |
| **9001 / 9050** | Tor SOCKS 默认端口 | 匿名网络 |
| **53**（非标准源端口） | DNS 外传通道 | 隐蔽信道 |
| **5555 / 6666 / 7777** | 常见反连端口 | 批量扫描特征 |

> **但"异常端口"不等于恶意**。企业环境的代理、监控 agent、数据库同步都用常见端口。**端口是线索，不是结论。**

**IP 判读要点**：

- **RFC 1918 私有地址**（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`）：**不说明任何问题**
- **回环**（`127.0.0.1`）、**链路本地**（`169.254.0.0/16`）：本机内部通信 / DHCP 失败地址，通常无意义
- **公网 IP**：需查归属。**但要警惕"CDN IP ≠ 真实服务端"**——域名的解析结果往往是 CDN 节点
- **IPv6**：注意是否有 IPv4 映射地址（`::ffff:a.b.c.d` 形式）

<a id="section-7"></a>

### 2.5 内存中的明文通信内容

网络结构里只有 IP 和端口，**真正的通信内容在别处**：HTTP 请求/响应在套接字缓冲区与进程堆，聊天/邮件正文在客户端进程的消息结构，浏览器表单与页面缓存在浏览器进程内存，文件传输片段在套接字缓冲区。

提取手段都是 `dumpfiles` 配合定向 `strings`。

> ⚠️ **重要现实**：现代 HTTPS 流量在内存里也是加密的，**直接搜不到明文**。但**三个位置仍可能有明文**：
> 1. TLS 握手的 SNI（Server Name Indication）字段——客户端为加速/共享而明文发送的服务名，**这是 HTTPS 下最可靠的可见线索**
> 2. **应用层在加密前写入缓冲区的数据**
> 3. **证书链中的域名信息**
>
> **SNI 的取证价值极高**：它能证明"这台机器曾尝试连接某个域名"，即使流量加密。`strings` 输出中域名通常是明文 ASCII 或 UTF-8。

<a id="section-8"></a>

### 2.6 内存与抓包的互补

| 能力 | 内存 | 抓包 |
|---|---|---|
| 已关闭的连接 | **可能可见**（池残留） | ❌ 已关闭永远看不到 |
| 加密流量内容 | 看不到明文 | 看不到明文 |
| 域名（SNI） | **可从内存字符串提取** | 可从握手包提取 |
| 事后分析 | ✅ 可反复分析同一份镜像 | ❌ 需重新采集 |
| 需要预置 | 需事先装好抓包工具 | **必须事先部署** |

> **核心互补关系**：抓包必须事先部署，事后再想抓已经来不及；内存是事后唯一的机会，但内容层面受限于当时应用状态。**两者结合**：`netscan` 告诉你"有连接到这个 IP"→ 查威胁情报 → 拿 IP 换到具体域名 → 在内存里 grep 该域名找证据链。

内存的时间戳精度不够做因果排序，Sysmon 事件 3/7 的连接记录带毫秒级时间且落在日志里，能与 `netscan` 结果逐条对齐，聚合与导出方式见[Sysmon 与日志聚合](../../computer/computer-registry-log/computer-registry-log-sysmon.md)。

---

<a id="section-9"></a>

## 三、操作步骤

<a id="section-10"></a>

### 3.1 第 1 步：枚举连接（两个插件都要跑）

```bash
# netstat：内核活动链表（当前真实状态）；netscan：内核池扫描（含已关闭连接与残留）
python3 vol.py -f DigiForensics-mem.raw -r csv windows.netstat > netstat.csv
python3 vol.py -f DigiForensics-mem.raw -r csv windows.netscan  > netscan.csv
head -1 netstat.csv ; head -1 netscan.csv        # 先确认列名
```

<a id="section-11"></a>

### 3.2 第 2 步：交叉验证（**本篇核心步骤，不可跳过**）

> ⚠️ **先确认列位**。`-r csv` 的输出**第一列是 `TreeDepth`**，其后才是插件的实体列。`netscan` 与 `netstat` 的列定义**完全一致**（源码核实，两者 `TreeGrid` 逐字段相同），共 10 个实体列 + 1 个 `TreeDepth`：
>
> | `$1` | `$2` | `$3` | `$4` | `$5` | `$6` | `$7` | **`$8`** | `$9` | `$10` | `$11` |
> |---|---|---|---|---|---|---|---|---|---|---|
> | TreeDepth | Offset | Proto | **LocalAddr** | **LocalPort** | **ForeignAddr** | **ForeignPort** | **State** | PID | Owner | Created |
>
> 所以"四元组 + 状态"的键是 **`$4|$5|$6|$7|$8`**。`$9` 是 **PID**，不是状态——**把 `$9` 当状态用是本步骤最常见的错误**，它会让"仅 netscan 有"的集合里混进同一连接的不同进程归属，比对结论直接失效。**漏掉 `TreeDepth` 同样会影响结果**：会让整体错位一列。

```bash
# 键 = 四元组 + 状态 = $4|$5|$6|$7|$8（$9 是 PID，别搞错）
awk -F',' 'NR>1 {gsub(/"/,""); print $4"|"$5"|"$6"|"$7"|"$8}' netstat.csv \
  | sort -u > /tmp/netstat_keys.txt
awk -F',' 'NR>1 {gsub(/"/,""); print $4"|"$5"|"$6"|"$7"|"$8}' netscan.csv \
  | sort -u > /tmp/netscan_keys.txt
comm -13 /tmp/netstat_keys.txt /tmp/netscan_keys.txt | tee /tmp/only-netscan.txt  # 仅 netscan 有
comm -23 /tmp/netstat_keys.txt /tmp/netscan_keys.txt                              # 仅 netstat 有

# C) PID 归属不一致（stale data 典型特征）：把 PID 并入键做二次比对
awk -F',' 'NR>1 {gsub(/"/,""); print $4"|"$5"|"$6"|"$7"|"$8"|"$9}' netscan.csv \
  | sort -u > /tmp/netscan_withpid.txt
awk -F',' 'NR>1 {gsub(/"/,""); print $4"|"$5"|"$6"|"$7"|"$8"|"$9}' netstat.csv \
  | sort -u > /tmp/netstat_withpid.txt
comm -13 /tmp/netstat_withpid.txt /tmp/netscan_withpid.txt
```

**判读规则表（务必写进报告）**：

| 情形 | 解释 | 结论写法 |
|---|---|---|
| **两边都有** | 采集时刻确实活动的连接 | **可作为结论，强度最高** |
| 仅 netscan 有，`ESTABLISHED` | **可能已关闭，也可能纯属残留** | ⚠️ **不能下结论**，须另有证据；标注"待验证" |
| **仅 netscan 有，`TIME_WAIT`** | 连接**确实建立过**，本机主动关闭 | 可作为"曾有连接"的证据，强度中等 |
| **仅 netscan 有，`LISTENING`** | 端口监听，可能是残留 | ⚠️ 不能下结论，需与 `netstat` 和磁盘侧交叉 |
| **仅 netstat 有** | netscan 漏检 | 以 netstat 为准 |

> **为什么"TIME_WAIT 更可信"**：`TIME_WAIT` 是 TCP 正常关闭流程产生的**活跃状态**——残留的 `TCB` 状态字段虽然没被清，但要成为 `TIME_WAIT` 必须曾经真的进入过这个状态。相比之下 `ESTABLISHED` 是连接存续最长的状态，也是最常被残留保存的值，最容易被"冒充"。

<a id="section-12"></a>

### 3.3 第 3 步：筛选高价值连接

```bash
# 只看公网出口连接（过滤私有地址和回环）
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.netstat \
  | grep -vE '10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.0\.0\.|0\.0\.0\.0'
# 监听端口（后门驻留信号） / 高危端口
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.netstat | grep -i 'LISTENING'
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.netstat \
  | grep -iE ':(4444|1337|9001|9050|5555|6666|7777) '
# netscan 的公网连接（按 3.2 交叉验证后才能引用）
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.netscan \
  | grep -vE '10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.0\.0\.|0\.0\.0\.0' \
  | tee /work/netscan-public.txt
```

<a id="section-13"></a>

### 3.4 第 4 步：定位连接归属进程

```bash
# 从 netstat 输出拿 PID，再查该进程
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.pslist | grep -E '\s<PID>$|<可疑PID>'
# 可疑进程的完整命令行（判断它是否"本该"联网）
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.cmdline --pid <PID>
# 进程加载了什么（判断是真实浏览器还是伪装）
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.dlllist --pid <PID>
# 该进程的注入检查（并发是后门常见行为）
python3 vol.py -f DigiForensics-mem.raw -r csv windows.malware.malfind --pid <PID>
```

> **归属判断的关键**：**不是每个网络进程都该有网络连接。** `notepad.exe` 有外连、Word 进程连到公网 IP、系统服务连到非常规端口——这些都需要解释。

<a id="section-14"></a>

### 3.5 第 5 步：从内存提取域名与 URL

> ⚠️ **必须分块扫描**。`strings -a -n 6 DigiForensics-mem.raw` 会把整个镜像读进管道，16 GB 起步的镜像足以 OOM。定义一个可复用的分块函数（`bs=1M` 在 GNU/BSD 的 `dd` 上都可用，`skip` 的单位是**块**不是字节）：

```bash
IMG=DigiForensics-mem.raw

# 用法: scan_img <正则> <输出文件> [最小串长]
scan_img () {
  local re="$1" out="$2" min="${3:-6}" size step=64 i=0
  size=$(wc -c < "$IMG")
  : > "$out"
  while [ $((i*step)) -lt "$size" ]; do
    dd if="$IMG" bs=1M skip=$((i*step)) count="$step" status=none 2>/dev/null \
      | strings -a -n "$min" | grep -iE "$re" >> "$out" || true
    i=$((i+1))
  done
  sort -u -o "$out" "$out"
  wc -l "$out"
}

# 全量域名清单
scan_img '\.(com|net|org|cn|ru|top|xyz|info)([^a-z]|$)' /work/domains.txt
head -50 /work/domains.txt

# 可疑 TLD（TK/ML/GA/CF/GQ/Top/XYZ/zip/mov/pw/cc 等滥用托管）
scan_img '\.(tk|ml|ga|cf|gq|top|xyz|zip|mov|pw|cc)([^a-z]|$)' /work/suspicious-tld.txt

# C2 面板常见路径特征（最小串长放宽到 8，命中率更高）
scan_img '/(gate|panel|login|update|check|beacon|task|report|upload)\.php' \
  /work/c2-paths.txt 8

# 用 netscan 拿到的 IP 反查上下文（通常能看到 Host 头或 JSON 载荷）
scan_img '203\.0\.113\.45' /work/ip-context.txt
head -20 /work/ip-context.txt
```

> **块边界会切断字符串**：分块扫描会漏掉恰好跨在 64 MiB 边界上的串。实践中把 `step` 从 64 降到 32、或对高价值 IP 单独提高 `-n` 精度后重扫即可。这属于已知且可说明的局限，写进报告即可，不要假装"已完整覆盖"。

<a id="section-15"></a>

### 3.6 第 6 步：提取通信内容

```bash
# 导出某进程内存中缓存的文件（含套接字缓冲、下载内容等）
mkdir -p /work/filedump
python3 vol.py -f DigiForensics-mem.raw -o /work/filedump \
  windows.dumpfiles --pid <可疑PID> --dump

# 签名与 HTTP 头提取
for f in /work/filedump/*; do echo "=== $(basename $f) ==="; file "$f"; done
strings -a /work/filedump/* 2>/dev/null \
  | grep -iE '^(GET|POST|HTTP/|Host:|User-Agent:|Authorization:|Cookie:)' \
  | sort -u | head -40
```

<a id="section-16"></a>

### 3.7 第 7 步：与其他证据交叉

内存里的 IP 必须在**另一个独立来源**找到对应记录，才能作为可靠结论。

孤证不立。

可用的交叉源：

- **磁盘侧**：浏览器历史、Hosts 文件、下载目录；
- **日志侧**：Windows 高级防火墙日志、Sysmon 事件 3（网络连接，**默认关闭**，需事先配置）、代理服务器日志。

> ⚠️ 注意方向性：`netscan` 是**事后**唯一还能看到已关闭连接的机会，但它的独有信息恰好又是**最不可靠**的那部分。交叉验证的方向是"用可靠源确认不可靠源的候选"，不是反过来。

---
<a id="section-17"></a>

## 四、常见陷阱

网络内存痕迹的核心问题是**证据的强度与其形态的相关性是反的**：最有说服力的那条（一条活动的对外 `ESTABLISHED`）恰恰最可能不是真的，最不显眼的那条（内存里的明文 HTTP 请求）反而最可靠。

本章按插件原理差异、CSV 列位、stale data 归因、IP 端口解读、字符串提取、结论表述六个环节展开。

<a id="section-18"></a>

### 4.1 插件原理与交叉验证

<a id="section-19"></a>

#### 陷阱 1：直接引用 `netscan` 的 `ESTABLISHED` 作为结论

**现象**：`netscan` 输出一条 `192.168.1.100:50021 → 203.0.113.45:443 ESTABLISHED`，报告写"查获时该机正在与 203.0.113.45 建立加密连接"。

**原因**：1 把这个坑称为本板块最需要警惕的。内核的内存分配器**不会主动清零已释放的内存**——连接关闭后 TCB 结构被释放回分页池，**但字段仍保留旧的 IP、端口、PID、状态值**。2.2 的时间轴把这讲得很细：T2 释放 ≠ 清零，T3 该内存块可能被其他对象**部分**复用（覆盖部分字段），T5 扫描时若特征字段"看起来合法"就被报出。而状态字段（`TcpState`）在固定偏移、释放时没被改，所以仍是 `ESTABLISHED`。2.1 的对照表直接标注：`netscan` 的"已释放的残留"一项是"**会误报**"。

**影响**：案例第 2 步给出了教科书级的形态——netscan 里两条到 `203.0.113.45` 的 `ESTABLISHED`（PID 6180），在 `netstat` 里查 PID 6180 只有一条**指向完全不同 IP** 的 `CLOSE_WAIT`。

如果不做交叉验证，这条连接几乎可以蒙混过关成为"确证"，而它实际上什么都不证明。

案例的引文把"排除了一个看似最有力的证据"称为本案最有价值的一条。

**核查**：**`netscan` 的输出是候选，不是结论**。

3.2 的判读规则表把"两边都有"标为"可作为结论，强度最高"，把"仅 netscan 有 + `ESTABLISHED`"标为「⚠️ **不能下结论**，须另有证据；标注"待验证"」。

引用 netscan 结果前必须先跑 `netstat` 并做差集比对，这一步是 3.2 标题里写明的"**本篇核心步骤，不可跳过**"。

<a id="section-20"></a>

#### 陷阱 2：只跑 `netscan` 或只跑 `netstat`

**现象**：只跑了 `netscan`，看到 61 条连接逐条分析；或者只跑了 `netstat`，看到 34 条就写"该机当时的外联连接如下"。

**原因**：两者的能力集是**互补而非包含**的。2.1 的对照表显示 `netstat` **看不到**已关闭的连接，`netscan` **会误报**残留。`netscan` 的独有价值在 2.1 的引文里讲得很具体——一次短暂的 beacon 通信可能只持续几秒，抓包抓不到，日志可能没开，但内核池里还留着结构，这让它成为发现"短暂外联"的独门工具。而 `netstat` 走内核活动链表，与 `tasklist`、`netstat -ano` 看到的是同一份数据，可靠性最高。**任何单独使用都会得出片面结论**，且两种片面的方向相反。

**影响**：只跑 `netstat` 会漏掉最隐蔽的通信（而这正是委托方最关心的"是否有隐蔽外联"）；只跑 `netscan` 会把一堆残留当成活动连接，让报告充满无法辩护的结论。

案例第 1 步两个都跑并记录条数（34 / 61）——**差值 27 条本身就需要解释**，这个动作是后续所有分析的起点。

**核查**：**两个都跑、都存档、都做差集**。

3.1 是"两个插件都要跑"，3.2 的差集比对是核心步骤。

差值出现时不要急着逐条看内容，**先看差值规模**：差值越大，残留的可能性越高。

<a id="section-21"></a>

#### 陷阱 3：差集方向搞反

**现象**：`comm -13` 和 `comm -23` 用反了，把"仅 netstat 有"当成"仅 netscan 有"，判读规则整个颠倒。

**原因**：`comm` 的参数语义是「只在第一个文件、`只在第二个文件`、`两个文件都有`（`-1`/`-2`/`-3` 前缀）。`comm -13 A B` 输出的是"**只在 B 中**"的行。3.2 的代码块里 `A` 是 netstat_keys、`B` 是 netscan_keys，所以 `-13` 出来的才是"仅 netscan 有"。速查的注释也专门标了「`-13` = 只在右边（netscan）」。

方向搞反的风险在于：判读规则表是按"仅 netscan 有"这一情形写的结论，方向一反，"不能下结论"就变成了"以 netstat 为准"，性质完全相反。

**影响**：把不能下的结论变成了可下的结论，等于绕过了本篇的核心防线。

而且这个错误**不会报错**——`comm` 正常输出，差集非空，流程走完。

**核查**：**在命令里写注释标明方向**（速查的写法就是这样），或者用更直白的方式：分别用 `grep -Fxf` 做双向包含检查。

无论哪种方式，都要在报告里记录"仅 netscan 有 N 条、仅 netstat 有 M 条"这两个数字，这样复核时方向错误会立刻暴露。

<a id="section-22"></a>

#### 陷阱 4：CSV 列位取错，`$9` 当成状态用

**现象**：差集比对跑完，"仅 netscan 有"的集合里出现了同一个连接的不同进程归属，判读完全失效。

**原因**：3.2 的列位表（本篇做过源码核实，`netscan` 与 `netstat` 的 `TreeGrid` 逐字段相同）给出了确切位置：`-r csv` 输出**第一列是 `TreeDepth`**，其后是 `Offset, Proto, LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner, Created`。所以状态是 **`$8`**，**`$9` 是 PID**。原文直接点明：「**把 `$9` 当状态用是本步骤最常见的错误**，它会让"仅 netscan 有"的集合里混进同一连接的不同进程归属，比对结论直接失效」。还有一个连带错误——**漏掉 `TreeDepth` 会让整体错位一列**，此时 `$4` 变成了 `LocalPort`，键完全无意义。

**影响**：交叉验证失效，而这个失效是**静默**的——差集看起来合理，判读规则套上去也说得通，最后得出一个错误的排除或错误的确认。

案例第 2 步的判读正是靠"同一 IP 在 netscan 中对应两个不同 PID"这个现象发现矛盾的，而这个判读的前提就是列位正确。

**核查**：**先 `head -1` 确认表头再切列**（3.1 的命令里就有这一步）。

键的构造固定为 `$4|$5|$6|$7|$8`（四元组 + 状态），PID 归属的二次比对固定为 `$4|$5|$6|$7|$8|$9`。

**把列位表抄进报告的方法论章节**——它同时说明了比对是如何做的。

<a id="section-23"></a>

### 4.2 stale data 与归因

<a id="section-24"></a>

#### 陷阱 5：stale data 导致错误归因到无辜进程

**现象**：`netscan` 显示某外连连接的 PID 是 6844，报告写"进程 6844 与境外 IP 通信"，并对该进程定性。

**原因**：2.2 的引文框直接警告——「PID 字段可能被新对象覆盖成别的进程 PID——最危险，会错误归因到无辜进程」，并强调「stale data 影响的不只是"连接是否存在"，还包括"**是哪个进程**"。这是误伤无辜进程的高发点」。机制在时间轴里：T3 那一步"该内存块被其他对象**部分**复用"，被复用的恰好可能是 PID 字段。所以一个已经关闭的连接，其 PID 可能指向一个当时完全无关的进程。

**影响**：**误伤无辜进程**是最难挽回的一类错误。

你不仅给出了错误的技术结论，还在报告里给一个无关进程贴上了恶意标签——如果那个进程属于一个正常运行的业务系统，委托方的第一反应是"你们的分析不可靠"。

案例第 4 步的归属结论之所以能被定为"强"，是因为它靠的是**进程命令行 + 内存内容归属**（`svchost -k wuauserv` 持有该域名的明文内容），**不是靠 netscan 的 PID 字段**。

**核查**：**归属结论必须有第二个独立证据**。

3.4 的归属链条就是四步——`pslist` 查 PID 是否存在且活动、`cmdline` 看命令行是否"本该"联网、`dlllist` 判断进程真身、`malfind` 查注入。

案例第 3 步正是靠内存里提取到的 `Host: cdn-update-check.example.com` 与 `GET /api/v2/manifest` 明文内容，再结合 PID 4928 的命令行，才建立归属。

netscan 的 PID 只能作为检索线索，不能作为归属依据。

<a id="section-25"></a>

#### 陷阱 6：把 `TIME_WAIT` 写成"当时活跃"

**现象**：在 netscan 的差集里看到 `TIME_WAIT` 状态的连接，报告写"采集时该机与某 IP 处于通信状态"。

**原因**：`TIME_WAIT` 与 `ESTABLISHED` 的证据性质不同，这一点 2.3 的引文框讲得很清楚——**`TIME_WAIT` 残留本身就是有效证据**，它表明连接**确实建立过**且是本机主动关闭的；而孤立的 `ESTABLISHED` 残留不能证明任何事。3.2 的引文进一步解释了为什么 `TIME_WAIT` 更可信：它要成为 `TIME_WAIT` **必须曾经真的进入过这个状态**（`ESTABLISHED` 是存续最长的状态，最容易被残留保存、最容易被"冒充"）。"曾建立过"与"采集时活跃"是两个不同强度的命题。

**影响**：混淆这两个命题，会让一个中等强度的证据被当成最强证据使用。

反过来，若把 `TIME_WAIT` 判成"不可信"而丢弃，又会浪费掉 netscan 最有价值的那部分输出。

**核查**：**表述精确到命题**。

`TIME_WAIT` 写"该机曾与 X 建立过连接，本机为关闭方"，强度中等；`ESTABLISHED` 且 `netstat` 里没有，写"发现候选连接，**待验证**"，不下结论。

3.2 判读规则表里这三行（两边都有 / 仅 netscan+`ESTABLISHED` / 仅 netscan+`TIME_WAIT`）**应该原样进报告**。

<a id="section-26"></a>

#### 陷阱 7：只看 netscan 的一处矛盾就排除，没做全局一致性检查

**现象**：某条连接在 netscan 里有、netstat 里没有，就单独把它排除，不看其它同类条目。

**原因**：案例第 2 步给出的排除依据比"不在 netstat 里"更硬——它用了**双重矛盾**：① PID 6180 在 netstat 里的实际连接**指向完全不同的 IP**（`91.198.174.192:443` 的 `CLOSE_WAIT`）；② 同一 IP `203.0.113.45` 在 netscan 中还对应 PID 4928 的 `TIME_WAIT`——同一 IP 出现在不同 PID 上，说明这些结构**来自不同时刻，绝不可能是同一次活动的连接**。第二个论据是全局性的，它一句话排除了该 IP 的全部 netscan 条目，而不只是一条。

**影响**：逐条排除会把同一来源的多个条目当成独立事件处理，**导致重复计数和归因分散**。

而真正有力的证据是结构性的——**同一 IP 出现在不同 PID 上**这类现象说明的是"这批 netscan 条目来自不同时间点"这个整体事实。

**核查**：**按 IP / 按四元组做聚类分析**，而不是逐条判定。

检查：同一 IP 是否对应多个 PID？同一 PID 是否对应多个不相关的远端？状态与 PID 的组合是否自洽？

这些**结构性异常**是残留的强指纹，**一旦出现，该批次条目整体降级**。

案例的结论表把这条写成"强（**已明确排除**）"，依据正是这个结构性论证。

<a id="section-27"></a>

### 4.3 IP、端口与协议解读

<a id="section-28"></a>

#### 陷阱 8：把私有 IP、回环地址当外联证据

**现象**：把 `192.168.x.x`、`10.x.x.x`、`127.0.0.1` 的连接列为"网络活动"并写进报告。

**原因**：2.4 的判读要点写得很直接——**RFC 1918 私有地址不说明任何问题**，**回环、链路本地**（`127.0.0.1`、`169.254.0.0/16`）是本机内部通信 / DHCP 失败地址，**通常无意义**。这些是内网通信的正常形态，在 `netstat` 输出里占大多数。

**影响**：稀释报告。

把几十条内网连接列成"网络活动"，真正对外的那几条就被埋掉了。

3.3 的第一条命令就是先 `grep -vE` 过滤掉这些地址段，正是为了避免这个问题。

**核查**：**筛出公网出口连接再分析**（3.3 的第一条命令）。

`169.254.0.0/16` 值得单独留意——它是 DHCP 失败时的地址，**出现它意味着网络配置有问题**，本身可以是一个发现，但含义与"外联"无关。

<a id="section-29"></a>

#### 陷阱 9：把异常端口直接定性为恶意

**现象**：看到 `:4444`、`:9001`、`:9050` 就定性为后门 / Tor 通信。

**原因**：2.4 的端口表本身列出的说明里，4444 是"经典后门端口"、9001/9050 是"Tor SOCKS 默认端口"，但表格最后那句话是关键——**"异常端口"不等于恶意**，企业环境的代理、监控 agent、数据库同步都用常见端口。

**端口是线索，不是结论**——这与 2.4 对 LOLBin 的判读要点是同一个原则（可疑的不是"它是什么"，而是"它的目标是否异常"）。

**影响**：假阳性。而且端口类结论特别容易被反驳：委托方只需拿出"我们公司的监控 agent 就用这个端口"就能推翻。

**核查**：**端口必须结合进程身份**。

3.3 筛出高危端口后，第一件事是 3.4 的归属链——这个端口是哪个进程持有、它的命令行是否合理、它是真身还是伪装（`dlllist`）、有没有注入。

只有"异常端口 + 不该联网的进程 + 无合理解释"三者同时成立才构成发现。

<a id="section-30"></a>

#### 陷阱 10：把 CDN IP 当成攻击者 IP

**现象**：`netscan` 显示连接到某个云服务商 IP，查一下 ASN 觉得"可疑"，报告写"疑似连接到攻击者控制的服务器"。

**原因**：2.4 的 IP 判读要点明确提醒——要警惕"CDN IP ≠ 真实服务端"，域名的解析结果往往是 CDN 节点。一个 IP 属于某云服务商，这个事实对它承载了多少个租户的服务没有任何提示。案例第 2 步里 PID 6180 的实际连接是 `91.198.174.192:443`，被标注为"正常 CDN"——同一个案例里，CDN 连接和可疑连接出现在同一个 `svchost` 的不同 PID 上，这恰好说明 IP 层面的相似性毫无意义。

**影响**：**错误归因到具体攻击组织**，这是一个需要证据支撑的强定性。

威胁情报查询结果（IP 属于某服务商/某云）只能说明基础设施归属，**不能说明使用者身份**。IP 复用、云主机、代理出口都会让归属判断完全失效。

**核查**：**IP 证据必须升级到域名层**。

2.6 的引文给出了路径——`netscan` 告诉你"有连接到这个 IP"→ 查威胁情报 → **拿 IP 换到具体域名** → 在内存里 grep 该域名找证据链。

案例第 3 步正是这么做的：`ip-context.txt` 里的 `Host: cdn-update-check.example.com` 才是有价值的发现，而那个 IP 本身不是。

委托方要的是"与谁通信"，答案是域名，不是云厂商的 IP 段。

<a id="section-31"></a>

#### 陷阱 11：用 IPv4 的结果否定 IPv6 排查

**现象**：IPv4 侧排查干净，报告结论只写"未发现异常网络连接"，不提 IPv6。

**原因**：2.4 的最后一条判读要点就是注意是否有 IPv4 映射地址（`::ffff:a.b.c.d` 形式）——双栈环境里，同一个连接在 `netscan`/`netstat` 输出里可能以 `::ffff:` 形式出现，也可能是纯 IPv6 地址。**只筛 IPv4 会漏掉整类连接**，而且漏得悄无声息（因为 `::ffff:` 形式里嵌着 IPv4，用只匹配点分四段式的正则反而可能误命中，使得"IPv6 排查"看起来做了但结论错误）。

**影响**：覆盖不全的阴性结论。

而且 IPv6 在现代企业网络里是常态，不是边缘情况。

**核查**：**两种栈都要查**。

先看输出里的地址形态分布（`grep -c '::'`），再决定过滤规则——过滤 IPv6 时要**同时排除 `::ffff:` 映射地址**，否则会把它们当成 IPv6 连接重复统计。

阴性结论里逐项说明"IPv4 共 N 条已检、IPv6 共 M 条已检"，这样覆盖范围是明确的。

<a id="section-32"></a>

### 4.4 字符串提取与明文内容

<a id="section-33"></a>

#### 陷阱 12：以为 HTTPS 流量能从内存看明文

**现象**：在内存里 `grep` 某个 HTTPS 站点的关键词，搜不到，报告写"未发现与该站点的通信"。

**原因**：2.5 的警告框把现实讲得很清楚——现代 HTTPS 流量在内存里也是加密的，直接搜不到明文。2.6 的对照表里"加密流量内容"这一行，内存和抓包**都是"看不到明文"**。所以"搜不到"是加密的预期结果，**不是通信不存在的证据**。这不是工具能力问题，是协议设计。

**影响**：与"只看磁盘找 PowerShell 痕迹"（[第 08 篇](../memory-analyze/memory-analyze-memory-injection-and-evasion.md)）同型的方向性错误——**用最弱的方法检验了最强的假设**，把协议的必然结果当成了阴性证据。

**核查**：**转攻三个明文位置**（2.5 明确列出）：① **TLS 握手的 SNI 字段**——客户端为加速/共享而明文发送的服务名，**这是 HTTPS 下最可靠的可见线索**；② **应用层在加密前写入缓冲区的数据**；③ **证书链中的域名信息**。

案例第 3 步用的是第一类的近亲——**内存里的明文 HTTP 请求**（`Host:` 头 + `GET` 行），它能成立是因为那个连接在应用层是明文 HTTP。

没有明文就退到 SNI 和证书域名，不要硬找密文载荷。

<a id="section-34"></a>

#### 陷阱 13：`strings` 一次性读完整个大镜像导致 OOM

**现象**：`strings -a -n 6 DigiForensics-mem.raw > domains.txt`，命令跑了很久后被 kill，或者分析机内存耗尽。

**原因**：3.5 的警告框说得很直接——这会把整个镜像读进管道，16 GB 起步的镜像足以 OOM。`strings` 会缓冲输入并输出全部匹配，任何版本的 `strings` 在 GB 级输入上都会占满内存。**32 GB 镜像会导致 OOM**（这在采集时是正常配置，但分析机往往不是）。

**影响**：命令被 kill 后**已经写入的输出文件是不完整的**（如果重定向到文件），而你可能没注意到它提前中断了——**得到一份看起来正常但不完整的域名清单**，然后基于它做阴性结论。

**核查**：**用 3.5 的 `scan_img` 分块函数**。

它以 `dd bs=1M skip= count=` 逐块送入 `strings`，每块独立处理，内存占用恒定；最后 `sort -u` 去重。

要注意 `dd` 的 `skip` 单位是**块**不是字节（`bs=1M` 时 `skip=1` 表示跳过 1 MiB），速查里保留了这个细节。

<a id="section-35"></a>

#### 陷阱 14：分块扫描的块边界切断字符串，当成"已完整覆盖"

**现象**：`scan_img` 跑完，某个高价值 IP 的上下文只搜到半条字符串，报告按"未发现更多上下文"写。

**原因**：3.5 的引文指出了这个结构性局限——**块边界会切断字符串**，分块扫描会漏掉恰好跨在 64 MiB 边界上的串。这是分块的固有代价，**不是 bug**。原文的态度也很明确：「这属于已知且可说明的局限，写进报告即可，不要假装"已完整覆盖"」。

**影响**：把工具的已知局限伪装成完整覆盖。

如果报告里写"已全量扫描内存中的通信内容"，而实际漏了一部分边界串，这句话是不可辩护的——对方只要构造一个跨边界的高价值串就能证明你的覆盖声明不成立。

**核查**：**把局限写进报告**，并给出缓解措施——把 `step` 从 64 降到 32（减半边界命中概率）、对高价值 IP 单独提高 `-n` 精度后重扫。

**更稳的做法是对已定位的区域定向重扫**（用 `dumpfiles` 导出可疑进程的内存空间再搜，那里没有块边界问题）。

报告里写"分块扫描（块大小 64 MiB），跨块边界的字符串可能被截断，已通过块大小减半与定向重扫覆盖高价值目标"。

<a id="section-36"></a>

#### 陷阱 15：管道 `grep` 匹配到任意列就当结果

**现象**：用 `grep -i 'LISTENING'` 或 `grep -E '^(GET|POST|...)'` 过滤输出，结果里出现无关内容。

**原因**：`grep` 对**整行**做匹配，**任何位置命中都算**。在 `netstat` 的 CSV 里，端口号、IP、Owner 名称任意一处含 `LISTENING` 都会命中；在 `dumpfiles` 导出的文件里，二进制内容里偶然出现的 `GET` 字样也会命中。**先看表头、确认列名后再筛**（3.1、3.3 的命令里都有 `head -1` 这一步）。

**影响**：假阳性进入结论。

`grep -i 'LISTENING'` 命中一条 `LISTENING` 状态但地址是 `0.0.0.0:445` 的常规服务共享，与"后门监听"的含义完全不同。

**核查**：**先 `-r csv` 导出，用列名精确定位**（`--filters` 是按列名子串过滤，见[第 03 篇](../memory-acquire/memory-acquire-volatility3.md)）。

`strings` 提取通信内容时用**行首锚定**（3.6 的 `^(GET|POST|HTTP/|Host:...)` 就是这个处理），并且**先 `file` 确认导出对象的类型**——对二进制内容做行首锚定的字符串搜索本身就有误报可能。

<a id="section-37"></a>

### 4.5 结论表述与阴性发现

<a id="section-38"></a>

#### 陷阱 16：把"netscan 发现"当唯一依据做归属定性

**现象**：整个网络结论都建立在 `netscan` 输出的基础上，没有引入第二个证据源。

**原因**：3.7 的原则是**孤证不立**——内存里的 IP 必须在**另一个独立来源**找到对应记录，才能作为可靠结论。而 3.7 的警告框点出了方向性这个关键点：`netscan` 是事后唯一还能看到已关闭连接的机会，但它的独有信息恰好又是最不可靠的那部分。所以交叉验证的方向是"用可靠源确认不可靠源的候选"，不是反过来——不能用 netscan 去"确认"防火墙日志或浏览器历史。

**影响**：结论的证据结构是空的。

可用的交叉源 3.7 列了三类——磁盘侧（浏览器历史、Hosts 文件、下载目录）、日志侧（Windows 高级防火墙日志、Sysmon 事件 3，注意**默认关闭，需事先配置**）、代理服务器日志。

一个都不查就出结论，等于把"技术手段的输出"当成了"事实"。

**核查**：netscan 的每一条目都要走一遍"可靠源确认"流程，确认不了的标为"待验证"。案例第 3 步转向内存明文内容（`ip-context.txt`、`domains.txt`）、第 4 步转向进程归属（`cmdline` + `malfind`）——这才是把 netscan 的候选转成可靠结论的路径，也是案例引文强调"实际成立的证据比那条被排除的连接更有价值，且不依赖 netscan"的原因。

<a id="section-39"></a>

#### 陷阱 17：Linux 上套用 `netscan`

**现象**：拿到 Linux 内存镜像后跑 `windows.netscan`（或照抄本篇命令），报错或输出异常，转而认为"该镜像分析不了"。

**原因**：Volatility 3 的 Linux 插件没有 `netscan`。2.4（[第 03 篇](../memory-acquire/memory-acquire-volatility3.md)）的警告框点名了一批"看起来合理但不存在"的插件名，**`linux.netscan` 正在其中**——它看起来合理是因为 Windows 侧确实有这个插件名。Linux 侧的对应能力由 `linux.sockstat`（套接字统计）、`linux.ip.Addr`（接口地址）承担。

**影响**：把插件名不存在误判成镜像或工具链有问题。

而且这会连带错过 Linux 侧的对应分析（内核模块的 netfilter 钩子检查、`linux.lsof` 打开的套接字等），导致该镜像的网络侧结论缺失。

**核查**：**先 `vol.py -h` 核对实际可用插件**（[第 03 篇](../memory-acquire/memory-acquire-volatility3.md)3.5 的固化脚本就是这个用途），Linux 侧用 `linux.sockstat` / `linux.ip.Addr`，深度分析见[第 09 篇](memory-artifact-linux-android.md)。

**报告里写明用的是哪个插件、覆盖了哪些结构类型**——Linux 与 Windows 的网络工件机制不同，结论的适用范围也不同。
<a id="section-40"></a>

## 五、案例示例

<a id="section-41"></a>

### 5.1 netstat 与 netscan 差集的 PID 归属矛盾排除

**场景**

查获一台 Windows 11 笔记本的内存镜像 `DigiForensics-mem.raw`（16 GB RAM）。委托方要求确认"该机是否与某境外组织控制的基础设施通信"。

这条路径的难点在于：`netscan` 输出里直接出现了两条到目标 IP 的 `ESTABLISHED` 记录。

如果不加验证就写进报告，这会是最有力也最脆弱的一条证据 —— 它足以支撑指控，但只要对方做一次交叉核对就会发现是错的。

**处置过程**

两个插件都跑，因为它们走的是完全不同的内核结构：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -r csv windows.netstat > /work/netstat.csv
$ python3 vol.py -f DigiForensics-mem.raw -r csv windows.netscan  > /work/netscan.csv
netstat: 34 条
netscan:  61 条
```

**27 条差值本身就需要解释**，不是因为 27 是可疑数字，而是因为差值意味着两个数据源的覆盖范围不同。

构造可比对的键并做差集。

**键必须包含四元组 + 状态 + PID**，只用四元组会把同一地址不同状态的记录混在一起：

```bash
$ python3 - <<'PY' > /tmp/netstat_keys.txt
import csv
for r in csv.DictReader(open('/work/netstat.csv', encoding='utf-8')):
    print('%s %s:%s %s:%s %s %s' % (r['Proto'], r['LocalAddr'], r['LocalPort'],
          r['ForeignAddr'], r['ForeignPort'], r['State'], r['PID']))
PY

$ python3 - <<'PY' > /tmp/netscan_keys.txt
import csv
for r in csv.DictReader(open('/work/netscan.csv', encoding='utf-8')):
    print('%s %s:%s %s:%s %s %s' % (r['Proto'], r['Laddr'], r['LPort'],
          r['Raddr'], r['RPort'], r['State'], r['PID']))
PY

$ comm -13 <(sort /tmp/netstat_keys.txt) <(sort /tmp/netscan_keys.txt) | head -30
TCPv4  192.168.1.100:50021  203.0.113.45:443    ESTABLISHED  6180
TCPv4  192.168.1.100:50037  198.51.100.22:4444  ESTABLISHED  6180
TCPv4  192.168.1.100:50102  203.0.113.45:443    TIME_WAIT    4928
```

**PID 6180 是第一条记录的 PID。** 核对它在 `netstat`（活动链表）里的实际连接：

```bash
$ grep '6180' /work/netstat.csv
Proto  LocalAddr          LocalPort  ForeignAddr      ForeignPort  State       PID
TCPv4  192.168.1.100:50019  91.198.174.192:443   ESTABLISHED  6180
TCPv4  192.168.1.100:50044  93.184.216.34:443    CLOSE_WAIT   6180
```

同一个 PID 6180，在活动链表里持有的是到 `91.198.174.192`（正常 CDN）和 `93.184.216.34` 的连接，完全不涉及 `203.0.113.45`。

再核对第二点 —— 同一 IP 出现在不同 PID 上：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -r csv windows.netscan | grep '203.0.113.45'
Proto  Laddr                 LPort  Raddr          RPort  State        PID  Owner
TCPv4  192.168.1.100:50021   50021  203.0.113.45   443    ESTABLISHED  6180  -
TCPv4  192.168.1.100:50037   50037  198.51.100.22 4444   ESTABLISHED  6180  -
TCPv4  192.168.1.100:50102   50102  203.0.113.45   443    TIME_WAIT    4928  svchost.exe
```

`203.0.113.45` 同时出现在 PID 6180（`ESTABLISHED`）和 PID 4928（`TIME_WAIT`）名下，且 6180 那两行的 `Owner` 列为 `-`（无关联进程对象）。

一个 IP 出现在两个不同时刻的不同 PID 下，说明这些结构体来自不同的历史时刻，不可能属于同一次活动。

**结论**

| netscan 中的记录 | 判定 | 依据 |
|---|---|---|
| PID 6180 → `203.0.113.45:443 ESTABLISHED` | **内核池残留，非活动连接** | 同 PID 在活动链表的连接指向完全不同的 IP；`Owner` 列为空 |
| PID 6180 → `198.51.100.22:4444 ESTABLISHED` | 同上，池残留 | 同上 |
| PID 4928 → `203.0.113.45:443 TIME_WAIT` | 结构真实，但状态表明连接已结束 | 归属 `svchost.exe`，与 6180 的记录非同一时刻 |

| 结论 | 强度 |
|---|---|
| netscan 中两条 `ESTABLISHED` **不能作为通信证据** | 强（PID 归属矛盾 + Owner 空 + 跨 PID 同 IP） |
| `203.0.113.45` 相关结构确实存在于内存池 | 强 |
| 该 IP 在采集时刻无活动连接 | 中（`netstat` 活动链表内无对应项） |

**能证明的**：内存池中存在指向该 IP 的连接结构；采集时刻的活动连接表中不含该 IP。

**不能证明的**：不能证明"该机从未与该 IP 通信"。

池残留恰恰说明**过去某个时刻**有过相关结构 —— 它证明历史接触，不证明当前活跃。

**未覆盖范围**：仅在采集窗口内、对 `netstat`（活动 TCP 表）与 `netscan`（内存池扫描）两个维度做比对；未覆盖 UDP 端点的 `netstat` 等价项、已被覆盖复用的内核池块、以及镜像时间窗口之外的通信。

**误判对照**

这是本篇最重要的一个误判：看到 `ESTABLISHED` 就当成"正在通信"。

`netscan` 扫的是非分页/分页内存池中的 `TCP_ENDPOINT` 结构。

内核池是**循环复用的** —— 一个 TCP 连接结束、其结构被释放回池后，池块不会立即被清零。后续新的连接对象分配到同一地址，会覆盖旧内容；但在下一次覆盖之前，旧的结构体连同其中的地址、端口、状态字段会原样留在内存里。

正确判据是三条同时成立才认定"正在通信"：

1. **在活动表中存在** —— `windows.netstat` 遍历内核活动 TCP 表，该 IP 必须在此出现
2. **PID 归属一致** —— netscan 记录与 netstat 记录中的 PID 必须对应同一进程
3. **Owner 字段非空** —— netscan 的 `Owner` 列能关联到 `_EPROCESS`；为空说明结构已失去进程上下文

本次三条**全部不满足**。

按错误判据走，代价是最严重的：报告里写"检出与目标基础设施的活动通信连接"，而复核方只需跑一条 `netstat` 就能看到该 IP 根本不在活动表里 —— 这条证据一旦被推翻，同报告中依赖它的其他结论都会受质疑。

反向也要注意：不要因为排除了 netscan 的记录，就认为该 IP 完全无关。

`TIME_WAIT` 那条（PID 4928）**归属清晰、状态明确**，它是真实的历史连接痕迹。

正确做法是把它降级使用 —— 作为"曾发生接触"的证据，而不是"正在通信"的证据。

**排除的是结论强度，不是事实本身。**

<a id="section-42"></a>

### 5.2 服务宿主持有非预期域名的内容归属

**场景**

承接 5.1。排除了 netscan 的误导记录后，需要回答一个更本质的问题：**那台机器上到底有没有指向目标基础设施的痕迹？**

答案在内存里的明文通信内容上。这条路径的判定逻辑是"域名 → 内容 → 持有进程 → 该进程是否合理持有它"，四层逐级收窄。

**处置过程**

第一步，提取全镜像字符串并检索目标 IP 的上下文：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -q windows.vadyarascan \
    --pid 4928 --pattern "203.0.113.45" --dump > /work/ip-context.txt
$ grep -iF '203.0.113.45' /work/ip-context.txt | head -20
Host: cdn-update-check.example.com
GET /api/v2/manifest HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/120
Accept: application/json
```

第二步，交叉检索域名本身，确认字符串的独立存在：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -q windows.vadyarascan \
    --pattern "cdn-update-check.example.com" | head
0x1f2a0000  0x7ff6a1234000  cdn-update-check.example.com
0x1f2b0000  0x7ff6a1234000  /api/v2/manifest
0x1f2c0000  0x7ff6a1234000  {"client":"...","uuid":"8f3a...","ts":1773475200}
```

**三处独立命中**，且第三条是一段结构化 JSON（含 `uuid` 与时间戳 `ts`）。

这不是随机的字节残留。

第三步，定位持有进程并核对其职责：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -r pretty windows.cmdline | grep '4928'
4928   C:\Windows\system32\svchost.exe -k wuauserv -p
```

`-k wuauserv` 是 Windows Update 服务组。**该服务组的正常网络行为是访问微软更新基础设施**，持有指向其他域名的 HTTP 请求内容与它的职责不符。

第四步，把这个不符与注入检测结果合并：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -r csv windows.malware.malfind \
    | grep -E '4928|7124'
PID   Process     Start       VAD              Size    Protection
4928  svchost.exe 0x1a4e2000  0x7ff6a1234000   0x18000  PAGE_EXECUTE_READWRITE
7124  svchost.exe 0x1a3e5000  0x7ff7a1230000   0x2a000  PAGE_EXECUTE_READWRITE
```

4928 与 7124 是两个不同 PID 的 svchost，**都命中 RWX 私有页注入**。

7124 正是 5.1 中发现的那个摘链隐藏进程。

第五步，验证注入区确实承载了这段内容 —— 把内容归属与注入位置对应起来：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -q windows.vadinfo --pid 4928 \
    | awk '$1 ~ /^0x7ff6a1234000/ {print $1, $3, $4, $5}'
0x7ff6a1234000  0x18000  PAGE_EXECUTE_READWRITE  Private
```

域名字符串的 VA 落在 `0x7ff6a1234000` 起始的注入区内（`0x1f2a0000` 是 VAD 内的偏移，所属 VAD 基址为 `0x7ff6a1234000`）。

**内容、注入区、进程三者对齐。**

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| `cdn-update-check.example.com` 与其请求内容存在于该机内存 | `vadyarascan` 三处独立命中，含完整 HTTP 头与结构化 JSON | 强 |
| 该内容由 PID 4928 持有 | `--pid 4928` 限定下的命中；`cmdline` 显示为 `svchost -k wuauserv` | 强 |
| 该进程持有与其职责不符的内容 | wuauserv 服务组的预期目标为微软更新基础设施 | 中（基于服务职责的推断） |
| 该进程内存在注入代码 | `malfind` 命中 `PAGE_EXECUTE_READWRITE` + `Size=0x18000` | 强 |
| 该机存在两组独立的异常进程 | 4928 与 7124 均为注入命中，7124 另有摘链特征 | 强 |

**能证明的**：采集时刻该机内存中存在指向该基础设施的 HTTP 请求内容，且该内容位于一个被注入的服务宿主进程的私有可执行区内。

**不能证明的**：
- **不能证明通信成功**。内存里有请求内容，不等于收到了响应，更不等于上传了数据
- **不能证明数据外传**。要证明外传需要响应内容、流量体积、或对端日志
- **不能证明该进程被攻击的时间**。内存内容没有创建时间

**未覆盖范围**：仅在采集窗口内、对 PID 4928 的 VAD 空间做了明文检索；**未覆盖** TLS 加密连接的内容、已释放的 VAD、以及该进程可能存在的其他注入区。

**误判对照**

这个案例的误判在于**"域名 + 进程"就算闭环**。

判据要落到"职责符合性"这一层上。

`svchost.exe -k wuauserv` 持有 HTTP 请求内容，这本身不说明问题 —— 任何 Windows 组件都可能在内存里残留别人的内容（共享的 DLL 缓冲、页面缓存、堆残留）。

**关键判据是这个内容与持有者的角色是否匹配。**

三级判据：

| 层级 | 判据 | 本案 |
|---|---|---|
| 内容存在 | 字符串在内存中出现 | ✅ 三处命中 |
| 归属明确 | 限定 `--pid` 后仍命中，且落在注入区而非共享缓冲 | ✅ VA 在注入区内 |
| 职责不符 | 持有者的服务组职责与内容指向不符 | ✅ wuauserv vs 非微软域名 |

三条同时成立才构成"该进程持有异常内容"的结论。

只满足第一条时报"内存中存在可疑域名"是成立的；满足前两条时报"该进程持有可疑内容"是勉强的；三条全满足才能报"该进程职责与行为不符"。

第二个误判方向是把"职责不符"直接写成"该进程已被控制"。

判据是**职责不符只说明行为异常，不说明原因**。可能是：进程被注入并以宿主身份发起通信、进程内的其他组件（某个被污染的共享库）发起了通信、或内容只是被动残留。

要归因到具体机制，需要在注入区内容层面做进一步归属分析 —— 本案未覆盖这一步，所以结论强度只到"职责不符"。

按最激进的判据（"svchost 里有不明域名 = 已被控"）走，代价是报告中出现了**超出证据的归因**。

委托方据此采取处置措施（隔离整个域控节点）后，若复核发现只是被动残留，处置措施与结论的差距会成为责任问题。

第三个容易忽略的点：`ts` 字段。

JSON 里的 `"ts":1773475200` 是一个 Unix 时间戳，可以换算成绝对时间并与采集窗口、USN 日志、网络日志做时间线对齐。

这类内嵌时间戳是内存证据里少有的、可独立验证时间归属的字段，本案未充分利用 —— 报告里应当写明"该时间戳已换算为 X，与 Y 记录吻合/不吻合"，而不是只把 JSON 当内容存在性证据。

<a id="section-43"></a>

## 六、扩展阅读方向

内存里的连接记录有一个特殊的双重性：它比日志完整，又比日志更容易被误读。

下面五组材料分别补的是交叉验证、协议侧深挖、归属定性、落盘对照、结论边界。

<a id="section-44"></a>

### 6.1 交叉验证：把单一来源变成两条证据

这一组解决本篇最核心的风险——`netscan` 报出的连接可能只是内核池残留。任何一条要写进报告的连接，都需要第二条独立路径确认。

- [PCAP 网络流量取证](../memory-network/memory-network-pcap.md)——流量侧如何独立支撑外传结论，结论强度分级表是全库通用口径。
- [SRUM 数据库分析](../../computer/computer-browser-behavior/computer-browser-behavior-srum.md)——落盘的应用流量统计，可与内存连接互为印证。
- [浏览器取证](../../computer/computer-browser-behavior/computer-browser-behavior-browser-forensics.md)——浏览器侧的连接与访问痕迹，内存里挖出的 URL 需要它来落地。
- [事件日志深度分析](../../computer/computer-registry-log/computer-registry-log-windows-event-log-analysis.md)——防火墙、服务与网络相关事件，是内存灭失后的替代面。
- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md)——当两侧时间线矛盾时，判断哪一侧被操纵。

<a id="section-45"></a>

### 6.2 协议深挖与归属定性

这两组相邻议题解决同一个问题的两个环节：连接存在不等于内容外传，而外传需要归属到具体进程。 要判定外传，光有 IP 和端口不够，需要协议层内容特征把连接归属到行为。

- [Sysmon 与日志聚合](../../computer/computer-registry-log/computer-registry-log-sysmon.md)——网络连接事件与进程创建事件的时序拼接，是把连接归属到行为的常用手段。
- [FSEvents 与时间机器](../../computer/computer-log-persistence/computer-log-persistence-fsevents.md)——macOS 侧的连接留存与本地快照，可与内存侧对照。
- [统一日志与 LaunchAgents](../../computer/computer-log-persistence/computer-log-persistence-macos-unified-logs-and-launch-agents.md)——macOS 的统一日志包含网络子系统记录，可与内存侧连接对照。
- [Keychain 与 Safari 痕迹](../../computer/computer-security/computer-security-keychain-safari.md)——浏览器凭据与访问记录的落盘侧形态。
- [进程与注入检测](../memory-analyze/memory-analyze-process-and-injection-detection.md)——PID 到进程的映射、可疑进程判定，是归属链条的起点。
- [注入执行与免杀痕迹](../memory-analyze/memory-analyze-memory-injection-and-evasion.md)——连接由一个被注入了代码的进程发起时，结论的表述方式不同。
- [Shell 痕迹与命令历史](../../computer/computer-shell/computer-shell-shell.md)——Linux 侧的进程与命令行痕迹，跨平台归属对照时必需。

<a id="section-46"></a>

### 6.3 落盘对照：远控与外传工具

这一组把内存里的连接与磁盘上的工具配置对照。光有一条到陌生 IP 的连接，说明不了什么；光有一套远控配置，也说明不了它连过。 两侧合起来才构成"该机具备外传能力且具备外传痕迹"。

- [远程工具凭据解密](../../crypto/crypto-app/crypto-app-remote-tool-credential-preservation.md)——远控软件在磁盘侧的凭据与配置固定方法，与内存侧的连接记录互为补充。
- [浏览器密码库与 Token 解密](../../crypto/crypto-app/crypto-app-browser-passwords-and-tokens.md)——内存里挖出的令牌，落到浏览器凭据库中做交叉确认。
- [计划任务与持久化痕迹](../../computer/computer-persistence/computer-persistence-scheduled-tasks-and-persistence.md)——远控的持久化载体，Linux 侧对照。
- [包管理器与软件清单](../../computer/computer-persistence/computer-persistence-package-manager-and-software-inventory.md)——远控工具的安装痕迹，可与连接时间线比对。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md)——交叉验证动作必须留痕，这是本篇第 2 步不可跳过的理由。
- [SSH 痕迹与密钥取证](../../computer/computer-persistence/computer-persistence-ssh.md)——SSH 外传通道的痕迹，内存里的会话与密钥材料。

<a id="section-47"></a>

### 6.5 判据与边界：报告能怎么写

这一组专门处理结论表述。连接记录里的"方向"要变成"结论"，中间隔着一整套强度分级与阴性发现规则。

- [内存证据的可采性与报告](memory-artifact-memory-evidence-and-reporting.md)——阴性发现的限定写法、结论强度分级、采集痕迹的交代。
- [取证概念与分类](../../fundamentals/fundamentals-concepts/fundamentals-concepts-digital-forensics-concepts.md)——内存侧连接记录的证据地位，以及它与归属证据之间的距离。
- [时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md)——采集区间与连接时间字段的换算，以及时区标注。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md)——提取明文通信内容、第三方通信数据的授权边界与最小化要求；交叉验证动作本身也必须按[取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md)留痕。
<a id="section-48"></a>

## 七、命令速查

```bash
# ===== 1. 两个插件都要跑 =====
python3 vol.py -f DigiForensics-mem.raw -r csv windows.netstat > netstat.csv
python3 vol.py -f DigiForensics-mem.raw -r csv windows.netscan  > netscan.csv
head -1 netstat.csv ; head -1 netscan.csv        # 先确认列名

# ===== 2. 交叉验证（必做）=====
# -r csv 首列是 TreeDepth，实体列从 $2 起
# 列序：TreeDepth,Offset,Proto,LocalAddr,LocalPort,ForeignAddr,ForeignPort,State,PID,Owner,Created
# 键 = 四元组 + 状态 = $4|$5|$6|$7|$8（$9 是 PID，别搞错）
awk -F',' 'NR>1 {gsub(/"/,""); print $4"|"$5"|"$6"|"$7"|"$8}' netstat.csv \
  | sort -u > /tmp/netstat_keys.txt
awk -F',' 'NR>1 {gsub(/"/,""); print $4"|"$5"|"$6"|"$7"|"$8}' netscan.csv \
  | sort -u > /tmp/netscan_keys.txt
comm -13 /tmp/netstat_keys.txt /tmp/netscan_keys.txt   # 仅 netscan 有（残留？已关闭？）
comm -23 /tmp/netstat_keys.txt /tmp/netscan_keys.txt   # 仅 netstat 有（以 netstat 为准）
# 判读：两边都有 → 采集时确实活动（最强）
#        仅 netscan + ESTABLISHED → 可能残留，不能下结论
#        仅 netscan + TIME_WAIT → 证明"曾建立"，不证明"当时活跃"
#        PID 归属与其他条目矛盾 → 判定为残留

# ===== 3. 筛选高价值连接 =====
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.netstat \
  | grep -vE '10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.0\.0\.|0\.0\.0\.0'
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.netstat | grep -i 'LISTENING'
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.netstat \
  | grep -iE ':(4444|1337|9001|9050|5555|6666|7777) '

# ===== 4. 进程归属 =====
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.pslist | grep -E '\s<PID>$'
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.cmdline --pid <PID>
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.dlllist --pid <PID>
python3 vol.py -f DigiForensics-mem.raw -r csv windows.malware.malfind --pid <PID>

# ===== 5. 域名与 URL 提取（分块，勿一次读全镜像）=====
IMG=DigiForensics-mem.raw
scan_img () {  # 用法: scan_img <正则> <输出文件> [最小串长]
  local re="$1" out="$2" min="${3:-6}" size step=64 i=0
  size=$(wc -c < "$IMG"); : > "$out"
  while [ $((i*step)) -lt "$size" ]; do
    dd if="$IMG" bs=1M skip=$((i*step)) count="$step" status=none 2>/dev/null \
      | strings -a -n "$min" | grep -iE "$re" >> "$out" || true
    i=$((i+1))
  done
  sort -u -o "$out" "$out"; wc -l "$out"
}
scan_img '\.(com|net|org|cn|ru|top|xyz|info)([^a-z]|$)' /work/domains.txt
scan_img '\.(tk|ml|ga|cf|gq|top|xyz|zip|mov|pw|cc)([^a-z]|$)' /work/suspicious-tld.txt
scan_img '/(gate|panel|login|update|check|beacon|task|report|upload)\.php' /work/c2-paths.txt 8
scan_img '203\.0\.113\.45' /work/ip-context.txt
head -20 /work/ip-context.txt

# ===== 6. 通信内容提取 =====
mkdir -p /work/filedump
python3 vol.py -f DigiForensics-mem.raw -o /work/filedump windows.dumpfiles --pid <PID> --dump
for f in /work/filedump/*; do echo "=== $(basename $f) ==="; file "$f"; done
strings -a /work/filedump/* 2>/dev/null | grep -iE '^(GET|POST|HTTP/|Host:|User-Agent:|Authorization:)' \
  | sort -u | head -40

# ===== Linux（注意：没有 netscan）=====
python3 vol.py -f DigiForensics-mem.raw linux.sockstat
python3 vol.py -f DigiForensics-mem.raw linux.ip.Addr
python3 vol.py -f DigiForensics-mem.raw linux.sockscan
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 内存与专项分析 — 网络连接与流量痕迹」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《网络连接与流量痕迹》（CC BY-SA 4.0）`

文中 `DigiForensics-mem.raw` 为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。

---
