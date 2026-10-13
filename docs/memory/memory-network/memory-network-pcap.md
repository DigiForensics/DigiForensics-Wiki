---
title: "网络流量与 PCAP 取证"
slug: "memory-network-pcap"
canonical: "https://www.digiforensics.cn/wiki/memory-network-pcap"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:49+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "memory"
space: "内存与专项取证"
node_path: ["网络痕迹"]
---

# 网络流量与 PCAP 取证

> **关键词**：PCAP、PCAPNG、NetFlow、会话重组、TLS 元数据、HTTP 对象导出、JA3、snaplen、内容缺口
> **难度**：进阶
> **前置知识**：[内存取证总览](../memory-acquire/memory-acquire-memory-forensics-overview.md)、TCP/IP 协议栈、五层模型、文件哈希

**技术边界声明**：本文只讨论对**已获授权**检材中网络流量证据的离线分析。全文不涉及中间人劫持、证书透明性投毒、TLS 会话密钥提取、无线握手破解等主动干预手段。需要解密明文时，唯一的合规路径是依法取得会话密钥或由用户提供解密材料，不得以技术手段绕过加密。


<a id="section-1"></a>

## 一、概述

网络流量是**直接记录数据传输过程的证据类型**——在"数据真的离开过主机"这类命题上，它提供的记录最贴近传输本身。

主机侧工件——浏览器历史、下载目录、Shell 历史、数据库操作日志——都只能证明"本机发生过某个动作"，或者干脆只能证明"某个文件被访问过"。

它们回答不了那个最关键的问题：**这份数据到底有没有走网卡？走到哪里去了？**

流量证据的价值在于它是**传输过程的直接记录**。

但它的局限同样独特，而且是所有证据类型里最容易被夸大的：

- **它是采样的、不是完整的**。抓包点的位置、镜像口的配置、设备的 `snaplen` 设置、运营商的流量留存策略，任何一环都会造成内容缺口。
- **它是密文的、不是明文的**。现代互联网流量绝大部分跑在 TLS 上，你能看到的只有连接元数据，不是内容。
- **它是归属模糊的**。抓到一个公网 IP，这个 IP 可能是攻击者、可能是 CDN 节点、可能是 NAT 出口、可能是运营商透明代理。

所以本篇不打算教你怎么用 Wireshark 点开一个包。

要解决的是另一个问题：**一份抓包能证明什么，不能证明什么。**

一份 PCAP 能可靠支撑的结论层级大致是这样的：

| 结论强度 | 需要的证据 | 表述示例 |
|---|---|---|
| 弱 | 会话存在 | 「该主机在 03-14 09:12:07 向 `203.0.113.44:443` 发起 TCP 连接」 |
| 中 | 传输了某类数据 | 「该连接上传了 4.2 MB 数据，方向为客户端→服务端」 |
| 强 | 内容可识别 | 「上传内容为 ZIP，SHA256 为 `…`，与检材 `DigiForensics-leak.zip` 一致」 |
| 极强 | 内容可归属 | 「上传内容与本案批次的 `DigiForensics-batch-07.xlsx` 逐字节一致」 |

很多报告卡在第二层就开始写第四层的措辞，这是本领域最高频的表述事故。

第四章会专门处理这件事。

还有一件事需要先分清：**流量证据不止 PCAP 一种形态**。

交换机镜像口导出的全包、路由器上的 NetFlow/sFlow 记录、主机本机抓的 loopback 抓包、云厂商的流量镜像日志，是四种性质完全不同的东西。

证据能力差别极大。混为一谈比技术错误更严重。

---

<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 流量证据的三种形态

**形态一：全包抓包（PCAP / PCAPNG）**

保存了每个报文的头部，以及按 `snaplen` 决定是否保存载荷部分。分析能力最强，是本文的主体。典型来源是交换机 SPAN 口、网桥 TAP、主机 `tcpdump`、IDS 旁路。

形态二：流记录（NetFlow v5/v9、sFlow、IPFIX）

不保存报文，只保存「一段时间内某对端点之间的汇总统计」：字节数、包数、起止时间、接口、协议、TCP 标志位、下一跳。体积比全包小两到三个数量级，能保留数天的历史，但**没有载荷**。

形态三：应用层日志（代理日志、CDN 日志、WAF 日志、VPN 网关日志）

由某个具体服务生成，内容是该服务自己看到的请求。最贴近业务语义，但**只覆盖经过该服务的那部分流量**，且字段由服务方定义、可被篡改。

三者的证据地位完全不同：

```text
证据能力
  ↑
  │  ██ 全包抓包      —— 可证明内容、可做重组、可算哈希
  │  ████████ 应用层日志 —— 业务语义清晰，但受服务方视角限制
  │  ██████████████ 流记录 —— 可证连接与流量规模，无内容
  └──────────────────────────────────────→
       覆盖面窄 ←──────────────────────→ 覆盖面宽
```

一个常见误解是"流记录信息少所以没用"。

实际上在长期行为分析上，流记录比全包更有价值——它能告诉你三个月前的连接情况，而全包根本不会被保留三个月。

选错形态会导致**证明力的方向性错误**：拿流记录去做内容结论，或者拿一段 20 分钟的全包去否认长期行为。

<a id="section-4"></a>

### 2.2 采集点决定证据边界

同一个终端的流量，在不同采集点看到的画面完全不同。

这一点必须在分析前想清楚，否则结论会越界。

| 采集点位置 | 能看到 | 看不到 |
|---|---|---|
| 终端本机（网卡抓包） | 该终端**全部**连接，含未加密部分 | 被硬件卸载/内核旁路绕过的流量 |
| 接入交换机 SPAN | 该端口进出全部流量 | 交换机自身管理流量、跨 VLAN 路由后的重写结果 |
| 汇聚/出口路由器 | 该网段**跨出互联网**的流量 | 内部东西向流量、镜像口丢包的部分 |
| 运营商侧 | 跨运营商边界的流量，带五元组 | 明文内容（有合规限制，多已加密） |
| 云 VPC 流日志 | VPC 内东西向流量的元数据 | 载荷内容、VPC 外流量 |

两条推论：

**第一，SPAN 口是「镜像」不是「复制」。** 端口带宽超过镜像口带宽时会**静默丢包**，且交换机通常不报警。

更隐蔽的情况是单镜像口被配置成多个目标端口时，超过源端口速率的流量会随机丢弃。判断方法见 3.3 的丢包检查。

**第二，NAT 会重写地址。** 出口路由器上看到的源地址是**公网出口地址**，不是内网主机的地址。

所以「抓到某主机访问 `1.2.3.4`」这句话在出口侧无法成立——你只能证明「某内网地址经该 NAT 设备访问了 `1.2.3.4`」。

要从地址池反推具体主机，需要配合 DHCP 日志、ARP 表、连接日志、NetFlow 的接口信息或防火墙会话表。

<a id="section-5"></a>

### 2.3 PCAP 容器结构

理解容器结构不是为了手工解析，而是为了**读懂工具报出的警告**。

经典 PCAP 文件由一段 24 字节的文件头加若干条记录组成：

```text
文件头（24 字节，全局唯一）
├── magic         4B  0xa1b2c3d4 = 微秒；0xa1b2c3d4 大端变体 = 纳秒
├── version_major 2B
├── version_minor 2B
├── thiszone      4B  本地时区偏移（几乎所有现代抓包工具写 0）
├── sigfigs       4B  时间戳精度
├── snaplen       4B  每个报文截取的最大长度
└── linktype      4B  链路层类型（1 = Ethernet）

报文记录（每条 16 字节头 + 变长数据）
├── ts_sec        4B  秒
├── ts_usec       4B  微秒（或纳秒）
├── incl_len      4B  实际保存的字节数
└── orig_len      4B  线上原始长度
```

三个字段的含义差别是陷阱的根源：

- `incl_len`（实际保存）可能小于 `orig_len`（线上原始）。差值就是被截断的部分。Wireshark 会在包列表里显示 `[TCP segment of a reassembled TCP message]` 或 `Packet size limited during capture`，在专家信息里标为 `Truncated`。看到 `orig_len > incl_len` 就意味着载荷不全，任何内容层面的结论都不成立。
- **`snaplen` 是全局的**，写在文件头。所有报文按同一上限截。常见配置是 1500（只够以太网头 + IP 头 + 少部分 TCP 载荷）或 262144（足够绝大多数场景）。
- **这个值无法事后修复。** 载荷没抓就是没抓，只能靠别处的证据补，不能靠工具「还原」。

<a id="section-6"></a>

### 2.4 PCAPNG：多接口与元数据

PCAPNG 是 PCAP 的后继格式（RFC 增强版），最重要的差别是**一个文件里可以容纳多个接口**。

PCAPNG 由若干种**块（Block）**构成，每块有类型、长度、内容和填充：

| 块类型 | 名称 | 作用 |
|---|---|---|
| `0x0A0D0D0A` | SHB | Section Header，一个文件可有多个 section |
| `0x00000001` | IDB | Interface Description Block，定义一个接口及其时间基准 |
| `0x00000006` | EPB | Enhanced Packet Block，含报文与可插注释 |
| `0x00000004` | SPB | Simple Packet Block，无时间戳 |
| `0x00000005` | ISB | Interface Statistics Block，含丢包/错误计数 |
| `0x00000008` | NRB | Name Resolution Block，存 IP→名字的解析结果 |

两个实务要点：

第一，`if_name` 与 `if_index` 决定归属。

合并多个来源的抓包时，务必保留接口标识。否则分析时无法区分「内网 A 到 B 的流量」和「同地址的互联网流量」。

命令行导出接口名用 `-e frame.interface_name`，用 `-Y 'frame.interface_name == "eth0"'` 过滤。

第二，`epb_dropcount` 是最有价值却最少被看的字段。

ISB 与 EPB 里都有丢包计数。抓包软件崩溃、被 OOM kill、或者用了轮转抓包而没轮转完，都会留下这个数字。

它一旦非零，整份文件的完整性就有了一个可量化的折扣。

```bash
# 读出接口清单与丢包统计
tshark -r file.pcapng -T fields -e frame.interface_name -e frame.interface_id \
       -e frame.interface_drops_all 2>/dev/null | sort -u
```

<a id="section-7"></a>

### 2.5 三种分析粒度：包、流、重组体

初学者最大的困惑是「Wireshark 到底给我看的是什么」。

实际上它提供了三个粒度，混用会导致结论越界。

**包（packet / frame）** —— 单个 IP 报文的头部视图。回答「这个包从哪来、到哪去、带什么标志位」。

**流（flow / conversation）** —— 按五元组（源 IP、源端口、目的 IP、目的端口、协议）聚合的报文集合。回答「这两端之间总共传了多少、何时开始结束、谁先发起」。`Conversations` 视图和 `conv,tcp` 报表都是这个粒度。

重组体（reassembled stream / object） —— 把跨包的数据按应用层协议重新拼成的连续内容。HTTP 响应体、FTP 文件、SMB 事务、邮件正文的提取都在这一层。

关键区别在于**重组体的完整性不是自动保证的**。

`Follow TCP Stream` 对 HTTP 有效，对 TLS 无效，对自定义二进制协议可能错位——因为 TCP 是字节流，工具靠启发式规则猜边界在哪。

猜错就会得到「前半段正常、后半段乱码」的结果。

因此正确的工作方式是**先看流，再看重组，最后才下内容结论**：

```text
会话表（谁和谁、传了多少）
   ↓ 收敛到可疑的少数流
协议分布（这条流里是什么协议）
   ↓
重组尝试 + 完整性检查
   ↓
哈希比对
   ↓
内容结论
```

跳过前两步直接 Follow Stream 是在几百条流里盲猜，通常只能命中最显眼的那一条。

<a id="section-8"></a>

### 2.6 应用层协议的可读性分层

不是所有协议都能读出内容。分析前先判断目标协议属于哪一层。

| 层级 | 协议示例 | 能拿到什么 | 重组可行性 |
|---|---|---|---|
| 明文文本 | HTTP、SMTP、POP3、FTP 控制通道、Telnet、IRC | 完整内容与语义 | 高 |
| 结构化明文 | DNS、SIP、DHCP、NetBIOS、SMB1 | 结构化字段 | 中 |
| TLS 包裹明文 | HTTPS、IMAPS、POP3S、SMTPS、FTPS | 握手元数据 + 载荷密文 | 载荷不可重组 |
| 应用层自加密 | 某些 IM 的私有协议、SSL VPN 隧道 | 几乎只有连接特征 | 低 |
| 传输层加密 | SSH、IPsec、WireGuard、GRE 封装 | 隧道端点信息 | 载荷不可重组 |
| 静态加密文件传输 | SFTP over HTTP、加密压缩包走 HTTP | 密文块，可作字节证据 | 字节可重组，内容不可读 |

最后一行的实践意义常被低估：**即使内容是密文，重组出的字节依然是有价值的证据**。

它有确定的长度、确定的时间、确定的 SHA256。

如果委托方提供了对应的解密密钥或解密后文件，密文字节的哈希比对可以精确证明「这段传输的内容就是那份文件」。

这是「无法解密」场景下最实用的路径。

<a id="section-9"></a>

### 2.7 TLS 加密面与可见元数据

TLS 的目的是保护内容，但握手过程是明文的，这就是分析工作的入口。理解哪些字段可见、哪些已被加密，才能判断一个结论能不能写。

```text
TCP 三次握手
   ↓
ClientHello  ← 明文
   ├─ legacy_version / supported_versions    协议版本
   ├─ cipher_suites                          密码套件列表（JA3 输入）
   ├─ extensions                            （JA3 输入）
   └─ sni (server_name)                      明文主机名（客户端发）
   ├─ application_layer_protocol_negotiation (ALPN)   h2 / http/1.1
   ├─ supported_groups / signature_algorithms
   └─ key_share                              密钥交换组
   ↓
ServerHello  ← 明文
   ├─ selected_version / cipher_suite
   ├─ extensions
   └─ certificate 明文证书（服务器发）
       ├─ subject / SAN 域名列表
       ├─ serialNumber / 有效期
       └─ 公钥算法与长度
   ↓
   [握手其余部分开始加密]
Application Data ← 密文，此后不可读
```

**SNI 是最有价值也最容易被过度解读的字段。**

三个必须知道的限制：

1. SNI 只在 ClientHello 里明文，服务器名不加密。 但当客户端使用 ECH（Encrypted Client Hello） 或 **ESNI** 时，SNI 被加密，只留下公开的加密扩展，此时抓包只能看到「加密的客户端问候」。
2. QUIC / HTTP3 的 SNI 通常在加密握手包（Initial 包）内，且 Initial 包本身用公开可解的初始密钥保护，所以主流工具仍能解析——但版本演进中这个机制有过变化，工具支持不一致。
3. SNI 是「客户端声称要访问的域名」，不是「实际回应的服务器」。 域名可以指向 CDN 节点、可以被反向代理改写，也可能因为 Hosts 文件或 DNS 劫持而指向任意地址。**SNI 与目的 IP 的不一致本身是有价值的发现**，但不能简单等同于「造假」。

除了 SNI，还有两组值得提取的元数据：

**证书信息** —— 服务器证书的 `SAN` 字段常常暴露内部域名或泛域名（`*.corp.example.com`），是内网测绘的线索。

证书序列号与有效期也能用来关联不同时间抓到的同一台服务器。

**TLS 指纹** —— JA3 是对 ClientHello 的 `CipherSuites`、`Extensions`、`EllipticCurves`、`ECPointFormats` 四项按序拼接后取 MD5 得到的 32 位十六进制串；JA4 改进了排序与截断问题，格式更稳定。

用途是在无法解密内容时，用指纹聚类判断两组连接是否来自同一客户端软件。

```text
同一指纹 + 相同 JA3 + 相同 TLS 库默认配置 → 极可能同一客户端软件
不同指纹但同源 IP + 同时段           → 需进一步区分是多用户还是多进程
```

要注意 JA3 相同不等于同一个人。

大量程序使用相同的库（Python `requests`、Go 标准库、Java 默认栈）会产生完全相同的 JA3。

它的作用是**排除**（不同指纹必然不同软件）而不是**认定**（相同指纹不能证明同一人）。

<a id="section-10"></a>

### 2.8 HTTP 对象导出的完整性问题

Wireshark 的 `File > Export Objects > HTTP` 是最常用的操作，但它的输出**默认不完整**。

这一点在实务中造成过大量误判。

不完整的原因是 HTTP 对象可能来自多个来源：

- **单个完整响应**（有 `Content-Length`，内容在一个响应内）→ 导出成功。
- 分块传输（`Transfer-Encoding: chunked`） → 现代 Wireshark 能正确解码，但老版本会失败。
- **被截断的响应**（`infolen > caplen`）→ 导出的是**前一段**，后面被 `snaplen` 吃掉。
- **分段传输**（Range 请求、大文件断点续传）→ 每次只到一段，导出得到的是碎片。
- **多个对象共享一个流**（HTTP/1.1 流水线）→ 解析错位，取到的可能是两个对象拼接。

因此导出后必须做完整性检查，导出成功不等于内容完整。 检查方法：

```bash
# 1. 看响应体是否以 Wireshark 标记的截断提示结尾（文本类）
file /work/http-objects/200-1.bin
tail -c 200 /work/http-objects/200-1.bin | strings | tail -5

# 2. 与头部声明的长度对比
tshark -r DigiForensics-net.pcap -Y 'http.response' \
  -T fields -e frame.number -e http.content_length -e http.content_length_header

# 3. 对可识别类型直接验证魔数
file /work/http-objects/*.bin | head -20
```

`file` 命令的输出是**最有效的第一道筛子**。

如果导出物被描述为 `data` 而你期望它是 ZIP 或 PE，那基本可以断定重组失败或只拿到了片段。

还有一个隐蔽的坑：**导出的对象没有原始文件名**。

工具用的是 `序号-状态码.bin` 这样的命名。文件在传输时的名称只在 HTTP 请求头或响应头里，导出时需要单独提取并建立映射表：

```bash
tshark -r DigiForensics-net.pcap -Y 'http.request or http.response' \
  -T fields -e frame.number -e http.host -e http.request.uri \
  -e http.content_disposition -e http.request.method \
  -e http.response_for.uri 2>/dev/null | head -30
```

`http.content_disposition` 里的 `filename=` 才是服务端声称的文件名，这个字段经常被忽略，而它往往是唯一的文件名来源。

<a id="section-11"></a>

### 2.9 NetFlow 与全包抓包的分工

流记录的价值在长期行为分析。做一次选型时按这三步判断：

```text
问题是「这 8 小时里发生了什么」？
  → 全包抓包，能看内容

问题是「这三个月里这台主机联系过哪些 IP」？
  → 流记录，PCAP 根本没有三个月

问题是「这台主机一共外传了多少数据」？
  → 流记录（有 src_bytes/dst_bytes），可累加
```

NetFlow 常见版本的关键差异：

| 版本 | 关键字段 | 实务意义 |
|---|---|---|
| v5 | 固定 24 字节记录，7 元组 + 字节/包计数 | 覆盖广但无聚合维度 |
| v9 | 可变长，支持多字段与聚合模板 | 能看到源/目的 AS、接口、掩码 |
| IPFIX | v9 的标准化后继，支持企业自定义字段 | 常见运营商设备默认 |

分析时要特别注意**方向**：`src_bytes` / `dst_bytes` 是**以采集设备视角**计的。

经过 NAT 的会话里，这两列与终端的实际上传/下载方向**可能是反的**。

判断方向要看源地址是不是内网段，而不是看 `src_bytes` 大小就认定是上传。

导出流记录后做汇总：

```bash
tshark -r flow.dat \
  -T fields -e src -e srcport -e dst -e dstport -e prot \
  -e src_bytes -e dst_bytes -e first -e last 2>/dev/null \
  | sort -u > /work/flow-summary.tsv

# 按会话终点聚合，找出外联最多的对端
awk -F'\	' '{print $4}' /work/flow-summary.tsv | sort | uniq -c | sort -rn | head -20
```

<a id="section-12"></a>

### 2.10 时间基准：抓包里最容易出错的一项

抓包的时间戳是一串 64 位整数，解释它需要三个信息，缺一个就会错。

**第一，时区。** 抓包设备不记录时区，只记录 UTC 时刻。`thiszone` 字段几乎所有现代工具都写 0。

这意味着同一个时间戳，在不同分析师手里会被解释成不同时区的不同时刻，差值可达一天。

这在跨时区协作的案件里是真实事故来源。

**第二，时钟偏差。** 抓包主机的系统时间可能不准。

抓包开始前、结束后各与可信时间源对比一次，把偏差记进报告。

这一步的成本是 1 分钟，不做的代价是全部时间线结论都不可靠。

**第三，NTP 跳变。** 采集中途的时间同步会造成时间戳突然前跳或后跳。

表现为时间排序错乱或出现负的时间差。

```bash
# 固定时区解释，并把抓包时间归一到 UTC
tshark -r DigiForensics-net.pcap \
  -t ad -T fields -e frame.time_epoch -e frame.time -e ip.src -e ip.dst 2>/dev/null \
  | head -5

# 抓包主机与可信时间源比对
chronyc tracking 2>/dev/null || ntpq -p 2>/dev/null
timedatectl status 2>/dev/null | head -8
```

报告里的时间表述必须带时区后缀或明确注明，裸时间戳是跨机构复核时最容易产生分歧的地方。

相关换算方法见[时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md)。

---

<a id="section-13"></a>

## 三、操作步骤

以下流程以一份 Linux 抓包主机为例，检材命名为 `DigiForensics-net.pcap`。所有路径、IP、域名均为虚构示例。

<a id="section-14"></a>

### 3.1 第 1 步：登记来源与固定哈希

在碰任何工具之前先固定检材。流量文件的来源信息往往比内容更稀缺，一旦脱离原始来源就再也无法补回。

```bash
mkdir -p /work/net/{objects,reassembled,logs}

# 1. 登记来源（手写或脚本生成，两种都要）
cat > /work/net/case-sources.md <<'EOF'
# 检材来源登记
| 序 | 文件名 | 采集点 | 采集设备 | 起止(本地时区) | 时区 | 提供方 | 备注 |
|---|---|---|---|---|---|---|---|
| 1 | DigiForensics-net.pcap | 出口交换机 Gi0/24 SPAN | 备查见来源单 | 待补 | 待补 | 委托方网络组 | 时钟偏差待测 |
EOF

# 2. 固定哈希（用相对路径保存，便于复现）
cd /work/net
sha256sum DigiForensics-net.pcap | tee logs/hash-original.txt
md5sum    DigiForensics-net.pcap >> logs/hash-original.txt
ls -l --time-style=full-iso DigiForensics-net.pcap
file     DigiForensics-net.pcap

# 3. 立即只读化工作副本（原件不参与任何分析）
chmod 444 DigiForensics-net.pcap
cp --reflink=auto DigiForensics-net.pcap /work/net/DigiForensics-net-work.pcap
```

来源登记里的**时区**一栏不要留空留到后面补。现场问清楚，比事后猜测便宜得多。哈希与保管链的整体要求见[证据保管链与委托证明](../../fundamentals/fundamentals-chain/fundamentals-chain-chain-of-custody-and-authorization.md)。

<a id="section-15"></a>

### 3.2 第 2 步：格式识别与规范化

```bash
# 识别容器格式与基本信息
file DigiForensics-net-work.pcap
capinfos -a -e -c -u -y -I DigiForensics-net-work.pcap 2>/dev/null \
  || tshark -r DigiForensics-net-work.pcap -q -z io,phs 2>/dev/null | head -20

# 统一为 pcapng（保留多接口与注释，比降级成 pcap 更安全）
editcap -F pcapng DigiForensics-net-work.pcap /work/net/DigiForensics-net-normalized.pcapng
capinfos -c -d -u /work/net/DigiForensics-net-normalized.pcapng

# 修正明确的格式性问题：删除两端多余 pad，修正时间戳乱序
editcap -B /work/net/DigiForensics-net-normalized.pcapng \
        /work/net/DigiForensics-net-fixed.pcapng
```

**降级到 pcap 会丢失接口标识**。

如果源文件是 pcapng 且有多个采集接口，直接用 pcapng 工作，不要图省事转换。

<a id="section-16"></a>

### 3.3 第 3 步：规模摸底与丢包检查

这一步的输出决定后面所有结论的可信度。

必须先做完。

```bash
# 1. 总体规模
capinfos -c -a -e -d -M -s \
  /work/net/DigiForensics-net-fixed.pcapng

# 2. 接口清单与丢包计数（pcapng 才有意义）
tshark -r /work/net/DigiForensics-net-fixed.pcapng \
  -T fields -e frame.interface_name -e frame.interface_id -e frame.interface_drops_all 2>/dev/null \
  | sort -u | tee logs/interfaces.txt

# 3. 抓包截断统计：incl_len < orig_len 的报文数
tshark -r /work/net/DigiForensics-net-fixed.pcapng \
  -Y 'frame.cap_len < frame.len' \
  -T fields -e frame.number -e frame.len -e frame.cap_len 2>/dev/null \
  | tee logs/truncated.txt | wc -l

# 4. 截断报文里，最大帧长分布（判断 snaplen 实际取值）
awk -F'\	' '{print $2}' logs/truncated.txt | sort -n | uniq -c | tail -5

# 5. 专家信息里的丢包与重组失败警告
tshark -r /work/net/DigiForensics-net-fixed.pcapng \
  -q -z expert 2>/dev/null | tee logs/expert.txt | head -40

# 6. 时间戳单调性检查
tshark -r /work/net/DigiForensics-net-fixed.pcapng \
  -T fields -e frame.number -e frame.time_epoch 2>/dev/null \
  | awk -F'\	' 'NR>1 && $2 < prev {c++; if(c<=10) print "乱序:", $1, prev, $2} {prev=$2} END {print "总乱序数:", c+0}'
```

**分析结果判读规则**：

| 检查项 | 通过标准 | 不通过时的处理 |
|---|---|---|
| `interface_drops_all` | 全为 0 | 有值则记入报告的完整性折扣，量级大时内容结论降级 |
| 截断报文数 | 接近 0 | 有大量截断则**所有内容层面结论作废**，只保留会话层结论 |
| 专家信息 | 无 `Packet size limited` | 同上 |
| 时间乱序 | 0 或极少 | 大量乱序先查采集中断，别急着分析 |

第 4 项的分布尤其关键。

若被截断报文的原长全部聚在同一个值（比如 1514 或 262144），说明这是 `snaplen` 造成的系统性截断。

分布很散则是另一回事：链路本身的问题，或采集中途换了配置。

<a id="section-17"></a>

### 3.4 第 4 步：会话与端点清单

```bash
cd /work/net

# TCP 会话报表（最常用）
tshark -r DigiForensics-net-fixed.pcapng -q -z conv,tcp 2>/dev/null \
  | tee logs/conv-tcp.txt | head -30

# IP 会话报表
tshark -r DigiForensics-net-fixed.pcapng -q -z conv,ip 2>/dev/null | head -25

# 端点排行
tshark -r DigiForensics-net-fixed.pcapng -q -z endpoints,ip 2>/dev/null | head -25

# 协议分层统计（判断这是不是一份可分析的文件）
tshark -r DigiForensics-net-fixed.pcapng -q -z io,phs 2>/dev/null \
  | tee logs/protocols.txt | head -30

# 会话清单导出为 TSV，便于后续脚本处理
tshark -r DigiForensics-net-fixed.pcapng -q -z conv,tcp 2>/dev/null \
  | awk 'NR>5 && $0 ~ /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print}' \
  > logs/conv-tcp.tsv
```

拿到会话表后先做三件事，而不是立刻钻进某一条流：

1. **划出公网与内网**。`10/8`、`172.16-31/12`、`192.168/16`、`127/8`、`169.254/16` 是内网或链路本地，看到这些地址的一端不构成外联证据。
2. **按数据量排序**，找出传输量最大的若干条会话。
3. **按时间排序**，找出非工作时段仍在活动的会话。

<a id="section-18"></a>

### 3.5 第 5 步：DNS 域名清单

DNS 查询记录是成本最低、覆盖面最广的一步，几乎总能给出方向。

```bash
# 全部 DNS 查询
tshark -r DigiForensics-net-fixed.pcapng -Y 'dns.flags.response == 0' \
  -T fields -e frame.time_epoch -e ip.src -e dns.qry.name 2>/dev/null \
  | sort -u | tee logs/dns-queries.tsv | wc -l

# 只看返回了结果的查询（过滤 NXDOMAIN 与空查询）
tshark -r DigiForensics-net-fixed.pcapng \
  -Y 'dns.flags.response == 1 && dns.flags.rcode == 0' \
  -T fields -e dns.qry.name -e dns.a 2>/dev/null \
  | sort -u | tee logs/dns-resolved.tsv | head -30

# 按域名聚合，看访问频次
cut -f1 logs/dns-resolved.tsv | sort | uniq -c | sort -rn \
  | tee logs/dns-top.txt | head -30

# 找出非常规顶级域与长域名（自动化外联、DGA 特征的粗筛）
cut -f1 logs/dns-queries.tsv | sort -u \
  | grep -vE '\.(com|net|org|cn|gov|edu|io|co|me|info|xyz|top|site|online|club|shop|icu|cfd|vip|wang|link|space|ltd|work|fun|store|tech|cloud|app|dev|pro|net|uk|de|fr|jp|kr|ru|it|nl|se|ca|au|br|in|tw|hk|sg)\s*$' \
  | head -30
```

最后一条粗筛**只能作为线索，不能作为结论依据**。

大量正常站点使用新顶级域或数字顶级域，也存在合法的 CDN 与服务域名。

把它当作"人工复核清单"，不要写成"恶意域名"。

对高价值域名，逐个问三个问题：它与案子的时间线是否吻合、它是否是已知的中转服务、它的解析结果在抓包里是否能与后续连接对上。

<a id="section-19"></a>

### 3.6 第 6 步：HTTP 对象导出

```bash
mkdir -p /work/net/objects
cd /work/net

# 1. 建立「传输 → 文件名」映射（导出物本身没有文件名）
tshark -r DigiForensics-net-fixed.pcapng \
  -Y 'http.request || http.response' \
  -T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst \
                 -e http.host -e http.request.method -e http.request.uri \
                 -e http.response.code -e http.content_type \
                 -e http.content_length -e http.content_disposition 2>/dev/null \
  | tee logs/http-index.tsv | head -20

# 2. 导出（-q 静默，--export-objects 目录必须已存在）
tshark -r DigiForensics-net-fixed.pcapng \
  --export-objects http,/work/net/objects -q 2>/dev/null

# 3. 逐个验证类型与完整性
cd /work/net/objects
for f in *; do
  printf '%-28s %10s  ' "$f" "$(stat -c%s "$f")"
  file -b "$f"
done | tee /work/net/logs/objects-type.txt

# 4. 找出被截断的导出物（文本类以 Wireshark 截断标记结尾）
for f in *.html *.txt *.json *.csv; do
  [ -f "$f" ] || continue
  tail -c 120 "$f" | grep -q 'Wireshark' && echo "疑似截断: $f ($(stat -c%s "$f") 字节)"
done | tee -a /work/net/logs/objects-type.txt

# 5. 目录里的非空文件数——0 就是最典型的失败模式
ls -1 /work/net/objects | wc -l
```

`--export-objects` 参数与 `tshark -r` 之间不能省 `-q` 之外的选项顺序；导出目录**必须预先创建**，否则静默产出 0 个文件。

这是"导出成功但目录为空"最常见的原因。

<a id="section-20"></a>

### 3.7 第 7 步：TLS 元数据与指纹

```bash
# 1. SNI 清单（明文可见的域名）
tshark -r DigiForensics-net-fixed.pcapng -Y 'tls.handshake.type == 1' \
  -T fields -e frame.time_epoch -e ip.dst -e tls.handshake.extensions_server_name 2>/dev/null \
  | sort -u | tee logs/tls-sni.tsv | head -30

# 2. 服务器证书主体与 SAN（内网测绘线索）
tshark -r DigiForensics-net-fixed.pcapng -Y 'tls.handshake.type == 11' \
  -T fields -e ip.src -e x509sat.uTF8String \
                 -e x509ce.dNSName -e x509af.serialNumber 2>/dev/null \
  | sort -u | tee logs/tls-cert.txt | head -20

# 3. 协商结果：协议版本与密码套件
tshark -r DigiForensics-net-fixed.pcapng -Y 'tls.handshake.type == 2' \
  -T fields -e ip.src -e ip.dst \
                 -e tls.handshake.version -e tls.handshake.ciphersuite \
                 -e tls.handshake.extensions_alpn_str 2>/dev/null \
  | sort | uniq -c | sort -rn | head -20

# 4. JA3 指纹（tls.handshake.ja3 需 Wireshark 3.5+）
tshark -r DigiForensics-net-fixed.pcapng -Y 'tls.handshake.type == 1' \
  -T fields -e ip.dst -e tls.handshake.ja3_full 2>/dev/null \
  | sort -u | tee logs/ja3.txt | head -20

# 5. JA4（若支持，格式更稳定）
tshark -r DigiForensics-net-fixed.pcapng -Y 'tls.handshake.type == 1' \
  -T fields -e tls.handshake.ja4 2>/dev/null \
  | sort | uniq -c | sort -rn | head -20

# 6. QUIC / HTTP3
tshark -r DigiForensics-net-fixed.pcapng -Y 'quic' \
  -T fields -e frame.time_epoch -e ip.dst -e tls.handshake.extensions_server_name 2>/dev/null \
  | sort -u | head -20
```

第 3 项的输出同时回答两个问题：目标是否使用了弱套件（如 `TLS_RSA_WITH_AES_128_CBC_SHA` 这类无前向安全性的套件）、以及是否用了 `h2`。

若 ALPN 协商到 `h2` 而抓包工具版本太旧无法解析 HTTP/2 帧，**不能报告为"没有 HTTP 流量"**——这是工具能力问题，不是事实。

<a id="section-21"></a>

### 3.8 第 8 步：重组文件哈希与比对

```bash
cd /work/net

# 1. 对导出对象逐个计算多算法哈希
( cd objects && sha256sum * | tee /work/net/logs/objects-sha256.txt )
( cd objects && md5sum * >> /work/net/logs/objects-sha256.txt )

# 2. 与检材目录内的可疑文件做哈希比对
mkdir -p /work/suspect
grep -rfE ' .*' /dev/null 2>/dev/null   # 占位，保持脚本可读
if [ -d /work/suspect ]; then
  ( cd /work/suspect && sha256sum * 2>/dev/null ) > /work/net/logs/suspect-sha256.txt
  # 内连接只保留完全一致的项
  join -j 1 \
    <(sort /work/net/logs/objects-sha256.txt | grep -E '^[0-9a-f]{64}') \
    <(sort /work/net/logs/suspect-sha256.txt) 2>/dev/null \
    | tee /work/net/logs/hash-match.txt
fi

# 3. 需要时做按块比对（文件被分段传输的情况）
#    先用 foremost/scalpel 对可疑样本做签名定位，再逐字节比对
cmp -l /work/net/objects/200-1.bin /work/suspect/DigiForensics-batch-07.xlsx 2>&1 | head -5

# 4. 记录字节级一致的范围（若只部分一致）
python3 - <<'PY'
import hashlib, pathlib
a = pathlib.Path('/work/net/objects/200-1.bin').read_bytes()
b = pathlib.Path('/work/suspect/DigiForensics-batch-07.xlsx').read_bytes()
n = min(len(a), len(b))
diff = next((i for i in range(n) if a[i] != b[i]), n)
print(f'A={len(a)}B  B={len(b)}B  首处差异偏移=0x{diff:x} ({diff})')
print('A 前缀 SHA256:', hashlib.sha256(a[:diff]).hexdigest() if diff else '完全一致')
PY

# 5. 若需字节级证据，导出该对象的原始流并做时间线固定
tshark -r DigiForensics-net-fixed.pcapng -Y 'http.request.full_uri =~ "batch-07"' \
  -x 2>/dev/null | head -100 > /work/net/logs/相关报文十六进制.txt
```

第 4 步能回答一个常被忽略的问题：导出物与检材文件是完全一致，还是同一个文件的不同部分。

首处差异偏移加上双方长度，足以支撑"该 HTTP 响应体是 `DigiForensics-batch-07.xlsx` 的前 4,194,304 字节"这样的精确表述。

<a id="section-22"></a>

### 3.9 第 9 步：与主机侧证据交叉

流量证据单独使用很容易越界，必须交叉。

交叉的方向决定了结论的可信等级。

```bash
# 交叉一：域名/URL ↔ 浏览器历史（同一时间窗内是否出现）
tshark -r /work/net/DigiForensics-net-fixed.pcapng -Y 'http.request || tls.handshake.type==1' \
  -T fields -e frame.time -e http.host -e http.request.full_uri 2>/dev/null \
  | sort -u > /work/net/logs/web-requests.tsv
# 与 sqlite / firefox places.sqlite 的 url + visit_time 对齐

# 交叉二：外联 IP ↔ 主机侧连接记录
#   内存：见 memory-special/06（netscan 与 netstat 双向差集）
python3 vol.py -f DigiForensics-mem.raw windows.netscan
python3 vol.py -f DigiForensics-mem.raw windows.netstat
# 抓包里的公网 IP 是否出现在 netstat 活跃连接中

# 交叉三：外传文件 ↔ 下载目录 / 临时目录 / 邮件附件
sha256sum /work/net/logs/objects-sha256.txt | cut -d' ' -f1 > /work/net/logs/obj-hash-only.txt
find /mnt/evidence/Users/*/Downloads -type f -exec sha256sum {} \; 2>/dev/null \
  | grep -f /work/net/logs/obj-hash-only.txt

# 交叉四：连接时间 ↔ 系统时间线（Prefetch / ShimCache / UsnJrnl / auth.log）
```

交叉的价值在于**互相证伪**。常见的矛盾情形及其处理：

| 矛盾 | 可能原因 | 处理 |
|---|---|---|
| 抓到连接，主机侧无任何痕迹 | 进程被删、日志轮转、镜像不完整 | 记录矛盾，不能只取其一 |
| 主机有下载记录，抓包无对应传输 | 传输走了加密协议 / 镜像时间窗不含该时段 / 走了非该网卡的路径 | 复核时间窗与接口范围 |
| 抓包时间比系统时间早几分钟 | 抓包主机时钟偏差 | 用 2.10 的方法测量并记录偏差 |

<a id="section-23"></a>

### 3.10 第 10 步：固化报告

报告里的每一条流量结论，都应能被下述清单覆盖：

```text
[ ] 时间标注了时区，并说明抓包主机时钟偏差
[ ] 源 IP 是否经 NAT 重写，说清楚
[ ] 该结论属于「会话层」还是「内容层」
[ ] 若为内容层：incl_len 与 orig_len 是否一致、是否被 snaplen 截断
[ ] 若为内容层：重组文件的大小、类型、SHA256
[ ] 阴性结论是否限定了范围（时间窗、采集点、协议、截断情况）
[ ] 提取出的文件哈希是否与检材中的某个文件匹配，匹配方式是什么
[ ] SNI / 目的 IP 之间的关系是否已经核实（CDN / 反代 / 劫持的可能）
[ ] 未使用任何解密或主动干预手段
```

流量类证据还有一个交付习惯：**原始 PCAP 与分析产物必须一起归档**。

分析产物（会话表、域名清单、导出对象、哈希清单）都由 PCAP 派生，脱离 PCAP 就无法复核。

归档时 PCAP 保持原始哈希不变，分析副本单独记录。

---

<a id="section-24"></a>

## 四、常见陷阱

<a id="section-25"></a>

### 4.1 证据边界类

<a id="section-26"></a>

#### 拿 20 分钟的抓包否认长期行为

**现象**：报告写"经对服务器出口流量进行分析，未发现该主机向 `203.0.113.44` 的连接"，而委托方的问题是"过去三个月是否外传过数据"。

**原因**：抓包文件的时间跨度通常远小于委托问题的时间跨度。

交换机上的临时抓包可能只开了 20 分钟，业务系统的 NetFlow 留存可能只有 7 天，而问题问的是三个月。

这两段时间根本不是同一个集合。

**影响**：**方向性错误，且不可挽回**。

"未发现"会被对方引用为"该主机从未外联"，从而直接否定全部外泄主张。

后续即使再拿到历史证据，已出具的报告仍会被质证。

**核查**：**阴性结论必须四要素齐全**——时间窗、采集点、协议范围、完整性状态。

```text
❌ 未发现该主机向 203.0.113.44 的连接
✅ 在 2026-03-14 08:00:00 至 16:30:00（UTC+8）期间，
   于 server-gw-01 出口 Gi0/24 SPAN 口采集的 2.1 GB 抓包中，
   未发现目的地址 203.0.113.44 的 TCP/UDP 会话。
   该时段 interface_drops_all = 0，无 snaplen 截断。
   本结论不覆盖：①采集点之外的网络路径；②加密隧道内层协议；
   ③2026-03-14 08:00 之前及 16:30 之后的时段。
```

<a id="section-27"></a>

#### 把 NetFlow 记录当作"有内容"

**现象**：拿到 `flow.dat`，发现某会话 `src_bytes` 有 800 MB，直接写"该主机上传了 800 MB 数据"。

**原因**：流记录只有**计数**，没有**内容**。

它能证明"有 800 MB 的字节从 A 流向 B"，不能证明"上传的是涉案文件"。

同时 `src` 未必是终端——经过 NAT 时它是出口地址。

**影响**：把传输量直接等同于内容，构成无依据的事实认定。

**核查**：流记录只支撑"存在该量级的传输"这层结论。需要内容结论时，必须找到同时段的全包抓包或服务端日志。

<a id="section-28"></a>

#### 把云厂商流日志当全量记录

**现象**：拿到云平台 VPC 流日志，报告称"已全面排查该实例的全部网络活动"。

**原因**：VPC 流日志是**采样式**的（有采样率与聚合时间窗），且不覆盖出公网流量、不记录载荷。

它本身就有明确的字段缺失。

**影响**：用有缺口的日志声称"全面排查"，质证时会被直接指出范围夸大。

**核查**：先读该平台文档确认采样率与字段范围，在报告里明确写出"该来源为聚合流记录，含采样，非全量"。

<a id="section-29"></a>

#### 把"抓到了连接"当成"抓到了这个人的连接"

**现象**：在网关侧抓到 `192.168.1.50 → 203.0.113.44:443`，报告写"该内网主机访问了该站点"。

**原因**：出口侧看到的是 NAT 之后的地址。

`192.168.1.50` 只有在这一侧是**未 NAT 的内部路由段**时才保留原值；如果是在 NAT 之后，这个字段已经被改写。

反过来，若 `192.168.1.50` 出现在**公网出口**抓包里，它可能是**内网地址被伪造**或**代理自身地址**。

**影响**：把某台主机的行为归到另一台主机上，指向错误的人。

**核查**：明确写出采集点位置与是否 NAT。

要落到具体终端，需 DHCP 租约、ARP 表、防火墙会话日志或 NetFlow 接口信息做映射。

相关主机侧取证见[Windows 用户行为痕迹](../../computer/computer-registry-log/computer-registry-log-user-activity-artifacts.md)。

<a id="section-30"></a>

### 4.2 容器与截断类

<a id="section-31"></a>

#### 忽略 `snaplen`，对截断内容下结论

**现象**：导出的文件在 `file` 命令下显示 `Zip archive data`，报告称"已提取到完整的压缩包"，后续解压却失败。

**原因**：抓包时 `snaplen` 设为 1500，一个 4 MB 的 HTTP 响应被分成几千个包，每个包只保存 1500 字节。

Wireshark 尽力重组，但它**只能重组它有的字节**——结果是一份头部完整、体积只有 4 KB 左右的残缺 ZIP。

`file` 靠魔数识别，"看起来是 ZIP"与"是完整 ZIP"是两回事。

**影响**：**得出内容级结论，但结论无证据支撑**。这是流量分析里最高频的严重错误。

**核查**：**内容级结论前必查三项**：

```bash
# 1. 截断报文数
tshark -r f.pcapng -Y 'frame.cap_len < frame.len' -T fields -e frame.number | wc -l
# 2. 声明长度与实际内容长度是否一致
tshark -r f.pcapng -Y 'http.response' \
  -T fields -e http.content_length -e http.response_inferred
# 3. 实际重组长度
stat -c%s /work/net/objects/200-1.bin
```

三者对不上就不要写内容结论，改写会话层结论。

<a id="section-32"></a>

#### 用旧版 Wireshark 处理新格式

**现象**：分析含 HTTP/2 的抓包，报"没有 HTTP 流量"；或处理 QUIC 抓包，全部显示为未知协议。

**原因**：HTTP/2 的二进制帧头解析、QUIC 加密 Initial 包的解密，都依赖工具版本。旧版工具不是把流量标为"无法识别"而是直接不展示。

**影响**：**假阴性**。

报告写"未发现 HTTP 访问"，而实际全是 HTTP/2。

**核查**：先用协议统计看是否与预期相符（`io,phs` 里有没有 `tls` 但没有 `http`），若 TLS 握手存在而应用层无任何统计，就是工具解析能力不足。

升级工具，并使用 `tls.handshake.extensions_alpn_str` 确认协商结果。

**报告中要写清工具版本**：

```bash
tshark -v | head -2
```

<a id="section-33"></a>

#### 混用多接口抓包而不区分归属

**现象**：合并了三个 SPAN 口的 PCAPNG，分析时把内网东西向流量与互联网出向流量混在一起统计。

**原因**：PCAPNG 允许多个接口，各自有独立的时间基准与链路类型。合并时不保留 `if_name`/`if_index`，来源就不可分了。

**影响**：同一对 IP 在两个接口上出现，会被算成两条会话；时间基准不同的接口会相对错位。

**核查**：所有分析命令加接口过滤，分析产物里保留接口列：

```bash
tshark -r f.pcapng -e frame.interface_name -e frame.interface_id ...
tshark -r f.pcapng -Y 'frame.interface_name == "Gi0/24"' ...
```

<a id="section-34"></a>

#### 把 SPAN 丢包当成"没有流量"

**现象**：某 IP 在抓包里完全没有出现，报告称该主机未与它通信。

**原因**：SPAN 是镜像不是复制。源口速率超过镜像口能力时，超出部分**静默丢弃**，交换机默认不告警。

`interface_drops_all` 会记录这个丢弃量。

**影响**：又一次假阴性，且方向相反（"没抓到"被当成"没发生"）。

**核查**：先看 `interface_drops_all`（3.3 第 2 步）。

非零就必须在所有阴性结论里加上"采集侧存在丢失"这一限定。

<a id="section-35"></a>

### 4.3 协议语义类

<a id="section-36"></a>

#### 把内网地址、SNI 域名、CDN 节点直接写成攻击者标识

**现象**：报告写"攻击者 IP 为 `203.0.113.44`，攻击源域名为 `cdn.example.net`"。

**原因**：公网 IP 可能是 CDN 节点、云厂商弹性 IP、代理出口、VPN 中转、动态住宅 IP。SNI 域名可能指向第三方服务。

两者都属于攻击者的说法，混淆了**基础设施**与**行为主体**。

**影响**：把无辜服务商写成攻击者，损害第三方声誉，可能引发法律责任。

真正的攻击者身份仍未查明。

**核查**：**分层表述**——

```text
✅ 观察到该主机于 03-14 09:12 与 203.0.113.44:443 建立 TLS 连接，
   ClientHello 中 SNI 为 cdn.example.net。
   经 DNS 反查，该地址归属某云厂商弹性 IP 段。
   ❌ 不写"攻击者 IP 为 203.0.113.44"
```

CDN 源站挖掘的具体方法见[CDN 识别与源站挖掘](../../server/server-web/server-web-cdn.md)。

<a id="section-37"></a>

#### 把 DNS 查询记录当成已建立连接

**现象**：从 DNS 查询里看到某域名，就写成"该主机访问了该网站"。

**原因**：DNS 查询可能来自预加载、缓存预取、其他应用、浏览器预连接，甚至根本没建立连接（解析失败、被拦截、被策略阻断）。**查询与连接是两件事。**

**影响**：把"意图"当成"事实"，尤其在"从未访问某站点"这类辩护点上会失效。

**核查**：DNS 记录只用于**线索与域名清单**。要证明访问，必须有对应的 TCP 会话：

```bash
# 该域名解析到的 IP 上是否真有会话
tshark -r f.pcapng -Y 'ip.addr == <解析到的IP> && (tcp.flags.syn==1 && tcp.flags.ack==0)'
```

<a id="section-38"></a>

#### 看到 TLS 就报告"无法分析"

**现象**：抓包里全是 TLS，报告直接写"因采用加密传输，无法获取具体内容，未做进一步分析"。

**原因**：TLS 隐藏了应用层载荷，但**握手过程完全明文**，且还有大量可关联的旁证。

SNI、证书、ALPN、JA3/JA4、连接时序、上传下载字节数、与主机侧文件哈希的匹配，都能在不解密的前提下形成有效证据链。

**影响**：放弃了大量可得证据，报告深度不足，在需要说明"能证明到什么程度"的场合显得能力不足。

**核查**：明确区分三类结论——**会话层**（可证明）、**元数据层**（可分析握手）、**内容层**（需授权密钥）。前两类不因加密而失效。程序化 TLS 流量识别思路可参考[WebShell 工具流量特征](../../server/server-web/server-web-webshell-traffic-patterns.md)。

<a id="section-39"></a>

#### 用 SNI 认定应用类型

**现象**：抓到 SNI 为 `api.example.com` 的连接，报告称"该流量为云 API 调用"。

**原因**：SNI 是客户端**声称**要访问的域名，可以是任意值。攻击工具完全可以把 SNI 设成正常业务域名以混入流量。

**影响**：把伪装流量判成正常业务，漏掉一条关键证据线。

**核查**：SNI 只作**分类线索**。

应用类型的确认需要至少一项独立证据：ALPN 协商、JA3 指纹聚类、传输模式（请求响应节奏）、或与主机侧进程/文件的对应关系。

<a id="section-40"></a>

#### 把私有 IP 段当外联证据

**现象**：分析中列出 `192.168.x.x` 与某个地址的连接，作为"该主机主动外联"的证据。

**原因**：`10/8`、`172.16-31/12`、`192.168/16`、`127/8`、`169.254/16` 都是内部或链路本地地址。这条连接在内网范围内，不构成外联。

**影响**：把内网正常通信当外联线索，报告里堆满无意义条目，反而淹没真正的外联。

**核查**：分析第一步就把会话按地址属性分桶，只对**公网端点**做外联分析。主机侧地址的判读见[内存取证中的网络连接与流量痕迹](../memory-artifact/memory-artifact-memory-network-artifacts.md)。

<a id="section-41"></a>

### 4.4 归因与时间类

<a id="section-42"></a>

#### 不标时区、默认用本地时区解释抓包时间

**现象**：抓包工具显示 `Mar 14, 2026 01:12:07`，报告写"03-14 01:12 访问"。委托方所在时区是 UTC+8，实际事件发生在 09:12。整份报告的时间线全部偏移 8 小时。

**原因**：抓包**只记录 UTC 时刻，不记录时区**。

工具按本机时区渲染，分析师看到的"本地时间"取决于他机器的时区设置。

多人协作时每个人都可能看到不同的值。

**影响**：**整条时间线错位**，且错位后与日志、监控、用户陈述无法对齐，整个报告的可信度被质疑。

这类错误一旦发现，需要全文重做。

**核查**：

```text
1. 报告里所有时间统一标注时区（推荐统一为 UTC+8，并注明原始抓包为 UTC）
2. 采集时记录抓包主机的时区设置（date +%Z）
3. 分析时用 epoch 排序，渲染时再转本地时区
4. 交付时附一份 epoch ↔ 本地时间对照表
```

时间换算的完整方法见[时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md)。

<a id="section-43"></a>

#### 不测抓包主机时钟偏差

**现象**：抓包主机是台从未联网的旧机器，系统时间停在三年前，采集完成后才发现。

**原因**：抓包工具无法检测自身时钟错误。系统时间不准时，所有时间戳都是错的，而文件本身看不出任何异常。

**影响**：**所有基于时间的关联全部失效**——与 auth.log 对不上、与 Prefetch 对不上、与监控截图对不上。

整份分析退化为只能做无时序的统计。

**核查**：**采集前后各测一次**，把偏差写进报告：

```bash
# 采集前
date -u +"%Y-%m-%dT%H:%M:%SZ"; chronyc tracking 2>/dev/null | head -3
# 采集后
date -u +"%Y-%m-%dT%H:%M:%SZ"
```

若偏差为 Δ，报告里注明"抓包主机系统时钟较可信时间源快/慢 Δ，所有抓包时间需相应调整"。无法测量时，应在报告中明确"时间戳的绝对准确性未经校验，仅可用于相对时序分析"。

<a id="section-44"></a>

#### 把同一时刻的多条流量归到同一个进程

**现象**：抓包里若干连接时间相近，报告称"某程序几乎同时发起这些连接"。

**原因**：抓包**没有进程概念**。同一毫秒的多条流量可能来自同一进程，也可能是多个进程并发。时间接近只说明时序相关，不说明同源。

**影响**：进程级归因错误。

要落到具体进程，必须引入主机侧证据（内存中的 `netscan`/连接表、EUID、浏览器历史、进程创建日志）。

**核查**：抓包结论止于"会话层"，进程归因交给主机侧证据。

交叉方法见[网络连接与流量痕迹](../memory-artifact/memory-artifact-memory-network-artifacts.md)。

<a id="section-45"></a>

#### 把"抓包缺失时段"当成"该时段无活动"

**现象**：抓包文件在 10:20 到 11:00 之间没有报文，报告写"该时段主机无网络活动"。

**原因**：可能的原因至少有五种：采集中断、文件轮转、链路故障、主机断网、抓包进程被 OOM 杀掉。只有"主机确实未联网"是其中一种，而且通常是最后一种。

**影响**：把**采集失败**表述成**事实否定**。

**核查**：先区分"没有报文"和"有报文但都是空段"。

后者用 `interface_drops_all` 与 `epb_dropcount` 判断；前者要查采集侧记录（进程日志、链路 uptime、交换机计数器）。

**任何长时间空档都必须在报告中显式说明原因。**

<a id="section-46"></a>

### 4.5 加密流量类

<a id="section-47"></a>

#### 试图绕过 TLS 加密

**现象**：想用 SSLStrip、ARP 欺骗、中间人代理去获取明文。

**原因**：这类操作是对通信的主动干预，在多数司法辖区本身可能违法，且**破坏了证据的原始状态**。

同一台机器上，合法取得的 PCAP 与被劫持取得的流量在可采性上完全不同。

**影响**：**证据被排除 + 法律风险**。

这是本领域最不能碰的红线。

**核查**：**唯一合规路径**是依法取得会话密钥（如依法向服务方调取 TLS session key 日志）或由委托方提供解密材料。

在没有这些材料时，正确结论是"内容不可读，会话与元数据可分析"。

<a id="section-48"></a>

#### 用会话密钥解密但不区分 TLS 1.2 / 1.3

**现象**：拿到 session key 日志，加载后大部分连接解密失败。

**原因**：TLS 1.2 用 RSA 密钥交换时，会话密钥由 ClientHello 生成的随机数经 RSA 加密传输，所以主密钥可从 ClientHello 解出。

TLS 1.3 引入 (EC)DHE 后不存在这种情况，主密钥由密钥交换协议协商产生，与 RSA 私钥无关，session key 日志也通常不提供。

**影响**：误判为"密钥不对"，进而怀疑材料的可靠性。

**核查**：先统计 `tls.handshake.version` 的分布。

1.2 占主导时可以尝试 RSA 密钥交换路径；1.3 只能用 `SSLKEYLOGFILE` 类日志，且需要该端点在握手时确实导出了密钥。

```bash
tshark -r f.pcapng -Y 'tls.handshake.type == 2' \
  -T fields -e tls.handshake.version | sort | uniq -c
```

<a id="section-49"></a>

#### 用命令行参数猜 TLS 版本或强制降级

**现象**：看到 443 端口就按 TLS 1.2 处理，忽略实际协商结果。

**原因**：服务端可以只支持 1.3，也可以双栈。实际协商结果在 ServerHello 里，且 ALPN、密码套件都是协商出来的。

**影响**：协议层分析结论错误。

1.3 移除了 RSA 密钥交换、移除了会话 ID、握手延迟被引入——这些差异会直接影响你的分析能力判断。

**核查**：读 ServerHello 的实际协商值（3.7 第 3 步），不要从端口推断。

<a id="section-50"></a>

### 4.6 结论表述类

<a id="section-51"></a>

#### 把"未在抓包中找到"写成"不存在"

**现象**：报告中大量出现"未发现""不存在""无相关记录"，读起来像是对全部事实的否定。

**原因**："未在 X 范围内发现 Y" 与 "Y 不存在" 是完全不同的断言。

前者的真值完全取决于 X 的范围，而范围本身总有缺口（时间窗、采集点、协议、加密、丢包、存储位置）。

**影响**：报告被整体质疑严谨性；对方只需指出一个缺口，整份报告的可信度就会崩塌。

**核查**：**所有阴性结论强制加范围限定**，模板：

```text
未在 {时间窗} 的 {采集点与文件名} 中，
针对 {协议范围}，
发现 {目标} 的 {证据类型}。
限制：{加密 / 截断 / 采集点覆盖范围 / 日志留存期}
```

<a id="section-52"></a>

#### 把哈希一致直接写成"就是同一份数据"

**现象**：导出对象的 SHA256 与检材文件一致，报告写"上传的文件就是案发文件"。

**原因**：哈希一致能证明**字节完全相同**，但不能证明**来源与时间**。一个文件被复制到多处、多次上传，在抓包里会呈现多个内容相同的传输。

**影响**：把"内容同一"升格为"行为同一"，缺少行为唯一性支撑。

**核查**：区分三个层次——**内容一致**（哈希匹配）、**传输发生**（抓包中存在该内容的传输）、**行为归属**（该传输由被调查人发起）。

第三层需要主机侧或身份证据支撑。

哈希方法见[哈希与完整性校验](../../fundamentals/fundamentals-concepts/fundamentals-concepts-hashes-and-integrity-verification.md)。

<a id="section-53"></a>

#### 把导出对象当作原始文件

**现象**：把 HTTP 导出物直接作为检材提交，文件名用工具默认的 `200-1.bin`。

**原因**：导出物是 Wireshark 的重组结果，**不是原始字节流**。

它可能被截断、可能缺头、可能顺序错误。

把它当原始文件交给后续分析（解压、解析、跑恶意样本）会失败，且失败的结论可能被误认为"文件本身有问题"。

**影响**：后续工具链全线失败。

更糟的是有人会把"解压失败"写成"该压缩包已损坏"。

**核查**：导出物一律视为**派生产物**，在目录里与原始 PCAP 分离存放，命名带上来源帧号。若需正式检材，重新用 `tcpflow` / `tshark --export-objects` 并附完整的来源帧号与哈希清单。

<a id="section-54"></a>

#### 报告里不写工具版本

**现象**：报告列出了 tshark 的分析结论，未记录 Wireshark/tshark 版本。

**原因**：流量分析的能力边界与工具版本强相关。新版才支持的字段（旧版报空）、版本间解码差异（QUIC、HTTP/2），都会导致"字段为空"这类假阴性。

**影响**：复核者无法重现；出现争议时无法界定是工具限制还是事实。

**核查**：报告的分析环境一节固定记录 `tshark -v` 输出、`editcap -V` 输出，以及所有非标准字段解析所依赖的插件版本。环境登记的整体做法见[取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md)。

---

<a id="section-55"></a>

## 五、案例示例

<a id="section-56"></a>

### 5.1 HTTP POST 上传的哈希闭环与时钟偏差修正

**场景**

某制造企业法务部报备，怀疑内部人员通过外网将客户名单外传。委托方提供两份检材：

```text
1. DigiForensics-net.pcap      2.1 GB  出口 Gi0/24 SPAN
                               采集窗口 2026-03-14 08:00 — 16:30 (UTC+8)
                               采集设备：网闸旁路工控机，时钟未校准
2. DigiForensics-laptop.dd    500 GB  ThinkPad T480 / Windows 10 22H2
                               采集人：委托方 IT，2026-03-20，只读挂载
```

委托问题是"离职员工 A 在离职前是否通过互联网外传客户名单"。

**授权范围限定为离线分析，不含任何解密或主动干预** —— 这一点决定了 TLS 会话的内容层结论永远不可得，报告必须从一开始就承认这个边界，而不是等到写结论时才发现。

抓包类案件里**"时间基准"和"字节同一性"是两个独立的成败点**，任一处理不当都会让整条链断掉。

**处置过程**

第一步，来源登记与哈希固定。

**抓包工控机的时钟偏差必须在此刻就量出来并单列**：

```bash
$ sha256sum DigiForensics-net.pcap
7c1f4a...  DigiForensics-net.pcap

# 采集工控机时区 UTC+8，与可信时间源（NTP）比对
$ ntpdate -q ntp.internal.example.com | tail -2
offset  -252.418  # 慢 4 分 12 秒
```

慢 4 分 12 秒。这个偏差必须在后续所有时间标注中统一修正，不能只在附录提一句。

第二步，格式规范化与完整性检查。这一步决定后续结论能否成立：

```bash
$ capinfos -c -a -e -d -M -s DigiForensics-net.pcap
Number of packets: 1,847,293
First packet time: 2026-03-14 08:00:03
Last packet time:  2026-03-14 16:29:58
File size:         2.1 GB
Data size:         1.94 GB (2,223,331,742 bytes)
Packet size limit: 262144 bytes   ← snaplen 足够，未截断

$ tshark -r DigiForensics-net.pcap -T fields -e frame.interface_name \
    -e frame.interface_drops_all | sort -u
Gi0/18	0
Gi0/24	0
$ tshark -r DigiForensics-net.pcap -Y 'frame.cap_len < frame.len' \
    -T fields -e frame.number | wc -l
0
$ tshark -r DigiForensics-net.pcap -q -z expert | head -12
# 无 Packet size limited，无 Malformed
```

**无截断、无丢包。内容层面结论的前提满足。**

很多案件里这一步做不到，做不到就必须把结论降级到"仅能作流量统计"。

第三步，会话表收敛，按传输量排序找异常：

```bash
$ tshark -r DigiForensics-net.pcap -Y 'frame.interface_name=="Gi0/24"' \
    -q -z conv,tcp | head -18
192.168.1.50  50234 → 198.51.100.77   443      1.82 GB     4,181,663 pkts
192.168.1.50  50388 → 203.0.113.9     80         11.2 MB      9,204 pkts
192.168.1.50  50117 → 198.51.100.77   443        8.4 MB       5,110 pkts
```

**两行需要分开处理**：第 1 行 1.82 GB 是 TLS（内容不可读），第 2 行 11.2 MB 是明文 HTTP（内容可读）。委托方要回答的问题只能由后者回答。

第四步，**先做归属核实再下判断**，这一步不能跳：

```bash
$ tshark -r DigiForensics-net.pcap -Y 'tls.handshake.type==2 && ip.addr==198.51.100.77' \
    -T fields -e x509sat.uTF8String -e x509ce.dNSName | sort -u
CN = DigiForensics Cloud Storage Ltd., O = DigiForensics Cloud Storage Ltd.
DNS: *.storage.example.net, *.s3.storage.example.net
DNS: *.cdn.example.net
```

证书 SAN 指向对象存储服务。**目的 IP 的归属需要独立证据**，证书里的组织名不等于该 IP 的所有者：

```bash
$ tshark -r DigiForensics-net.pcap \
    -Y 'ip.addr==198.51.100.77 && tls.handshake.extensions_server_name' \
    -T fields -e tls.handshake.extensions_server_name | sort -u
files.digi-forensics-cloud.example.net
```

SNI 与证书 SAN 一致，且该地址段经**委托方网络组的资产台账**核实为企业所用对象存储节点。

核实来源是委托方，本方只作记录并注明未经独立核实。

第五步，走明文 HTTP 这条线。注意上一步的结论表述限定为"该终端向企业所用的对象存储服务传输了 1.82 GB"，**不写"外传到外部"**。

```bash
$ tshark -r DigiForensics-net.pcap --export-objects http,/work/net/objects -q
$ ls /work/net/objects | wc -l
3
$ file -b /work/net/objects/200-1.bin
Microsoft Word 2007+
$ stat -c%s /work/net/objects/200-1.bin
11714560
$ tshark -r DigiForensics-net.pcap -Y 'http.response' -T fields -e http.content_length
1048576
10485760
0
```

导出物 11,714,560 字节 > 声明长度 10,485,760。

导出物多于声明说明多个 HTTP 对象被合并导出，直接用它做比对会得到错误的哈希。

**放弃导出物，改为按流导出**：

```bash
$ tshark -r DigiForensics-net.pcap -Y 'http.response && http.response.code==200' \
    -T fields -e frame.number -e http.content_disposition | head -3
# 无 Content-Disposition，服务器未提供文件名
$ tshark -r DigiForensics-net.pcap -q -z follow,tcp,ascii,0 | head -20
POST /upload HTTP/1.1
Host: files.example-net-upload.invalid
```

`POST /upload` 确认这是上传而非下载。 这一条决定了行为的性质：下载文件是接收数据，上传文件是送出数据。

第六步，主机侧哈希比对：

```bash
$ cd /mnt/evidence/Users/a.wang/Downloads && sha256sum *
9f2c...  客户名单-2026Q1-终版.xlsx
$ cd /work/net/objects && sha256sum 200-1.bin
9f2c...  200-1.bin
```

第七步，三方时间线闭合。**这一步必须用修正后的时间**：

```bash
# 抓包侧（原始）
$ tshark -r DigiForensics-net.pcap -Y 'http.request.method=="POST"' \
    -T fields -e frame.time -e ip.dst | head -2
1752412701.482  203.0.113.9
# 换算：+252.418 秒修正 → 2026-03-14 10:38:22 (+08:00)

# 主机侧
$ grep -i 'files.example-net-upload' /mnt/evidence/Windows/WebCache/*.db
Chrome 历史命中 2026-03-14 10:38:22，URL /upload
$ stat -i /mnt/evidence/Users/a.wang/Downloads/客户名单-2026Q1-终版.xlsx | grep Birth
Birth: 2026-03-13 22:10:41
$ grep '2026-03-14T10:3' /mnt/evidence/Windows/System32/winevt/Logs/Security.evtx
4624  03/14/2026 10:38:19  已成功打开文件  \Device\HarddiskVolume2\...\客户名单-2026Q1-终版.xlsx
```

文件生成于前一日 22:10 → 次日 10:38:19 被打开 → 10:38:22 抓包显示 POST 上传 10,485,760 字节且 SHA256 一致。 三方时间闭合。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 2026-03-14 10:38:22（已修正时钟偏差）该终端向 `203.0.113.9:80` POST 上传 10,485,760 字节 | 抓包会话重组 + 请求方法 | 强 |
| 上传字节与笔记本上该文件完全一致 | SHA256 逐位一致 | 强（字节同一性） |
| 该文件在上传前 3 秒被打开 | Security.evtx 4624 与抓包时间差 3 秒 | 强（三方时间闭合） |
| 行为性质为上传而非下载 | `POST /upload` 请求行 | 强 |
| `203.0.113.9` 归属为境内某 IDC | 委托方网络组提供，**本方未独立核实** | 中（单一来源） |
| 该文件内容是否为客户名单 | 属于业务部门认定 | **不在本报告范围** |

**能证明的**：一次具体的上传行为、字节层面的同一性、以及三方可对齐的时间链。

**不能证明的**：
- **不能证明文件内容是客户名单。** 哈希一致证明字节相同，内容认定是业务部门的事
- **不能证明操作者身份。** 日志记录的是账号 `a.wang` 的会话，不是物理在场的人
- **不能证明这是唯一一次。** 见 5.3

**未覆盖范围**：抓包窗口仅 8.5 小时（03-14 08:00–16:30）；未覆盖出口外的其他路径、其他采集点、其他协议；**本次未使用任何解密、中间人或主动干预手段。**

**误判对照**

这个案例的误判点密度很高，最值得写的三个：

其一，把 `--export-objects` 的产物直接拿去比对哈希。

本案导出物 11,714,560 字节而 HTTP 声明 `Content-Length` 为 10,485,760，**多出 1,228,800 字节**。

原因有三：同一 TCP 流中多个 HTTP 响应被合并、chunked 编码边界与 tshark 的切分点不一致、以及响应体之后的下一个响应头被并入。

判据是**导出物体积必须与协议声明的长度一致**。

不一致时有两条路：按流单独导出（`follow,tcp,raw,<流号>`），或用 `http.content_length` 逐响应核对。

本次按流导出后得到正确的 10,485,760 字节，哈希才与主机侧一致。

**若直接用导出物，哈希必然不匹配** —— 而不匹配的成因可能被误读为"文件被改过"或"抓到的是别的文件"，进而引出完全错误的结论。

**其二，把证书里的组织名当作 IP 归属的证明。**

本案证书 `O = DigiForensics Cloud Storage Ltd.` 看起来已经把 `198.51.100.77` 归到了某公司名下。

但 TLS 证书的 `O` 字段由**证书持有者自行填写**，它证明的是"证书签发给了这个名称的主体"，不是"这个 IP 属于该公司"。

判据是 **IP 归属要靠 IP 侧的独立证据**：反向 DNS、PTR 记录、WHOIS、路由表/BGP 归属、或者委托方的资产台账。

本次用的是委托方台账，**并在报告中明确标注该来源与未独立核实的事实**。

IP 归属直接影响"内传"还是"外传"的定性，这条判据不能省。

**其三，忘记修正采集端时钟偏差，导致时间链对不上。**

本案偏差为**慢 4 分 12 秒**。

若不修正，文件被打开的时间（10:38:19，Windows 日志）与上传时间（10:38:26 未修正）之间会呈现 7 秒的差，看起来像"上传发生在打开之后很久" —— 削弱了因果链条的说服力。

更糟的情况是偏差方向相反时，两个时间顺序颠倒，会得出"先上传后打开"的错误结论。

判据：任何来自抓包的绝对时间在使用前必须确认时区与时钟源。

检查项是四项：时区（`capinfos` 的时间呈现 + 工控机设置）、与可信时间源的偏差量与方向（快/慢）、偏差是否在采集窗口内恒定、以及是否跨越了夏令时或 NTP 校时点。

本案四项全部确认后，才在报告里统一标注"已修正 +252.418 秒"。

按错误判据走的代价：时间链是"文件→打开→上传"这条证据链的骨架。

骨架错了，字节哈希再一致，委托方也会问"你怎么知道是同一份文件在同一时间被传的"。

<a id="section-57"></a>

### 5.2 大流量 TLS 会话的证据降级

**场景**

承接 5.1。1.82 GB 的 TLS 会话在会话表里排在第一位，传输量是第二名的 160 倍。委托方在初稿讨论中明确问："1.82 GB 这个量级，是不是才是真正的问题？"

这个问题的答案需要非常克制。

**它是线索，不是结论。**

**处置过程**

第一步，确认这个会话在技术层面能查到什么、查不到什么：

```bash
$ tshark -r DigiForensics-net.pcap -Y 'tcp.port==443 && ip.dst==198.51.100.77' \
    -T fields -e tls.record.content_type -e tls.handshake.type | sort | uniq -c
  4181663 23          # Application Data（密文）
   1     22          # Handshake
   2     20          # Change Cipher Spec
```

4,181,663 个 `content_type=23`（Application Data） —— 全部是密文。

授权范围明确排除解密与中间人手段，因此这 1.82 GB 的内容层结论在法律与技术上都不可能得到。

第二步，把能查的元数据查全 —— 加密不等于无信息：

```bash
$ tshark -r DigiForensics-net.pcap -Y 'tcp.port==443 && ip.dst==198.51.100.77' \
    -T fields -e tcp.stream -e frame.len | awk '{s[$1]+=$2; c[$1]++} END{for(i in s) print s[i], c[i], i}' \
    | sort -rn | head -5
# 字节数    包数    流号
  912443002 1042003 47
  887210445 1098442 63
  25180449   21422  18
```

会话是分散在多个 TCP 流上的（不是单流大传输），**这个形态本身有信息**：多流并行下载/上传常见于对象存储的并发分片、CDN 回源、以及备份客户端。

第三步，看时序分布 —— 判断是持续活动还是一次性批量：

```bash
$ tshark -r DigiForensics-net.pcap -Y 'tcp.port==443 && ip.dst==198.51.100.77' \
    -T fields -e frame.time_epoch | sort -n | python3 -c "
import sys, datetime
ts = [float(l) for l in sys.stdin]
buckets = {}
for t in ts:
    h = datetime.datetime.utcfromtimestamp(t).strftime('%H')
    buckets[h] = buckets.get(h, 0) + 1
for h in sorted(buckets):
    print('%s时  %8d 包' % (h, buckets[h]))
"
08时      48210 包
09时     118204 包
10时      96088 包
11时      52116 包
12时      48880 包
13时      63002 包
14时     104712 包
15时      98104 包
16时      17394 包
```

**8.5 小时里持续有流量，14 时出现次高峰。**

这个形态与"一次性大批量外传"的假设不符，与"正常工作时段的对象存储使用"更吻合。

第四步，尝试从 TLS 元数据里找可归因的线索（**不触碰内容**）：

```bash
$ tshark -r DigiForensics-net.pcap -Y 'tls.handshake.type==2 && ip.dst==198.51.100.77' \
    -T fields -e tls.handshake.extensions_server_name \
             -e tls.handshake.ciphersuite \
             -e x509sat.printableString | sort -u
files.digi-forensics-cloud.example.net
TLS_AES_256_GCM_SHA384
DigiForensics Cloud Storage Ltd.
```

拿到的是：**SNI 域名、密码套件、证书主体**。这三项都是握手阶段的明文元数据，**不构成对 1.82 GB 内容的任何认定**。

第五步，把问题退回给委托方 —— 这是本案最关键的一步：

```text
致委托方：

关于 192.168.1.50 与 198.51.100.77 之间 1.82 GB TLS 流量，本方已完成
以下可查项：

  1. 传输总量、时长、会话分布（18 个 TCP 流，最小 25 MB）
  2. 时序分布（8.5 小时内持续，非一次性突发）
  3. TLS 握手元数据（SNI = files.digi-forensics-cloud.example.net，
     TLS_AES_256_GCM_SHA384，证书主体 DigiForensics Cloud Storage Ltd.）
  4. 目的 IP 归属（依据贵方资产台账，未经本方独立核实）

本方无法提供的内容层结论：授权范围明确排除解密、中间人与主动干预，
该会话全部为 TLS 1.3 Application Data（4,181,663 帧），内容不可读。

请贵方确认：贵方资产台账中，账号 a.wang 是否有该对象存储服务的
业务使用授权？该服务是否有正常的员工使用场景（如备份、同步、
内部资料归档）？本方可将时序分布与贵方业务时间做进一步比对。
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 存在 1.82 GB TLS 传输 | 会话统计 + 4,181,663 帧 Application Data | 强 |
| 传输分散于 18 个 TCP 流，8.5 小时内持续 | 流级字节分布 + 时序直方图 | 强 |
| 目的服务为企业所用的对象存储 | SNI + 证书 SAN + 委托方台账 | 中（IP 归属为单一来源） |
| **该传输内容与本案相关** | — | **无法认定（内容不可读）** |
| **该传输构成数据外泄** | — | **无任何证据支持** |

**能证明的**：一次大规模 TLS 传输的存在、规模、时序形态、以及握手元数据。

**不能证明的**：
- **不能证明内容是什么。** 不是"暂时无法查"，而是**在授权范围内永远不可查** —— 这个区别必须在报告中讲清
- **不能证明传输的数据归属。** 可能是本人文件、可能是缓存/同步的重复数据、可能是共享空间
- **不能证明这是"真正的问题"。** 它的量级异常，但形态更接近正常使用

**未覆盖范围**：TLS 内容（授权排除）、目的 IP 的独立归属核实（依赖委托方）、其他采集点与出口路径、流级重组后的内容特征（需解密）。

**误判对照**

这个案例是本篇最值得写的误判样本，因为它太典型了：**把"量级异常"读成"性质异常"。**

判据有三层，量级只是第一层的入口：

| 层级 | 判据 | 本案 |
|---|---|---|
| 事实层 | 传输量 1.82 GB 确实存在 | ✅ 成立 |
| 形态层 | 是否符合恶意外传的时序与结构特征 | ❌ 不符合：18 流并行、8.5 小时持续、14 时次高峰 |
| 归属层 | 内容是否属于委托方认定的敏感数据 | ❌ **不可得** |

三层里只有第一层成立，结论就只能停在"传输量异常大"这一层。

把第一层的结论直接升到第三层（"外泄了 1.82 GB"），超出了现有流量证据能支持的范围。

具体到字段，形态层的判据是三个可测量的形态特征：

1. **流分布** —— 恶意外传常见单流或少量流的大块传输；本次 18 个流、25 MB–912 MB 均匀分布，符合对象存储的并发分片形态
2. **时序连续性** —— 一次性外传是突发脉冲；本次 8.5 小时持续 4.8 万–11.8 万包/小时，是工作节奏
3. **与业务的时间对齐** —— 本次 14 时的次高峰若能与"某项定时备份/同步任务"对齐，形态层就彻底闭环

第三个方向：`content_type=23` 帧数被当成"传输次数"。

4,181,663 帧是 TLS 记录数，**不是请求数也不是文件数**。

TLS 会把数据切成 16 KB 左右的记录，每条 Application Data 帧携带的明文（加密前）通常在 12–16 KB 之间。

用帧数推断"传输了多少个文件"会得出完全错误的结论。

判据是**帧数 × 平均记录长度 ≈ 总字节数**（本次 4,181,663 × 约 466 B ≈ 1.95 GB，与实际 1.94 GB 吻合），而"文件数"需要应用层信息才能获得 —— 而应用层信息在加密后不可得。

按错误判据走的代价：报告写"发现 1.82 GB 数据外传"，委托方据此对外发供应商启动调查程序、通知客户。

而实际上这可能只是员工把私人照片备份到了公司配发的存储账号。

这个代价不体现在技术层面，而体现在委托方的商务关系上。

<a id="section-58"></a>

### 5.3 反例：8.5 小时抓包支撑不了"仅此一次"的结论

**场景**

5.1 与 5.2 的分析完成后，委托方在结论讨论会上提出一个非常自然的问题：**"那就只这一次吧？"**

这个问题的答案必须是明确的"不知道"，而且必须说清楚为什么。

这条路径要处理的是**时间覆盖范围与委托问题范围不匹配**这个结构性问题 —— 当抓包窗口受存储容量限制、明显短于调查周期时，它在流量取证中就很常见。

**处置过程**

第一步，把两个时间范围并排列出来，而不是分别描述：

```bash
$ python3 - <<'PY'
import datetime
cap  = (datetime.datetime(2026, 3, 14, 8, 0, 3),
        datetime.datetime(2026, 3, 14, 16, 29, 58))
emp  = (datetime.datetime(2025, 9, 1),      # 入职
        datetime.datetime(2026, 3, 18))     # 离职
print('抓包窗口: %s ~ %s  宽 %s' % (cap[0], cap[1], cap[1] - cap[0]))
print('委托范围: %s ~ %s  宽 %d 天' % (emp[0], emp[1], (emp[1]-emp[0]).days))
print('覆盖比例: %.4f%%' % (100 * (cap[1]-cap[0]).total_seconds()
                            / (emp[1]-emp[0]).total_seconds()))
PY
抓包窗口: 2026-03-14 08:00:03 ~ 2026-03-14 16:29:58  宽 8:29:55
委托范围: 2025-09-01 ~ 2026-03-18  宽 198 天
覆盖比例: 0.0448%
```

**0.0448%。**

这个数字必须出现在报告里，它是"不能写仅此一次"的量化依据。

第二步，找可用的替代证据源。

关键在于：替代源能证明什么、不能证明什么，与主检材完全不同。

```bash
# 替代源一：出口 NetFlow（无内容，有五元组 + 字节数 + 起止时间）
$ ls /evidence/netflow/
NF-2026-03-13-2026-03-20.csv.gz
$ zcat /evidence/netflow/NF-2026-03-13-2026-03-20.csv.gz | head -1
ts,srcIP,srcPort,dstIP,dstPort,proto,bytes,packets,inputIf,outputIf,tos
$ zcat /evidence/netflow/NF-2026-03-13-2026-03-20.csv.gz \
    | awk -F, '$2=="192.168.1.50" && $4=="203.0.113.9"' | head
1752374820,192.168.1.50,51204,203.0.113.9,80,TCP,10485760,9204,Gi0/24,Gi0/18,0
```

NetFlow 覆盖 7 天、证明 03-14 的传输量为 10,485,760 字节 —— 与抓包一致。

但 NetFlow **没有内容、没有请求方法、没有目的 URL**，它只能证明"有 10,485,760 字节去往 203.0.113.9:80"。

第三步，量化 NetFlow 能扩展到的范围：

```bash
$ zcat /evidence/netflow/NF-2026-03-13-2026-03-20.csv.gz \
    | awk -F, '$2=="192.168.1.50" && $4=="203.0.113.9" {print $1, $7}' \
    | while read t b; do
        printf '%s  %s\
' "$(date -r "$t" '+%Y-%m-%d %H:%M:%S')" "$b"
      done
2026-03-14 10:38:22  10485760
（仅此一条，7 天内无其他）
```

**7 天内该终端仅向该地址传输过一次。**

注意这条结论的强度：它证明"7 天内一次"，不证明"任职期间一次"。

第四步，检查 7 天之外还有什么可用：

```bash
$ ls /evidence/netflow/
# 仅 NF-2026-03-13-2026-03-20.csv.gz
# 无更早的 NetFlow（保留期 30 天，但更早文件已归档至冷存储，本次未取得）
$ ls /evidence/proxy/
proxy-2026-03-14.log.gz
# 仅有一天，且为 HTTPS CONNECT 记录，无 URL 路径
$ zcat /evidence/proxy/proxy-2026-03-14.log.gz \
    | grep '192.168.1.50' | grep '203.0.113.9' | head -1
1752412701 CONNECT 192.168.1.50:51204 -> 203.0.113.9:80
```

代理日志只有 03-14 一天，且该条是 CONNECT 到 80 端口的记录（代理对 80 端口通常只记 CONNECT 目标，不记路径）。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 抓包窗口宽度为 8 小时 29 分 55 秒 | `capinfos` 首末包时间 | 强 |
| 该窗口仅覆盖委托问题时间范围的 0.0448% | 8.5 h vs 198 天 | 强（计算事实） |
| 7 天 NetFlow 范围内，该终端向 `203.0.113.9` 仅传输一次，字节数与抓包一致 | NetFlow 单条记录 vs 抓包 | 强 |
| 7 天 NetFlow 范围内无其他同目的地址传输 | 全量筛选 | 中（NetFlow 覆盖范围内） |
| **整个任职期间仅此一次** | — | **不成立（无证据支持）** |

**准确的结论表述**（这是本案唯一可接受的写法）：

```text
关于"是否仅此一次"：

一、本报告可证明：2026-03-14 10:38:22（UTC+8，已修正采集端时钟
   偏差 +252.418 秒），被调查终端 192.168.1.50 向 203.0.113.9:80
   发起 HTTP POST /upload，传输 10,485,760 字节，SHA256 与笔记本上
   客户名单-2026Q1-终版.xlsx 完全一致。

二、本报告可证明：委托方提供的出口 NetFlow（覆盖 2026-03-13 至
   2026-03-20，共 7 天）范围内，该终端向 203.0.113.9 的传输记录仅
   此一条，字节数与上述一致。

三、本报告不能证明：2026-03-14 08:00 之前及 16:30 之后、以及
   NetFlow 覆盖期之外（2026-03-13 之前）的传输情况。抓包窗口仅
   8.5 小时，NetFlow 覆盖 7 天，而委托问题涉及的时间范围为 198 天，
   前者占后者的 0.0448%。

四、因此，"该终端在整个任职期间是否仅发生过一次上传"这一问题，
   依据现有检材无法回答。若需回答，请委托方提供覆盖 2025-09 至
   2026-03 全期间的出口流量或 NetFlow 记录。
```

**未覆盖范围**：

| 未覆盖项 | 原因 | 能否补足 |
|---|---|---|
| 2026-03-14 08:00 前 / 16:30 后 | 抓包窗口限制 | 需同采集点同参数的其他日期抓包 |
| 2026-03-13 之前的 195 天 | NetFlow 未提供 | 需委托方从冷存储调取 |
| 出口以外的路径（VPN、移动网络、U 盘、私接路由器） | 采集点仅覆盖 Gi0/24 | 需终端侧证据 |
| 内网横向传输 | 采集点为出口 SPAN | 需内网采集点 |
| 非 TCP 流量 | 未导出完整统计 | 需全协议统计 |

**误判对照**

这个案例的误判是本篇陷阱章节反复警告的那一类，但它值得单独用一个案例来写，因为它是流量取证里"最自然的一个追问"。

委托方问"就这一次吧"，分析方答"是的，就这一次"。

这个回答在**字面上完全正确**（在 8.5 小时的窗口里确实只有一次），**但它在实务上是有害的** —— 委托方会把它理解为"整个调查期间只有一次"，并据此结案。

判据是**任何"仅此一次"类结论都必须同时携带三个数字**：

| 数字 | 本案 | 作用 |
|---|---|---|
| 检查范围 | 抓包 8.5 h + NetFlow 7 天 | 界定了结论的适用域 |
| 委托问题范围 | 198 天 | 让读者看到差距 |
| 覆盖比例 | 0.0448% | 把差距变成可感知的量 |

判据的通用形式：阴性结论与"唯一性"结论都必须写成「在 X 范围的 Y 检查内，未发现 Z」的句式，并附上未覆盖清单。

少了范围限定，"未发现第二次"就变成了"没有第二次"，这是两个完全不同的命题。

第二个误判点：用 NetFlow 的 7 天结论覆盖 198 天的问题。

NetFlow 与 PCAP 的证据能力差异必须写明：

| 维度 | PCAP | NetFlow |
|---|---|---|
| 内容 | 有（TLS 内容除外） | **无** |
| 请求方法 / URL | 有 | **无** |
| 五元组 | 有 | 有 |
| 字节数 / 包数 | 有 | 有 |
| 起止时间 | 逐帧 | 流级 |
| 可证明的事实 | 传输内容与时间的对应 | 仅"有这么多字节到过那里" |

本次 NetFlow 的作用是"印证字节数"，不是"独立证明上传行为"。

如果没有 PCAP，NetFlow 只能证明"10,485,760 字节去往 203.0.113.9:80" —— 连"这是上传而不是下载"都无法判断。

报告里把 NetFlow 写成印证证据（corroborating evidence）而不是并列证据（parallel evidence），这个区分必须明确，否则委托方会误以为有两个独立证据，实际只有一个。

第三个实操细节：`NF-2026-03-13-2026-03-20.csv.gz` 覆盖 7 天，而抓包只有 03-14 一天。

注意这个重叠关系 —— NetFlow 覆盖 03-14 的那条记录，其字节数与抓包完全一致（10,485,760）。

这个一致性本身是两项证据交叉印证的机会：它证明了 NetFlow 的采集未丢包、字节统计口径与抓包一致。

如果两者不一致，反而要追查 —— 可能抓包丢了包，也可能 NetFlow 采样有误差。

交叉时出现不一致是发现问题的时机，一致则强化可信度，两种情况都值得写进报告。

<a id="section-59"></a>

## 六、扩展阅读方向

| 方向 | 说明 |
|---|---|
| 流量与内存交叉 | 从内存恢复的连接表与抓包会话表做双向差集，是归属分析的核心手段 |
| 容器内东西向流量 | 微服务架构中数据外泄常发生在集群内部，公网抓包完全看不到 |
| 无线与移动流量 | 蜂窝数据、Wi-Fi 关联帧的捕获与位置证据，与 SIM 卡位置分析互补 |
| 分布式追踪 | Jaeger / OpenTelemetry / Sidecar 的 span 记录，可与 PCAP 精确对齐 |
| 流量侧数据泄露检测 | DLP / NDR 的告警日志，字段结构与 NetFlow 接近但含更多应用语义 |

本篇与内存侧的网络分析是同一问题的两半。

抓包能证明「数据确实走了网卡」，但不能证明「是哪个进程走的」；内存里的连接表能给出进程归属，但只反映采集时刻的快照。

两者做双向差集，才能同时覆盖"传输量异常"与"进程归属"这两个维度——具体方法与 stale data 陷阱见[网络连接与流量痕迹](../memory-artifact/memory-artifact-memory-network-artifacts.md)。

在 Web 侧，流量特征常常是给日志定性服务的。

把抓包里的工具请求模式与 WebShell 的工具流量特征对照，可以判断日志中的可疑请求到底是漏洞利用还是工具自身回调，见[WebShell 工具流量特征](../../server/server-web/server-web-webshell-traffic-patterns.md)。

而在处理可疑目的地址时，CDN 与代理的层层转接会把归因带偏，需要专门剥离，见[CDN 识别与源站挖掘](../../server/server-web/server-web-cdn.md)。

采集环节的规范直接决定后面能做多少。

镜像制作与远程在线取证的边界见[远程勘验与在线取证](../../imaging/imaging-acquire/imaging-acquire-remote-evidence-collection.md)，流量镜像的部署位置选择属于该环节的决策项。

---

<a id="section-60"></a>

## 七、命令速查

```bash
# ===== 0. 环境登记（写进报告的分析环境一节）=====
tshark -v | head -2
editcap -V | head -2

# ===== 1. 检材固定 =====
mkdir -p /work/net/{objects,logs}
cd /work/net
sha256sum DigiForensics-net.pcap | tee logs/hash-original.txt
md5sum    DigiForensics-net.pcap >> logs/hash-original.txt
file     DigiForensics-net.pcap
chmod 444 DigiForensics-net.pcap
cp --reflink=auto DigiForensics-net.pcap work.pcap

# ===== 2. 格式识别与规范化（pcapng 保留多接口）=====
capinfos -c -a -e -d -M -s -I work.pcap
editcap -F pcapng work.pcap normalized.pcapng
editcap -B normalized.pcapng fixed.pcapng

# ===== 3. 完整性：丢包 / 截断 / 时间乱序（内容结论的前置门禁）=====
tshark -r fixed.pcapng -T fields -e frame.interface_name \
       -e frame.interface_id -e frame.interface_drops_all | sort -u
tshark -r fixed.pcapng -Y 'frame.cap_len < frame.len' \
       -T fields -e frame.number -e frame.len -e frame.cap_len | wc -l
tshark -r fixed.pcapng -q -z expert | head -40
tshark -r fixed.pcapng -T fields -e frame.number -e frame.time_epoch \
  | awk -F'\	' 'NR>1 && $2<prev {c++} {prev=$2} END {print "乱序数:", c+0}'

# ===== 4. 会话与端点 =====
tshark -r fixed.pcapng -q -z conv,tcp | head -30
tshark -r fixed.pcapng -q -z conv,ip  | head -25
tshark -r fixed.pcapng -q -z endpoints,ip | head -25
tshark -r fixed.pcapng -q -z io,phs | head -30
tshark -r fixed.pcapng -Y 'frame.interface_name=="Gi0/24"' -q -z conv,tcp

# ===== 5. DNS 域名清单 =====
tshark -r fixed.pcapng -Y 'dns.flags.response==0' \
  -T fields -e frame.time_epoch -e ip.src -e dns.qry.name | sort -u
tshark -r fixed.pcapng -Y 'dns.flags.response==1 && dns.flags.rcode==0' \
  -T fields -e dns.qry.name -e dns.a | sort -u
# 只看查询对应的 IP 上是否真有会话
tshark -r fixed.pcapng -Y 'ip.addr==<IP> && tcp.flags.syn==1 && tcp.flags.ack==0'

# ===== 6. HTTP 对象导出（目录必须预先创建，否则静默产出 0 文件）=====
mkdir -p objects
tshark -r fixed.pcapng -Y 'http.request || http.response' \
  -T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst \
                 -e http.host -e http.request.method -e http.request.uri \
                 -e http.response.code -e http.content_type \
                 -e http.content_length -e http.content_disposition
tshark -r fixed.pcapng --export-objects http,objects -q
for f in objects/*; do printf '%-24s %10s  ' "$f" "$(stat -c%s "$f")"; file -b "$f"; done
# 声明长度 vs 实际长度
tshark -r fixed.pcapng -Y 'http.response' \
  -T fields -e http.content_length -e http.response_inferred

# ===== 7. TLS 元数据与指纹 =====
tshark -r fixed.pcapng -Y 'tls.handshake.type==1' \
  -T fields -e frame.time_epoch -e ip.dst -e tls.handshake.extensions_server_name
tshark -r fixed.pcapng -Y 'tls.handshake.type==11' \
  -T fields -e ip.src -e x509sat.uTF8String -e x509ce.dNSName -e x509af.serialNumber | sort -u
tshark -r fixed.pcapng -Y 'tls.handshake.type==2' \
  -T fields -e ip.src -e ip.dst -e tls.handshake.version \
                 -e tls.handshake.ciphersuite -e tls.handshake.extensions_alpn_str | sort | uniq -c
tshark -r fixed.pcapng -Y 'tls.handshake.type==1' -T fields -e ip.dst -e tls.handshake.ja3_full | sort -u
tshark -r fixed.pcapng -Y 'tls.handshake.type==1' -T fields -e tls.handshake.ja4 | sort | uniq -c
tshark -r fixed.pcapng -Y 'quic' \
  -T fields -e ip.dst -e tls.handshake.extensions_server_name | sort -u

# ===== 8. 哈希与字节级比对 =====
( cd objects && sha256sum * ) | tee logs/objects-sha256.txt
( cd objects && md5sum * ) >> logs/objects-sha256.txt
join -j 1 <(sort logs/objects-sha256.txt | grep -E '^[0-9a-f]{64}') \
         <(sort /work/suspect/sha256.txt) | tee logs/hash-match.txt
cmp -l objects/200-1.bin /work/suspect/sample.xlsx 2>&1 | head -5
python3 - <<'PY'
import hashlib, pathlib
a = pathlib.Path('objects/200-1.bin').read_bytes()
b = pathlib.Path('/work/suspect/sample.xlsx').read_bytes()
n = min(len(a), len(b))
d = next((i for i in range(n) if a[i] != b[i]), n)
print(f'A={len(a)}B B={len(b)}B 首处差异=0x{d:x} ({d})')
print('A 前缀 SHA256:', hashlib.sha256(a[:d]).hexdigest() if d else '完全一致')
PY

# ===== 9. 主机侧交叉（取自笔记本镜像，只读挂载）=====
python3 vol.py -f DigiForensics-mem.raw windows.netscan
python3 vol.py -f DigiForensics-mem.raw windows.netstat
find /mnt/evidence/Users/*/Downloads -type f -exec sha256sum {} \; \
  | grep -f logs/obj-hash-only.txt

# ===== 10. NetFlow 汇总（注意 src/dst 方向受 NAT 影响）=====
tshark -r flow.dat -T fields -e src -e srcport -e dst -e dstport -e prot \
       -e src_bytes -e dst_bytes -e first -e last | sort -u > logs/flow-summary.tsv
awk -F'\	' '{print $4}' logs/flow-summary.tsv | sort | uniq -c | sort -rn | head -20

# ===== 11. 时区与时钟偏差 =====
date +%Z; date -u +"%Y-%m-%dT%H:%M:%SZ"
chronyc tracking 2>/dev/null | head -3 || ntpq -p 2>/dev/null
tshark -r fixed.pcapng -t ad -T fields -e frame.time_epoch -e frame.time -e ip.src -e ip.dst | head -5
```

---

**版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 内存与专项分析 — 网络流量与 PCAP 取证」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《网络流量与 PCAP 取证》（CC BY-SA 4.0）`

文中 `DigiForensics-net.pcap`、`DigiForensics-laptop.dd`、`DigiForensics-batch-07.xlsx`、`DigiForensics-leak.zip`、`客户名单-2026Q1-终版.xlsx`、`files.example-net-upload.invalid` 等均为示例名称，指向虚构或已脱敏的检材与资源，与真实案件、组织无关。

文中全部 IP 地址取自 RFC 5737 文档保留段（192.0.2.0/24、198.51.100.0/24、203.0.113.0/24），不可路由。

本文不包含、也不导向任何解密、劫持或协议降级手段。涉及加密流量时，唯一合规路径是依法取得会话密钥或由委托方提供解密材料。
