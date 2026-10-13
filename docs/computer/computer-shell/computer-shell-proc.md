---
title: "/proc 虚拟文件系统取证"
slug: "computer-shell-proc"
canonical: "https://www.digiforensics.cn/wiki/computer-shell-proc"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:49+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "computer"
space: "计算机取证"
node_path: ["Shell 与命令历史"]
---

# /proc 虚拟文件系统取证

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/computer-shell-proc)

<a id="section-1"></a>

## 一、概述

Linux 内核把自己的运行时状态挂在 `/proc` 上。那不是磁盘上的目录——里面绝大多数「文件」是内核在你读取的瞬间现生成的。

这个性质决定了整件事的全部前提：

> `/proc` 里的内容只能在线获取。断电后的磁盘镜像里，`/proc` 是一个空目录。

跟 Windows 取证里「内存态工件丢失」算是同一类问题。但 Linux 有个明显优势：不做内存镜像，只要在**断电前**用只读命令把关键项**导出成文件**，就能拿到大量带时间戳的运行时证据。

而这批证据在离线镜像里无法重建。

所以 `/proc` 的取证价值几乎全押在一件事上：**现场有没有做在线采集，采得全不全**。这个判断得在现场做完，事后补不回来。

这一层的位置很特殊：它不属于「拿到镜像之后」的任何环节，它属于「拿到镜像之前」。

**上游**是现场处置决策。是否断电、是否先做内存采集、是否在断电前导出 `/proc`，**这三个决定必须在现场几秒内做完**，依据见[远程勘验与在线取证](../../imaging/imaging-acquire/imaging-acquire-remote-evidence-collection.md)。

**它自己**要在采集前确认容器环境。在容器内 `/proc` 是宿主机视角还是容器视角，取决于挂载方式与 cgroup 配置。判错会把宿主机的进程误认成容器的。

**下游支撑**归属分析。`/proc/net/tcp` 里的连接要反查进程才能定性，「哪个进程走的」是流量分析的必答项；环境变量里的凭据进入后续分析，但**只做离线分析与最小化提取，不做在线使用**。

它与内存取证是替代关系而非并列：来不及做完整内存镜像时，逐项导出 `/proc` 是成本低得多的折中方案。

能提供四类离线磁盘上难以获得的证据：

| 证据类型 | 典型位置 | 为什么磁盘上找不到 |
|---|---|---|
| 进程完整命令行 | `/proc/<pid>/cmdline` | 进程退出即消失；`bash_history` 只记交互命令，不记脚本参数 |
| 进程环境变量 | `/proc/<pid>/environ` | **常含数据库口令、API token、云凭据**；不落盘、无法 grep 到 |
| 被删除但仍打开的文件 | `/proc/<pid>/fd/` | **文件已从目录树删除，但 inode 仍被进程持有**——经典反取证场景 |
| 真实网络连接 | `/proc/net/tcp`、`/proc/<pid>/net/tcp` | 内存态；日志里可能完全没有 |

具体到每个子项的判读点：

| 子项 | 内容 | 关键判读点 |
|---|---|---|
| `/proc/<pid>/cmdline` | NUL 分隔的参数序列 | **可执行文件路径与参数都能取到，与历史文件互补** |
| `/proc/<pid>/environ` | NUL 分隔的环境变量 | 敏感度高，摘录必须脱敏 |
| `/proc/<pid>/fd/` | 打开的文件描述符软链 | 指向 `(deleted)` 的条目即被删除但仍被持有的文件 |
| `/proc/<pid>/maps`、`status` | 内存映射与状态 | 指向的匿名可执行区是进程注入的线索 |
| `/proc/net/tcp`、`tcp6` | 连接与监听状态 | **地址与端口是十六进制小端编码**，直接读会得到反的结论 |
| `/proc/<pid>/net/tcp` | 命名空间视图 | 与 `/proc/net/tcp` 内容可能不同，容器内差异尤其明显 |
| `/proc/<pid>/cgroup` | 容器归属线索 | 判定进程属于哪个容器的基础 |
| 危险项 | `/proc/kcore` 等 | `/proc/kcore` 相当于内核内存视图，绝不能在原机上读取 |

三个判定要先立起来：十六进制编码的解码方向、命名空间的隔离效果，以及**删除状态下文件仍被持有的含义**。最后一类是最有价值、也最容易被忽略的。

答得出来的是：案发当时系统上有哪些进程在跑、每个进程带什么参数、谁持有哪些已删除的文件、当时有哪些网络连接及其归属进程，以及**某些文件在被删除后是否仍被某个进程占用**。

答不出来的，以及几个必须先认清的边界：

**离线镜像里的一切。** 镜像中的 `/proc` 是空目录。这不是「没有进程」，而是「这个证据形态不适用于离线分析」——报告里写错这句话，会让一次本可在线完成的调查变成不可能。

**历史。** `/proc` 是**当前快照**，不记录任何过去。它能回答「现在有什么」，不能回答「一小时前有什么」。

**已退出进程的任何信息。** 进程一退出，`/proc/<pid>` 立即消失，**没有历史记录可查**。

**网络连接的目的地内容。** 它给出的是连接与进程归属，**「传输了什么」需要网络侧材料**，见[网络流量与 PCAP 取证](../../memory/memory-network/memory-network-pcap.md)。

**容器内的完整视图。** 若 `/proc` 未按容器隔离，你看到的可能混入了宿主机进程，**边界判定不清时不能直接下结论**。

**敏感凭据的后续使用。** `environ` 里的 token 与口令**只做离线记录与最小化摘录**，任何在线使用都不在取证范围内。

要读懂这些，得先有 Linux 进程模型——进程是运行态实体，`/proc` 是它的文件系统投影而非存储；了解文件描述符与 inode 的引用关系，否则没法解释「文件已删除但 fd 仍指向它」；掌握 socket 状态机与 TCP/IP 基础，**否则十六进制解码出来的地址端口方向会搞反**；熟悉十六进制与小端序的换算，这是 3.4 解码环节的前提；了解容器与 cgroup 的基本概念，能识别 `/proc/<pid>/cgroup` 的归属信息。

还有一条纪律：**所有操作不得改变系统状态**，涉及写盘或触发内核动作的项必须在采集前排除。

<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 为什么 `/proc` 离线读不到

`/proc` 是一个**由内核导出的虚拟文件系统**（procfs）。目录项和文件内容都是**读取时按需生成**的：

```
读 /proc/1234/cmdline  →  内核从当前 task_struct 生成字节流返回
进程退出              →  /proc/1234/ 整个目录立即消失
```

由此可得：

| 场景 | `/proc` 是否有内容 |
|---|---|
| 机器**运行中** | 有（实时快照） |
| **断电**后做 dd 镜像 | **空目录**（`proc` 只是镜像里的一个空壳目录） |
| 机器运行中做**在线/内存镜像** | **仍需单独采集**——dd 磁盘镜像不包含 `/proc` 内容 |
| 采集 `DigiForensics-mem.raw` 后关机 | `/proc` 内容**只在内存镜像里**，需从内存中恢复（难）；**最好是在关机前先导出** |

给现场处置的建议：如果委托方可能需要进程/连接证据，在断电前用 3.1 的只读命令把 `/proc` 关键项导出到独立分区或外接介质。

这个动作成本极低，几秒就完事，但决定了这类证据是否还能取得。**一旦断电，这批证据就无法再采集。**

<a id="section-4"></a>

### 2.2 `/proc/<pid>/` 关键子项

| 路径 | 内容 | 格式要点 | 取证价值 |
|---|---|---|---|
| `/proc/<pid>/cmdline` | **完整命令行** | **★ 参数之间用 NUL（`\0`）分隔，不是空格** | ★★★★★ 进程实际执行了什么；**能证明脚本的真实参数** |
| `/proc/<pid>/environ` | **环境变量** | NUL 分隔的 `KEY=VALUE` | ★★★★★ **常含口令/token/云凭据** |
| `/proc/<pid>/cwd` | **当前工作目录** | 软链接（`readlink` 取目标） | ★★★★ 进程在哪个目录操作文件 |
| `/proc/<pid>/exe` | **可执行文件本体** | 软链接；**已被删除时目标带 `(deleted)`** | ★★★★★ `(deleted)` 表示"文件目录项已删但进程仍在运行" |
| `/proc/<pid>/root` | 进程的根目录 | 软链接；容器场景有用 | ★★★ chroot/容器判断 |
| `/proc/<pid>/fd/` | **打开的文件描述符** | 目录，每项是软链到实际文件 | ★★★★★ **能看到已删除但仍打开的文件** |
| `/proc/<pid>/maps` | **内存映射布局** | 文本，含每段权限和路径 | ★★★★ 定位注入的匿名可执行段、无文件映射的可疑内存 |
| `/proc/<pid>/status` | 进程状态 | 文本键值对 | ★★★ `Name/Pid/PPid/Uid/Gid/Threads/State` |
| `/proc/<pid>/stat` | 进程统计 | 单行文本，字段多且是**第 4 个字段是命令名（含括号）** | ★★★ 取启动时间的换算基础 |
| `/proc/<pid>/statm` / `smaps` | 内存用量/细节 | 文本 | ★★ smaps 可看是否有 RWX 匿名段 |
| `/proc/<pid>/mountinfo` | 该进程看到的挂载 | 文本 | ★★★ **容器场景判断挂载来源** |
| `/proc/<pid>/cgroup` | cgroup 归属 | 文本 | ★★★★ **容器/系统d 服务归属判定** |
| `/proc/<pid>/loginuid` | 触发登录审计的 uid | 文本 | ★★★ 登录归属（需 pam_loginuid 启用） |

> ⚠️ `cmdline` 与 `environ` 用 NUL 分隔，不是空格也不是换行。 直接 `cat` 会看到"连成一片"或终端不换行。必须用 `tr '\0' ' '` 或 `xargs -0` 转换。 这是最常见的 `/proc` 读取错误之一。
>
> ⚠️ `/proc/<pid>/exe` 显示 `(deleted)` 的含义：文件的目录项已被删除（`unlink`），**但 inode 仍被该进程持有映射**——所以程序还在运行，但**磁盘上已经没有这个文件了**。这正是"删除日志文件后继续写入日志"的实现基础，也是**能同时给出文件名、路径与运行中进程的直接证据**。

<a id="section-5"></a>

### 2.3 `/proc/net/tcp` 的结构与十六进制编码

`/proc/net/tcp`（`tcp6`/`udp`/`udp6` 同理）是**当前网络连接与套接字的快照**，第一行是表头：

```
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 ...
   1: 0100007F:1F90 0201A8C0:C350 01 00000000:00000000 00:00000000 00000000     0        0 54321 ...
```

**前 4 列是要解析的重点**：`sl`（序号）、`local_address`（本地地址）、`rem_address`（对端地址）、`st`（状态）。

编码规则是本篇的核心知识点，一句话：地址部分是 32 位（IPv4）或 128 位（IPv6）的十六进制，但按 4 字节一组、每组内部字节序反转（小端）存放。

拿 `0100007F`（IPv4 的 127.0.0.1）走一遍：

```
十六进制字符串：  01 00 00 7F
每 2 位倒序（字节交换）：  7F 00 00 01
按点分十进制读：  127.0.0.1
```

解码步骤因此是：把 8 位十六进制看作一个小端 32 位整数，再用网络字节序解释。等价于"每 2 位倒序一次"。

端口部分是普通十六进制，**没有字节交换**：`1F90` = `0x1F90` = **8080**（十进制）。

本篇要求的核心验证：`0100007F:1F90` → 地址 `0100007F` 倒序为 `7F000001` → **127.0.0.1**；端口 `1F90` → **8080**。**结果 = `127.0.0.1:8080`** ✓

**IPv6 的规则**：地址是 **128 位 = 4 个 32 位字**，**每个 32 位字各自做一次小端字节交换**，再按网络序拼成 16 字节。

| `/proc/net/tcp6` 中的值 | 解码结果 |
|---|---|
| `00000000000000000000000001000000` | `::1` |
| `000080FE0000000000000001000000` | `fe80::1` |
| `B80D012000000000000000001000000` | `2001:db8::1` |

IPv4 与 IPv6 的区分看地址字段的十六进制**长度**：**8 个字符 = IPv4**（`/proc/net/tcp`），**32 个字符 = IPv6**（`/proc/net/tcp6`）。两者不会出现在同一个文件里。

**状态字段 `st` 是一字节十六进制**（常用）：

| `st` | 状态 | 取证含义 |
|---|---|---|
| **`0A`** | **LISTEN** | 监听中的端口；**非预期端口的 LISTEN = 值得深挖** |
| **`01`** | **ESTABLISHED** | 活跃连接；指向外部 IP 的 ESTABLISHED 说明该时刻存在对外连接，是否外传需另取流量侧证据 |
| `06` | TIME_WAIT | 连接刚进入关闭后的等待状态 |
| `08` | CLOSE_WAIT | **对端已关闭、本端未关闭**（进程未正确收尾，可能是程序异常，也可能出现在某些常驻实现中） |

<a id="section-6"></a>

### 2.4 `/proc` 下的网络与其它全局文件

| 路径 | 内容 |
|---|---|
| `/proc/net/tcp`、`tcp6`、`udp`、`udp6` | 连接与套接字快照（**本网络命名空间**） |
| `/proc/net/arp` | **ARP 缓存**（近期通信过的同网段 IP，局域网取证有用） |
| `/proc/net/route` | 路由表（可判断网关/内网网段） |
| `/proc/net/dev` | 各网卡流量统计（收发字节数，粗略判断外传量） |
| `/proc/net/unix` | Unix domain socket |
| `/proc/net/xt_qtaguid/stats` | 按 UID 统计流量（**部分内核/发行版才有**） |
| `/proc/modules` | 已加载内核模块（与[第 04 篇](../computer-persistence/computer-persistence-scheduled-tasks-and-persistence.md)的模块排查联动） |
| `/proc/mounts`、`/proc/mountinfo` | 挂载表（判断 tmpfs、bind mount、容器挂载） |
| `/proc/uptime` | **系统运行时长（秒）** ★ | 用来判断机器上次启动时间 |
| `/proc/stat` | 系统启动以来的 CPU 时间累计 |

`/proc/uptime` 是"这台机器上次什么时候启动的"的快速答案：`uptime 秒数 + 当前时间 = 启动时刻`。

但断电机器的 `/proc` 是空的，所以这个方法只在线可用。离线的等价做法是从日志/journal 的首次启动记录推断。

<a id="section-7"></a>

### 2.5 `/proc/kcore` 与危险项

`/proc/kcore` 是**内核内存的转储接口**，大小约等于物理内存（甚至更大）。**它绝不是普通文件。**

绝对不要 `cat`、`cp`、`dd`，也不要挂载后去浏览它。在多数系统上尝试读取会导致系统**立即挂起或崩溃**（它可能触发巨大的不可恢复读），某些配置下还可能造成数据泄露。

它属于内存取证的范畴——需要时用专门的内存采集工具（在断电前从另一个接口获取），不是本篇的操作对象。

同理需要谨慎的还有：`/proc/self/mem`（需权限，且可致崩溃）、`/proc/kallsyms`（需 root，部分系统已限制）。

<a id="section-8"></a>

### 2.6 容器环境下的 `/proc` 差异

在容器里，`/proc` 的"视角"是容器的，不是宿主机的。 这是取证时必须先判定的前提。

| 差异点 | 宿主视角 | 容器内视角 |
|---|---|---|
| `/proc/<pid>` | 所有进程 | **只能看到容器内 PID 命名空间里的进程**（容器 PID 1 = 应用自身） |
| `/proc/net/tcp` | 宿主全部连接（默认 net namespace） | **仅该网络命名空间内的连接**（`--network=host` 时才共享宿主） |
| `/proc/mounts` | 宿主完整挂载 | 容器内的挂载（含 overlay） |
| `/proc/<pid>/root` | `/` | **容器自己的根文件系统** ★ |
| `/proc/1/environ` | systemd 的环境 | **容器的启动命令与环境**（容器取证的第一入口） |

**容器取证的关键入口**（若 `/proc` 是在容器内采集的）：

```bash
# 容器内的 PID 1 命令行 = 容器启动了什么
tr '\0' ' ' < /proc/1/cmdline; echo
tr '\0' '\
' < /proc/1/environ | grep -iE 'PASSWORD|SECRET|TOKEN|KEY|DATABASE|DSN'
# 容器的 cgroup 归属（回到宿主可见的容器 ID）
cat /proc/1/cgroup
# 容器看到的挂载（含 overlay 层）
cat /proc/1/mounts | grep -E 'overlay|/etc/hosts|/etc/resolv.conf'
```

判定方法很简单：若 `/proc/1/cmdline` 显示的不是 systemd/init 而是应用名（nginx、python、java 等），说明这份 `/proc` 是在容器命名空间内采集的。

此时"看不到某进程"是命名空间隔离的结果，**不代表进程不存在**。这一点必须在报告中说明，否则会把"命名空间隔离"误判为"无此进程"。

---

<a id="section-9"></a>

## 三、操作步骤

<a id="section-10"></a>

### 3.1 第 1 步：不破坏系统的现场采集（在断电/关机之前执行）

目标：把 `/proc` 里的关键项导出为普通文件。 全程只读，不 kill 任何进程。

```bash
#!/bin/bash
# 在线 /proc 采集脚本（只读；输出到 /evidence/proc-snapshot）
OUT=/evidence/proc-snapshot
mkdir -p "$OUT"

# 1) 全局快照
uptime > "$OUT/uptime.txt"
date -u +'%Y-%m-%dT%H:%M:%SZ' > "$OUT/collected-at-utc.txt"
cp /proc/net/tcp "$OUT/net-tcp.txt" 2>/dev/null
cp /proc/net/tcp6 "$OUT/net-tcp6.txt" 2>/dev/null
cp /proc/net/arp "$OUT/net-arp.txt" 2>/dev/null
cp /proc/net/route "$OUT/net-route.txt" 2>/dev/null
cp /proc/modules "$OUT/modules.txt" 2>/dev/null
cp /proc/mounts "$OUT/mounts.txt" 2>/dev/null

# 2) 逐进程采集关键项（NUL 分隔必须转换！）
for p in /proc/[0-9]*; do
  pid=$(basename "$p"); d="$OUT/pid-$pid"; mkdir -p "$d"
  tr '\0' ' ' < "$p/cmdline"  > "$d/cmdline.txt" 2>/dev/null   # ★ NUL→空格
  tr '\0' '\
' < "$p/environ" > "$d/environ.txt" 2>/dev/null   # ★ NUL→换行
  readlink "$p/exe"           > "$d/exe.txt"      2>/dev/null
  readlink "$p/cwd"           > "$d/cwd.txt"      2>/dev/null
  cp "$p/status" "$d/status.txt"                  2>/dev/null
  cp "$p/maps"  "$d/maps.txt"                     2>/dev/null
  cp "$p/cgroup" "$d/cgroup.txt"                  2>/dev/null
  ls -l "$p/fd" > "$d/fd-list.txt"                2>/dev/null   # 含 "(deleted)"
done

# 3) 全盘建立 fd → 目标 索引（已删除文件一眼可见）
grep -l 'deleted' "$OUT"/pid-*/fd-list.txt 2>/dev/null
grep -h 'deleted' "$OUT"/pid-*/fd-list.txt 2>/dev/null
```

只读原则：`/proc/<pid>/environ` 和 `/proc/<pid>/fd/` 通常需要 root（`environ` 受 `PTRACE_MODE_READ` 限制），**用 `sudo` 读取是必要的，但仍属只读**。

绝不要 `kill`、`kill -9`、写 `/proc/.../mem`，也不要尝试 `echo > /proc/.../...`。

<a id="section-11"></a>

### 3.2 第 2 步：进程清单与高价值筛选

```bash
# 进程清单（命令行 + exe + 用户）
cd /evidence/proc-snapshot
for d in pid-*; do
  pid=${d#pid-}
  printf '%-8s %-10s %s\
' "$pid" "$(cat $d/exe.txt 2>/dev/null | xargs basename 2>/dev/null)" \
    "$(cat $d/cmdline.txt 2>/dev/null | cut -c1-90)"
done | sort -n

# ★ 筛出 exe 指向已删除文件的进程（"删了文件还在跑"）
grep -l 'deleted' pid-*/exe.txt 2>/dev/null | while read f; do
  echo "$f → $(cat "$f")  cmd: $(cat "${f%exe.txt}cmdline.txt")"
done

# ★ 筛出 exe 位于临时/异常路径的进程
grep -hE '/tmp/|/dev/shm/|/var/tmp/|/home/[^/]+/\.' pid-*/exe.txt 2>/dev/null

# 环境变量里的敏感信息（脱敏后再进报告）
grep -hiE 'PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY|PRIVATE|DATABASE_URL|^DSN=' \
  pid-*/environ.txt 2>/dev/null | sed -E 's/=(.{0,4}).*/=\1****(已脱敏)/'
```

<a id="section-12"></a>

### 3.3 第 3 步：已删除但仍被打开的文件（`fd/` 核心用法）

```bash
cd /evidence/proc-snapshot
# fd-list.txt 形如：
# total 12
# lrwx------ 1 root root 64 Mar 18 09:41 3 -> /var/log/auth.log
# lrwx------ 1 root root 64 Mar 18 09:41 4 -> /tmp/.kworkerd (deleted)     ← ★

# 提取所有 (deleted) 条目
grep -h -- '-> .*(deleted)' pid-*/fd-list.txt 2>/dev/null | sort -u

# 提取所有指向日志/数据库/配置的打开句柄（判断进程正在写什么）
grep -hE -- '-> /(var/log|var/lib|etc)' pid-*/fd-list.txt 2>/dev/null | sort -u
```

`fd/` 揭示的"已删除但仍打开"是**需要重点解释的状态**。典型场景：

| 场景 | `/proc` 表现 |
|---|---|
| 删掉自己的可执行文件后继续运行 | `/proc/<pid>/exe → /path/bin (deleted)` |
| 清空日志文件后继续写入（`> file` 而非 `rm`） | 文件名仍在，但 inode 指向未链接的 inode |
| 删除配置文件后进程仍持有 | `fd → /etc/xxx.conf (deleted)` |

注意区分两种"删除"：`truncate`/`> file`（清空）**不产生 `(deleted)`**，因为目录项还在；只有 `rm`/`unlink` 才产生。

所以"没看到 `(deleted)`"不等于"没被清空"——清空痕迹要靠文件大小与日志内容断档来判断（见[第 02 篇](../computer-log/computer-log-system-log-analysis.md)）。

<a id="section-13"></a>

### 3.4 第 4 步：`/proc/net/tcp` 解码（可运行代码）

**先看原始内容**：

```bash
cat /evidence/proc-snapshot/net-tcp.txt
#  sl  local_address rem_address   st ...
#   0: 0100007F:1F90 00000000:0000 0A ...   ← 127.0.0.1:8080 LISTEN
#   1: 0100007F:1F90 0201A8C0:C350 01 ...   ← 127.0.0.1:8080 → 192.168.1.2:50000 ESTABLISHED
```

**方法一：shell 快速解码（不依赖额外工具）**

```bash
# 解码一行：local_address 的第 1 列
decode4() { printf '%d.%d.%d.%d' 0x${1:6:2} 0x${1:4:2} 0x${1:2:2} 0x${1:0:2}; }
decode_port() { printf '%d' "0x$1"; }

while read -r sl local rem st rest; do
  [ "$sl" = "sl" ] && continue
  la=${local%%:*}; lp=${local##*:}; ra=${rem%%:*}; rp=${rem##*:}
  [ ${#la} -eq 8 ] || continue          # 仅 IPv4
  printf '%s:%s -> %s:%s  st=%s\
' \
    "$(decode4 $la)" "$(decode_port $lp)" "$(decode4 $ra)" "$(decode_port $rp)" "$st"
done < /evidence/proc-snapshot/net-tcp.txt
# 127.0.0.1:8080 -> 0.0.0.0:0            st=0A
# 127.0.0.1:8080 -> 192.168.1.2:50000   st=01
```

`decode4` 的原理：`${1:6:2}` 取第 7-8 个字符（`7F`）作为第一段，`${1:0:2}` 取第 1-2 个字符（`01`）作为第四段——**这正是"每 2 位倒序"**。端口 `0x1F90` = 8080，**不倒序**。

方法二：Python 完整解码（同时处理 IPv4/IPv6 与状态）

```python
#!/usr/bin/env python3
import sys, socket, struct

def dec4(h):
    """/proc/net/tcp: 8 位十六进制 = 小端 32 位整数 -> 点分十进制"""
    return socket.inet_ntoa(struct.pack("<I", int(h, 16)))

def dec6(h):
    """/proc/net/tcp6: 128 位 = 4 个 32 位字，每字各自小端 -> 网络序拼接"""
    raw = b"".join(struct.pack("<I", int(h[i:i+8], 16)) for i in range(0, 32, 8))
    return socket.inet_ntop(socket.AF_INET6, raw)

STATES = {"01":"ESTABLISHED","02":"SYN_SENT","03":"SYN_RECV","04":"FIN_WAIT1",
          "05":"FIN_WAIT2","06":"TIME_WAIT","07":"CLOSE","08":"CLOSE_WAIT",
          "09":"LAST_ACK","0A":"LISTEN","0B":"CLOSING"}

def main(path):
    with open(path) as f:
        next(f)                                  # 跳过标题行
        for ln in f:
            p = ln.split()
            if len(p) < 4:
                continue
            la, lp = p[1].split(":")
            ra, rp = p[2].split(":")
            d = dec6 if len(la) == 32 else dec4   # 8 位=IPv4，32 位=IPv6
            print(f"{d(la)}:{int(lp,16):<6} -> {d(ra)}:{int(rp,16):<6} "
                  f"{STATES.get(p[3], p[3])}")

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/proc/net/tcp")
```

**运行与验证**：

```bash
python3 decode_proc_net.py /evidence/proc-snapshot/net-tcp.txt
# 127.0.0.1:8080    -> 0.0.0.0:0        LISTEN
# 127.0.0.1:8080    -> 192.168.1.2:50000 ESTABLISHED
# 0.0.0.0:22        -> 0.0.0.0:0        LISTEN
```

**解码规则速查**：

| 输入 | 步骤 | 结果 |
|---|---|---|
| `0100007F` | 每 2 位倒序 → `7F000001` | `127.0.0.1` |
| `1F90` | 直接十六进制转十进制 | `8080` |
| `00000000` | — | `0.0.0.0` |
| `C350` | — | `50000` |
| `0100007F:1F90` | 地址 + 端口 | **`127.0.0.1:8080`** ✓ |

<a id="section-14"></a>

### 3.5 第 5 步：从连接反查进程

`/proc/net/tcp` 有 `inode` 列（第 10 列），可与 `fd` 里的 socket 编号关联，定位到具体进程：

```bash
cd /evidence/proc-snapshot
# 1) 先取可疑连接的 inode（先解码出目标 IP/端口）
awk '$2 ~ /0100007F:1F90/ {print "inode="$10}' net-tcp.txt
# inode=54321

# 2) 再在所有进程的 fd 里找 socket:[54321]
grep -l 'socket:\[54321\]' pid-*/fd-list.txt 2>/dev/null
# pid-2210/fd-list.txt        ← 是 2210 号进程持有该连接
cat pid-2210/cmdline.txt
cat pid-2210/exe.txt
```

`ss` 和 `netstat` **读的就是同一份内核数据**（`/proc/net/tcp` 或 `netlink` 的 `inet_diag`）。所以 `ss`/`netstat` 的结果可以与解码结果互相验证。

若不一致（`ss` 有而 `/proc/net/tcp` 无），通常是**网络命名空间不同**（容器场景）造成的。

<a id="section-15"></a>

### 3.6 验证环节

| 验证对象 | 方法 | 通过标准 |
|---|---|---|
| 采集完整性 | 采集时间戳 vs 机器运行状态 | `collected-at-utc.txt` 早于关机时间；`uptime.txt` 显示机器在运行 |
| NUL 转换正确 | `cmdline.txt` 用空格分隔、`environ.txt` 用换行 | 不出现"连成一片"或乱码 |
| 解码正确 | `0100007F:1F90` 必得 `127.0.0.1:8080` | 已知样例回归验证通过 |
| 命名空间判定 | `/proc/1/cmdline` 是否为 systemd | 非 systemd → 标注"容器视角" |
| 连接归属 | socket inode ↔ `fd` 关联 | 能定位到具体 PID，或明示"无法归属" |

---
<a id="section-16"></a>

## 四、常见陷阱

本章按采集时机 → 快照判读 → 解析编码 → 结论表述归组，每条给出：现象、为什么会误判、误判代价、正确做法。
★ 标记表示该操作会导致原始检材永久灭失或不可逆改变，执行前必须停下来确认。

<a id="section-17"></a>

### 4.1 采集时机与现场处置

<a id="section-18"></a>

#### 陷阱 1：★ 断电/关机之后才发现需要 `/proc` 证据

**现象**：现场处置时只做了磁盘镜像，机器断电关机。分析阶段才发现需要看进程列表、网络连接、进程环境变量，而镜像里的 `/proc` 是一个空壳目录。

**原因**：`/proc` 是内核导出的虚拟文件系统，目录项和文件内容都是读取时按需生成的，磁盘上不存在任何实体数据。

`read /proc/1234/cmdline` 是内核从当前 `task_struct` 生成字节流返回；进程一退出，`/proc/1234/` 整个目录立即消失。

因此**断电后这批证据物理上不可能从磁盘镜像里恢复**。就算在运行中做了内存镜像（`DigiForensics-mem.raw`），`/proc` 内容也只在内存镜像里，需要复杂的内存恢复，实际效果远不如现场导出。

**影响**：**不可逆灭失**。这批证据里包含三类别处拿不到的东西：① 只存在于进程环境里的凭据（`/proc/<pid>/environ` 里的数据库口令、云 token——案例第 4 步就抓到了 nginx worker 持有的 `DB_PASSWORD`）；② 已删除但仍被持有的文件（`fd/` 里的 `(deleted)` 句柄）；③ 实时网络连接状态（`/proc/net/tcp` 里的 `ESTABLISHED`）。

这些在断电后无法再采集，报告里只能写"该类证据本次不可得"。

**核查**：**在断电前用 3.1 节的只读脚本导出**，这个动作成本极低（几秒）、全程只读、不 kill 任何进程。导出后立刻记录采集时刻与哈希：

```bash
cat /evidence/proc-snapshot/collected-at-utc.txt     # 快照时刻是证据的一部分
sha256sum /evidence/proc-snapshot/net-tcp.txt /evidence/proc-snapshot/pid-*/exe.txt
```

现场处置建议要写进方案：如果委托方可能需要进程/连接证据，在断电前完成 `/proc` 导出。这条建议的价值不在分析阶段，而在关机按钮按下之前。

<a id="section-19"></a>

#### 陷阱 2：★ 采集时读取 `/proc/kcore`，或往 `/proc` 里写任何东西

**现象**：为"完整备份系统状态"，尝试 `cp /proc/kcore /evidence/`，或在测试某个进程时执行 `echo x > /proc/<pid>/mem`。

**原因**：`/proc/kcore` 是内核内存的转储接口，大小约等于物理内存（甚至更大），它绝不是普通文件。

在多数系统上尝试读取会导致系统**立即挂起或崩溃**。分析者看它是一个"路径明确、大小已知"的文件，容易以为只是慢。

同样，`/proc/<pid>/mem` 是进程的内存写入接口，往里写会直接改变目标进程的行为。

**影响**：**采集动作本身会摧毁现场。**

`/proc/kcore` 读取失败可能让内核陷入不可响应状态，导致数据未落盘；而写 `/proc/<pid>/mem` 会污染正在运行的进程，可能触发它的检测逻辑、改变行为、甚至自毁。

两者都不可逆，且**销毁的是一个正在运行、随时可能断电的系统**。

**核查**：**采集只读，且只读白名单内的路径**。

3.1 节脚本里的采集项（`cmdline`/`environ`/`exe`/`cwd`/`status`/`maps`/`cgroup`/`fd` 列表 + `net-*`/`modules`/`mounts`）都是安全的；`kcore`、`mem`、`sysrq-trigger` 一律不碰。

需要内核级信息时用 `/proc/modules`、`/proc/mountinfo` 这些文本接口替代。

<a id="section-20"></a>

### 4.2 快照判读

<a id="section-21"></a>

#### 陷阱 3：把"进程在快照时刻存在"当成"该进程在案发时段一直存在"

**现象**：快照里发现 PID 3341 运行 `/usr/local/bin/.cache/sysd`，报告写「攻击者的后门进程自 22:49 起持续运行」。

**原因**：`/proc` 快照是某一时刻的瞬时状态，它只回答"采集那一刻有什么"，不回答"之前有什么、持续了多久"。

PID 也可能被复用——Linux 的 PID 会循环分配，一个高 PID 号不代表它是后来才创建的进程。

案例第 1 步的 `uptime.txt` 显示 `up 412 days`，即机器已连续运行 412 天，这个 PID 号完全可能对应一个完全不同的、更早的进程。

**影响**：把瞬时状态推成持续行为，会虚构出一条长达数小时的驻留时间线。而这个时长往往是风险评级（"长期驻留"vs"临时使用"）的直接输入。

**核查**：**PID 快照只能给"存在性"，时长必须另有来源**。

可行的时间证据：`/proc/<pid>/stat` 字段 22（starttime，系统启动后的时钟节拍数）配合 `btime` 可算出**进程启动时刻**——这是快照里唯一能定时间的数据点；除此之外靠文件系统 `ctime` 链、auth.log 的命令记录、持久化配置的 mtime。

"进程已运行 X 小时"这类结论必须有 stat 的 starttime 支撑，不能靠 PID 号大小或直觉。

<a id="section-22"></a>

#### 陷阱 4：把 `/proc/<pid>/exe` 的 `(deleted)` 读成"文件不存在，所以无证据"

**现象**：`readlink /proc/3341/exe` 返回 `/usr/local/bin/.cache/sysd (deleted)`，分析者在磁盘上 `find` 这个路径一无所获，于是判定"无此程序，排除"。

**原因**：`(deleted)` 的含义是目录项已被 `unlink`，但 inode 仍被该进程持有映射——程序还在运行，磁盘上却没有这个文件了。

它同时给出文件名、路径、正在运行的进程三样东西，在磁盘上已无对应文件时是直接证据。

案例第 2 步的 `sysd` 正是如此——持久化配置里 `ExecStart=/usr/local/bin/.cache/sysd` 还在，但载荷文件已从磁盘消失。"服务配置还在、载荷已删"是需要与运维清理等替代解释区分的中间状态。

而这个载荷的存在只能由 `/proc` 证明。

**影响**：把它当成"无证据"就丢掉了本主题最核心的一类发现。

更糟的是，如果你据此写"该载荷不存在，服务无法启动"，就漏掉了一个正在运行的恶意进程。

**核查**：把 `(deleted)` 视为**最高优先级发现**，并做三件事。

① 立刻固定快照里该 PID 的全部相关项（`cmdline`、`environ`、`fd/`、`maps`、`cgroup`）并记哈希；② 记录 PID、路径、进程启动时刻（`stat` 的 starttime）；③ 与持久化配置、auth.log 的命令记录交叉，确认"何时被启动、为何被删"。

**若快照不可得，这条证据本次无法取得**——必须在报告的证据局限里写明。

<a id="section-23"></a>

#### 陷阱 5：把 `fd/` 里的普通句柄当成"该文件正在被写"

**现象**：`/proc/1189/fd/4 -> /var/log/apt/history.log.1.gz`（无 deleted），报告写「该进程正在写 apt 历史日志」。

**原因**：`fd/` 列出的是进程打开的所有描述符，包含读、写、还有仅用于查询属性或作目录引用的。

描述符的打开模式（`O_RDONLY`/`O_WRONLY`/`O_RDWR`）要看 `fdinfo/` 里对应项的 `flags` 字段才能确定。很多服务（如 rsyslog、systemd-journald、logrotate）会**长期持有日志文件的读句柄用于跟踪轮转**，这属于正常行为。**"持有"与"正在写"是两件事。**

**影响**：会把系统正常行为（`apt`/`dpkg` 相关进程持有归档日志的句柄）误报为"日志正在被篡改"。

案例第 3 步的 `pid-1189/fd/4 -> /var/log/apt/history.log.1.gz (deleted)` 有 `(deleted)` 标记，这才是真正值得追的点——**归档被删了但仍被持有**。

**核查**：区分三种情况并分别定性。

① **`(deleted)` 句柄** → 最高优先级（文件已删但仍持有，可继续读写，可从 `/proc/<pid>/fd/<n>` 直接读出内容）；② **指向仍在的文件的句柄** → 需要 `cat /proc/<pid>/fdinfo/<n>` 看 `flags` 判定读写模式，且要结合进程类型判断是否合理；③ **指向非常规路径的句柄**（临时目录、已删除配置）→ 单独记录。

报告里对每条句柄写出"目标路径 + 是否 deleted + 进程身份 + 定性"四要素。

<a id="section-24"></a>

#### 陷阱 6：把 `cmdline` 直接 `cat` 后按空格切分解析

**现象**：`cat /proc/3341/cmdline` 输出一行连成片的内容，分析者按空格切出参数，得到错误的参数列表；看到某个参数"包含奇怪的空格"就认为格式异常。

**原因**：`cmdline` 与 `environ` 的字段是用 NUL（`\0`）分隔的，不是空格也不是换行。

直接 `cat` 会看到"连成一片"或终端不换行。`cmdline` 的第一个参数是程序路径（通常与 `exe` 相同），后续是原始参数——**参数本身可以合法地包含空格**，按空格切分必然错位。

而 `environ` 的 `KEY=VALUE` 同样用 NUL 分隔。

**影响**：参数解析错位会让脚本调用的真实参数失真——本篇 2.2 特别指出 `cmdline` 的价值在于"**能证明脚本的真实参数**"，错位恰好毁掉了这个价值。

而且这种错误很隐蔽：输出看起来"是一行文本"，不报错。

**核查**：**采集时就完成转换**（3.1 节的脚本已经这么做了）：

```bash
tr '\0' ' '  < /proc/<pid>/cmdline > cmdline.txt     # NUL→空格
tr '\0' '\
' < /proc/<pid>/environ > environ.txt     # NUL→换行
```

对已经采集成"连成一片"的历史快照，用 `tr` 补救：

```bash
tr '\0' '\
' < cmdline.txt
```

参数内含空格时，空格转换会丢失边界——遇到可疑参数（路径含空格、base64 串）要回到原始 NUL 分隔形式重解，报告里标注"该参数含空格，边界依据 NUL 分隔确定"。

<a id="section-25"></a>

### 4.3 编码解析

<a id="section-26"></a>

#### 陷阱 7：把 `/proc/net/tcp` 的地址字段当十六进制直读

**现象**：看到 `0100007F:1F90` 直接读成 "地址 `0100007F`，端口 `1F90`"，报告里出现一个不存在的十六进制地址。

**原因**：地址部分是 32 位（IPv4）或 128 位（IPv6）的十六进制，但按 4 字节一组、每组内部字节序反转（小端）存放。

所以 `0100007F` 必须"每 2 位倒序一次"变成 `7F000001`，再按点分十进制读才是 `127.0.0.1`。

IPv6 更复杂：128 位 = 4 个 32 位字，**每个 32 位字各自做一次小端字节交换**，再按网络序拼成 16 字节。

**影响**：地址解错会让整张连接表指向不存在的 IP。

基于错误 IP 的结论（"攻击者从 127.0.0.1 连接"这种荒唐结果，或者把内网地址认成公网地址）会直接摧毁报告的技术可信度。

**核查**：解码步骤要写成可复核的形式，并**在报告里保留原始值与解码结果两列**。IPv4 的等价说法是"把 8 位十六进制看作小端 32 位整数，再用网络字节序解释"：

```
0100007F:1F90  →  地址 0100007F 倒序为 7F000001 → 127.0.0.1
                →  端口 1F90（端口不交换）= 8080
                →  结果 127.0.0.1:8080
```

IPv6 参考值：`00000000000000000000000001000000` → `::1`；`B80D012000000000000000001000000` → `2001:db8::1`。IPv4 与 IPv6 用地址字段的十六进制长度区分：8 个字符是 IPv4（`/proc/net/tcp`），32 个字符是 IPv6（`/proc/net/tcp6`），两者不会出现在同一个文件里。

<a id="section-27"></a>

#### 陷阱 8：把 `/proc/net/tcp` 的连接状态读反

**现象**：`st` 字段值 `0A` 被当成"已建立的活跃连接"，报告写「发现攻击者与外部保持活跃连接」。

**原因**：`st` 是单字节十六进制的 TCP 状态码，语义是固定映射的：`0A` = **LISTEN**（监听中，**根本没有对外连接**）、`01` = **ESTABLISHED**（活跃连接）、`06` = TIME_WAIT（刚关闭）、`08` = CLOSE_WAIT（**对端已关闭、本端未关闭**——进程未正确收尾，程序异常或常驻实现均可能出现）。

把 `0A` 读成活跃连接，方向就完全错了。

**影响**：`0A` 是监听状态，把它读成外传通道，会凭空造出一条"数据外传正在进行"的结论；或者反过来，因为"只有 LISTEN 没有 ESTABLISHED"而写"无外传行为"。

**核查**：判定存在对外连接的判据是 `01`（ESTABLISHED）且对端地址指向外部；它给出的是连接事实，传输内容仍需流量侧证据。

`0A`（LISTEN）只说明"该端口在监听"——**非预期端口的 LISTEN 本身值得深挖**（说明有服务在监听不该有的端口），但它不代表有连接。

同理 `08`（CLOSE_WAIT）堆积是进程未正确收尾的信号，恶意程序可能刻意不关闭以维持后门，普通程序缺陷也会产生同样的形态，这条要单独提取并结合进程身份定性。

<a id="section-28"></a>

### 4.4 结论表述

<a id="section-29"></a>

#### 陷阱 9：把"快照采集时刻与登录时刻不自洽"当作细节放过

**现象**：快照采集时刻是 09:40:55，auth.log 里攻击者的连接建立是 09:40:58.771、会话关闭是 09:41:07。快照里**有**那条连接，分析者直接采信并写进报告。

**原因**：采集时刻落在连接建立之前 3 秒，而连接仍然出现在快照里——这两件事不可能同时为真。

案例第 1 步自己点出了这个自洽性要求：「若采集时刻晚于 09:41:07 的 `session closed`，则该连接不应存在；**两者必须自洽**」。

这说明快照要么不是同一时刻的产物，要么时钟不同步，要么那条连接的来源需要重新解释。

**影响**：不自洽的证据一旦被采纳，后续基于它的所有结论（"抓到了数据外传通道"）都建在流沙上。对方只需核对时间戳就能推翻整条证据链。

**核查**：每条来自 `/proc` 快照的发现，都要用采集时刻与其它工件的时间交叉验证，这是本篇特有的自洽性检查：

```bash
cat /evidence/proc-snapshot/collected-at-utc.txt      # 快照时刻
grep 'Accepted\|session opened\|session closed' /evidence/auth-merged.txt
```

三种可能的解释要逐一排除：① 时钟不同步（比对 `uptime.txt` 的 `up` 时长与 auth.log 的首次启动记录）；② 快照是多时刻拼接的（检查各文件的 mtime 是否一致）；③ 连接确实在采集前建立（**以 auth.log 为准，修正快照时刻的解读**）。

自洽性检查的结论要写进报告，而不是留给读者自己发现。

<a id="section-30"></a>

#### 陷阱 10：把"环境变量含明文口令"直接写进报告

**现象**：从 `/proc/2210/environ` 提取到 `DB_PASSWORD=S3cr3t...`，报告里原文照抄完整口令。

**原因**：**这是取证材料的处置规范问题，但后果是现实的。**

报告是流转文件——会给委托方、可能进入诉讼材料、可能被归档。**凭据一旦以明文出现在报告里，就必须视为已泄露**：数据库口令的轮换成本、该口令是否复用于其他系统、日志访问权限是否需要收紧，这些都会因为报告的扩散而扩大损失面。

**影响**：不可逆的凭据泄露。而且这在合规场景下可能直接构成数据泄露事件本身——**取证报告泄露了它本该保护的凭据**，这是最尴尬的一种失败。

**核查**：报告只写"存在性与归属"，完整值留在受控的证据目录里。

采集与脱敏一步完成：

```bash
grep -hiE 'PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY|PRIVATE|DATABASE_URL|^DSN=' \
  pid-*/environ.txt 2>/dev/null \
  | sed -E 's/=(.{0,4}).*/=\1****(已脱敏)/'
```

**脱敏后仍要写全四要素**：变量名（`DB_PASSWORD`）、所在进程（PID 2210 = nginx worker）、值的前 4 位（便于委托方在自己环境里定位）、以及"完整值保存在 `/evidence/…` 并已记录哈希"。

委托方需要的是"哪个服务的哪个凭据需要轮换"，不是凭据本身。

<a id="section-31"></a>

## 五、案例示例

<a id="section-32"></a>

### 5.1 断电前 proc 快照定案活跃会话与已删除载荷

**场景**

Ubuntu Server 22.04 Web 服务器。委托方要求查明数据是否被外传、以及是否有"删了文件仍在运行"的可疑进程。**现场在断电前获得了 `/proc` 在线快照** `proc-snapshot`（含全部采集内容）。磁盘检材 `DigiForensics.dd`（raw），ext4 起始扇区 1181696，**随后断电**。

这条路径值得走，因为这是全案中唯一能证明"攻击者在某个瞬间仍在线"的证据类型。

磁盘镜像无论分析多久都只能证明"过去发生过什么"，而运行态才能证明"此刻正在发生什么"。

**处置过程**

第 1 步，确认快照有效性与机器运行状态：

```bash
cat /evidence/proc-snapshot/collected-at-utc.txt
# 2024-03-18T01:40:55Z          ← 采集时刻（UTC）
cat /evidence/proc-snapshot/uptime.txt
# 01:40:55 up 412 days, 03:17,  1 user,  load average: 0.31, 0.28, 0.24
```

快照于 2024-03-18 09:40:55（本地 UTC+8） 采集，即断电前约 1 分钟，机器处于运行状态。**系统已运行 412 天未重启。**

这意味着 `/proc` 里的 PID 与进程启动时间可以横向参照：启动时间接近 412 天前、且身份不属于正常长驻服务的进程值得单独核查——长期运行本身不构成可疑，需结合可执行路径与服务配置判断。

第 2 步，筛出"exe 已删除"的进程（**需重点核查的状态**）：

```bash
cd /evidence/proc-snapshot
grep -l 'deleted' pid-*/exe.txt 2>/dev/null | while read f; do
  echo "$f → $(cat "$f")  cmd: $(tr '\0' ' ' < "${f%exe.txt}cmdline.txt")"
done
# pid-3341/exe.txt → /usr/local/bin/.cache/sysd (deleted)   cmd: /usr/local/bin/.cache/sysd
```

**PID 3341 运行的可执行文件已从磁盘删除。** `exe` 是内核持有的 inode 引用，**`rm` 只删目录项，进程照常运行**。

第 3 步，用 fd 找被删除的日志/配置文件：

```bash
grep -h -- '-> .*(deleted)' pid-*/fd-list.txt 2>/dev/null | sort -u
# 11 -> /tmp/.kworkerd (deleted)                              ← pid-3341 持有
# 4  -> /var/log/apt/history.log.1.gz (deleted)              ← pid-1189 持有
```

第 4 步，环境变量取证（**必须脱敏**）：

```bash
grep -hiE 'PASSWORD|SECRET|TOKEN|APIKEY|DATABASE_URL' pid-*/environ.txt 2>/dev/null \
  | sed -E 's/=(.{0,4}).*/=\1****(已脱敏)/' | head
# pid-2210/environ.txt:DB_PASSWORD=S3cr****(已脱敏)     ← nginx worker 持有数据库口令
# pid-1189/environ.txt:PGPASSWORD=****(已脱敏)
```

第 5 步，`/proc/net/tcp` 解码找外传连接：

```bash
python3 decode_proc_net.py /evidence/proc-snapshot/net-tcp.txt | grep ESTABLISHED
# 127.0.0.1:8080    -> 192.168.1.2:50000   ESTABLISHED
# 10.0.0.5:22       -> 203.0.113.77:41892  ESTABLISHED     ← ★ 外部 IP
```

第 6 步，从连接反查进程（**inode 关联，三步法**）：

```bash
# 1) 取该连接的 socket inode
awk '$2=="0500000A:0016" && $3 ~ /^4D7100CB:/ {print "inode="$10}' /evidence/proc-snapshot/net-tcp.txt
# inode=55123

# 2) 在所有进程 fd 里找该 socket
grep -l 'socket:\[55123\]' pid-*/fd-list.txt
# pid-9201/fd-list.txt

# 3) 读该进程身份
tr '\0' ' ' < pid-9201/cmdline.txt; echo
# sshd: deploy@pts/0            ← ★ 正是攻击者的 SSH 会话进程
```

编码自检：`10.0.0.5` 每 2 位倒序 = `05 00 00 0A` → `0500000A` ✓；`203.0.113.77` 倒序 = `4D 71 00 CB` → `4D7100CB` ✓；`22` = `0016` ✓。

**把解码结果写进报告前必须用脚本反验一遍**——写成 `4D03C3CB` 会被解成 `203.195.3.77`，与目标 IP 完全不符，且报告仍"看起来合理"。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 采集时刻（2024-03-18 09:40:55 本地）存在到 `203.0.113.77` 的 ESTABLISHED SSH 连接，属 `sshd: deploy@pts/0` 会话 | `/proc/net/tcp` ESTABLISHED + socket inode 关联到 `sshd: deploy@pts/0` + auth.log 二次登录；三项分属连接表、进程身份与登录日志三类工件 | 强（连接存在已确认；`203.0.113.77` 为文档示例保留段地址，实际分析需按部署网段替换） |
| 载荷 `/usr/local/bin/.cache/sysd` 与 `/tmp/.kworkerd` 的目录项已删除，但进程 3341 仍在运行 | `/proc/3341/exe` 与 `fd` 均标 `(deleted)`，两处为同一进程的不同项，分别说明 exe 与打开句柄状态 | 强（删除者身份见 5.2，需与 `auth.log` 交叉） |
| `sysupdate` 服务因载荷被删已无法正常工作 | unit 的 `ExecStart` 指向的路径已不存在 | 强（机制可解释） |
| 存在持有数据库口令的进程环境，**该凭据不落盘** | `/proc/2210/environ` | 强（**但采集后已随断电丢失**） |
| 本案**无内存镜像**，但断电前的 `/proc` 快照补足了运行时证据 | 采集脚本 + 时间戳 | 强（方法学价值） |

**必须诚实标注的局限**：`environ` 里的凭据只存在于采集那一刻的内存中，机器现已断电。

**若取证时未在断电前完成采集，该类证据本次无法取得**——这是本案正面结论的前提条件，应作为方法学结论单独强调。

**误判对照**

本案最容易得出的错误结论是「`/proc/3341/exe` 显示 `/usr/local/bin/.cache/sysd (deleted)`，说明攻击者**在 3341 这个进程里执行了它**，所以该进程就是攻击者的主进程」——前半句对，后半句的定性是错的。

**正确判据是 PID 3341 的启动时间与父进程**，两个字段：

1. PID 3341 的 `stat` 字段（starttime）。它给出的是**自开机起的秒数偏移**，换算后可知进程何时启动。若该值是 03-18 采集当日或 03-17 22:49 前后（对应 `sysupdate.service` 的 `Restart=always` 拉起时刻），说明它是**服务反复重启产生的短生命周期子进程**；若是很早的偏移值（数百天），则说明它**长期驻留**。**这两种形态对"是否为主进程"的结论完全不同。**
2. `/proc/3341/status` 的 `PPid`。若 PPid 是一个 `systemd`（PID 1）的子进程，则 3341 是**服务的 worker**，攻击者是通过 `sysupdate.service` 间接运行它的；若 PPid 已被回收（`PPid: 0`），说明**它的父进程已经退出**，这个进程是脱离的孤儿进程，**那才是"攻击者在交互式会话里手动起的后台进程"**。

**按错误判据走的代价**：把服务 worker 误判为"攻击者主进程"，会得出"攻击者在实时监视这台机器"的结论，从而**建议委托方保持在线监控、不必清理**。而实际情形是这个 worker 的载荷已被删除、服务已失效——**真实威胁等级比误判结论低**，但误判会让处置优先级错配：真正该做的是清理残留的 unit/crontab 配置（因为载荷随时可能被重新投放），而不是盯监控。

第二个易错点：把 `(deleted)` 读成"文件被攻击者删了，所以这是反取证行为"。 正确判据是**删除时机的自洽性**：`sysupdate.service` 的 `ExecStart` 指向的路径已不存在，而服务仍在跑——这在 `Restart=always` 下是**必然状态**（服务启动过 → 文件被删 → 崩溃 → 重启 → 启动失败 → 再崩）。进程 3341 之所以还活着，是因为它启动时文件还在。所以 `(deleted)` 证明的是"**文件在进程运行期间被删除**"，至于删除者是攻击者还是运维清理，本案无法从 `/proc` 单独确定，需要与 `auth.log` 的 sudo 行和文件时间戳交叉。

---

<a id="section-33"></a>

### 5.2 断电前快照与磁盘镜像的交叉时序

**场景**

同系列主机 `app04`（Ubuntu 22.04），委托方要求确定"攻击者清理痕迹的具体时刻"。检材 `DigiForensics.dd` 与断电前采集的 `proc-snapshot`（采集于 2024-03-18 09:40:55 本地）。

这条路径值得走，因为`/proc` 快照能给出"某个路径在某一刻是否存在"，而这是磁盘时间戳给不出的。

删改文件会把 mtime 更新为删除时刻，反而抹掉了痕迹。

**处置过程**

第 1 步，从快照取"路径存在性"的时间证据（**这是 `/proc` 独有的能力**）：

```bash
# exe 指向的路径：采集时刻已删除
cat /evidence/proc-snapshot/pid-3341/exe.txt
# /usr/local/bin/.cache/sysd (deleted)

# 进程持有的 fd：这些文件在采集时刻还存在（已被 unlink 但句柄有效）
grep -E '^11 ->' /evidence/proc-snapshot/pid-3341/fd-list.txt
# 11 -> /tmp/.kworkerd (deleted)
```

**关键区别**：`exe.txt` 里的 `(deleted)` 表示**目录项已消失**；而 `fd-list.txt` 里的 `(deleted)` 表示**文件内容仍被这个进程持有**。

**后者证明"文件在采集时刻还能被读出内容"**——这是完全不同的结论强度。

第 2 步，尝试从 fd 恢复内容（**这是本文档中 `fd` 的主要用途**）：

```bash
# 若快照采集时对 fd 做了 cp，deleted 文件的内容是救回来的唯一机会
ls -l /evidence/proc-snapshot/fd-content/pid-3341/fd-11 2>/dev/null
# -rw-r--r-- 1 root root 154880 2024-03-18 09:40:55
file /evidence/proc-snapshot/fd-content/pid-3341/fd-11
# ELF 64-bit LSB pie executable, x86-64, stripped
sha256sum /evidence/proc-snapshot/fd-content/pid-3341/fd-11
# a1b2c3...  ← 与 /usr/bin/xxx-agent 的哈希不同，可区分变体
```

**已删除的载荷内容被完整恢复**——磁盘镜像上无法取得该内容，`fd` 是当时的唯一来源。

第 3步，从快照取进程启动时间并换算（区分"长期驻留"与"刚被拉起"）：

```bash
cat /evidence/proc-snapshot/pid-3341/stat.txt
# 3341 (sysd) S 1 2201 3341 3341 0 -1 4194560 ...
# 第 22 个字段 starttime（自开机秒）= 2894412
awk '/btime/{print $2}' /proc/stat   # 开机时间戳（分析机上取镜像内值）
# 1710720000
python3 -c "import datetime;print(datetime.datetime.fromtimestamp(1710720000+2894412))"
# 2024-03-18 01:46:52  → 本地 09:46:52
```

进程 3341 启动于 2024-03-18 09:46:52 本地，即**采集时刻（09:40:55）之后**。

这说明**它是在快照采集完成之后才出现的**，快照里的 3341 与实际启动的 3341 **不是同一个进程世代**。

这一点必须写明，否则会得出"快照里的进程在跑"的错误结论。

第 4 步，与磁盘侧时间戳交叉：

```bash
stat -c '%n mtime=%y ctime=%z size=%s' /mnt/df/usr/local/bin/.cache/sysd 2>&1
# ls: cannot access '/mnt/df/usr/local/bin/.cache/sysd': No such file or directory
# → 文件已不存在，无 mtime 可查（删除后时间戳消失）

# 查父目录的 mtime（目录项变动会更新目录 mtime）
stat -c '%n mtime=%y' /mnt/df/usr/local/bin/.cache/ 2>&1
# ls: cannot access: No such file or directory
# → 整个目录被删，目录本身也无时间戳
```

第 5 步，找删除动作的日志侧证据（**时间上应当早于快照**）：

```bash
grep -iE 'rm |unlink|shred' /mnt/df/home/deploy/.bash_hist.bak
# #1710725900
# rm -rf /usr/local/bin/.cache
# → epoch 1710725900 = 2024-03-18T01:38:20Z = 本地 09:38:20

grep -iE 'sudo.*COMMAND=' /evidence/auth-merged.txt | sed -n '/Mar 18 09:3/p'
# Mar 18 09:38:20 web01 sudo:  deploy : COMMAND=/bin/rm -rf /usr/local/bin/.cache
# → 与历史 epoch 秒级吻合，双源印证
```

**结论**

- 删除动作定案于 2024-03-18 09:38:20 本地：`rm -rf /usr/local/bin/.cache`（`.bash_hist.bak` 的 `#1710725900` 与 `auth.log` 的 `sudo COMMAND=/bin/rm -rf ...` **秒级双源印证**）。快照采集于 09:40:55，**删除发生在采集前 2 分 35 秒**。
- 因此快照里 `pid-3341/exe.txt` 出现 `(deleted)`、而 `fd` 仍持有 `/tmp/.kworkerd`——**两个状态是自洽的**：`.cache` 目录被 `rm -rf` 删掉了（所以 exe 标 deleted），而 `/tmp/.kworkerd` **不在 `.cache` 目录内**，是被单独删除的（所以进程仍持有它的句柄）。
- **已删除载荷的内容被完整恢复**：从 fd 内容快照取回 `/tmp/.kworkerd` 的 ELF 文件（154880 字节），SHA256 `a1b2c3...`。**这是本次检验中该文件内容在磁盘之外的唯一副本。**
- **必须写明的采集局限**：快照中 PID 3341 的 `starttime` 换算为 09:46:52，**晚于快照采集时刻 09:40:55**。因此**不能声称"快照证明该进程在采集时刻正在运行"**。

  `/proc` 快照是一次性读取各目录，不同目录的读取时刻存在毫秒级到秒级的漂移，且进程在采集窗口内可能已经重启。

  正确表述是「快照记录了 PID 3341 的存在，其 `starttime` 字段表明该 PID 对应的进程实例启动于 09:46:52，与采集时刻不自洽，说明采集期间发生过进程世代更替，PID 被复用或进程已重启」。

**误判对照**

本案最容易得出的错误结论是「快照显示 `pid-3341/exe.txt` 里是 `(deleted)`，而 `pid-3341/stat.txt` 的 starttime 换算出来是 09:46:52，这两个数据矛盾，说明快照被篡改或采集有问题，运行时证据不可信，应予排除」。

正确判据是 `/proc` 快照的采集语义与 PID 复用机制。三层：

1. **快照是"多个目录的多次读取"，不是一个原子时刻**。采集脚本逐个读取 `/proc/<pid>/` 下各子目录、逐行读取 `/proc/net/tcp`，整个过程耗时数秒到数十秒。**不同 PID 的数据来自略微不同的时刻**，因此"某个进程的 starttime 晚于快照标注的采集时刻"在秒级精度下完全可能。
2. PID 会复用，而 inode 与 starttime 组合是进程身份的唯一标识。PID 3341 可能在采集后被系统分配给了新进程。单看 PID 编号没有意义，必须 `(PID, starttime)` 一起比对。
3. `collected-at-utc.txt` 记录的是采集脚本开始或结束的某个时刻，不是"所有数据的同时刻"。把它当作原子时间点使用，是这类快照最常见的误用。

**按错误判据走的代价**：把矛盾读成"证据不可信"并排除整个快照，**会连带丢掉本案最有价值的两项证据**——从 fd 恢复出的 `/tmp/.kworkerd` 内容副本，以及"删除动作发生在采集前 2 分 35 秒"这个时序关系。

丢掉前者意味着**该载荷内容无法再取得**（磁盘上已无副本）；丢掉后者意味着无法把删除行为与攻击者会话关联。

因为一个秒级的时序瑕疵而否定整份运行态证据，是运行态取证中代价很高的判断错误。

第二个易错点：把 `fd` 里的 `(deleted)` 与 `exe.txt` 里的 `(deleted)` 当成同一件事。 正确判据是两者的语义不同：

| 位置 | 含义 | 能推出什么 |
|---|---|---|
| `exe.txt` 的 `(deleted)` | **可执行文件的目录项已被删除** | 该路径在采集时刻**已不存在于文件系统** |
| `fd-list.txt` 的 `(deleted)` | **该 fd 指向已被 unlink 的 inode** | 该文件**内容仍可读**，句柄有效 |

**按这个区分，误判代价是**把"内容还能读"误当成"文件还在"，从而**放弃从 fd 恢复内容**——而这恰恰是运行态取证相对于磁盘取证的核心优势。**当磁盘上文件已删时，fd 是唯一的抢救机会。**

---

<a id="section-34"></a>

### 5.3 反例：fd 残留导致的口令文件误报为泄露凭据

**场景**

某台 Ubuntu 22.04 应用服务器 `app11`，委托方在一次例行检查中看到 `/proc` 快照里有多个进程持有数据库口令，怀疑"凭据已在内存中长期暴露，应立即轮换全部密钥"。检材为该机在例行采集时保存的 `proc-snapshot`。

这条路径值得写，因为**"看到口令"和"口令可被利用"之间有本质区别**，而取证报告的措辞直接决定后续的处置成本。

**处置过程**

第 1 步，定位持有凭据的进程及其**真实身份**：

```bash
grep -lE 'DB_PASSWORD|PGPASSWORD' /evidence/proc-snapshot/pid-*/environ.txt
# /evidence/proc-snapshot/pid-2210/environ.txt
# /evidence/proc-snapshot/pid-1189/environ.txt

for p in 2210 1189; do
  echo "== pid-$p =="
  tr '\0' ' ' < /evidence/proc-snapshot/pid-$p/cmdline.txt; echo
  grep -E '^(Name|PPid|Uid):' /evidence/proc-snapshot/pid-$p/status.txt
done
# == pid-2210 ==
# nginx: worker process
#   Name: nginx   PPid: 2201   Uid: 33 33 33 33
# == pid-1189 ==
# /usr/lib/apt/methods/http
#   Name: apt-http   PPid: 1120   Uid: 0 0 0 0
```

**关键**：`Uid: 33 33 33 33` 是 `www-data`，`nginx: worker process` 是正常业务进程。

pid-1189 的 cmdline 是 `/usr/lib/apt/methods/http`，是 apt 的 HTTP 传输方法，**正在执行系统包更新**。

第 2 步，确认口令的来源是**环境继承**而非外部注入：

```bash
# nginx master 的 environ 里也有同一个口令 → 说明是 master 传给 worker 的
grep -c DB_PASSWORD /evidence/proc-snapshot/pid-2201/environ.txt
# 1
grep -c DB_PASSWORD /evidence/proc-snapshot/pid-2210/environ.txt
# 1
# 父进程有 → 子进程继承 → 正常的服务启动方式

# apt 的口令来自哪里？
grep -oE '^(http_proxy|https_proxy)=' /evidence/proc-snapshot/pid-1189/environ.txt
# https_proxy=http://user:PASS****@proxy.corp.internal:3128
# → 是代理认证口令，且 apt-http 进程会在事务结束后退出
```

第 3 步，评估**暴露面**（谁能读到这些 environ）：

```bash
ls -l /evidence/proc-snapshot/ | head -3
# -rwx------ 1 root root  4096 2024-03-18 09:40 collected-at-utc.txt
# → 采集目录权限 700，仅 root 可读

# 原始 /proc 下的 environ 权限
# /proc/<pid>/environ  = -r--------  owner = 进程属主
# → 只有 root 与该进程属本能读
ls -l /mnt/df/proc/2210/environ 2>/dev/null
# -r-------- 1 www-data www-data
```

第 4 步，确认进程生命周期（**关键：短生命周期 vs 常驻**）：

```bash
cat /evidence/proc-snapshot/pid-1189/status.txt | grep -E '^(State|PPid)'
# State: S (sleeping)   PPid: 1120
cat /evidence/proc-snapshot/pid-1120/cmdline.txt | tr '\0' ' '; echo
# /usr/bin/apt-get -y upgrade
# → apt 事务进行中，结束后 pid-1189 随父进程退出
# 对比：pid-2210 是 nginx worker，随 master 长期驻留
```

第 5 步，查是否有非预期的外部可达（**这才是真正的风险判据**）：

```bash
python3 decode_proc_net.py /evidence/proc-snapshot/net-tcp.txt | grep -E 'LISTEN'
# 0.0.0.0:80       LISTEN
# 0.0.0.0:22       LISTEN
# 127.0.0.1:3306    LISTEN      ← ★ 数据库只监听回环，未对外暴露
# 0.0.0.0:8080     LISTEN
```

**结论**

- **确实存在凭据驻留内存**：`nginx: worker process`（pid-2210，属主 `www-data`）的 environ 含 `DB_PASSWORD`；`/usr/lib/apt/methods/http`（pid-1189，属主 root）的 environ 含代理认证口令。**该结论成立，须写入报告。**
- **但暴露面极为有限，三项判据同时成立**：
  1. **来源正常**：nginx 的口令由 master（pid-2201）继承而来，属服务启动方式；apt 的口令是 `https_proxy` 的代理认证，来自系统代理配置。**均非外部注入。**
  2. **读取权限受控**：`/proc/<pid>/environ` 权限为 `-r--------`，属主是 `www-data`，**只有 root 与 `www-data` 能读**；快照目录权限 700 仅 root 可读。**普通用户无法读取。**
  3. **服务面收敛**：MySQL 监听 `127.0.0.1:3306`（仅回环），**数据库端口未对外暴露**，从网络上无法直接利用该口令。
- **另需区分生命周期**：`pid-1189` 隶属正在进行的 `apt-get -y upgrade` 事务，通常随事务结束退出；`pid-2210` 是 nginx worker，随 master 长期驻留。**两者在"持续暴露时间"上存在数量级差异。**
- **对委托方问题的准确答复**：「本机 `/proc` 环境变量中确实存在数据库口令与代理认证口令，但其暴露面为 root 与服务属主可读、数据库仅监听回环地址，符合正常的服务配置形态。建议的处置是常规性的：不在本条结论上启动全量凭据轮换；若委托方关注的是凭据在内存中的驻留，可考虑将数据库口令从环境变量改为受限配置文件（`my.cnf` 段，权限 600）或使用 systemd `LoadCredential`。同时须记录一条真实局限：机器已于采集后断电，这些凭据当前已不在内存中，若要评估"历史上是否存在第三方读取过这些 environ 的痕迹"，需依赖审计日志（`execve` 记录）或内存镜像，本案无此类证据，因此该问题在本案中不可回答**。」

**误判对照**

本案最容易得出的错误结论是「`/proc` 快照里直接读到了数据库明文口令 `DB_PASSWORD`，且该进程属主是 `www-data`（非 root），说明数据库凭据以明文形式对普通服务账户可见，攻击者一旦拿下 www 用户的 RCE 即可直接获取数据库完全控制权——必须立即启动全量凭据轮换，并认定这构成一起凭据管理失职事件」。

**正确判据是三项缺一不可的"可利用性"检验**，本案三项全部不成立：

1. **读取者是谁**。`/proc/<pid>/environ` 的权限是 `-r--------`，属主为 `www-data`。能读它的只有 root 和 www-data 自己。判据不是"口令明文存在"，而是"**谁能读到它**"。若 `cat /proc/2201/environ` 以普通用户身份执行，会得到 `Permission denied`。
2. **凭据能连到什么**。MySQL 监听 `127.0.0.1:3306`——**只有本机能连**。从网络侧无法直接利用。即便口令泄露，攻击者仍需先在该主机上取得代码执行能力。"有口令"与"口令可被利用"之间隔着"可达性"这一环。
3. **来源是否异常**。口令由服务 master 继承、来自系统代理配置，**均为标准做法**。异常的判据是"口令出现在不该出现它的进程里"（比如出现在 `sshd` 或某个临时 shell 的 environ 中），本案不属于此列。

**按错误判据走的代价**：这是**处置成本最高的一类误判**。

把"常规配置形态"定性为"凭据管理失职事件"，会触发一次全量凭据轮换——涉及所有数据库、所有服务账号、所有 API 密钥，且需要停机窗口。

而本案经检验并无实际暴露，反而**掩盖了真正值得关注的问题**（服务端口 `0.0.0.0:8080` 对外监听这一项需要独立评估）。

这类"看到密钥就报警"的判据，会让取证报告的专业度崩塌——因为它把"发现"直接等同于"事故"。

第二个易错点：因为"已经断电、口令已不在内存中"就把这条发现降级为"无需处理"。 正确判据是：**结论的对象是采集时刻的系统状态，不是当前状态。**

报告要回答的是"在 2024-03-18 09:40:55 那一刻，该主机上存在明文数据库口令且属主可读"——**这是对当时事实的陈述，与机器现在是否断电无关**。

但同样必须写明的是另一件事：该凭据在采集后已随进程退出而消失，本案无法回答"历史上是否有第三方读取过它"。

后者是真正的取证问题，且**需要有 `execve` 审计或内存镜像才能回答**。把"现在查不到了"写成"从未有人读过"是阴性结论越界；把"现在查不到了"写成"风险已消除"是状态与事实混淆。

---
<a id="section-35"></a>

## 六、扩展阅读方向

<a id="section-36"></a>

### 前置基础：这一篇的决策发生在现场，方法论先要立住

- [远程勘验与在线取证](../../imaging/imaging-acquire/imaging-acquire-remote-evidence-collection.md) —— 断电时机、在线采集与内存采集的取舍。**本篇几乎所有价值都取决于这个决定**，方法论在这一篇。
- [内存采集方法](../../memory/memory-acquire/memory-acquire-memory-acquisition-methods.md) —— 更完整的替代方案。来不及做完整内存镜像时，逐项导出 `/proc` 是成本低得多的折中，两者的取舍是同一问题的两面。
- [取证工件地图](../computer-persistence/computer-persistence-persistence-artifact-map.md) —— 离线视角的完整工件清单，其中「`/proc` 离线读不到」这一行正是本篇存在的理由。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 保全优先与现场处置纪律。**所有操作必须只读**，写盘动作不可逆。

<a id="section-37"></a>

### 同层深入：运行时证据的其它来源

- [内存取证总览](../../memory/memory-acquire/memory-acquire-memory-forensics-overview.md) —— 运行时证据的完整能力边界。`/proc` 给出的是进程与连接的元数据，内存里才有实际内容。
- [网络连接与流量痕迹](../../memory/memory-artifact/memory-artifact-memory-network-artifacts.md) —— 内存侧的网络连接表。本篇的 `/proc/net/tcp` 与它做双向差集，才能同时覆盖「传输量异常」与「进程归属」两个维度。
- [进程与注入检测](../../memory/memory-analyze/memory-analyze-process-and-injection-detection.md) —— `/proc/<pid>/maps` 的内存映射在内存侧的对应分析。两处都看，能区分「普通的多段映射」与「注入的可疑可执行区」。
- [Shell 痕迹与命令历史](computer-shell-shell.md) —— 与 `cmdline` 互补。历史文件记交互输入，`cmdline` 记实际在跑的东西，包括脚本与子进程。

<a id="section-38"></a>

### 相邻议题：别的系统上的同类工件

- [Windows Profile 机制](../../memory/memory-acquire/memory-acquire-windows-profile.md) —— Windows 侧的运行时快照机制。两边对照能看清「内核提供统一接口」与「按进程逐个导出」的架构差异。
- [Linux 与 Android 内存取证](../../memory/memory-artifact/memory-artifact-linux-android.md) —— 同一操作系统的另一类运行时证据。
- [网络流量与 PCAP 取证](../../memory/memory-network/memory-network-pcap.md) —— 「连接存在」与「传了什么」是两个问题，**前者本篇能答，后者要靠流量侧。**

<a id="section-39"></a>

### 工具与规范：容器环境下的特殊约束

- [只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md) —— 本篇在线采集为主，但**任何需要挂载卷的环节同样要遵守只读原则**。
- [证据文件格式](../../fundamentals/fundamentals-chain/fundamentals-chain-dd-e01-aff4-evidence-formats.md) —— 导出的 `/proc` 文本与二进制项的归档容器选择。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md) —— `environ` 含凭据，**摘录范围必须与授权范围一致并做脱敏**。

<a id="section-40"></a>

### 判据与反例：什么样的解释不能成立

- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— 删除文件时工具留下的自证痕迹。「文件已从目录树删除但仍被进程持有」这个状态本身就是痕迹的一种，该篇讲的是痕迹消失后如何识别。
- [取证技能树](../../fundamentals/fundamentals-process/fundamentals-process-forensics-learning-path.md) —— 现场处置能力在技能树里的位置，以及它与实验室分析能力的区别。
<a id="section-41"></a>

## 七、命令速查

```bash
# ===== 1. 在线采集（断电前执行，全程只读）=====
# 关键：cmdline/environ 必须做 NUL 转换
tr '\0' ' '  < /proc/1/cmdline; echo          # PID 1 是什么（判定容器视角）
tr '\0' '\
' < /proc/1/environ | grep -iE 'PASSWORD|SECRET|TOKEN|KEY|DSN'
readlink /proc/self/exe /proc/self/cwd       # exe / cwd
ls -l /proc/self/fd/                          # 打开的文件描述符

# 全量快照（见 3.1 完整脚本）；最小可用版本：
OUT=/evidence/proc-snapshot; mkdir -p "$OUT"
cp /proc/net/tcp "$OUT/net-tcp.txt"; cp /proc/net/arp "$OUT/net-arp.txt"
for p in /proc/[0-9]*; do d="$OUT/$(basename $p)"; mkdir -p "$d"
  tr '\0' ' ' < "$p/cmdline" > "$d/cmdline.txt"
  tr '\0' '\
' < "$p/environ" > "$d/environ.txt"
  readlink "$p/exe" > "$d/exe.txt"; readlink "$p/cwd" > "$d/cwd.txt"
  ls -l "$p/fd" > "$d/fd-list.txt"; cp "$p/maps" "$d/maps.txt"; done

# ===== 2. 筛选高价值痕迹 =====
grep -l 'deleted' $OUT/pid-*/exe.txt | while read f; do echo "$f → $(cat $f)"; done  # exe 已删除
grep -h -- '-> .*(deleted)' $OUT/pid-*/fd-list.txt | sort -u                            # fd 指向已删除
grep -hE '/tmp/|/dev/shm/|/var/tmp/' $OUT/pid-*/exe.txt                                  # 临时目录 exe
grep -hiE 'PASSWORD|SECRET|TOKEN|APIKEY' $OUT/pid-*/environ.txt | sed -E 's/=(.{0,4}).*/=\1****/'  # 脱敏

# ===== 3. /proc/net/tcp 解码（地址小端、端口不倒序）=====
# shell 版
decode4() { printf '%d.%d.%d.%d' 0x${1:6:2} 0x${1:4:2} 0x${1:2:2} 0x${1:0:2}; }
while read -r sl local rem st rest; do [ "$sl" = "sl" ] && continue
  la=${local%%:*}; lp=${local##*:}; ra=${rem%%:*}; rp=${rem##*:}
  [ ${#la} -eq 8 ] || continue
  printf '%s:%s -> %s:%s st=%s\
' "$(decode4 $la)" "$(printf '%d' 0x$lp)" \
    "$(decode4 $ra)" "$(printf '%d' 0x$rp)" "$st"; done < /evidence/proc-snapshot/net-tcp.txt
# 验证：0100007F:1F90  →  127.0.0.1:8080   ✓（1F90 = 8080，不倒序）

# Python 完整版（同时支持 tcp6）
python3 decode_proc_net.py /evidence/proc-snapshot/net-tcp.txt
# st: 01=ESTABLISHED  0A=LISTEN  06=TIME_WAIT  08=CLOSE_WAIT

# ===== 4. 连接 ↔ 进程归属（socket inode 关联）=====
# 1) 从 net-tcp.txt 取某连接的 inode（第 10 列），再在 fd 里找 socket:[inode]
grep -h 'socket:\[INODE\]' $OUT/pid-*/fd-list.txt
# 2) 交叉验证：ss 读的是同一份内核数据
ss -tnp state established        # 在线可用；离线用上面的解码结果

# ===== 5. 容器视角判定 =====
tr '\0' ' ' < /proc/1/cmdline; echo      # systemd/init → 宿主视角；应用名 → 容器视角
cat /proc/1/cgroup                      # 容器 ID
grep overlay /proc/1/mounts             # 容器分层挂载

# ===== 6. 危险项（禁止操作）=====
# cat /proc/kcore      ← 会导致系统挂起/崩溃
# cat /proc/self/mem   ← 需权限且可致崩溃
# 绝不：kill 进程、echo > /proc/...、debugfs -w、mount -o rw
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — Linux 取证 — /proc 虚拟文件系统取证」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《/proc 虚拟文件系统取证》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-mem.raw` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
