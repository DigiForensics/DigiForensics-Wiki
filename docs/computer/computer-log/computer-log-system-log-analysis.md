---
title: "系统日志深度分析"
slug: "computer-log-system-log-analysis"
canonical: "https://www.digiforensics.cn/wiki/computer-log-system-log-analysis"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:51+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "computer"
space: "计算机取证"
node_path: ["日志分析"]
---

# 系统日志深度分析

<a id="section-1"></a>

## 一、概述

Linux 日志分析真正的困难只有一个：你要找的那份日志，可能不叫那个名字，也可能不在那个目录，甚至可能已经不是文本了。

落到磁盘上是这么几件事。

`/var/log/auth.log` 在 CentOS 上不存在。`/var/log/secure` 在 Ubuntu 上不存在。路径是发行版的家庭作业，不是操作系统的常量。

systemd 的 journal 是自研二进制容器。`grep` 和 `strings` 上去只能得到不完整碎片，字段边界全丢。

`logrotate` 会把昨天的日志改名并压缩过去。你要找的那个时间窗口，大概率躺在 `.gz` 里，不在当前文件里。

三者叠在一起，后果很具体：你可能完整地报告了一份「没有记录」的日志，而记录就在归档里躺着。

这层证据的位置是**分析环节的主机侧证据入口**，属于本 wiki 里「计算机取证」大板块的起点之一，往下同时喂两个环节。

时间线合并。日志给出的是「什么时间、什么身份、什么动作」，**但传统 syslog 格式没有年份**，跨源对齐得单独做一步（见 [时间线重建](computer-log-linux-timeline-reconstruction.md)）。

持久化与后继行为判读。登录成功之后发生了什么、日志没覆盖的时段是否还有痕迹，靠 [计划任务与持久化痕迹](../computer-persistence/computer-persistence-scheduled-tasks-and-persistence.md)。

上游是**采集与接入**，这里有个容易忽略的依赖：所有命令都在**只读挂载或离线目录**上执行。直接对着镜像挂载点跑 `journalctl` 或 `last` 会产生副作用——写 journal、生成 `.bash_history`。接入方式不对，后面所有分析的可信度都要打折。

先看落点。`/etc/os-release` 是判断发行版家族的唯一入口，先读它再定路径，顺序反了就是在找错文件。Debian 系与 RHEL 系的路径对照（`auth.log` / `secure`、`syslog` / `messages`）见 2.1。

journald 有两个存储位置。

`/var/log/journal/<machine-id>/` 落盘持久，`/run/log/journal/` 纯内存，断电即失。

所以「journal 不存在」和「journal 在 `/run`」是两个完全不同的结论。

里面的 `.journal` 是二进制，必须用 `journalctl --directory` 读，不能 `grep`。

`strings` 出来的碎片既不完整也不可靠，字段会错位。

导出成文本之后用哪种格式，同样决定精度：`short`、`short-precise`、`iso8601` 的精度和时区标注各不相同，只有 `short-precise` 带亚秒和时区偏移。

**格式选错等于丢掉字段。**

文本日志这一侧，路径由配置决定。`/etc/rsyslog.conf` 与 `rsyslog.d/` 里可以写任意输出路径，「没有 auth.log」本身就可能是被改过的证据。

`/etc/logrotate.conf` 与 `logrotate.d/` 决定归档命名（`.1`、`.2`、日期后缀）、保留期和压缩策略。

**保留期就是「日志最多能回溯多久」的上限**——配置里写 7 就只能看 7 天。

行格式上有几类事件必须一眼认出：`Failed password`、`Accepted password`、`session opened`、`session closed`、`sudo: ... COMMAND=`。

其中 `COMMAND=` 行带具体命令，是提权行为最硬的证据。

传统 syslog 的时间格式是 `Mar 17 22:41:15`。**没有年份，没有时区**，跨源对齐时这两项都缺。

日志之外还有三个独立源。

`wtmp` / `btmp` / `lastlog` 记登录成功与失败，`last -f` 可以离线读。

`/home/<user>/.sudo_as_admin_successful` 是提权发生过的痕迹。

**零字节文件的 mtime 就是事件时间**，可以和日志交叉。

`/var/log/audit/audit.log` 由 `auditd` 写出，**同样是二进制，要用 `ausearch`**。文件访问和权限变更里有些东西，系统日志根本不覆盖。

最后看断电痕迹：journal 的 `session closed` 是否早于断电。**这决定了历史日志可不可信。**

答得出来的有四件：某台 Linux 的日志实际落在哪些路径、某个时间窗口的事件在当前文件还是归档里、有没有成功的登录与提权、以及某个「消失的日志」是轮转、清理还是配置改动造成的。

回答不了的部分也得说清。

`sudo` 行能看到命令。普通 SSH 会话里敲的命令不在系统日志里，得去 `~/.bash_history` 或审计日志找。而且 `bash_history` 只在会话正常退出时落盘，**强杀会话会全丢**。

登录之后做了什么——那是 [计划任务与持久化痕迹](../computer-persistence/computer-persistence-scheduled-tasks-and-persistence.md) 的范围。

「没有记录」不等于「没有发生」。logrotate 保留期、审计未启用、应用自身日志覆盖、外部转发接收端都可能造成缺失，**阴性发现必须限定范围**。

攻击者是谁（自然人）回答不了。IP 可被代理、可被跳板，**日志里的来源地址是网络层事实，不等于行为人**。

传统日志的年份也回答不了。除非有 journal 或其他带年份的源来补，**否则不能声称具体年份**。第五章案例里的年份是 journal 补的，不是推断的。

断电前最后那段时间的日志，若 journal 只在 `/run`，**该时段不可得**，必须写成证据局限。

开始之前先确认三件事：能读写 Linux 命令行、知道 Debian 与 RHEL 的路径划分不是随便定的、并且已经把只读接入做完再动手。难的不是工具，是**顺序**：先定发行版、再定路径、再定轮转状态、最后才读内容。跳一步的代价，是你分析了一个根本不存在的文件，而且自己不知道。

<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 日志落盘路径：Debian 系 vs RHEL 系

判断顺序：先读 `/etc/os-release`，再按下表取路径。

| 记录内容 | **Debian / Ubuntu** | RHEL / CentOS / Rocky / Alma |
|---|---|---|
| **认证/授权/sudo** | `/var/log/auth.log` | `/var/log/secure` |
| **系统总日志**（服务启动、内核通用） | `/var/log/syslog` | `/var/log/messages` |
| 内核启动/模块加载 | `/var/log/kern.log` | `/var/log/messages` |
| 守护进程运行日志 | `/var/log/daemon.log` | 各服务自己的文件 |
| 邮件、cron、启动 | `mail.log`、`cron.log` | `/var/log/maillog`、`/var/log/cron` |
| 崩溃转储 | `/var/log/apport.log`（Ubuntu） | `/var/log/messages`（`crash` 关键字） |
| **登录成功 / 失败历史** | `/var/log/wtmp` / `/var/log/btmp` | 同 |
| **当前在线会话** | `/run/utmp` | 同 |

> ⚠️ `syslog`（Debian）与 `messages`（RHEL）不是简单改名。 两者的 facility 映射与默认覆盖的子系统范围都可能不同，跨发行版比较哪些服务写了日志时不要假设等价。
>
> ⚠️ 最小化安装（`systemd` 但无 rsyslog）根本没有纯文本日志，只有 journal。**以 `ls` 的实际结果为准，不要以习惯为准。**

<a id="section-4"></a>

### 2.2 journald：二进制格式与「双位置」陷阱

`systemd-journald` 统一收集日志。和 rsyslog 相比有两处关键区别：**格式是自研二进制**，以及**存储位置有两个**。

| 位置 | 存储形式 | 重启后 | 何时使用 |
|---|---|---|---|
| `/run/log/journal/<machine-id>/` | **内存易失（tmpfs）** | **全部丢失** | `Storage=volatile` 或 `auto` 但目录不存在 |
| `/var/log/journal/<machine-id>/` | **磁盘持久** | 保留 | `Storage=persistent`，或 `auto` 且目录已存在 |

`<machine-id>` 来自 `/etc/machine-id`。

`Storage=auto` 是所有发行版的默认值。`auto` 不会自动创建 `/var/log/journal`——它只是目录存在就写盘，不存在就退回内存。

所以能否拿到持久化 journal，完全取决于该目录在镜像里是否实际存在，跟发行版叫什么名字没有必然关系：

| 发行版 | 出厂状态 | 说明 |
|---|---|---|
| Debian / Ubuntu | 多数为易失，**部分版本/镜像预建目录** | 目录存在则持久，否则易失 |
| RHEL 7 及更早 | 易失（`/var/log/journal` 不存在） | 需管理员显式开启 |
| RHEL 8+ / Rocky / Alma | **多数预建 `/var/log/journal`** | 出厂即持久 |
| 最小化 / 容器镜像 | journald 常被 mask 或不运行 | 只有 JSON 日志（`/var/log/pods/`，非 journal 格式） |

> **取证含义**：若机器**强制断电 / 被 kill -9**，而 journal 只在 `/run/log/journal`（内存）——**那部分日志已随内存一起消失，磁盘上无法恢复**。必须以 `/var/log/journal/<machine-id>/` 是否存在为准，不能凭发行版推断。

**journal 文件家族**（同一 machine-id 目录下）：

| 文件 | 内容 |
|---|---|
| `system.journal` | 系统级日志（PID 1 及各服务的 stdout/stderr） |
| `user-<UID>.journal` | 某用户级日志（如 `user-0.journal` = root） |
| `remote-<host>.journal` | 转发自远端的（集中日志场景） |
| `*.journal~` | 损坏或不完整文件的备份 |

**不能直接 grep。** journal 是「entry 列表」的二进制序列化，每条 entry 含单调时钟、实时时钟、PID、UID、进程名、正文等字段。

只能通过 `journalctl`（在线）或专用解析库（离线）读。`strings` 只能捞到正文片段，时间戳、优先级、结构化字段都会丢失或错位，不能作为定性依据。

<a id="section-5"></a>

### 2.3 journalctl：必须用工具读，输出格式决定取证精度

离线读镜像中的 journal 有两种方式：`--file <单个 .journal>` 或 `--directory <目录，自动合并该机全部 .journal>`。

| 参数 | 作用 |
|---|---|
| `-u <unit>` / `--directory` / `--file` | 按 systemd 单元过滤 / 读目录 / 读单文件 |
| `_COMM=sshd` / `_UID=0` / `_PID=` | 按进程名 / 运行用户 / PID 过滤（**比 grep 精确**，过滤发生在结构化字段上） |
| `-k` | 内核日志 |
| `--since` / `--until` | 时间窗口过滤（**收敛时间线的第一道工具**） |
| `-f` | 实时跟随（仅在线取证） |
| `--no-pager` | **必须加**，否则输出进 pager 会截断 |
| **`-o short-precise`** | **取证首选**：微秒 + 明确时区偏移 |
| `-o json` / `-o export` | 结构化全字段，便于机器处理 |

为什么 `-o short-precise` 是首选：亚秒精度加上明确的时区偏移，两样都给了。

前者解决「同一秒内多条日志谁先谁后」——爆破和批量操作场景里这是刚需。后者避免把本地时间误当 UTC。默认的 `-o short` 只到秒。

<a id="section-6"></a>

### 2.4 rsyslog 配置：日志路径是配置项，不是常量

`/etc/rsyslog.conf` 与 `/etc/rsyslog.d/*.conf` 用 `facility.severity → 文件` 定义去向。**文件名和路径由管理员决定，不能假定固定值。**

```
# Debian 系 50-default.conf 的典型规则
auth.*      /var/log/auth.log
authpriv.*  /var/log/auth.log
kern.*      /var/log/kern.log
cron.*      /var/log/cron.log
local7.*    /var/log/boot.log
```

取证第一步就是读配置，搞清楚哪个文件收什么；重点看 `/etc/rsyslog.d/50-default.conf`，以及任何指向非常规路径、非标准文件名或 `/dev/null` 的规则——**这些就是发现**。

**三种日志消失方式**（都是篡改信号，**不等于无活动**）：

| 消失方式 | 特征 | 判定依据 |
|---|---|---|
| **截断当前文件** | `auth.log` 大小为 0 或骤减；`.1`/`.gz` 归档不连续 | 文件大小/归档连续性 |
| **改 rsyslog 配置** | 规则写 `auth.* /dev/null`，或删掉 `auth.*` 规则 | 配置文件自身的 `mtime`/`ctime` 是独立证据 |
| **停掉日志服务** | rsyslog / journald 未运行 | journal 里 `systemctl` 的服务状态记录可印证 |

<a id="section-7"></a>

### 2.5 logrotate：轮转决定你要找的日志在哪个文件里

```
/var/log/auth.log          ← 当前活跃文件（正在写入）
/var/log/auth.log.1        ← 上一周期（.1 最近，未压缩）
/var/log/auth.log.2.gz     ← 再上周期（已 gzip）
/var/log/auth.log.3.gz     ← 更早
（若配了 dateext，形如 auth.log-20240310.gz）
```

`/etc/logrotate.conf` 是全局默认，`/etc/logrotate.d/<service>` 逐服务配置。取证必看指令：

| 指令 | 取证含义 |
|---|---|
| `rotate N` | 保留 N 个旧档。`rotate 0` = 覆盖即消失，历史被刻意切断 |
| `daily`/`weekly`/`monthly` | 时间分辨率（`daily` = 每天一个分界） |
| `compress` | 归档被 gzip，**必须 `zcat` 才能读** |
| `delaycompress` | 上一轮才压 → **存在未压缩的 `.1`，最易漏的一档** |
| `missingok` / `notifempty` | 缺失/为空则跳过 → **没有日志 ≠ 被清** |
| `dateext` | 归档名带日期，合并时需确认字典序=时间序 |

**取证含义**：`rotate 0` 或配置被删 → 检查该 `logrotate.d` 文件的 `mtime`/`ctime`；归档编号不连续（只有 `.1` 没有 `.2`）→ 有人删过中间档（配置层面的正常成因见 4.1 陷阱 5）。

**`.gz` 里常藏着入侵的初始阶段**，别只看当前文件。

> ⚠️ **`.gz` 的文件属性时间不能替代内部时间戳。** 文件的 `mtime` 是被压缩或改名的时间，行内时间才是事件发生时间。**判定事件时间一律用日志行内时间戳。**

<a id="section-8"></a>

### 2.6 auth.log / secure 关键事件与三种时间戳格式

| 事件关键字 | 含义 | 取证价值 |
|---|---|---|
| `Accepted password for <user> from <ip> port <pt> ssh2` | **密码登录成功** | 成功入侵最直接证据；`<pt>` 是**客户端临时端口** |
| `Accepted publickey for <user> from <ip> port <pt> ssh2: RSA SHA256:...` | **公钥登录成功** | 查对应 `authorized_keys`（见[第 05 篇](../computer-persistence/computer-persistence-ssh.md)） |
| `Failed password for (invalid user )?<user> from <ip> port <pt> ssh2` | **密码失败** | 爆破；`invalid user` = 在猜用户名 |
| `Invalid user <user> from <ip> port <pt>` | **无效用户** | 扫描器行为；用户名常来自字典库 |
| `session opened for user <user> by (uid=0)` | **会话建立** | 会话起点（`Accepted` 才是认证成功，两者都要） |
| `session closed for user <user>` | **会话结束** | 算会话时长；也是「机器何时还活着」的锚 |
| `sudo: ... COMMAND=/path/cmd` | **sudo 执行** | **提权操作的具体命令，本类最高价值** |
| `usermod`/`useradd` 的 PAM 行 | **账户变更** | 账号被创建/改组的证据 |

**「port 22」的常见误读**：`Accepted password for deploy from 198.51.100.7 port 40582 ssh2` 里的 `40582` 是**客户端源端口**，也就是 ephemeral 端口，**不是服务端口**。

sshd 的服务端口固定 22；`port <n> ssh2` 里的 `n` 恒为客户端临时端口。

**别拿源端口当服务端口去分析。**

**三种时间戳格式（务必分清）**：

| 来源 | 格式示例 | 有无年份 | 精度 | 备注 |
|---|---|---|---|---|
| **传统 syslog**（auth.log/messages） | `Mar 18 09:41:07` | **无年** | 秒 | 跨年归档要靠文件名/轮转顺序推断，有歧义 |
| **rsyslog RFC3339**（需自定义模板） | `2024-03-18T09:41:07.123456+08:00` | 有 | **微秒+时区** | 默认模板**不带**年份与时区 |
| journald（`journalctl -o short-precise`） | `2024-03-17T23:58:04.123456+08:00` | 有 | **微秒** | 默认 `short` 为秒+时区偏移 |

> **无年份是真实痛点**：`Mar 18 09:41:07` 是哪一年？单看一行无法判定。结合 (1) 文件系统时间戳；(2) 归档文件名与轮转顺序；(3) 与 journal（**有年**）交叉——**journal 是给传统日志补年的最好锚点**。

**时区**：认证日志时间戳**通常是本地时间，且无时区标记**；journal 的 `short-precise` **带时区偏移**。统一到 UTC 的方法见[第 08 篇](computer-log-linux-timeline-reconstruction.md)。

<a id="section-9"></a>

### 2.7 sudo / 提权痕迹

认证日志里跟 sudo 相关的行有四类，分开看：

1. **认证**：`user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/bash`
2. **执行**：`sudo:  user : COMMAND=/usr/bin/xxd /etc/shadow`（**执行了什么**）
3. **策略**：`sudo: pam_unix(sudo:session): session opened for user root`
4. **失败**：`sudo:  user :  incorrect password attempt`（累计失败会触发锁定）

**Ubuntu 特有**：`~/.sudo_as_admin_successful` 存在 = 该用户**曾成功执行过 sudo**。

它是**有用的辅助证据**（说明该用户是 sudoer 且用过），**但不能代替日志**——里面既没有命令，也没有可信时间戳。

---

<a id="section-10"></a>

## 三、操作步骤

<a id="section-11"></a>

### 3.1 第 1 步：确认日志在哪，而不是假设

```bash
# 1. 日志目录全貌 + 轮转归档
ls -l --time-style=long-iso /mnt/df/var/log/
# 特别关注：auth.log / secure / syslog / messages / *.journal / *.gz / *.1

# 2. 读 rsyslog 配置（判断是否有改路径/丢弃）
grep -vE '^\s*#|^\s*$' /mnt/df/etc/rsyslog.conf | head -40
grep -RniE '\*\s+/var/log|/dev/null|\*\.\*' /mnt/df/etc/rsyslog.d/ 2>/dev/null

# 3. journal 存在性与存储模式（以实际目录为准，不凭发行版推断）
cat /mnt/df/etc/machine-id
ls -la /mnt/df/var/log/journal/$(cat /mnt/df/etc/machine-id)/ 2>/dev/null
grep -iE '^\s*Storage' /mnt/df/etc/systemd/journald.conf 2>/dev/null
# 目录存在 → 持久化 ✓ ；目录不存在且 Storage 未改 → 易失，断电前日志不可得
```

<a id="section-12"></a>

### 3.2 第 2 步：合并归档 + 当前文件，按时间排序

**单一日志可能有多个档位。** 按最旧到最新合并（`.1` 比当前文件更早，直接 cat 会错序）：

```bash
cd /mnt/df/var/log
# 顺序：*.gz（由旧到新）→ .1 → 当前
{
  ls -1tr auth.log.*.gz 2>/dev/null | while read f; do zcat "$f"; done
  cat auth.log.1 2>/dev/null
  cat auth.log
} > /evidence/auth-merged.txt
wc -l /evidence/auth-merged.txt
# RHEL 系把 auth.log 换成 secure
```

> 用了 `dateext` 时文件名形如 `auth.log-20240301.gz`，`ls -1tr` **必须确认字典序恰等于时间序**（对 `YYYYMMDD` 成立）。若后缀不是日期序，改为合并后按**行内时间戳**排序。

<a id="section-13"></a>

### 3.3 第 3 步：导出 journal 为文本（不在二进制上 grep）

```bash
journalctl --directory /mnt/df/var/log/journal \
           -o short-precise --no-pager > /evidence/journal-precise.txt
wc -l /evidence/journal-precise.txt

# 只看认证相关（过滤发生在结构化字段上，比 grep 精确）
journalctl --directory /mnt/df/var/log/journal _COMM=sshd \
           -o short-precise --no-pager | grep -iE 'Accepted|Failed|Invalid|session'

# 内核日志
journalctl --directory /mnt/df/var/log/journal -k -o short-precise --no-pager
```

> ⚠️ 精简系统可能未安装 `journalctl`。此时 `strings` 捞到的片段**只能作为线索，不能直接下结论**；正式分析应在分析机上装对应版本 `systemd` 工具再读。

<a id="section-14"></a>

### 3.4 第 4 步：认证日志关键事件提取

```bash
grep -iE 'Accepted (password|publickey|keyboard-interactive)' /evidence/auth-merged.txt

# 失败登录 + 无效用户 → 源 IP 排行
grep -iE 'Failed password|Invalid user|authentication failure' /evidence/auth-merged.txt \
  | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sort | uniq -c | sort -rn | head

grep -iE 'sudo.*COMMAND=' /evidence/auth-merged.txt          # 提权命令
grep -iE 'sudo.*incorrect password' /evidence/auth-merged.txt # sudo 失败
grep -iE 'session (opened|closed) for user' /evidence/auth-merged.txt
grep -iE 'usermod|useradd|groupadd|chpasswd' /evidence/auth-merged.txt
```

<a id="section-15"></a>

### 3.5 第 5 步：logrotate 保留期与消失判据

```bash
for svc in auth syslog messages secure wtmp btmp; do
  f=/mnt/df/etc/logrotate.d/$svc
  [ -f "$f" ] && { echo "== $f =="; grep -vE '^\s*#|^\s*$' "$f"; }
done

# 归档连续性（缺失中间档 = 可能被删）
ls -1 /mnt/df/var/log/ | grep -E 'auth|secure' | sort -V
# 期望：auth.log  auth.log.1  auth.log.2.gz  auth.log.3.gz ...
# 若只有 auth.log 无任何 .1/.gz，且 mtime 很新 → 可疑
```

| 验证对象 | 通过标准 |
|---|---|
| 发行版与日志路径匹配 | 路径与家族对应，或由 rsyslog 配置解释 |
| rsyslog 配置可信 | 日志内容与规则应写入的 facility 一致 |
| journal 读取完整 | 末行时间接近最后活动时间，无解析错误 |
| 传统日志 vs journal 同事件 | 二者能相互补足（补年份、微秒排序） |
| 归档无异常缺口 | `.1`/`.gz` 编号连续，无中间缺失 |

---
<a id="section-16"></a>

## 四、常见陷阱

本章按**证据链环节**归组：采集环境 → 时间基准 → 事件识别 → 结论表述。每条给四段：现象、为什么会误判、误判代价、正确做法。

★ 标记表示该操作会导致原始检材永久灭失或不可逆改变，执行前必须停下来确认。

<a id="section-17"></a>

### 4.1 日志落点的采集环境

<a id="section-18"></a>

#### 陷阱 1：拿「印象里的路径」去找日志，把找不到写成「系统没记」

**现象**：在 CentOS/Rocky 镜像上执行 `ls /var/log/auth.log`，文件不存在，于是报告写「该系统未启用认证日志，登录行为不可查」。

**原因**：**日志路径是发行版的家庭作业，不是操作系统的常量。**

本篇 2.1 那张表说得很清楚：Debian/Ubuntu 把 `auth.*`/`authpriv.*` 写到 `/var/log/auth.log`，RHEL 系写到 `/var/log/secure`；系统总日志 Debian 是 `syslog`，RHEL 是 `messages`。

同一件事在不同发行版落在不同文件名上，所以文件不存在绝大多数情况只是**找错了名字**，不是没记。

**影响**：阴性结论里代价最高的一类。你给出的是登录行为不可查，委托方据此认为这台机器没有登录记录；而如果 `/var/log/secure` 里完整记着全部 `Accepted password`，这份报告不只是结论错——后面所有基于它的排除推理（这台机器没人登录过）全部作废。

**核查**：先读发行版再取路径，别凭习惯：

```bash
cat /mnt/df/etc/os-release                     # ID_LIKE 决定走哪一列
ls -l /mnt/df/var/log/ | grep -iE 'auth|secure|syslog|messages'
```

再往下读 `/etc/rsyslog.conf` 与 `/etc/rsyslog.d/*.conf`，以配置里 `auth.*` / `authpriv.*` 的实际去向为准。

**配置是权威答案，文件名只是默认值。**

<a id="section-19"></a>

#### 陷阱 2：★ 以读写方式挂载原始镜像，或把原始镜像当系统根启动

**现象**：为方便查看，直接 `mount -o rw /dev/loop3 /mnt/df`；或者更糟，把 `DigiForensics.dd` 挂成 `/` 之后跑了 `journalctl`、`systemctl`、`apt`，看起来日志更完整了。

**原因**：镜像里带着一套**完整可运行的系统配置**。

一旦以 rw 挂载，内核会在 journal 上补写 recovery 记录，rsyslog 会按原配置继续往 `/var/log/` 里追加，logrotate 还可能触发轮转。

你看到的更多日志其实是**分析动作自己产生的**。

而 `auth.log` 的当前文件一旦被追加，你再也分不清哪几行是现场、哪几行是你写的。

**影响**：现场污染不可逆。更麻烦的是**造出了伪证据**——伪造出来的 `session opened` 行和真实的一模一样，质证时无法自证清白；被压缩的归档档位也会因新轮转被移位甚至覆盖。

**核查**：全程 `mount -o ro,loop,noexec,nodev`。要写分析产物就写到镜像外的 `/evidence` 目录。

必须执行写操作时，先用 `dd` 复制出工作副本（`DigiForensics-work.dd`），并把原件只读挂载、工作副本可写这一条写进证据处理记录。

所有 `journalctl`、`systemctl`、`logrotate` 类动作只在工作副本上跑。

<a id="section-20"></a>

#### 陷阱 3：直接在 `.journal` 二进制文件上 grep

**现象**：对 `system.journal` 执行 `grep -a "sshd"` / `strings`，拿到一堆碎片，据此写出关键事件结论。

**原因**：journal 是 **entry 列表的二进制序列化**，不是行式文本。

每条 entry 含单调时钟、实时时钟、`_PID`、`_UID`、`_COMM`、优先级、正文等多个变长字段。

直接 grep 只能碰到正文字符串相邻位置的偶然拼接，字段会错位、跨 entry 粘连，时区和单调时钟完全丢失。

碎片里那个 IP 和用户名，很可能是相邻两条无关 entry 被拼到了一起。

**影响**：用碎片下结论，等于把看起来像当成就是。最典型的翻车是碎片里凑出一组时间加命令，时间却来自相邻的另一条 entry，拼出一个**不存在的因果关系**。这类错误在报告里极难自查，却会在质证环节被对方直接推翻。

**核查**：必须走 journal 接口。离线用 `journalctl --file <单个.journal>` 或 `journalctl --directory <目录>`（后者自动合并该机全部 journal）。

过滤条件写在结构化字段上（`_COMM=sshd`、`_UID=0`），而不是 grep 正文。

精简系统缺 `journalctl` 时，`strings` 的结果只能记为线索，待独立验证，不进结论表。

<a id="section-21"></a>

#### 陷阱 4：只提取当前活跃日志，漏掉 `.1` / `.gz` 归档档位

**现象**：镜像里 `auth.log` 只有 40 多行，于是判定该机日志仅记录最近一天。而同一目录下 `auth.log.1`、`auth.log.2.gz` 静静躺着。

**原因**：**当前文件永远只保存最近一个轮转周期。** 轮转把旧内容搬进带序号的档位，`compress` 再把更早的档位压成 `.gz`。

还有个坑：`delaycompress` 会让上一轮故意不压缩，于是最容易漏的那一档——未压缩、体积最大的那个——恰好是 `.1`。分析者 `ls` 时只按文件名匹配了 `auth*` 精确名，`.1`/`.2.gz` 就被过滤掉了。

**影响**：入侵的初始阶段（最初 foothold、最早的失败尝试、账号创建）恰恰在最早的归档里。只读当前文件等于**系统性地丢掉案发时刻**，你得出的攻击始于昨晚可能是假的。

**核查**：按轮转顺序由旧到新合并成单一文本再分析：

```bash
cd /mnt/df/var/log
{ zcat auth.log.2.gz 2>/dev/null; cat auth.log.1; cat auth.log; } > /evidence/auth-merged.txt
```

用 `find /mnt/df/var/log -name '*.gz' -o -name 'auth.log.*'` 确认档位齐全。

只看到当前文件、没有任何档位，同时文件 `mtime` 很新——那是被截断的信号，不是机器很干净。

<a id="section-22"></a>

#### 陷阱 5：归档编号不连续时，直接认定「有人删了中间档」

**现象**：`/var/log/` 下只有 `auth.log` 和 `auth.log.2.gz`，没有 `auth.log.1`，报告写「`.1` 档已被人工删除，构成日志篡改证据」。

**原因**：**归档编号缺口有若干种完全正常的成因。** ① `delaycompress`：上一轮故意不压缩，于是 `.1` 是唯一未压缩档，`.2.gz` 之外的层级可能正好还没产生；② `rotate N` 设置很小而轮转间隔是 `weekly`/`monthly`，档位序号不是连续产出；③ `notifempty` + 某个空档：某周期内日志为空，logrotate 不生成对应文件；④ `dateext` 模式下归档名带日期后缀，编号概念本身就不存在，看起来"缺号"其实是命名不同。真正的判据是归档序列与 logrotate 配置是否吻合，而不是编号本身是否连续。

**影响**：把配置行为写成蓄意篡改，是取证报告里最需要避免的一类指控——**误报的篡改结论比漏报严重得多**，它会直接改变委托方对内部人员的怀疑方向，甚至触发内部调查。

**核查**：**先读配置，再判连续性。** 把 `/etc/logrotate.d/<service>` 的 `rotate` / `daily|weekly|monthly` / `compress` / `delaycompress` / `dateext` / `notifempty` 逐项与实际档位对照，只有在**配置预期该有而实际缺失**时才算异常。

```bash
# 配置预期
cat /mnt/df/etc/logrotate.d/rsyslog
# 实际档位（含大小与时间）
ls -l --time-style=long-iso /mnt/df/var/log/ | grep -E 'auth|secure'
```

异常结论的写法：「该服务配置为 `<rotate N>` + `<compress>`，按 `<daily>` 间隔应产出 `.1` 至 `.N.gz`；实际存在 `.2.gz` 而缺 `.1`，且 `.2.gz` 的 mtime 晚于 `<时间>`（正常轮转下 `.1` 的 mtime 应早于 `.2.gz`），缺口与配置预期不符」。**先有配置比对，再下结论。**

<a id="section-23"></a>

### 4.2 时间基准与排序

<a id="section-24"></a>

#### 陷阱 6：以为传统 syslog 行里自带年份

**现象**：合并后的文本第一行是 `Mar  4 08:12:03 web01 sshd[2210]: Accepted password ...`，分析者直接把它归到 2024 年 3 月 4 日，理由是机器是 2024 年的。

**原因**：传统 syslog 行内时间戳只有月-日-时-分-秒，没有年份，也没有时区。

年份必须从外部补。本篇的处理方式是用 journal（有年，且 `-o short-precise` 带时区偏移）作锚点。

凭镜像的 `mtime`、文件创建时间，或案件发生在某年来补年——这些都是假设，不是证据。

**影响**：跨年时间线会整体错位一年，而且错得极其自然，每一行都看起来合理。

某个事件的年份一旦错了，把它和 Prefetch、文件时间戳、wtmp 交叉比对时会得到毫无意义的差值，而这些差值又会被当成时间戳篡改之类的结论继续推演。

**核查**：先从 journal 取一条有年、带时区偏移的记录作锚点（`journalctl --directory ... -o short-precise`），把传统日志的月-日-时分秒对齐到该年。

跨年时单独处理 12 月→1 月的 rollover。

报告里要写明年份由 journal 补齐这一来源。

<a id="section-25"></a>

#### 陷阱 7：用归档文件的属性时间代替行内时间戳

**现象**：把 `auth.log.2.gz` 的 `mtime`（显示 2024-02-25 23:59）当成这段日志记录的事件时间，进而推出攻击发生在 2 月 25 日。

**原因**：**轮转动作会重写文件的时间属性。**

归档的 `mtime` 实际含义是被轮转搬移或被压缩的那一瞬间，不是里面任何一条记录的事件时间。

压缩档位尤其误导：`gzip` 写出的是压缩完成时间，与被压缩内容的真实时间区间可能相差整整一个轮转周期。

**影响**：这类错误会把日志被归档的时间混进时间线。与 Prefetch 执行时间、文件 mtime 并列展示时，会凭空造出一个虚假的集中活动假象。

**核查**：**判定事件时间一律用日志行内时间戳。**

文件属性时间只用来回答另一个问题——这个文件最后一次被改动是什么时候。判断有没有人动过归档时用它。两者在报告里必须分列，不可互换。

<a id="section-26"></a>

#### 陷阱 8：跨源对齐时把 journal 的 UTC 与 syslog 的本地时间直接相减

**现象**：journal 里一条记录的 `-o short-precise` 输出显示 `2024-03-17T23:58:04+08:00`，传统日志里同一事件显示 `Mar 18 07:41:15`，分析员把两个数一减，得出「两者差 7 小时 43 分，说明传统日志的时间被改过」。

**原因**：2.6 那一行就是这个坑的正解：认证日志时间戳通常是本地时间且无时区标记，journal 的 `short-precise` 带时区偏移。 时区信息只有一边有，不做归一就直接比较，得到的差值是**两个约定之差**（CST 与 UTC 的 8 小时，再叠加操作习惯），不是篡改痕迹。而两个时区约定不同、格式差异大，正是最容易让人先入为主的地方——看到「不一致」的第一反应通常是「有人改过」，而不是「我没换算」。

**影响**：这是一类**会自我强化的错误**。一旦得出「时间戳被篡改」的结论，后续所有时间差都会被往这个方向解读，最后把一个时区换算失误包装成一条重磅篡改发现。而这种结论在质证时是最容易被推翻的——只需出示时区配置即可。

**核查**：**对齐前一律先统一到 UTC。** 传统日志用 journal 提供的锚点（见陷阱 5 的做法）确定它用的是哪个时区，再做加减；报告里两个源的时间都带时区标注。

```bash
# 先确认系统时区，再确认日志行的时区约定
cat /mnt/df/etc/timezone                       # 或 timedatectl 的输出
# journal 侧始终带偏移，可直接换算
journalctl --directory /mnt/df/var/log/journal -o short-precise --no-pager | head -1
# 输出形如 2024-03-17T23:58:04.123456+08:00  ← 偏移量直接给出了时区
```

判据：同一事件在两个源上的差值若恰好等于时区偏移量，就是时区问题；若不等于且无法用时区解释，才需要考虑篡改。 报告句式：「该事件在 journal（UTC+8）为 `<T1>`，在 `auth.log`（本地时间，无时区标记）为 `<T2>`，归一后一致，**两者差值 `<Δ>` 等于时区偏移量，非篡改**」。

<a id="section-27"></a>

#### 陷阱 9：用 `-o short`（默认）的秒级精度判断同一秒内的先后

**现象**：`journalctl --directory ... | grep 'Accepted'` 输出里有多条 `session opened`，时间戳精确到秒但秒相同，分析员按输出顺序认定「先 open 后 close」，判断为「同秒内建立了三个会话」。

**原因**：默认的 `-o short` 只到秒，而排序的依据是那秒的起点。 同一秒内发生的多个事件，输出顺序是 journald 存储顺序而不是严格的因果顺序——它由 entry 的写入路径决定，多线程日志、转发来的日志都可能打乱。2.3 把 `-o short-precise` 定为取证首选，原因就是亚秒精度加上时区偏移这两样都需要；在爆破与批量操作场景里，「同一秒内谁先谁后」是刚需（一次失败的 `Accepted` 和随后的 `session closed` 顺序颠倒，会让「会话时长」算出负数）。

**影响**：因果顺序错乱会直接改变结论。一个被读成「登录后立即登出」的异常短会话，如果实际是「先登出后登录」（两条不同会话挤在同一秒），那么基于它的「异常登录尝试」分析就完全落空；反过来，一个正常会话可能被算成异常时长。

**核查**：凡涉及同秒内顺序的判断，导出时一律用 `-o short-precise`，并优先用 journald 的单调时钟字段（`_MONOTONIC`）而非实时时钟排序——后者在时钟被调整时会乱序。`journalctl -o json` 保留全部字段，必要时按 `_MONOTONIC` 排。

```bash
# 需要同秒内精度时
journalctl --directory /mnt/df/var/log/journal -o short-precise --no-pager | grep 'session'
# 需要严格顺序时用 JSON 输出按单调时钟排
journalctl --directory /mnt/df/var/log/journal -o json --no-pager \
  | python3 -c "
import json,sys
rows=[json.loads(l) for l in sys.stdin if l.strip()]
rows.sort(key=lambda d: int(d.get('_MONOTONIC',0)))
for d in rows[:20]:
    print(d.get('_MONOTONIC'), d.get('__REALTIME_TIMESTAMP'), d.get('MESSAGE','')[:60])
"
```

报告里凡给出毫秒级时序的，说明导出格式为 `short-precise`；**凡是同秒内多条事件参与推断的，逐条核对亚秒位**。

<a id="section-28"></a>

### 4.3 事件识别与字段语义

<a id="section-29"></a>

#### 陷阱 10：把 `port <n>` 当成服务端口

**现象**：从 `Accepted password for deploy from 203.0.113.77 port 40210 ssh2` 里读出服务在 40210 端口，据此排查 40210 上的服务。

**原因**：**sshd 日志里的 `port` 是客户端源端口**，即客户端 connect 时绑定的那个临时端口，不是被连接的服务端口。sshd 的服务端口是 22（除非改了 `Port` 指令）。

同一个源 IP 的多次登录会看到一堆不同的 `port` 值，正是因为临时端口每次都不同。

**影响**：会把源 IP 的客户端临时端口变化读成对方在多个服务上活动，虚构出多目标横向扫描的结论。或者反过来，因为 40210 上没有服务而排除掉真实的登录事件。

**核查**：服务端口从配置取——`/etc/ssh/sshd_config` 的 `Port` 指令，不从日志行取。

日志行的 `port` 只用于判断**连接是否来自同一个源端口的连续会话**（重传、半开连接），以及配合 `last` 里的端口列做交叉验证。

<a id="section-30"></a>

#### 陷阱 11：把 `session opened` 当成认证成功

**现象**：报告统计出成功登录 N 次，依据是 `session opened for user deploy by (uid=0)` 这类行。

**原因**：`session opened` 是 **PAM 会话建立阶段**的记录。它前面还有 `Accepted password/publickey`（认证成功）、`pam_unix` 授权，后面还可能有 `session closed`。

计数时若把两者都当登录成功，数量直接翻倍。

更麻烦的是某些配置下会存在只有 `session` 行而没有对应 `Accepted` 行的场景（密钥代理、证书认证走别的 PAM 栈，或者日志被部分截断）。这时以 `session` 为准，就会把不完整记录算成完整登录。

**影响**：登录次数是很多报告的核心量化指标。翻倍会让攻击者登录了 3 次变成 6 次，直接影响暴力破解速率和攻击持续时间的判断。

**核查**：认证成功的判据是 `Accepted password|publickey|keyboard-interactive` 行，本篇的提取命令就是按这个正则做的。

`session opened`/`closed` 只用来确定**会话区间**，也就是从登录到登出的持续时长。报告里两个指标分开写：`Accepted` 计成功次数，`session` 计会话数。

<a id="section-31"></a>

#### 陷阱 12：用 `.sudo_as_admin_successful` 认定提权

**现象**：发现 `/home/deploy/.sudo_as_admin_successful` 存在且 mtime 是案发当日，据此写「`deploy` 于该时间执行了提权操作」。

**原因**：这个文件是 0 字节的标记文件，只记录这个用户曾成功用过 sudo 这一个比特。

它不含命令，也不含可信时间戳——mtime 会被后续任何一次 sudo 覆写。它告诉你至少成功过一次，仅此而已。

**影响**：拿它去论证提权时间和提权后做了什么，等于用一个布尔值承载全部结论。

案例中真正定案的是 auth.log 里的 `sudo: ... COMMAND=/usr/bin/apt-get install -y netcat` 这类行——命令内容、时间、用户三者齐备。少了这一层，`COMMAND=` 之后的所有行为链都塌了。

**核查**：提权结论一律以 auth.log 里的 `sudo.*COMMAND=` 行为准，用 `grep -iE 'sudo.*COMMAND='` 提取，失败提权看 `sudo.*incorrect password`。

`.sudo_as_admin_successful` 只能作为**旁证**，确认该用户确实有 sudo 权限且用过，并且要明确标注它不含命令与准确时间。

<a id="section-32"></a>

#### 陷阱 13：用 `facility` 反查时把 `authpriv` 与 `auth` 当成同一条

**现象**：报告按 facility 统计认证事件，写「`auth.*` 共 `<N>` 条、`authpriv.*` 共 `<M>` 条」，并把两者相加或分别列出，读者以为这是两类不同的认证行为。

**原因**：2.4 那段典型规则里，`auth.*` 与 `authpriv.*` **指向同一个文件**：

```
auth.*      /var/log/auth.log
authpriv.*  /var/log/auth.log
```

这是 rsyslog 的设计：`auth` 是给一般工具用的 facility，`authpriv` 是给特权组件（`su`、`sudo`、login 等）用的，两者都落到 `/var/log/auth.log`。所以按 facility 分类出来的两组数**不是行为分类，是同一个文件里的两种写入来源**。而 `sudo` 的命令（2.7 里那四类行）恰恰多数走 `authpriv`，密码认证走 `auth`——若按 facility 下结论，等于把「用了 sudo」和「通过了密码认证」当成互斥的两种事。

**影响**：这类分类错误会让「提权次数」的统计口径失真——分析员从 `auth` 那一组里数登录、从 `authpriv` 那一组里数 sudo，看起来分类清晰，实际上两组数据在同一条时间线里交错，`sudo: COMMAND=` 行与它前面的 `Accepted password` 行是**同一会话的先后两步**，分开统计就丢掉了这个关联。

**核查**：**facility 用于定位文件，不用于分类事件。** 事件分类按内容关键字（`Accepted` / `Failed` / `Invalid user` / `session opened|closed` / `sudo.*COMMAND=` / `sudo.*incorrect password`），并在报告里注明计数来自哪个文件、用了哪几条正则。`sudo` 与认证的关联靠**同一 TTY / 同一用户的相邻行**来建立，不是靠 facility 归类。

<a id="section-33"></a>

#### 陷阱 14：把 PAM 的 `pam_unix` 行当成登录成功记录

**现象**：`grep -c 'pam_unix' auth.log` 得到一个数，作为「该机共有 N 次成功登录」，与 `Accepted password` 的计数对比后取较大值。

**原因**：`pam_unix(sshd:session)` 这类行是 PAM 会话管理模块发出的，与认证结果没有一一对应关系。 认证成功有明确的 `Accepted` 行，失败有 `Failed` 行、错误密码有 `authentication failure`，而 `pam_unix` 行在会话建立与关闭时各出现一次，**无论认证成功还是失败，只要走到了会话阶段就会记录**。2.7 把 sudo 相关的行分成认证/执行/策略/失败四类，正是要提醒「同一类关键字的行不代表同一类事实」。

**影响**：把 PAM 行当登录统计，会同时高估（策略行被算成成功）和漏掉（某些认证方式不产生 `Accepted` 行）。它还容易让人误以为某次认证「成功但没日志」——实际上只是没产生 `Accepted` 行。

**核查**：**认证结果只认三类行**：`Accepted password|publickey|keyboard-interactive`（成功）、`Failed password|authentication failure`（失败）、`Invalid user`（无效用户名）。`pam_unix` 行用于确定会话区间与权限切换，不进登录计数。报告里两个指标分开列，并注明各自的提取正则。

<a id="section-34"></a>

### 4.4 结论表述

<a id="section-35"></a>

#### 陷阱 15：把「日志缺失」写成「无活动」

**现象**：某时段日志为空或日志文件消失，报告结论写「该时段内无异常活动」。

**原因**：日志为空有**至少四种互不相同的成因**，而它们的取证含义完全相反：根本没启用（rsyslog 未运行）、只存在于内存 journal（断电后随内存消失）、被清空或被改路由到 `/dev/null`、确实没有活动。

**这四种在磁盘上的表现可能都是文件是空的。** 把它们合并成一种解释，等于在证据缺失时替检材编了一个最无害的答案。

**影响**：这是取证报告里最不可辩护的阴性结论。危害还是双向的。

真实成因如果是被人清空，你等于帮攻击者消除了痕迹而毫不知情。真实成因如果是断电导致日志不可得，你的结论会给出一份根本不存在的干净。

**核查**：按本篇 2.4/2.5 逐项排除，并**把排除过程写进报告**：

① 读 `rsyslog.conf` + `rsyslog.d/` 确认去向；
② 查 `/var/log/journal/<machine-id>/` 目录是否实际存在（`Storage=auto` 不会自动创建它）；
③ 查 logrotate 保留策略与归档编号连续性；
④ 查相关配置文件自身的 `mtime`/`ctime` 是否异常。

排除之后仍有无法覆盖的时段，结论必须写成「**该时段证据不可得**（原因：断电 + journal 仅存于 `/run/log/journal`）」，并列入报告的证据局限章节。

**不能写成无异常。**

<a id="section-36"></a>

#### 陷阱 16：跨重启重建时间线时，把两个 boot 周期的事件混进同一条线

**现象**：journal 里导出 2024-03-10 到 03-18 的全部记录，按 `__REALTIME_TIMESTAMP` 排序后发现「00:00 整有一条服务停止、紧接着 00:01 又启动」，报告写「服务在零点自动重启」。

**原因**：不按 boot 周期切分，跨重启的事件会被排进同一条时间线，而重启本身会制造出看似连续的记录。 journal 的每个 entry 带 `_BOOT_ID` 字段，标识它来自哪一次启动，重启后该值会变。一台机器在取证窗口内重启过若干次，那么「上一轮启动的最后一条」和「下一轮启动的第一条」在时间上可能只差几秒——把它们直接连起来看，就会读出「零点自动重启」这种并不存在的周期性行为。第五章案例那台机器是**强制断电**的，断电在 journal 里同样表现为 boot 周期边界。

**影响**：**编造出一条规律性行为。** 「服务每天零点自动重启」这类结论会把调查导向错误方向（配置里的定时任务、崩溃自愈，而不是人为操作），而后文所有基于它的推断——为什么重启、是不是被踢出、能否归因——都会跟着走偏。

**核查**：按 `_BOOT_ID` 分组，每个 boot 周期单独成段，段间标出边界。

```bash
journalctl --directory /mnt/df/var/log/journal -o json --no-pager \
  | python3 -c "
import json,sys,collections
g=collections.defaultdict(list)
for l in sys.stdin:
    l=l.strip()
    if not l: continue
    d=json.loads(l); g[d.get('_BOOT_ID','?')].append(d)
for bid,ds in sorted(g.items(), key=lambda kv: min(int(x.get('__REALTIME_TIMESTAMP',0)) for x in kv[1])):
    ds.sort(key=lambda d: int(d.get('__REALTIME_TIMESTAMP',0)))
    print(bid, len(ds), ds[0].get('__REALTIME_TIMESTAMP'), '→', ds[-1].get('__REALTIME_TIMESTAMP'))
"
```

写法：「该窗口内共 `<N>` 个 boot 周期（`_BOOT_ID` 为 `<id1>`、`<id2>`…），各周期事件已分别分析；**跨 boot 记录未做连续解读**——周期 `<id1>` 末条为 `<T1>`，周期 `<id2>` 首条为 `<T2>`，两者之间的间隔不代表任何活动」。某周期是否为**正常关机**另作判断，看它有没有正常收尾（`systemd-shutdown` 或以 `session closed` 结尾），这与 1.3 末尾那个断电判据是同一件事。

<a id="section-37"></a>

## 五、案例示例

<a id="section-38"></a>

### 5.1 爆破登录与提权链的日志侧定案

**场景**

Ubuntu Server 22.04 Web 服务器（主机名 `web01`，Debian 系，ext4）。委托方要求查明 2024-03-17 至 03-18 期间是否有未授权访问。检材 `DigiForensics.dd`（raw，ext4 起始扇区 1181696），时区 `Asia/Shanghai`。系统**强制断电**，无正常关机记录。

与[取证工件地图](../computer-persistence/computer-persistence-persistence-artifact-map.md)是同一台主机、同一条时间线。委托方的问题只有一个：**3 月 17 日夜里到底有没有人登进来过。**

因为认证日志同时给出时间、身份、来源地址、认证结果四要素，其余工件都缺其中一两项，所以本节从认证日志切入。

**处置过程**

第 1 步，确认日志落点与 journal 存储模式（顺序不能反）：

```bash
ls -l --time-style=long-iso /mnt/df/var/log/ | grep -iE 'auth|syslog|journal|messages|secure'
# -rw-r----- 1 root adm  48213 2024-03-18 09:41  auth.log      ← 当前，断电前最后写入
# -rw-r----- 1 root adm 120344 2024-03-04 23:59  auth.log.1    ← 约两周前（logrotate 轮转）
# -rw-r----- 1 root adm   8801 2024-02-25 23:59  auth.log.2.gz ← 更早，已压缩
# drwxr-sr-x+ 2 root systemd-journal 4096 2024-03-18 09:41 journal/   ← 目录存在

cat /mnt/df/etc/machine-id
# 3a7f8c2e1b4d5e6f7a8b9c0d1e2f3a4b
ls /mnt/df/var/log/journal/3a7f8c2e1b4d5e6f7a8b9c0d1e2f3a4b/
# system.journal  user-0.journal      ← 磁盘持久化 ✓
```

第 2 步，合并三档 `auth.log` 补齐三周历史：

```bash
cd /mnt/df/var/log
{ zcat auth.log.2.gz 2>/dev/null   # 最旧（2 月下旬）
  cat  auth.log.1                  # 中间（3/04 - 3/17）
  cat  auth.log; } > /evidence/auth-merged.txt
wc -l /evidence/auth-merged.txt     # 1127 行，覆盖 2024-02-25 至 2024-03-18
```

第 3 步，提取成功/失败登录：

```
Mar  4 08:12:03 web01 sshd[2210]: Accepted password for deploy from 198.51.100.23 port 51234 ssh2
Mar 17 22:41:15 web01 sshd[9104]: Failed password for invalid user admin from 203.0.113.77 port 40122 ssh2
Mar 17 22:41:18 web01 sshd[9106]: Failed password for invalid user test from 203.0.113.77 port 40130 ssh2
Mar 17 22:41:22 web01 sshd[9109]: Invalid user oracle from 203.0.113.77 port 40144 ssh2
Mar 17 22:41:26 web01 sshd[9112]: Failed password for root from 203.0.113.77 port 40158 ssh2
Mar 17 22:43:07 web01 sshd[9201]: Accepted password for deploy from 203.0.113.77 port 40210 ssh2
Mar 17 22:43:09 web01 sshd[9201]: pam_unix(sshd:session): session opened for user deploy by (uid=0)
Mar 18 08:40:11 web01 sshd[9810]: Accepted publickey for svc-backup from 198.51.100.9 port 52002 ssh2: RSA SHA256:7Kx...
```

第 4 步，锁定提权命令：

```
Mar 17 22:44:01 web01 sudo:  deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash
Mar 17 22:47:33 web01 sudo:  deploy : COMMAND=/usr/bin/apt-get install -y netcat
Mar 17 22:48:20 web01 sudo:  deploy : COMMAND=/bin/chmod 4755 /tmp/.kworkerd
Mar 17 23:55:02 web01 sudo:  deploy : COMMAND=/usr/bin/crontab -l
```

第 5 步，用 journal 补年份并确定断电前最后时刻：

```bash
journalctl --directory /mnt/df/var/log/journal _COMM=sshd \
           --since "2024-03-17 22:00" --until "2024-03-18 10:00" \
           -o short-precise --no-pager | grep -iE 'Accepted|Failed|session|Disconnected'
```

```
2024-03-17T22:41:15.341892+08:00 web01 sshd[9104]: Failed password for invalid user admin from 203.0.113.77 port 40122 ssh2
2024-03-17T22:43:07.882110+08:00 web01 sshd[9201]: Accepted password for deploy from 203.0.113.77 port 40210 ssh2
2024-03-18T09:40:58.771200+08:00 web01 sshd[11203]: Accepted password for deploy from 203.0.113.77 port 44880 ssh2
2024-03-18T09:41:07.552918+08:00 web01 sshd[11203]: pam_unix(sshd:session): session closed for user deploy
```

第 6 步，跨源印证：

```bash
last -f /mnt/df/var/log/wtmp deploy | head
# deploy  pts/0  203.0.113.77  Sat Mar 17 22:43 - 23:55 (03:17)
# deploy  pts/0  203.0.113.77  Sun Mar 18 09:40 - 09:41
ls -l /mnt/df/home/deploy/.sudo_as_admin_successful
# -rw-r--r-- 1 deploy deploy 0 2024-03-17 22:44    ← 与 sudo 首条吻合 ✓
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 2024-03-17 22:41:15 起 `203.0.113.77` 发起用户名/口令扫描爆破 | auth.log + journal 双源一致 | 强 |
| 22:43:07 攻击者用 `deploy` 账户密码登录成功 | auth.log `Accepted` + journal + wtmp 三源印证 | 强 |
| 登录后提权 root，安装 netcat，对 `/tmp/.kworkerd` 设 SUID 4755 | auth.log 的 `sudo COMMAND=` 行（含具体命令） | 强 |
| 事件年份为 2024 | 由 journal（带年）补齐传统 syslog 缺失字段 | 强（双源） |
| 断电前会话正常结束，命令落盘完整 | journal `session closed` 早于断电 | 强 |

**不能证明的**：登录者自然人身份。`203.0.113.77` 是网络层事实，可能经代理或跳板；能归属的只有某个持有 `deploy` 正确口令的人在 22:43:07 通过 SSH 登录。另外，**断电前的具体命令内容日志本身不记录**，`COMMAND=` 只覆盖 sudo 提权那几条，普通会话内的命令要去 `~/.bash_history` 找。

**误判对照**

这个案子最容易得出的错误结论是：22:43:07 是一次正常运维登录，攻击者只是爆破失败而已。

理由看起来很充分——22:41 确实是失败的，失败 5 次后同一 IP 成功，这形态在很多日志里就是用户记错密码重试。

撑住这个案子的是三处具体字段的组合：

1. 失败行的用户名字段。`Failed password for invalid user admin` / `test` / `oracle` 里带 **`invalid user` 前缀**，说明连用户名都在猜。运维重试只会打同一个真实用户名，不会依次试 admin/test/oracle。`Invalid user oracle` 这行更是 sshd 侧的独立记录。
2. 间隔。22:41:15 到 22:41:26 共 11 秒 4 次尝试，且每次客户端源端口都不同（40122/40130/40144/40158），说明是 4 个独立 TCP 连接，不是同一次会话重试。
3. 行为序列。22:43:07 登录成功，随后 22:44:01 `sudo ... COMMAND=/bin/bash`（开交互 root shell）、22:47:33 `apt-get install -y netcat`、22:48:20 `chmod 4755 /tmp/.kworkerd`。运维不会在登录后 1 分钟内开 root shell，再给 `/tmp` 下的隐藏文件加 SUID。

**按错误判据走的代价**：把这条链定性为正常运维加爆破未遂，会落到两个后果。

一是不去查 `/home/deploy/.bash_history` 与 `/etc/crontab`，`deploy` 后续建立的后门完全漏掉。二是把 `203.0.113.77` 当成无辜的暴力破解源排除在本案之外，横向范围就断了。

另一个易错点：**`port 40210` 不是服务端口。**

sshd 的服务端口固定 22，日志行里的 `port` 恒为客户端临时端口。若据此去排查 40210 上的服务，既查不到东西，又容易因为该端口无服务反过来质疑这条登录记录本身的真实性。

---

<a id="section-39"></a>

### 5.2 rotate 0 与伪造补位：归档编号缺口指向日志清理

**场景**

同型号 Debian 12 服务器 `web07`，委托方追问 3 月 5 日到 3 月 9 日这段时间有没有登录记录。检材 `DigiForensics.dd`。

分析者第一眼看到 `/var/log/auth.log` 有内容、mtime 也正常，于是准备直接回答有记录。

这个案例要讲的是另一件事：日志缺失和日志被清理，在磁盘上的第一眼表现几乎完全相同，只能靠归档编号连续性和配置本身来区分。

**处置过程**

第 1 步，列目录并看归档编号：

```bash
ls -l --time-style=long-iso /mnt/df/var/log/ | grep -iE 'auth|^total'
# -rw-r----- 1 root adm 112044 2024-03-09 08:12  auth.log
# -rw-r----- 1 root adm  60021 2024-03-04 23:59  auth.log.1
# ← 注意：没有 .2.gz，没有 .3.gz
find /mnt/df/var/log -maxdepth 1 -name 'auth.log.*' -printf '%TY-%Tm-%Td %p\
' | sort
# 2024-03-04 auth.log.1
# 2024-03-09 auth.log
```

第 2 步，读该服务的 logrotate 配置（**这一步是定案的关键，不是补充**）：

```bash
grep -vE '^\s*#|^\s*$' /mnt/df/etc/logrotate.d/rsyslog
# /var/log/auth.log {
#     daily
#     rotate 0
#     missingok
#     notifempty
#     compress
#     delaycompress
#     sharedscripts
#     postrotate ... endscript
# }
ls -l --time-style=full-iso /mnt/df/etc/logrotate.d/rsyslog
# -rw-r--r-- 1 root root 412 2024-03-05 02:11:34+08:00
```

第 3 步，看 rsyslog 是否改了去向：

```bash
grep -vE '^\s*#|^\s*$' /mnt/df/etc/rsyslog.d/50-default.conf | grep -iE 'auth|/dev/null'
# auth.*      /var/log/auth.log
# authpriv.*  /var/log/auth.log
ls -l /mnt/df/etc/rsyslog.d/50-default.conf
# -rw-r----- 1 root adm 1067 2023-11-02 10:33:12+08:00   ← 远早于本次改动
```

第 4 步，验证当前文件内部时间跨度是否与每日轮转矛盾：

```bash
{ cat /mnt/df/var/log/auth.log.1; cat /mnt/df/var/log/auth.log; } > /evidence/auth-merged.txt
head -1 /evidence/auth-merged.txt
# Mar  3 00:07:44 web07 sshd[884]: Accepted publickey for svc-backup ...
tail -1 /evidence/auth-merged.txt
# Mar  9 08:12:03 web07 sshd[2201]: session closed for user root
awk '{print $1" "$2}' /evidence/auth-merged.txt | uniq -c | head -12
# 431 Mar  3
# 588 Mar  4
#   0 Mar  5      ← 计数为 0：整个 3 月 5 日缺失
# 612 Mar  6
```

第 5 步，在 journal 里找配置改动本身的动作：

```bash
journalctl --directory /mnt/df/var/log/journal --since "2024-03-05 01:30" --until "2024-03-05 03:00" \
           -o short-precise --no-pager | grep -iE 'logrotate|cron|CRON'
# 2024-03-05T02:11:35.882014+08:00 web07 CRON[28114]: (root) CMD (/usr/sbin/logrotate /etc/logrotate.conf)
# 2024-03-05T02:11:36.140922+08:00 web07 logrotate[28114]: removing /var/log/auth.log.1
```

**结论**

- `rotate 0` 意味着**轮转时旧内容被丢弃，而不是改名保留**。`logrotate` 在 02:11:36 明确 `removing /var/log/auth.log.1`，journal 记录与目录状态互证，3 月 5 日的认证日志是被系统配置丢弃的，不是查不到。
- 配置变更时间可以收敛到 **2024-03-05 02:11 前后**：logrotate.d/rsyslog 的 mtime 是 `2024-03-05 02:11:34`，journal 里 02:11:35 的轮转任务与 02:11:36 的 `removing` 记录，三者落在同一分钟内，构成独立印证。
- rsyslog 配置的 mtime 是 2023-11-02，可以排除通过改 rsyslog 把 auth 日志导向别处这条路径——auth 日志仍然只写 `/var/log/auth.log`。
- 所以委托方问题的正确答复是：「3 月 5 日 00:00–24:00 的认证日志因主机配置 `rotate 0` 而被丢弃，证据不可得」，而不是该日无登录活动。**缺口原因明确，但它仍然属于证据局限。**

**误判对照**

这个案子的错误结论有两种，方向相反，但都长得很自然。

误判 A：「3 月 5 日没有记录，说明这天没人登录。」 依据是 `auth.log.1` 的首行是 `Mar 3`、当前文件的首行是 `Mar 6`，中间直接断开——看起来就是没有活动。

撑住它的是 `rotate 0` 这条指令本身，加上 journal 里的 `removing` 行。

`rotate 0` 的语义是轮转时直接删除、不保留任何归档，**它的预期效果就是让昨天和更早的日志凭空消失**，与没人登录在文件层面完全同形。区分二者只能看配置与轮转动作的日志，因为**缺口本身没有信息量，缺口的成因才有**。

按误判 A 走的代价，是把一个**已知的证据销毁行为**写成中性结论，等于替行为人消除了痕迹而自己毫不知情；后续所有该时段无异常的排除推理全部作废。而且这个错误极难被质证环节发现——报告里没有任何一处写错。

误判 B：「归档缺号（只有 `.1` 没有 `.2.gz`）= 有人手动删了中间档，这是人为篡改的铁证。」 A 和 B 在本案里同时成立，是因为样本恰好同时具备两个成因。

这里要把两个成因分开验证。

`rotate 0` 能解释为什么永远不会有 `.2.gz`——每个周期都只删不存，编号根本涨不上去。

但它**解释不了 3 月 5 日这个特定日子的缺口**。

按 `rotate 0` 的行为，3 月 6 日的文件应该在 3 月 7 日轮转时被删、3 月 7 日的内容在 3 月 8 日被删，依此类推所有更早内容都会消失。不该出现 3 月 3 日的内容还完整留在 `.1` 里。

`Mar 3` 有 431 行、`Mar 4` 有 588 行，说明这份 `rotate 0` 配置不是一直生效，而是在 3 月 5 日才被改上去的。

按误判 B 走的代价方向相反：你会得到一个发现人为篡改日志的高强度结论，并据此推断攻击者主动清理痕迹、扩大怀疑面。**实际上篡改者可能只是改了一个配置项来省磁盘空间。**

同一个动作，在人的故事里是反取证，在运维的故事里只是配置管理。定性错了，后续的嫌疑人排序会跟着走偏。

判据小结：区分清理与无活动靠 `logrotate` 配置加 `journalctl` 的 `removing` 行；区分人为清理与配置生效靠**归档里残留的更早内容**——`rotate 0` 生效后不可能还留有生效前的日志。

---

<a id="section-40"></a>

### 5.3 反例：journal 只在 /run 时，断电前时段不可得

**场景**

CentOS Stream 9 服务器 `db02`，委托方要求确认 3 月 20 日系统是否发生过异常登录。检材 `DigiForensics.dd`，机器在 3 月 20 日 02:14 被强制断电（后续盘点发现未正常关机）。

本节是阴性发现的标准写法示范：证据不可得的时候，结论应该长什么样。

**处置过程**

第 1 步，先判断 journal 存不存在、存在哪：

```bash
cat /mnt/df/etc/os-release | grep -E '^(ID|VERSION_ID)='
# ID="centos"
# VERSION_ID="9"
ls -la /mnt/df/var/log/journal/ 2>&1
# ls: cannot access '/mnt/df/var/log/journal/': No such file or directory
ls -la /mnt/df/run/log/journal/ 2>&1 | head
# drwxr-xr-x 2 root root 4096 Mar 20 02:14 ./
```

第 2 步，读 journald 存储模式，确认是没配置还是没落盘：

```bash
grep -iE '^\s*Storage' /mnt/df/etc/systemd/journald.conf
#（无输出 = 保持发行版默认 Storage=auto）
# auto 的语义：/var/log/journal 存在就写盘，不存在就退回 /run（内存）
```

第 3 步，看纯文本日志的实际覆盖范围（journal 不可得时，这是本案唯一能用的时间源）：

```bash
ls -l --time-style=long-iso /mnt/df/var/log/ | grep -iE 'secure|messages|wtmp|btmp'
# -rw------- 1 root root 4821 2024-03-20 02:14 secure
# -rw-r--r-- 1 root root  2160 2024-03-19 23:59 secure.1
# -rw-r--r-- 1 root utmp  4210 2024-03-20 02:14 wtmp
head -1 /mnt/df/var/log/secure.1
# Mar 19 00:03:11 db02 sshd[1102]: Accepted publickey for svc-backup from 198.51.100.9 port 49312 ssh2
```

第 4 步，确认断电时刻，判断覆盖到哪里为止：

```bash
ls -l --time-style=full-iso /mnt/df/var/log/secure /mnt/df/var/log/wtmp
# -rw------- 1 root root 4821 2024-03-20 02:14:33+08:00 secure
# -rw-r--r-- 1 root utmp  4210 2024-03-20 02:14:29+08:00 wtmp
last -f /mnt/df/var/log/wtmp reboot shutdown | head -3
#（无正常 shutdown 记录，仅有 reboot）→ 与委托方所述强制断电一致
```

第 5 步，明确写出**未覆盖的范围**：

```bash
# journal 不可用 → 断电前 00:00–02:14 只有 /var/log/secure 覆盖，
# 且 secure 缺年份，需文件系统时间戳辅助界定边界
ls -l --time-style=long-iso /mnt/df/var/log/secure.1
# 2024-03-19 23:59  ← 上一轮轮转边界
# 因此 secure 精确覆盖 2024-03-20 00:00 至 02:14:33
```

**结论**

- **可确认的**：2024-03-20 00:00 至 02:14:33 期间，`/var/log/secure` 与 `wtmp` 有连续记录。窗口内未见成功的密码登录，只有 `svc-backup` 的公钥登录——属计划任务，与 `secure.1` 首行是同一账户，行为可解释。
- **不可得的三项证据**：① **断电前的精确时刻**——本机 journal 只在 `/run/log/journal`，随内存一起消失，`Storage=auto` 未启用落盘；② 断电前最后 30 分钟的 systemd 结构化日志（`_PID`、`_UID`、`_COMM` 等字段全部不可得）；③ 传统 syslog 缺失的**年份**——`Mar 20 09:12:03` 单看一行无法判定是 2024 年还是别的年份，只能靠 `secure.1` 的轮转边界（mtime 2024-03-19 23:59）间接推定 2024，属推定而非证据。
- 所以报告结论必须写成：「2024-03-20 02:14 断电时刻及之前的 systemd 级日志不可得（原因：journal 未持久化 + 强制断电）。在该不可得窗口内，本案不作任何行为判断。」
- **阴性发现的限定范围**：「在 `/var/log/secure`（覆盖 2024-03-20 00:00–02:14:33）与 `wtmp` 范围内，未发现异常登录记录。」

**误判对照**

本案最容易得出的错误结论是：`/var/log/journal` 不存在，说明这台机器关了 journald，没有结构化日志可用，所以无法分析。

这看起来是严谨的谨慎表述，实际上**既不准确也不完整**。

正确判据分三层：

1. **目录不存在 ≠ journald 未运行。** `Storage=auto`（所有发行版默认）不会自动创建 `/var/log/journal`。目录不存在时 journald 照常运行，只是把日志写在 `/run/log/journal` 的 tmpfs 里。`ls /mnt/df/run/log/journal/` 存在且 mtime 是 03-20 02:14——正是断电时刻——就证明**它一直在运行，是内存易失**。把未落盘说成未启用，会让报告的证据局限描述失真，委托方可能据此误判这台机器的日志配置水平。
2. **`secure` 仍然是可用证据，只是精度受限。** 不能因为 journal 缺失就跳过 `/var/log/secure`。它覆盖了断电当日 00:00 到 02:14:33，正是委托方最关心的时段，且 `Accepted`/`Failed`/`session` 四类行齐全。**能回答的问题必须回答**，只有确实拿不到的才写不可得。
3. 不可得的边界要精确到时刻，不能笼统写部分日志缺失。 精确边界是 `secure.1` 的轮转时间（2024-03-19 23:59）到断电（2024-03-20 02:14:33）。这段 2 小时 14 分内 `secure` 连续覆盖但 journal 不可得；02:14:33 之后**所有日志源都不可得**，机器已断电。分不清这两个窗口，委托方就无法判断哪些结论还有效。

**按错误判据走的代价**：写成无法分析或该机未启用日志，委托方很可能把这台主机从调查范围里划掉。

更糟的是，如果真实成因是运维改了 `Storage` 配置导致 journal 不落盘（本案 `/etc/systemd/journald.conf` 存在但无 `Storage` 行，指向默认值而非显式关闭），那这个配置本身就是一条应当上报的发现。笼统的未启用会把这个发现一起埋掉。

---
<a id="section-41"></a>

## 六、扩展阅读方向

<a id="section-42"></a>

### 前置基础

- [取证工件地图](../computer-persistence/computer-persistence-persistence-artifact-map.md) —— **解决这台机器的发行版家族是什么**。`/etc/os-release` 的读法、Debian 与 RHEL 的完整路径对照、`/tmp` 与 `/var/tmp` 为什么都要查都在那篇，本篇的路径表是它的子集。
- [只读接入与验证](../computer-persistence/computer-persistence-persistence-artifact-map.md#section-8) —— **本篇所有命令的前置条件**。对挂载点直接跑 `journalctl`、`last`、`cat` 都会产生写入痕迹，**先做完接入验证再开始分析**。

<a id="section-43"></a>

### 同层深入

- [时间线重建](computer-log-linux-timeline-reconstruction.md) —— **解决传统日志没有年份怎么对齐**。本篇只能确认某个文件里有 Mar 17 这条记录，**是哪一年、哪个时区由那篇解决**。跨源归一化、矛盾点处理、收敛策略都在那里。
- [计划任务与持久化痕迹](../computer-persistence/computer-persistence-scheduled-tasks-and-persistence.md) —— **解决登录成功之后发生了什么**。系统日志给出什么时候、以什么身份，**后继行为要靠持久化工件补齐**，两篇必须连着读。

<a id="section-44"></a>

### 相邻议题

- [取证工件地图（服务器）](../../server/server-panel/server-panel-linux-server-artifact-map.md) —— **解决服务自身的日志在哪**。本篇覆盖系统日志，Web/数据库/面板类服务有各自的日志目录，与 `/var/log` 不重合。
- [事件日志深度分析（Windows）](../computer-registry-log/computer-registry-log-windows-event-log-analysis.md) —— **横向对照读**。Windows 侧有独立的事件日志字段体系与审计策略，**两边的事件 ID 与字段语义不可互换**。
- [ext4 结构与 inode](../../filesystem/filesystem-unix/filesystem-unix-ext4-inode.md) —— **解决日志文件本身被删了还能不能找回来**。本篇假设日志文件存在，**该假设不成立时的路径在那篇**。
- [文件头与文件签名](../../filesystem/filesystem-ntfs/filesystem-ntfs-file-headers-and-signatures.md) —— 解决 `audit.log` 是什么格式、能不能直接读。它是二进制而非文本。

<a id="section-45"></a>

### 工具与规范

- `journalctl --directory` 读离线 journal 是本篇最关键的一条命令，参数组合见[命令速查](#section-47)——注意必须给 `--directory` 指向镜像里的路径，直接对挂载点读会写 journal。
- 传统日志合并归档与当前文件时，**要按轮转顺序拼接再排序**。直接 `cat auth.log* | sort` 会把 `Mar 17` 和 `Feb 3` 排错，因为**跨年时字符串排序不等于时间排序**。
- 报告里双源一致、三源印证的强度表述模板见[案例示例](#section-37)的结论表——**每个结论后面必须挂支撑证据清单**，这是日志类分析最容易被质证的部分。
- 采集授权与最小化原则见[合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md)——**日志含用户名、IP、命令，报告必须脱敏**。

<a id="section-46"></a>

### 判据与反例

- **判据一**：**路径不存在不等于日志没被记录**。至少四种解释：发行版不同、rsyslog 配置改过、被清理、轮转到归档。**必须四种都排除才能写无记录。**
- **判据二**：登录成功结论要三源印证（本篇案例：`Accepted` 行 + journal + `wtmp`）。**单源时强度降级并写明。**
- **判据三**：journal 的存在性本身是证据状态。`/var/log/journal` 存在才使断电前时段的结论可信；只在 `/run` 则必须声明该时段不可得。
- **反例一**：对 `.journal` 文件 `grep` 或只 `strings` 就当读过。**碎片不完整也不可靠**，必须 `journalctl` 导出。
- **反例二**：把当前日志被截断当成没有异常活动。截断本身是可疑迹象，`.gz` 归档里常留有更早记录——本篇开头列的三个翻车点里，第一个就是它。
- **反例三**：用传统 syslog 格式直接声称事件年份。**格式里根本没有年份字段**，必须由 journal 或其他带年源补齐，并写明补齐来源。
- **反例四**：把来源 IP 直接写成攻击者。**IP 是网络层事实，可能经代理或跳板**，主体归属要靠登录账户、认证方式、命令历史交叉。
- **反例五**：journal 缺失就写无异常活动。正确写法是「**断电前时段日志不可得**」——把证据缺口写成阴性结论，是本类文章最需要避免的一类错误。
<a id="section-47"></a>

## 七、命令速查

```bash
# ===== 1. 确认日志落点 =====
ls -l --time-style=long-iso /mnt/df/var/log/ | grep -iE 'auth|syslog|journal|secure|messages'
ls -1 /mnt/df/var/log/ | grep -E 'auth|secure' | sort -V      # 轮转连续性
find /mnt/df/var/log -maxdepth 1 \( -name '*.gz' -o -name '*.1' \) -printf '%TY-%Tm-%Td %p\
' | sort

# rsyslog 去向（含丢弃规则）
grep -vE '^\s*#|^\s*$' /mnt/df/etc/rsyslog.conf
grep -Rn '/dev/null' /mnt/df/etc/rsyslog.d/ 2>/dev/null

# journal 存储模式（只认目录实际存在性）
cat /mnt/df/etc/machine-id
ls -la /mnt/df/var/log/journal/$(cat /mnt/df/etc/machine-id)/ 2>/dev/null
grep -iE '^\s*Storage' /mnt/df/etc/systemd/journald.conf 2>/dev/null

# ===== 2. 合并轮转档位（最旧→最新）=====
cd /mnt/df/var/log
{ ls -1tr auth.log.*.gz 2>/dev/null | while read f; do zcat "$f"; done
  cat auth.log.1 2>/dev/null; cat auth.log; } > /evidence/auth-merged.txt
# RHEL 系：把 auth.log.* 换成 secure.*

# ===== 3. journal 导出为文本（不可直接 grep 二进制）=====
journalctl --directory /mnt/df/var/log/journal -o short-precise --no-pager \
  > /evidence/journal-precise.txt
journalctl --directory /mnt/df/var/log/journal _COMM=sshd \
  --since "2024-03-17 22:00" --until "2024-03-18 10:00" -o short-precise --no-pager
journalctl -k --since "1 hour ago" -p err -o short-precise --no-pager   # 内核 err+
journalctl _UID=0 --since today --no-pager                              # root 进程日志

# ===== 4. 认证事件提取 =====
grep -iE 'Accepted (password|publickey)' /evidence/auth-merged.txt      # 成功登录
grep -iE 'Failed password|Invalid user|auth failure' /evidence/auth-merged.txt \
  | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sort | uniq -c | sort -rn | head  # 爆破源排行
grep -iE 'sudo.*COMMAND=' /evidence/auth-merged.txt                       # 提权命令
grep -iE 'session (opened|closed) for user' /evidence/auth-merged.txt

# ===== 5. logrotate 保留策略 =====
for f in /mnt/df/etc/logrotate.conf /mnt/df/etc/logrotate.d/*; do
  echo "== $f =="; grep -vE '^\s*#|^\s*$' "$f"; done | head -60
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — Linux 取证 — 系统日志深度分析」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《系统日志深度分析》（CC BY-SA 4.0）`

文中 `DigiForensics.dd` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
