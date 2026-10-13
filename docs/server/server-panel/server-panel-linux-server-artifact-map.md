---
title: "Linux 服务器取证工件地图"
slug: "server-panel-linux-server-artifact-map"
canonical: "https://www.digiforensics.cn/wiki/server-panel-linux-server-artifact-map"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:51+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "server"
space: "服务器与云取证"
node_path: ["面板与控制台"]
---

# Linux 服务器取证工件地图

<a id="section-1"></a>

## 一、概述

把服务器和办公 PC 当成同一类检材，会直接用错处置方式。

差别不在硬件，在**证据生存条件**。办公 PC 通常已关机封存，磁盘是静止的，你可以慢慢分析。

服务器通常还开着。

Nginx 正在写 access.log，`logrotate` 每晚轮转，journald 在滚动，MySQL 的 binlog 正在被写满并删除。**你每多等一小时，证据就少一小时。** 这就是服务器取证与离线 PC 取证最根本的差别：服务器取证是一场和日志轮转的赛跑。

第二个差别在**信任模型**。办公 PC 上非管理员账户基本动不了系统目录；服务器上则不然——`/www/wwwroot` 站点目录对 Web 用户可写（业务硬需求），管理面板一个 Web 口令就等价于 root，失败成本从"单机影响"变成"一个上传点沦陷整机再横向内网"。

这直接决定了证据分布：服务器上最有价值的痕迹通常不在系统日志里，而在网站目录和 Web 访问日志里。涉 webshell、挖矿、篡改网站的案件，第一现场是站点根目录和 access.log，**而不是 `auth.log`**。

**在取证流程中的位置**：本篇是**服务器场景的入口与导航**，属于采集环节的前置判定层。它不解析任何东西，只回答三件事：**证据在哪里、活得多久、该按什么顺序抢**。深入分析见 [宝塔面板取证](server-panel-bt-panel-forensics.md) 与 [宝塔新版加密数据解密](server-panel-bt-panel-encrypted-data.md)，Web 服务器层见 [Nginx 与 Apache 配置取证](../server-web/server-web-nginx-apache.md)，后门层见 [网站目录与 WebShell 检测](../server-web/server-web-webshell-detection.md)。Linux 通用痕迹见 [Linux 取证工件地图](../../computer/computer-persistence/computer-persistence-persistence-artifact-map.md)，本篇不重复。

**涉及的证据形态**（Web 环境分散在三处，**下面三组路径都要查**，含取证价值与交叉引用见 2.3）：

| 路径 | 内容 |
|---|---|
| `/www/wwwroot/<site>/` | **宝塔站点根目录（对 Web 用户可写）** |
| `/www/server/panel/data/` 与 `logs/` | 面板数据库配置与操作日志 |
| `/www/server/panel/vhost/` | 宝塔生成的站点配置 |
| `/www/server/nginx/conf/` | 宝塔自编译的 Nginx（不是 `/etc/nginx`） |
| **`/www/wwwlogs/`** | 宝塔的网站日志目录（不是 `/var/log/nginx`） |
| **`/www/backup/`** | **宝塔自动备份（站点 + 数据库）** |
| `/var/www/`、`/etc/nginx/`、`/var/log/nginx/` | 源包安装 / 发行版环境 |
| `/etc/cron.d/`、`/var/spool/cron/crontabs/` | 计划任务（面板也能写） |
| `/root/.bash_history`、`/home/*/.bash_history` | **面板 / SSH 操作留下的命令历史** |
| `mysql-bin.0000xx`、`general_log` | binlog 与查询日志，拖库行为的痕迹通常优先在这两处找 |

> ⚠️ **最容易漏的三个目录**，逐项说明见 2.3 关键路径速查表。

**服务器证据为什么"活得短"**、**服务仍在运行意味着什么**——这两点是本篇的处置前提，推论与硬性顺序见 2.1 与 2.2。

本篇要回答的问题：服务器上证据散在哪些位置、哪些还活着、现场该怎么处置、按什么优先级往下查。

明确不在本篇范围内的：具体某个 WebShell 怎么工作（那是后门层的内容）；日志被覆盖掉的时段发生了什么（**只能写"未覆盖"，不能写"未发生"**）；面板里的加密配置怎么解（见 [宝塔新版加密数据解密](server-panel-bt-panel-encrypted-data.md)）；"access.log 里没有"不等于"没被访问"——日志可能被清、被轮转覆盖、或攻击者走了未记录日志的路径。

**内容边界**：本文用于**已获得合法授权**的取证场景，所有命令面向已授权的目标主机或已制作的只读镜像。目标是发现与固定证据，**不提供任何入侵手段**。检测到 WebShell、异常账户、可疑计划任务时，写的是**如何识别与如何排除误报**。

**读者前提**：需要 [Linux 取证工件地图](../../computer/computer-persistence/computer-persistence-persistence-artifact-map.md) 的通用痕迹基础、[取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) 的处置纪律，以及基本的 Web 服务架构认知。如果主机还在线，请先读 [2.2 服务仍在运行意味着什么](#section-4) 与 [3.1 第 0 步](#section-9)——这一步的顺序错了，后面所有分析都是在分析一个已经变过的现场。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 服务器证据为什么"活得短"

服务器上的记录不是"写下来就永久保存"，而是走一条有寿命的流水线：

```
Nginx 写 access.log ──┐
应用写业务日志 ───────┼──> logrotate 按 size/天 轮转 ──> 压缩归档 .gz
journald 写 journal ──┘                                    │ 保留 N 份
                                                           │ 超过保留数 → 覆盖/删除
binlog / 慢日志 ──> 写满 → 按 expire_logs_days 清理
临时文件 ──> systemd-tmpfiles 按 age 清理
```

| 机制 | 默认留存量级 | 丢失触发点 |
|---|---|---|
| `logrotate` 归档份数 | 通常 `rotate 7`～`rotate 14`（天或周） | 第 N+1 次轮转时最老那份被删除 |
| journald 持久化上限 | `SystemMaxUse` 常见 200M～4G | 超出后**丢弃最旧的日志**（不是停止写入） |
| MySQL binlog | `expire_logs_days` 默认 10 天 | 到期自动删除 |
| `/var/log/` 下 `*.1`、`*.gz` | 同上 | 覆盖或删除 |

**取证推论**：①"日志被覆盖"是常态而非异常，不能假设日志覆盖了入侵全程；②入侵若发生在半年前，access.log 可能只剩最近两周；③**发现覆盖本身就是结论的一部分**，它说明攻击者或管理员做过什么，必须写进报告，不能只写"未发现相关记录"。

<a id="section-4"></a>

### 2.2 服务仍在运行意味着什么

这是本篇最需要强调的部分。服务在线时，以下动作**会主动销毁或改写证据**：

| 你的动作（或时间的流逝） | 后果 |
|---|---|
| 什么都不做，等一天 | logrotate 覆盖掉最后一份包含入侵时段的 access.log |
| 攻击者发现自己被发现了 | 删除 WebShell、清空 history、`truncate -s 0` 清日志 |
| 你执行 `bt restart` / `service nginx restart` | 新 worker 启动，日志句柄变化，部分日志被截断重开 |
| 你执行 `rm`/`mv` 网站文件 | 目录项分离（ext4）后 `fls` 也难定位，覆盖数据概率高 |
| 磁盘写满 | 大量文件写入失败，**日志直接丢失**，站点报错 |
| 你关机 | `/tmp`（若 tmpfs）内容全部消失，`utmp` 清空，未落盘的 journal 丢失 |

**因此服务器现场的处置顺序是硬性的**：

```
1. 抢占式固定（分钟级）：内存镜像 + 关键日志定向复制 + 远程备份/只读快照（云主机）
                ↓
2. 网络层隔离（不是关机）：防火墙限流或断网，保留 SSH 通道给取证人员
                ↓
3. 决定是否停服（能冻结证据，但会中断业务 → 需委托方书面同意）
                ↓
4. 全盘镜像 → 5. 离线深度分析（此时已无时间压力）
```

> **关键判断**：**先固定后隔离，先隔离后停服，停服需授权。** 直接拔电虽然"最安全地冻结了现场"，但会销毁内存证据和 tmpfs 内容，对服务器往往是净损失。

<a id="section-5"></a>

### 2.3 关键路径速查表

按安装方式不同，Web 环境分散在三处，**三组路径都要查**：

| 路径 | 内容 | 取证价值 | 参见 |
|---|---|---|---|
| `/www/wwwroot/<site>/` | **宝塔站点根目录**（对 Web 用户可写） | ★★★★★ | [06](../server-web/server-web-webshell-detection.md) |
| `/www/server/panel/data/` | 面板数据库与配置 | ★★★★★ | [02](server-panel-bt-panel-forensics.md) / [03](server-panel-bt-panel-encrypted-data.md) |
| `/www/server/panel/logs/` | 面板请求与操作日志 | ★★★★★ | [02](server-panel-bt-panel-forensics.md) |
| `/www/server/panel/vhost/` | 宝塔生成的站点配置 | ★★★★★ | [05](../server-web/server-web-nginx-apache.md) |
| `/www/server/nginx/conf/` | **宝塔自编译的 Nginx**（非 `/etc/nginx`） | ★★★★★ | [05](../server-web/server-web-nginx-apache.md) |
| `/www/wwwlogs/` | **宝塔的网站日志目录**（非 `/var/log/nginx`） | ★★★★★ | [07](../server-web/server-web-webshell-traffic-patterns.md) |
| `/www/backup/` | **宝塔自动备份（站点+数据库）** | ★★★★ | [02](server-panel-bt-panel-forensics.md) |
| `/var/www/` | 源包安装 / 非面板环境的站点根 | ★★★★ | [06](../server-web/server-web-webshell-detection.md) |
| `/etc/nginx/`、`/var/log/nginx/` | 发行版安装的 Nginx 配置与日志 | ★★★★★ | [05](../server-web/server-web-nginx-apache.md) / [07](../server-web/server-web-webshell-traffic-patterns.md) |
| `/etc/passwd`、`/etc/shadow` | 账户与口令哈希 | ★★★★ | 见[《Linux 取证 — 取证工件地图》](../../computer/computer-persistence/computer-persistence-persistence-artifact-map.md) |
| `/etc/cron.d/`、`/var/spool/cron/crontabs/` | 计划任务（面板也能写） | ★★★★★ | 见[《计划任务与持久化痕迹》](../../computer/computer-persistence/computer-persistence-scheduled-tasks-and-persistence.md) |
| `/var/log/auth.log` / `secure` | SSH 登录记录 | ★★★★ | 见[《SSH 痕迹与密钥取证》](../../computer/computer-persistence/computer-persistence-ssh.md) |
| `/root/.bash_history`、`/home/*/.bash_history` | 面板/SSH 操作留下的命令历史 | ★★★★★ | 见[《Shell 痕迹与命令历史》](../../computer/computer-shell/computer-shell-shell.md) |

> ⚠️ **最容易漏的三个目录**（各对应一个陷阱，展开判据见陷阱 5–7）：
> 1. **`/www/backup/`** —— 宝塔每天自动备份网站和数据库，可能是**被加密前的原始数据**，也可能是攻击者已污染的副本。
> 2. **`/www/wwwlogs/`** —— 宝塔的日志不在 `/var/log/nginx`，去那里找会得到"没有访问日志"的错误结论。
> 3. `/www/server/nginx/conf/` —— 宝塔的 Nginx 是自己编译安装的，配置不在 `/etc/nginx`。

<a id="section-6"></a>

### 2.4 站点根目录的"可写"问题

这是服务器场景最核心的攻击面。Web 服务进程（`www-data` / `nginx` / `apache`）**必须能写站点目录**，否则无法接收上传——这是业务的硬需求，也是攻击者的入口：

```
任何一处上传/写入成功 → 写 .php 到站点目录（Web 进程对该目录可写且有执行权限）
   → HTTP 访问该文件，代码以 Web 服务账号执行
   → 该账号能读数据库配置（.env、config.php）→ 拿到库口令
   → 改配置把 WebShell 上传到任意站点 / 写 crontab（若有权限）→ 提权
```

**取证含义**：站点目录里出现的任何"非业务文件"都要单独解释（WebShell 不会自己写 README）。

权限组合要重点看。`755 root:root` 尚可，`777 www:www` 是重大风险信号；站点目录里有其他用户（如数据库账号）可写的子目录，则构成横向移动路径。

**PHP 禁用函数列表**是被篡改过的关键证据（`disable_functions` 被清空 = 有人在面板里改过它），见[第 05 篇](../server-web/server-web-nginx-apache.md)。

<a id="section-7"></a>

### 2.5 `/home` 与数据库层

`/home` 在服务器上的含义和 PC 不同。除运维账户 home（`.bash_history` 常有面板操作记录、`.ssh/authorized_keys` 是公钥植入位置）外，很多面板/环境的站点根本身也在这里。`/opt/`、`/usr/local/`、`/var/lib/tomcat/` 是应用实际部署位置，其中 `deploy.sh`、`.env`、`*.jar` 的 `mtime` 是判断"部署制品是否被动手脚"的锚点。

数据库层的工件决定案件最终能拿到什么数据。最重要的两个是 `general_log`（记录**所有**语句含 `SELECT`，默认关闭、体积巨大）与 binlog（默认开启、有天数上限、`ROW` 格式可还原每行改动的旧值/新值）。

拖库行为（`SELECT` 大量读取）在 binlog 与慢日志里的体现各有条件，须按陷阱 8 的三层判据确认。路径见下表（均在 `/var/lib/mysql/` 或 `/var/log/mysql/` 下，以实际环境为准）：

| 路径 | 内容 | 取证价值 |
|---|---|---|
| `mysql-bin.0000xx` | **binlog，含全部写操作** | ★★★★★ |
| `mysql.slow_query_log` | 慢查询（**批量导出数据的间接证据**） | ★★★★★ |
| `general_log` / `general_log_file` | 通用查询日志，含 `SELECT` | ★★★★★ |
| `error.log` | 错误日志 | ★★★★ |
| `show processlist` 导出 | **只能在线拿到**的当前活跃查询 | ★★★★★ |

---

<a id="section-8"></a>

## 三、操作步骤

<a id="section-9"></a>

### 3.1 第 0 步（现场在线时）：抢占式固定

**这一节只适用于服务器仍在运行的情况。** 顺序不可颠倒。

```bash
# 1) 记录时间基准与当前状态（先做，因为它几秒后就变）
date -u '+%Y-%m-%dT%H:%M:%SZ' | tee /evidence/collection-utc.txt
uptime; who -a; last -n 30
# 2) 当前网络连接与监听端口 —— 只存在于内存，抢时间价值最高
ss -tulpn | tee /evidence/netstat-live.txt
ss -tapn state established >> /evidence/netstat-live.txt
ps auxwwf | tee /evidence/ps-live.txt
# 3) 内存镜像（时间允许时优先做；LiME 需编译加载模块，AVML 静态可执行）
sudo ./avml /evidence/DigiForensics-mem.raw
sha256sum /evidence/DigiForensics-mem.raw | tee /evidence/mem.sha256
# 4) 关键日志定向复制（只 cp，不 mv、不 truncate）
mkdir -p /evidence/logs
for f in /var/log/nginx/*.log /www/wwwlogs/*.log /var/log/auth.log \
         /var/log/secure /www/server/panel/logs/*.log; do
  [ -f "$f" ] && cp -p --preserve=timestamps "$f" /evidence/logs/ 2>/dev/null
done
# 5) 面板数据与站点配置（数据库可能正在被写，需尽快复制）
cp -p  /www/server/panel/data/default.db /evidence/ 2>/dev/null
cp -rp /www/server/panel/data/db/       /evidence/bt-db/   2>/dev/null
cp -rp /www/server/panel/vhost/         /evidence/bt-vhost/ 2>/dev/null
cp -p  /www/server/panel/data/div.pl     /evidence/ 2>/dev/null
```

> ⚠️ **不要 `mv` 日志文件。** 移动会导致服务继续写入被移走的 inode（对已打开的 fd 而言），在原目录留下 `.1` 空壳，而你手上的文件是"活"的、还在被写的，内容不可复现。**`cp` 是唯一正确动作。**

<a id="section-10"></a>

### 3.2 第 1 步：只读接入与身份确认

```bash
grep -E '^(NAME|VERSION_ID)=' /mnt/df/etc/os-release
for d in /www/server/panel /opt/1panel /etc/webmin /www/wwwroot /var/www; do
  [ -d "/mnt/df$d" ] && echo "存在  $d" || echo "缺失  $d"
done
ls -d /mnt/df/www/server/nginx /mnt/df/etc/nginx /mnt/df/etc/httpd 2>/dev/null
```

<a id="section-11"></a>

### 3.3 第 2 步：优先级排序 —— "先看什么"

这是本篇最需要记住的清单。**顺序即价值密度**，前面的步骤能独立形成结论，后面的用于补全。

| 优先级 | 目标 | 具体动作 | 为什么排这个位置 |
|---|---|---|---|
| **1** | **网站目录** | 列 `/www/wwwroot` 全部站点；找非业务文件、异常 mtime、异常权限 | **唯一直接指向"已被入侵"的物证**，且不会被日志轮转冲掉 |
| **2** | **访问日志** | 分析 access.log 的可疑请求（见[第 07 篇](../server-web/server-web-webshell-traffic-patterns.md)） | 唯一能回答"什么时候、被怎么打进来的" |
| **3** | **计划任务 / 持久化** | crontab、`/etc/cron.d`、`systemd` 自定义 unit | 攻击者必留，清理成本高 |
| **4** | **账户与 SSH** | `passwd`、`shadow`、`authorized_keys`、`auth.log` | 回答"用什么身份进来" |
| **5** | **面板** | 面板日志、面板数据库、入口与口令（见[第 02 篇](server-panel-bt-panel-forensics.md)） | 面板常是最初入口，也可能被合法账号复用 |
| **6** | **命令历史** | `.bash_history`、`.zsh_history` | 极可能被清空，价值靠后但补充细节 |

```bash
# 优先级 1：网站目录总览（先看结构，不深入）
ls -la /mnt/df/www/wwwroot/
# drwxr-xr-x 1 www www  4096 2024-03-18 digiforensics-site   ← 唯一站点
# drwxr-xr-x 1 root root 4096 2022-06-01 default            ← 宝塔默认页
find /mnt/df/www/wwwroot -maxdepth 2 -type d -printf '%TY-%Tm-%Td %m %u:%g  %p\
' | sort

# 优先级 2：日志存在性与时间跨度（决定报告能写"覆盖 X 至 Y 时段"，超出范围不能下否定结论）
ls -l --time-style=long-iso /mnt/df/www/wwwlogs/ /mnt/df/var/log/nginx/ 2>/dev/null
```

<a id="section-12"></a>

### 3.4 第 3 步：定位可疑时间窗

优先级 1 和 2 都要用时间窗收敛：先找异常，再锚定时间。

```bash
# 1) 最近被改动的文件（Top 50）——锁定入侵时间区间
find /mnt/df/www/wwwroot -type f -printf '%T@ %TY-%Tm-%Td %TH:%TM %m %u:%g %s  %p\
' \
  | sort -n | tail -50
# 2) 站点目录自身的 mtime 变化 = 期间有文件增删（目录项变化会改目录 mtime）
stat -c '%n  mtime=%y  ctime=%z' /mnt/df/www/wwwroot/digiforensics-site/
# 3) 拿可疑文件的 mtime 去切访问日志 —— 发现 WebShell 使用记录的最短路径
stat -c '%y' /mnt/df/www/wwwroot/digiforensics-site/uploads/img/avatar.jpg
# 2024-03-17 22:48:14.000000000 +0800
grep 'avatar\.jpg' /mnt/df/www/wwwlogs/digiforensics-site.log.1 | head -20
```

| 时间关系 | 推断 | 强度 |
|---|---|---|
| access.log 中该文件**首次出现**的时间 ≈ 文件 mtime | 上传/写入后立即被访问 | 强（双源印证） |
| 文件 mtime **早于**任何一条访问记录 | 文件被写入但从未通过 HTTP 触发 | 中（可能通过 CLI/计划任务使用） |
| 文件 mtime **远晚于**站点建立时间且无业务解释 | 可疑写入 | 中（需结合内容判断） |
| 目录 mtime 与内部文件 mtime 相差很大 | 期间有文件增删 | 强 |

<a id="section-13"></a>

### 3.5 第 4 步：验证与记录

```bash
# 每一条"发现"都必须固定为独立证据（证据固定规范详见第 06 篇）
cp --preserve=all /mnt/df/www/wwwroot/digiforensics-site/uploads/img/avatar.jpg /evidence/
sha256sum /evidence/* | tee -a /evidence/hashes.txt
# 整站清单（否定结论需要全集支撑：证明"没有其他可疑文件"）
find /mnt/df/www/wwwroot -printf '%y %m %u:%g %s %TY-%Tm-%Td %TH:%TM  %p\
' \
  | sort -k7 > /evidence/site-manifest.txt
umount /mnt/df && sha256sum -c /evidence/evidence.sha256   # 证明分析过程未污染证据
```

---
<a id="section-14"></a>

## 四、常见陷阱

服务器取证的误判多数源于**一个默认假设：证据还在，而且完整**。

本章的三个来源依次是——① 位置找错（宝塔的路径和源包完全不同）；② 存在性推断（日志文件在 ≠ 那段时间的记录在）；③ 在活系统上做了会改写证据的动作。

本章按「处置时机 → 路径与环境 → 结论与边界」三段归组。

<a id="section-15"></a>

### 4.1 处置时机：先做什么才不毁证据

<a id="section-16"></a>

#### 陷阱 1：★ 先关机再取证

**现象**：到达现场发现服务器还开着，第一反应是「关机保护数据」，或者直接拔电源，然后接硬盘做镜像。

**原因**：关机**不会**冻结磁盘上的证据，但它会销毁三类只存在于运行态的东西。

① **内存**——正在运行的进程、已加载的模块、解密后的口令、内存中解出的 WebShell 内容、密钥。

② **`/tmp` 若为 tmpfs**——重启后内容全部消失，而很多工具把分片、暂存文件放这里。

③ **未落盘的数据**——journald 若未持久化、`utmp`/`wtmp` 重启后重写、页面缓存中尚未刷盘的日志尾部。

案例里运维已经重启过一次 Nginx，那次重启本身就是一个证据损失点。

**影响**：**这属于不可逆操作，且损失的是最难重建的一类证据。** 内存里往往存着明文的数据库口令、已经解密但只在内存的凭据、以及 WebShell 的真实执行链；这些在磁盘镜像里往往找不到。

**核查**：**先固定后隔离，先隔离后停服。**

顺序是：① 记录时间基准 → ② `ss`/`ps` 抓当前连接与进程 → ③ 内存镜像（AVML 静态可直接跑，LiME 需加载模块）→ ④ 关键日志与面板数据 `cp` 定向复制 → ⑤ 网络层隔离（防火墙断网，**保留一条 SSH 通道**）→ ⑥ 是否停服**由委托方书面决定**，因为停服会中断业务。

**网络隔离不等于关机**，「关机最安全」在这里是反的。

<a id="section-17"></a>

#### 陷阱 2：★ 在活系统上直接做全盘 `dd`

**现象**：为了尽快固定，直接 `dd if=/dev/sda of=/work/DigiForensics.dd` 一把梭。

**原因**：源盘还在被服务写入，**镜像内部不自洽**——文件系统元数据（inode 位图、目录块）来自某一时刻，数据块来自另一时刻，损坏时可能根本挂不上。

更实际的问题是**耗时**。百 GB 磁盘 dd 的时长远超日志轮转周期，**你在 dd 的过程中，日志正好被覆盖了一轮**。

**影响**：拿到一个可能挂不上的镜像，还搭进去了本该保住的日志窗口——两头落空。

**核查**：先做小体积、高价值的定向固定（日志、面板库、站点清单），再做镜像。

云主机优先用**存储层快照**（秒级、对源卷几乎无写入影响，事后基于快照起分析机）。物理机且必须 dd 时，在活系统上做只读 raw 镜像 + 接受文件系统层面的不一致风险，并同时用 `e2fsck -fn` 类只读检查评估一致性；条件允许时尽量缩小源分区范围而不是整盘。

<a id="section-18"></a>

#### 陷阱 3：`mv` 日志文件「腾地方」

**现象**：`/var/log` 满了（或想把日志挪到分析机），用 `mv` 把 `access.log` 移到别处。

**原因**：Nginx 的 worker **持有该文件的打开句柄**。`mv` 只改目录项，不改 inode——服务会继续写那个已经被移走的 inode，在原目录留下一个 0 字节或极小的 `.1` 空壳，而你手上那份文件是「活的」、内容还在变，**哈希算出来也复现不了**。

`mv` 跨文件系统时还会变成 copy+delete，反而更慢。

**影响**：**既没有得到稳定副本，又污染了原始目录。** 更糟的是你无法说明复制时点到底包含哪些内容，证据的完整性论证从此站不住。

**核查**：**永远用 `cp`**，且加 `-p`（`--preserve=timestamps`）保留时间戳。案例里用 `cp -p --preserve=timestamps` 是标准动作。

**在线系统的日志副本只能视为「某时刻的快照」**，写入期间无法保证一致性，这一点要写进报告；需要严格一致的全集时用存储快照。

<a id="section-19"></a>

#### 陷阱 4：分析员自己 `truncate` 或清空日志「配合排查」

**现象**：为了「干净地重跑一遍」，把某站点 access.log 清空或截断；或轮转配置里 `copytruncate` 造成的空洞被误当成删除痕迹。

**原因**：`truncate -s 0` 在服务器取证里是**教科书级的攻击者行为**——第五章里网站被篡改的案子，攻击者清日志正是关键证据。分析员自己做同样的事，**破坏形态与攻击行为完全一致**，事后无法区分。

**影响**：**销毁证据的动作被记录成了入侵的证据之一**，时间线被污染，报告的可信度受损。

**核查**：**取证机绝不清空、截断、重命名、移动任何目标机文件**，包括「看着可疑的日志」。需要验证某个行为时，在**镜像**上或分析机上做。

另外要知道一个合法成因：`copytruncate` 轮转方式会先复制后清空，**两次动作之间写入的少量记录会丢**。

所以 `.log` 突然变 0 字节、而 `.log.1` 完整，可能是**轮转策略导致而非清日志**。两种成因必须靠时间线与其它证据区分，不能只凭「0 字节」定性。

<a id="section-20"></a>

### 4.2 路径与环境：找错位置比找不到更糟

<a id="section-21"></a>

#### 陷阱 5：只查 `/etc/nginx` 就下「无访问日志」结论

**现象**：`/var/log/nginx/` 里什么都没有，于是报告写「该服务器无 Web 访问日志，无法还原攻击时间线」。

**原因**：**宝塔面板是自编译安装 everything 的**——Nginx 在 `/www/server/nginx/`、配置在 `/www/server/nginx/conf/`、站点配置在 `/www/server/panel/vhost/`、日志在 `/www/wwwlogs/`（**不是** `/var/log/nginx`）。

而源包安装的才在 `/etc/nginx` 和 `/var/log/nginx`。两套路径互不通用，**「目录为空」完全可能只是找错了地方**。

**影响**：**把「找错位置」写成「不存在」**，这是一个方向性错误——它会让人放弃时间线分析，而访问日志恰恰是唯一能回答「什么时候、被怎么打进来的」的证据。第五章的整条时间线都建立在 `/www/wwwlogs/` 上。

**核查**：**先做环境识别，再决定查哪套路径。**

判断依据不是「装没装宝塔」，而是**路径是否实际存在**：`ls -d /www/server/panel /www/server/nginx /etc/nginx /etc/httpd`，看 `/www/wwwroot` 是否存在（面板环境强特征）。`/www/wwwlogs/` 里文件名带站点域名（`digiforensics-site.log`）是宝塔的典型形态。

**三处都查一遍再谈「有没有」。**

<a id="section-22"></a>

#### 陷阱 6：漏掉 `/www/backup/`

**现象**：只查了站点目录、面板库、访问日志，报告里没有提自动备份目录。

**原因**：宝塔**每天自动备份站点与数据库**到 `/www/backup/`，这个目录在勒索与篡改案件里价值极高。

它可能包含**被加密前的原始数据**，可作为篡改的对照基线；也可能是攻击者已污染的副本（他完全可能同步替换备份）。它是**每天自动生成、不在站点目录清单里**的一个独立工件，天然容易被跳过。

**影响**：**唯一的对照基线丢失**。判断「首页被改成了什么」若只有被改后的版本，没有备份版本，篡改内容的还原度就受限；同时可能把一份含完整凭据的数据库备份落在报告范围之外而不登记。

**核查**：单独清点 `/www/backup/` 并与站点现状逐项比对——文件名、mtime、大小三项对上但内容变了，就是明确的篡改点。

备份里的数据库 dump 同样含明文口令，按凭据处理，不进证据目录明文存放，报告里只登记路径、时间与哈希。

<a id="section-23"></a>

#### 陷阱 7：忽略 `/www/server/panel/` 这一层的证据

**现象**：把面板当「运维工具」跳过，只看业务目录和 Web 日志。

**原因**：面板自身的三类工件在时间上经常**早于** WebShell 落地，是入口证据。

① `/www/server/panel/logs/`（`request.log` 记录面板登录与操作）——案例里面板成功登录时间比 WebShell 落地早 7 分钟，**这条时间差直接定性了入侵路径是「先拿面板」**。

② `/www/server/panel/data/default.db` 与 `data/db/`（面板库，记录账户、站点、操作记录）。

③ 面板**操作日志里的文件管理动作**（上传、编辑、重命名、保存）。

Web 日志里有攻击流量但面板日志里找不到对应的人操作，说明攻击者绕过面板走的是别的路——这个反差本身就是结论。

**影响**：**丢掉了最关键的入口定性证据。** 攻击者拿到的可能不是 Web 层漏洞而是**一个 Web 口令**，两条路径的整改措施完全不同（改 PHP vs 改面板口令 + 改安全入口）。案例中面板 8888 端口被外网连接，仅靠 Web 目录是发现不了这个入口的。

**核查**：**按 3.3 的优先级 5 单独处理面板层**：`request.log` 里的登录与操作记录、`default.db` 与 `data/db/`、`/www/server/panel/vhost/` 里的站点配置。

**面板访问日志与 Web 访问日志必须做时间轴对齐**——同一 IP 在两侧都出现且时间紧邻，是交叉印证；只在一侧出现，指向不同的入侵路径。

<a id="section-24"></a>

#### 陷阱 8：数据库层只看 binlog，漏掉 `general_log` 与慢日志

**现象**：只检查 `mysql-bin.0000xx`，没看慢查询日志和通用查询日志，就对「是否发生拖库」下结论。

**原因**：三个日志的能力不同，缺一不可。

binlog 默认开启、按 `expire_logs_days`（默认 10 天）自动删除——它最能还原每行改动的旧值/新值，但**过期就没了**。

**慢查询日志**（`long_query_time` 触发）会捕捉**单条耗时很长的全表 `SELECT`**，这正是批量导出的典型特征，但它默认可能未开启。

`general_log` 记录所有语句含 `SELECT`——证据最全，但**默认关闭**且体积巨大，通常只能从配置或残留文件确认它开过。

`ROW` 格式 binlog 能还原旧值，`STATEMENT` 只能看到语句。

**影响**：binlog 已过期时，唯一还可能留着拖库痕迹的就是慢日志（如果开过）。漏查它会把「证据已过期」误判成「没有拖库」。

**核查**：**先查配置确认每一层是否开过**（`slow_query_log`、`general_log`、`log_bin`、`binlog_format`、`expire_logs_days`），再决定去哪个文件里找。

「没开过」是取证局限，要写进报告；「开过但文件没了」是覆盖事实，两者结论强度不同。 另外 `show processlist` 的导出**只能在线拿到**，服务器关了就永远没了。

<a id="section-25"></a>

### 4.3 时间戳与结论边界

<a id="section-26"></a>

#### 陷阱 9：★ 用 `find -mtime` 判断「近期无异常」

**现象**：`find /www/wwwroot -mtime -7` 没有可疑输出，报告写「近 7 天站点目录内无异常文件」。

**原因**：**mtime 可以被任意设置**——`touch -d` 就能把时间改到任意过去时刻。`find -mtime` 的语义是「mtime 在 N 天内被修改过」，**它读的是文件头里那个可伪造的字段**。

而且 `find` 的输出是「最近修改的 N 个」，样本量极小；再叠加 mtime 早于入侵时间，文件就直接**掉出这个窗口**，看起来像「没有问题」。

**影响**：一个被 `touch` 过的文件完全可以在 `-mtime -7` 里消失，「无异常」的结论是空的。这类结论一旦被对方用 `stat` 反查就崩了。

**核查**：**以 `ctime` 交叉验证**。

ext4 的 `ctime`（inode 变更时间）**不可通过任何常规命令回溯修改**——它只能随 inode 实际变更（内容改、权限改、属主改、链接数变）而更新，因此是判断「近期是否被动过」的可靠锚点。

同时看 `mtime` 与 `ctime` 的**差值**：`ctime` 远新于 `mtime` 说明文件内容被改后又动过时间戳，属于明确的反取证信号（详见[《反取证手法与时间戳篡改检测》](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md)）。

<a id="section-27"></a>

#### 陷阱 10：登录记录为空就写「无异常登录」

**现象**：`last` 输出很少或为空，报告写「未发现异常登录」。

**原因**：三种截然不同的成因在 `last` 眼里长得一样。

① `utmp`/`wtmp`/`btmp` 被清空或截断——这是攻击者的标准清理动作。

② **该主机长时间无人通过交互式登录**（托管的网站服务器很常见），本来就没什么记录。

③ `lastlog`/`wtmp` 在关机时被重写或文件本身已被轮转清理。

`wtmp` 记录的是**交互式登录**，而面板登录、数据库口令爆破、SSH 密钥登录在别处——**面板登录根本不进 wtmp**（案例里的面板登录只在 `request.log` 里）。

**影响**：**把取证材料的缺失当成阴性发现**。委托方会据此排除「凭据泄露/横向移动」这一整条线，而攻击者可能正是用一次未被 wtmp 记录的面板登录进来的。

**核查**：**报告写法是「数据 + 事实」**：「`/var/log/wtmp` 最后一条记录为 `<时间>`，`<用户>`，来源 `<IP>`；该文件大小与 mtime 为 X，**无法覆盖 Y 时段**」。

**并且要说明记录为空本身是一个需要解释的现象**——如果一台对外提供服务的服务器 wtmp 是空的，那是异常信号而不是无害。

同时把面板登录记录（`request.log`）与 `auth.log`/SSH 日志一并纳入，**不要用单一来源否定登录行为**。

<a id="section-28"></a>

#### 陷阱 11：只看站点目录权限，不看「异常组合」

**现象**：看到 `/www/wwwroot/site` 是 `www:www` 755，报告写「站点目录权限异常，存在 WebShell 风险」。

**原因**：**站点目录对 Web 用户可写是业务硬需求**——Web 进程必须能写才能接收上传，`www:www` 755 是宝塔的标准形态，把它当异常是把正常配置当风险。

反过来，**只看不写也漏**：`777`、属主是数据库账号、站点目录内出现其他 uid 可写的子目录，才是真正的风险信号。

**影响**：**虚警**会稀释整份报告的可信度；漏看异常组合则漏掉真实的横向移动路径。

**核查**：**判据是「异常组合」而不是单个权限位**。

重点看三处：① 世界可写（`find -perm -0002`）；② **异常属主**（`find ! -user www`）——尤其是属主为数据库账号的目录，意味着一旦拿到数据库低权凭据就能直接写站点；③ 站点目录里是否出现了本不属于任何业务线的目录。

**权限是攻击面，不是攻击证据**——真正定性入侵靠的是非业务文件的内容与时间线，不是权限位。

<a id="section-29"></a>

#### 陷阱 12：把「未发现」写成无边界的否定结论

**现象**：报告写「未发现 WebShell」「未发现挖矿行为」「未发现异常」，然后全文没提日志只覆盖了 14 天。

**原因**：服务器取证的阴性发现**几乎必然是不完整的**，因为覆盖面被三重因素压缩。

① **时间**——logrotate 保留 N 份、binlog `expire_logs_days` 到期、journald `SystemMaxUse` 满后**丢弃最旧的日志**（不是停止写入），这些都无声地发生。

② **位置**——三套 Web 环境路径只查一套就下结论。

③ **状态**——日志可能已被清空，而清空本身就是攻击行为。

**「未发现」是这三者的函数，不是事实。**

**影响**：**阴性发现的强度被凭空抬高。** 委托方据此排除攻击者存在，停止排查、关闭日志、复机运行——真实攻击者可能只是被轮转冲掉了。

**核查**：阴性发现的写法必须是「范围 + 结论 + 未覆盖」三段式，例如：「在 `/www/wwwroot/digiforensics-site`（共 N 个文件，已生成完整清单存档）内按扩展名、文件头魔数、mtime 异常三项检查，**未发现**可执行 PHP 后门；**未覆盖**：`/www/backup/` 中的历史副本、已删除文件的 ext4 未分配区、页面缓存与内存、其余 6 个站点目录。」

**并且要单独写一节说明日志覆盖边界**（案例里「日志最早只到 2024-03-05」就是这么处理的）。

**发现覆盖本身就是结论**——它说明有人或某个机制动过日志，必须写，不能只写「未发现相关记录」。

<a id="section-30"></a>

### 4.4 时间基准与换算

<a id="section-31"></a>

#### 陷阱 13：把分析机的时区当成目标机的时区

**现象**：在分析机上只读挂载镜像后 `ls -l` 站点目录、看面板库文件的修改时间，直接与委托方提供的时间、或与 `request.log` 里的时间相减，算出「面板登录后 3 小时 WebShell 才落地」。

**原因**：ext4 里的时间戳、站点 `access.log`、面板 `request.log` **都不带时区标记**——`2024-03-17 22:41:03` 这种形式的语义是**目标机当时的本地时间**。

而取证分析机的时区由分析人员自己的机器决定，与目标机无关。

更要命的是**同一次采集里就并存两个基准**：本篇案例第 1 步的 `date -u` 采到 `2024-03-18T02:14:07Z`，而同一次输出的 `uptime` 另给一个墙上时钟；到第 2 步 `stat` 读出的站点文件时间又明确带 `+0800`，第 4 步 Nginx 日志同样带 `+0800`。

只有 `+0800` 这类带偏移的输出是自证的，不带标记的必须靠它反推目标机时区。

**影响**：整段时间线发生固定偏移，且**没有任何报错**。

最致命的是方向性：偏移可能刚好让「面板登录早于 WebShell 落地」这个**定性用的时间差**变成负值，报告就会得出「面板与站点篡改是两条无关的线」——与真相完全相反的结论，而它的推导过程看起来完全正常。

**核查**：**时间基准要和哈希一样作为采集元数据单独登记**，不能靠事后回忆。

第一步固定时就同时记录 UTC 时刻（`date -u`）与时区状态（`timedatectl`，并固定 `/etc/localtime` 与 `/etc/timezone` 两个文件），写进采集记录。

第二步，**全案统一到一个基准**渲染（建议 UTC），入库时为每条时间打时区标签，表格并列「原始值 + 时区」与「UTC 换算值」两列。

第三步，跨来源做减法前先确认基准一致——本章 3.3 采集块里 `date -u` 与 `uptime` 同屏出现的情形尤其危险，`uptime` 那个墙上时钟既不是 UTC 也没带标记，它的基准只能由 `timedatectl` 确定，不能凭它做换算。

<a id="section-32"></a>

## 五、案例示例

<a id="section-33"></a>

### 5.1 从活连接锁定攻击源并建立三重时间锚点

**场景**

委托方（某公司法务）报告其电商站点 `digiforensics.example.com` 首页被篡改为博彩广告，后台无法登录。现场为云主机，**系统仍在运行**，运维已重启过一次 Nginx。镜像 `DigiForensics.dd`（raw，100 GB），ext4 分区起始扇区 1181696。

这条路径值得先走，是因为**"活连接"是唯一能在一分钟内定住攻击源的材料**。

磁盘上的日志要翻几 GB 才有结论，而 `ss` 快照一次就把"哪个 IP 正在连"这个问题解决了——后面所有的文件与日志分析，都靠这个 IP 作为检索键。

没有它，就是在几千万行日志里大海捞针。

**处置过程**

**第 1 步 · 判断紧迫性并做抢占式固定**

```bash
date -u '+%Y-%m-%dT%H:%M:%SZ'; uptime
# 2024-03-18T02:14:07Z
# 14:13:31 up 96 days, 2 users, load average: 0.08   → 已连续运行 96 天，日志有完整轮转链
sudo ./avml /evidence/DigiForensics-mem.raw
ss -tulpn > /evidence/netstat-live.txt
ps auxwwf > /evidence/ps-live.txt
```

`ss` 输出里出现两条值得注意的连接：

```
tcp   LISTEN  0  511  0.0.0.0:8888    0.0.0.0:*  users:(("BT-Panel",pid=1284,fd=6))
tcp   ESTAB   0  0     203.0.113.77:51820   198.51.100.24:8888  users:(("python3",pid=2917,fd=9))
#                                                          ↑ 非常规来源 IP 正在连面板 8888
```

**这是本案的第一个发现**：一台 Python 进程正与外网 IP 保持到面板端口的连接。

注意 `users:(("python3",...))` 这个字段——**发起方是本机进程，不是外部客户端**；`198.51.100.24:8888` 是它连接的**目标**（即本机面板）。这一点方向性必须搞清楚，见误判对照。

**第 2 步 · 确认环境与日志边界**

```bash
ls -d /mnt/df/www/server/panel && echo "宝塔面板环境"
grep -E '^(NAME|VERSION_ID)' /mnt/df/etc/os-release     # NAME="Ubuntu" VERSION_ID="20.04"
ls -l --time-style=long-iso /mnt/df/www/wwwlogs/
# digiforensics-site.log 48291033 2024-03-18
# digiforensics-site.log.1 46120384 2024-03-17
# ...（共 14 份，最早为 2024-03-05）
```

**结论边界写死**：可分析时段 = **2024-03-05 至 2024-03-18**。更早的入侵行为无法从这个证据集判断，报告必须如此表述。

**第 3 步 · 优先级 1：网站目录**

```bash
find /mnt/df/www/wwwroot -type f -printf '%T@ %TY-%Tm-%Td %TH:%TM %m %u:%g %s  %p\
' \
  | sort -n | tail -12
# ...
# 2024-03-16 03:11:07  644 www:www  1194   .../public/index.php
# 2024-03-17 22:47:59  644 www:www   428   .../storage/.user.ini        ★ 异常
# 2024-03-17 22:48:14  644 www:www  17623  .../uploads/img/avatar.jpg  ★ 异常（见下）
# 2024-03-18 01:02:33  644 www:www  29041  .../public/index.php         ★ 首页被改
```

目录层级与建站日 2022-09-14 一致、无新增目录——但这只说明没新增目录，WebShell 根本不需要。

文件层三条异常记录集中在 2024-03-17 22:47～22:48 的 65 秒内，这就是本案的时间锚点。

第 4 步 · 用时间窗切访问日志（以 5.1 开头确定的 IP 为检索键）

```bash
grep -nE 'avatar\.jpg|\.user\.ini' /mnt/df/www/wwwlogs/digiforensics-site.log.1 | head
```

```
198.51.100.24 - - [17/Mar/2024:22:48:03 +0800] "POST /uploads/img/avatar.jpg HTTP/1.1" 200 4123 "-" "python-requests/2.31.0" "-" "-"
198.51.100.24 - - [17/Mar/2024:22:48:11 +0800] "POST /storage/.user.ini HTTP/1.1" 404 153 "-" "python-requests/2.31.0" "-" "-"
198.51.100.24 - - [17/Mar/2024:22:48:14 +0800] "GET /uploads/img/avatar.jpg HTTP/1.1" 200 17623 "http://digiforensics.example.com/" "python-requests/2.31.0" "-" "-"
198.51.100.24 - - [17/Mar/2024:23:02:41 +0800] "POST /uploads/img/avatar.jpg HTTP/1.1" 200 4210 "-" "python-requests/2.31.0" "-" "-"
```

**双源印证完成**：

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| `198.51.100.24` 是攻击源 IP | 内存 `ss` 捕获的活连接 + 访问日志多条记录，两源一致 | 强 |
| 2024-03-17 22:48:14 落地 WebShell | 文件 `mtime` 与日志首次 POST 时间**完全一致** | 强 |
| 该 IP 用脚本而非浏览器 | UA 为 `python-requests`，且**无 Referer** | 强 |
| 该 IP 的活动**至少持续到采集时刻 03-18 02:14** | `ss` 活连接 + 日志 23:02 的 POST | 强 |
| 该 IP 在 2024-03-05 之前无活动 | 日志最早只到 03-05 | **不成立——见误判对照** |

第 5 步 · 优先级 5：面板反查身份并固定证据

`request.log` 中该 IP 的一次**成功登录**时间为 **2024-03-17 22:41:07**——比 WebShell 落地早 7 分钟。结论指向：先拿下宝塔面板，通过面板文件管理上传 WebShell，随后篡改首页。完整面板证据链见[第 02 篇](server-panel-bt-panel-forensics.md)。

```bash
cp --preserve=all /mnt/df/www/wwwroot/digiforensics-site/uploads/img/avatar.jpg /evidence/
cp --preserve=all /mnt/df/www/wwwroot/digiforensics-site/storage/.user.ini   /evidence/
cp --preserve=all /mnt/df/www/wwwroot/digiforensics-site/public/index.php    /evidence/index-tampered.php
cp -p /mnt/df/www/wwwlogs/digiforensics-site.log.1 /evidence/
sha256sum /evidence/* | tee /evidence/hashes.txt
umount /mnt/df && sha256sum -c /evidence/evidence.sha256   # OK —— 分析未污染证据
```

**结论**

- 攻击链的时间顺序已闭合：22:41:07 面板登录成功 → 22:47:59 / 22:48:14 文件落地 → 01:02:33 首页篡改。三个时刻分别有面板日志、访问日志+文件 mtime、文件 mtime 独立支撑。
- 可分析时段 **2024-03-05 至 2024-03-18**，共 14 份轮转日志。
- 证据固定完成，`sha256sum -c` 校验通过。

**误判对照**

这个案例最容易出的错有两条，第一条几乎发生在每一次现场。

1. 把 `ss` 里的 `198.51.100.24` 当成"攻击者的 IP"写进报告。 这条连接的 `users:(("python3",pid=2917,fd=9))` 说明它是**本机进程**发起的，`198.51.100.24:8888` 是**连接目标**——**本机自己的面板地址**（本机内网地址恰好是 `198.51.100.24`）。

   判据：Nginx/PHP 站点的 `ss` 输出里，`users:` 后面有进程名且该进程属于本机，则这条是**出站连接**，方向是"本机 → 某处"，不是"某处 → 本机"。

   本案真正的攻击源 IP 来自访问日志的 `$remote_addr` 字段，两者是不同的证据面，不能混用。 若把本机 IP 写成攻击者 IP，报告会出现"攻击源 IP 与受害主机 IP 相同"这种自相矛盾，交付方专业性当场受损。

2. 把"日志最早只到 2024-03-05"读成"03-05 之前是干净的"。判据：轮转日志的**缺失**与**不存在活动**是两件事。轮转策略可能是按天 14 份保留（约 14 天），也可能是按容量截断，**原因未确认前不能反推更早时段**。

   正确表述是「在 2024-03-05 至 2024-03-18 共 14 份访问日志范围内，未发现 `198.51.100.24` 的其他活动」+ 列出未覆盖范围（更早日志、`/var/log/nginx/error.log` 的更早轮转、其他站点日志、面板自身日志的轮转策略）。

3. **判据**：`avatar.jpg` 的 `mtime`（22:48:14）与日志 GET 时间（22:48:14）一致，**只能证明"该时刻文件被写入过"**，不能证明"攻击者写入了它"。判别要靠**内容分析**（尾部 PHP 代码，详见 [第 06 篇](../server-web/server-web-webshell-detection.md)）与**权限/属主**（`www:www` 644 与站点其他文件一致，说明写入者是 Web 进程或以 www 身份写入）。

   **时间一致是必要条件，不是充分条件**——`cp -p` 或 `touch -d` 都能制造假的一致。

**按错误判据走的代价**：第 1 条踩中，报告会把本机内网地址列为攻击者，委托方拿着这个 IP 去追责或对外披露，**会指向自己的服务器**。

第 2 条踩中，委托方会把 03-05 之前排除出调查范围，而本案已知 22:41 就有了面板登录——如果真实入口更早（比如被删除的账号、遗留的备份文件），真凶会落在"已排除区间"。

第 3 条踩中则会让一个"时间巧合"被当成"落地证据"，一旦后续证明该文件由正常上传流程写入，整条攻击链的时间锚点就失守了。

<a id="section-34"></a>

### 5.2 伪装文件与 .user.ini 自动执行链的识别

**场景**

承接 5.1。委托方在看到时间线后问："`avatar.jpg` 是用户上传的头像吗？`.user.ini` 又是什么？为什么日志里 POST 它返回 404？"

三个问题指向同一件事：**这两个文件都不是正常业务产物**，但识别它们的判据完全不同——一个靠结构，一个靠 PHP 机制。

**处置过程**

第 1 步 · `avatar.jpg`：头部合法不代表整体合法

```bash
file /mnt/df/www/wwwroot/digiforensics-site/uploads/img/avatar.jpg
# JPEG image data, JFIF standard 1.01, 440x440, components 3   ← file 认为它是图片

# 定位 JPEG 结束标记 FFD9，看它后面还挂了多少
python3 - <<'PY'
p='/mnt/df/www/wwwroot/digiforensics-site/uploads/img/avatar.jpg'
d=open(p,'rb').read()
i=d.rfind(b'\xff\xd9')
print('size',len(d),'last FFD9 at',i,'trailing bytes',len(d)-i-2)
print('trailing sample:', d[i+2:i+70])
PY
# size 17623 last FFD9 at 4211 trailing bytes 13410     ← ★ 图像只占前 4.2 KB，后面挂了 13 KB
```

`file` 只看文件头的 JFIF 魔数，任何在合法 JPEG 后追加数据的文件都会通过它的检查。这是"伪装成立"的根本原因，也是判别的关键点。

第 2 步 · 与同目录正常图片做对比（没有对照就没有判据）

```bash
for f in /mnt/df/www/wwwroot/digiforensics-site/uploads/img/*.jpg; do
  python3 -c "
import sys;d=open(sys.argv[1],'rb').read();i=d.rfind(b'\xff\xd9')
print('%-24s size=%-7d trailing=%d'%(sys.argv[1].split('/')[-1],len(d),len(d)-i-2))" "$f"
done
# default_avatar.jpg    size=2841     trailing=0        ← 正常
# company_logo.jpg      size=15730    trailing=0        ← 正常
# avatar.jpg            size=17623    trailing=13410    ← ★
```

**判别力表**：

| 检查项 | 正常 JPEG | `avatar.jpg` | 判别力 |
|---|---|---|---|
| `file` 判定 | JPEG image data | JPEG image data | **无判别力**（只看魔数） |
| 最后一个 `FFD9` 的位置 | 文件末尾，trailing = 0 | 第 4211 字节，trailing = **13410** | **强** |
| trailing 起止是否闭合 | 无尾随数据 | 存在未闭合的 `<?php` / `?>` | **强** |
| 同目录横向对比 | 全部 trailing=0 | 唯一例外 | **强（统计性）** |

第 3 步 · `.user.ini`：一个不需要"新文件"的自包含执行链

```bash
cat /mnt/df/www/wwwroot/digiforensics-site/storage/.user.ini   # 只读查看，不执行
# auto_prepend_file=/www/wwwroot/digiforensics-site/storage/.user.ini
```

它的机制是 PHP-FPM 的 per-directory 配置：`.user.ini` 会被 PHP 自动读取（无需网站代码显式 include），`auto_prepend_file` 指向的路径在**每个 PHP 请求被处理前自动附加**。

而这里指向的路径**就是它自己**——**自包含，无需再投放任何其他文件**。

这个特性的取证价值在于：**它解释了为什么攻击者不需要新增目录或新增脚本**。

5.1 第 3 步"目录层级无新增"的观察，在这条机制下完全成立——WebShell 的载荷一直都在，只是被挂在了一个已有文件（`avatar.jpg`）的尾部。

**第 4 步 · 日志里那个 404 说明什么**

```
[17/Mar/2024:22:48:11] "POST /storage/.user.ini HTTP/1.1" 404 153
```

这是**攻击者自己的探测行为**，不是投递成功的记录：

1. `POST /uploads/img/avatar.jpg`（22:48:03）→ **200**，响应 4123 字节——**这一步是写入载荷**。
2. `POST /storage/.user.ini`（22:48:11）→ **404**——攻击者在**确认**这个路径是否已被 `.user.ini` 拦截或不可写。
3. `GET /uploads/img/avatar.jpg`（22:48:14）→ **200**，响应 **17623 字节 = 文件完整大小**——**验证写入成功**。

第 3 步的 200 且字节数等于磁盘上的文件大小，是**写入成功的直接确认**。中间那个 404 只是探测结果，不影响结论。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| `avatar.jpg` 是**尾部附加代码的伪装文件**，非正常图片 | 最后一个 `FFD9` 后有 13410 字节尾随数据；同目录 2 个正常图片 trailing 均为 0 | 强 |
| `avatar.jpg` 内含可执行 PHP 代码 | 尾随数据含 `<?php` / `?>` 配对标记 | 强（**本节不执行、不还原其逻辑，仅确认代码存在**） |
| `.user.ini` 构成**自包含的自动执行链** | `auto_prepend_file` 指向自身路径 | 强（机制可由 PHP 文档与实测共同确认） |
| WebShell 落地时间 22:48:14 | 文件 mtime + 日志 GET 字节数吻合 | 强 |
| 22:48:11 的 404 是**探测行为**，非投递失败 | 前后 200 记录与字节数构成完整序列 | 强 |

**本节只做识别，未做**：(a) 未在隔离环境执行该文件；(b) 未还原其完整功能逻辑；(c) 未确认该路径下是否还有同批次的其他伪装文件（这需要单独做一次全站结构扫描，见 [第 06 篇](../server-web/server-web-webshell-detection.md)）。

**误判对照**

最容易出的错是**把 `file` 的输出当结论**，以及**把 404 当投递失败从而推翻整个结论**。

1. **判据**：`file`、`xxd | head`、看魔数，**都只覆盖文件头部**。"头部合法 + 内容异常"这一类伪装（文档、图片、压缩包）全部逃逸。判别力必须来自**结构闭合性**（`FFD9`/`%%EOF` 是否在末尾）**加同目录横向对比**。单独看一个文件不构成结论，两个以上同类文件的一致性才构成基线。
2. **判据**：**404 不能推翻投递成功**。`POST /storage/.user.ini` 返回 404，只说明**这个请求本身**没成功；载荷是通过 `avatar.jpg` 投递的。判断投递成功要看 (a) 文件是否存在于磁盘、(b) 文件 mtime 是否对应、(c) 是否有一次**返回完整字节数**的读取。**本案三条齐备，与那个 404 无关。** 反过来说，若报告写"攻击者上传 .user.ini 失败，未部署"，那就与磁盘上确实存在的 `.user.ini` 直接矛盾了。
3. **判据**：`.user.ini` 不含可见的恶意代码，不代表它无害。它的危害在于**改变 PHP 解释器的行为**（让被指向的文件在每个请求前自动执行），**恶意代码在被指向的文件里**。凡出现 `auto_prepend_file`、`auto_append_file`、`include_path` 这几个 INI 指令，**一律按"执行链控制文件"处理并追查被指向路径**，不因文件本身内容无害而放过。
4. **判据**：本节**不能**证明这个伪装文件的代码被实际触发过。`auto_prepend_file` 生效需要 PHP 运行于 **CGI/FastCGI 模式**（`php.ini` 中 `fastcgi.` 前缀的配置在 FPM 下才生效）。判别依据是 `/mnt/df/www/server/php/*/etc/php.ini` 的 `;` 前缀注释状态与 Nginx 的 `fastcgi_pass` 配置。**本案该机制已确认生效**（由访问日志中 `avatar.jpg` 被当静态文件直接返回 200 这一点反证，见 5.3），但"机制生效"与"载荷已被执行过并产生外传"是两件事。

**按错误判据走的代价**：第 1 条踩中会漏掉站点上**其他**同类伪装文件——本案只查了一个文件名，若攻击者在 `uploads/` 下投放了 5 个伪装头像，只报 1 个，整改时只删 1 个，其余 4 个继续可用。这正是"结构扫描"必须覆盖全站而非抽查单个文件的原因。第 2 条踩中则会让委托方以为"上传失败了、应该没事"，**而磁盘上的 WebShell 一直存在**。

<a id="section-35"></a>

### 5.3 反例 首页篡改内容的取证与写入者身份不可得

**场景**

委托方是法务部门，最关心的问题有两个："首页的博彩广告是谁放上去的？"以及"能不能证明是那个 IP 干的？"

第一个问题可以回答，第二个问题在本案中**不能**。

归因时需说明证据来源及其能支持的结论范围。

**处置过程**

**第 1 步 · 固定并对比篡改前后的首页**

```bash
cp --preserve=all /mnt/df/www/wwwroot/digiforensics-site/public/index.php /evidence/index-tampered.php

# 结构与体积对比
wc -c /mnt/df/www/wwwroot/digiforensics-site/public/index.php
# 29041    ← 篡改后（3-16 时是 1194 字节）
head -12 /evidence/index-tampered.php
```

篡改方式很直接：把 1194 字节的原始入口文件**整体替换**为 29041 字节的新文件。这不是"注入片段"，是**替换**。

**第 2 步 · 篡改内容的性质认定**

```bash
# 提取外链域名（这是本页唯一需要委托方关注的信息）
grep -oE 'https?://[a-zA-Z0-9.-]+' /evidence/index-tampered.php | sort -u
# http://digiforensics-ads.example.net/
# http://198.51.100.24/panel/

grep -ciE 'iframe|<script' /evidence/index-tampered.php
# 3
```

页面被整体替换为包含 3 处外链（含一个 iframe）的博彩广告页，并同时携带 `http://198.51.100.24/panel/`——后者说明篡改者在页面里留了指向自己基础设施的引用。

第 3 步 · 写入者身份：能不能从 mtime 和属主推出来

```bash
stat /mnt/df/www/wwwroot/digiforensics-site/public/index.php
#   Modify: 2024-03-18 01:02:33.482901234 +0800
#   Change: 2024-03-18 01:02:33.482901234 +0800      ← 两者同秒 = 原地覆盖写，不是"新建+重命名"
# 权限: 644  属主: www  属组: www
```

`Change`（inode 变更时间）与 `Modify`（内容修改时间）**同秒**，说明是**原地覆写**。属主 `www` 与全站一致，这是 Web 进程（PHP-FPM 以 www 身份运行）写入的典型特征。

但这只能推到"**由 www 身份的进程写入**"这一步，再往后就不行了：

```bash
# 01:02:33 那一刻的访问日志
grep '18/Mar/2024:01:02' /mnt/df/www/wwwlogs/digiforensics-site.log
# 198.51.100.24 - - [18/Mar/2024:01:02:31 +0800] "POST /index.php HTTP/1.1" 200 29103 "..." "python-requests/2.31.0"
# 198.51.100.24 - - [18/Mar/2024:01:02:35 +0800] "GET / HTTP/1.1" 200 29103 "http://digiforensics.example.com/" "python-requests/2.31.0"
```

时间高度吻合（mtime 01:02:33 vs 日志 01:02:31），但**这里有一个必须说清的问题**：这一条 POST 是**从公网直接打到 `index.php` 的**。

而 `index.php` 被替换成 29 KB 的静态广告页——这说明能写入它的通道是面板文件管理或 WebShell，不是那个 POST（一个正常 PHP 文件不会因为一次 POST 请求就把自己整个换掉）。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 首页于 2024-03-18 01:02:33 被**整体替换**为 29041 字节的广告页 | mtime + `Change` 同秒 + 文件体积对比 | 强 |
| 篡改页含 3 处外链与 iframe，含 `http://198.51.100.24/panel/` | 页面内容提取 | 强 |
| 写入由 **www 身份的进程**完成 | 属主/属组 `www:www` 644 + 与全站一致 | 强 |
| 写入通道是**面板文件管理或 WebShell** | 文件被整体替换（PHP 文件不会自改写）+ 该 IP 22:41 面板登录 | 中（**推断，见误判对照**） |
| **该 IP 直接实施了首页篡改** | 仅有时空吻合 | **不成立——见误判对照** |
| 首页原始内容 | 3-16 版本 1194 字节 | **已不可得**（未备份，见未覆盖范围） |

**未覆盖范围**：「该站点 `public/index.php` 的单文件历史」。

**未取得**：原始版本内容（站点无版本控制、无备份文件，3-16 的 1194 字节版本已不可得）。

**未查**：其他站点的 `index.php` 是否同期被篡改（`/www/wwwroot/` 下可能有多个站点）。

**未查**：宝塔面板的**文件回收站/操作日志**中是否留有原文件——这是本案**最可能找回原始内容、却尚未尝试**的一条路径。

**误判对照**

这个案例最容易出的错，正是法务场景下代价最高的那种：**把"高度吻合"写成"确认实施"**。

1. **判据**：`mtime`（01:02:33）与访问日志 POST（01:02:31）相差 2 秒，**这是典型的"关联"而非"归因"**。判别力在于：那个 POST 打到的是 `index.php`，而 `index.php` 是一个 29 KB 的静态 HTML 页——它没有任何接收上传或重写自身的能力。如果真是这次 POST 导致文件改变，日志里应出现的是"文件被替换"的动作（面板文件管理、FTP PUT、或 WebShell 的写文件操作），而不是一次普通的 POST 请求。 正确表述是"该 IP 在篡改时刻前后 2 秒内有请求活动，写入通道经推断为面板文件管理或 WebShell，直接实施者待定"。
2. **判据**：属主 `www` 不能推出"是 PHP-FPM 写的"。`www` 身份的进程有三个可能来源：PHP-FPM（Web 请求）、宝塔面板（面板通常以 www 或面板用户运行文件管理）、以及攻击者拿到的 WebShell（以 www 身份运行）。**三者留下的属主完全相同，无法区分。** 正确表述是"以 www 身份写入"，而非"由 Web 请求写入"。
3. **判据**："首页被改"不等于"数据被窃"或"业务受损范围仅首页"。本案的判定范围只有 `public/index.php` 一个文件。若法务要评估损失，需要先做**全站篡改面清点**（其他站点的入口文件、模板文件、静态资源），**在清点完成前不得出具"仅首页被篡改"的结论**。

**按错误判据走的代价**：第 1 条踩中的代价在法务场景下是实质性的。报告若写"确认 `198.51.100.24` 实施了首页篡改"，而实际写入者可能是通过被盗用的第三方账号（云控制台、CDN 后台、开发者仓库）操作，**委托方据此发函追责的对象就是错的**。在涉及诉讼或商誉索赔的委托里，这类归因错误会让交付方承担连带责任。

第 2 条踩中则会让"Web 请求触发"这个错误机制被写进报告，而它一旦被技术人员复核就会立刻暴露，反过来削弱那些本来扎实的时间线结论。

<a id="section-36"></a>

## 六、扩展阅读方向

本篇是服务器侧的地图：它把工件排了位置与优先级，但没有逐层展开。下面按**你接下来要下钻的那一层**分组。

**Web 环境层：面板与站点管理**

- [宝塔面板取证](server-panel-bt-panel-forensics.md) —— `/www/server/panel/` 下的数据库、操作日志与配置。面板一次 Web 口令就等价于 root，它的日志因此比 auth.log 更值得先看。
- [宝塔新版加密数据解密](server-panel-bt-panel-encrypted-data.md) —— 新版面板把关键配置加密存储时的识别与处理。**只做离线解密，凭据脱敏。**
- [其他面板取证](server-panel-hosting-control-panel-forensics.md) —— 宝塔之外的国产面板对比。**路径规律相似但细节完全不同，凭印象查必错。**
- [Nginx 与 Apache 配置取证](../server-web/server-web-nginx-apache.md) —— `log_format` 字段决定了 access.log 里有哪些可用字段；`disable_functions` 被清空是重要证据。
- [网站目录与 WebShell 检测](../server-web/server-web-webshell-detection.md) —— 站点根目录可写是服务器最核心的攻击面。**本篇 2.4 那条链路就从这里展开。**
- [WebShell 工具流量特征](../server-web/server-web-webshell-traffic-patterns.md) —— **内容像 WebShell 但不确定时**，用流量特征区分是工具自身回调还是漏洞利用。
- [远程控制工具痕迹](server-panel-remote-control-artifacts.md) —— 面板与 SSH 之外的第三条通道。**远控凭据只做离线分析。**

**数据层：拖库的证据在哪**

- [MySQL 数据库取证](../../mobile/mobile-database/mobile-database-mysql.md) —— binlog、慢查询日志、`general_log` 的完整读法。**三层日志能力的差别见陷阱 8。**
- [SQLite 基础与结构](../../mobile/mobile-database/mobile-database-sqlite.md) —— 小型应用与脚本类站点的数据载体。
- [数据库与配置文件加密](../../crypto/crypto-app/crypto-app-database-configuration-decryption.md) —— 站点配置文件里库口令的识别与处置规范。

**网络归因：请求从哪来、往哪去**

- [CDN 识别与源站挖掘](../server-web/server-web-cdn.md) —— access.log 里的 IP 可能是 CDN 节点而不是攻击者，源站隐藏时归因要走另一条路。
- [网络流量与 PCAP 取证](../../memory/memory-network/memory-network-pcap.md) —— 日志证明"发生过"，流量证明"数据真的走了网卡"。**两者能支撑的结论强度差一级。**
- [Web 攻击痕迹还原](../server-log/server-log-web-attack-trace-reconstruction.md) —— Windows 侧的对应物。**IIS 与 Nginx 的日志字段不可直接互换。**

**现场处置与结论表述**

- [远程勘验与在线取证](../../imaging/imaging-acquire/imaging-acquire-remote-evidence-collection.md) —— 在线 vs 离线的证据能力差异、断电决策、内存采集。**本篇第 0 步的展开。**
- [取证装备与写保护器](../../fundamentals/fundamentals-practice/fundamentals-practice-forensics-equipment-and-write-blockers.md) —— 现场接入方式与只读原则。
- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— **日志被清、history 被删、时间戳归一化**的识别。"发现覆盖本身就是结论"的那一类证据在这一篇有判据。
<a id="section-37"></a>

## 七、命令速查

```bash
# ===== 0. 在线时的抢占式固定（分钟级，先做）=====
date -u '+%Y-%m-%dT%H:%M:%SZ' | tee /evidence/collection-utc.txt
uptime; who -a; last -n 30
ss -tulpn | tee /evidence/netstat-live.txt; ss -tapn state established >> /evidence/netstat-live.txt
ps auxwwf | tee /evidence/ps-live.txt
sudo ./avml /evidence/DigiForensics-mem.raw && sha256sum /evidence/DigiForensics-mem.raw
mkdir -p /evidence/logs
for f in /var/log/nginx/*.log /www/wwwlogs/*.log /var/log/auth.log \
         /var/log/secure /var/log/mysql/*.log /www/server/panel/logs/*.log; do
  [ -f "$f" ] && cp -p "$f" /evidence/logs/ 2>/dev/null     # 只 cp，不 mv
done

# ===== 1. 只读接入 =====
mmls /work/DigiForensics.dd
sudo mount -o loop,ro,offset=1181696,noload,noatime /work/DigiForensics.dd /mnt/df
findmnt -no OPTIONS /mnt/df
sha256sum /work/DigiForensics.dd | tee /evidence/evidence.sha256

# ===== 2. 环境识别（面板 or 源包；哪套 Nginx）=====
grep -E '^(NAME|VERSION_ID)=' /mnt/df/etc/os-release
for d in /www/server/panel /opt/1panel /etc/webmin /www/wwwroot /var/www; do
  [ -d "/mnt/df$d" ] && echo "存在  $d" || echo "缺失  $d"
done
ls -d /mnt/df/www/server/nginx /mnt/df/etc/nginx /mnt/df/etc/httpd 2>/dev/null

# ===== 3. 优先级 1：网站目录 =====
ls -la /mnt/df/www/wwwroot/
find /mnt/df/www/wwwroot -type f -printf '%T@ %TY-%Tm-%Td %TH:%TM %m %u:%g %s  %p\
' \
  | sort -n | tail -50
stat -c '%n  mtime=%y  ctime=%z  mode=%a  owner=%U:%G' /mnt/df/www/wwwroot/digiforensics-site/
find /mnt/df/www/wwwroot -perm -0002 -printf '%m %u:%g %p\
' | head -50      # 世界可写
find /mnt/df/www/wwwroot ! -user www -printf '%m %u:%g %p\
' | head -50      # 异常属主

# ===== 4. 优先级 2：日志边界（决定报告能写的时间范围）=====
ls -l --time-style=long-iso /mnt/df/www/wwwlogs/ /mnt/df/var/log/nginx/ 2>/dev/null
zcat -f /mnt/df/www/wwwlogs/digiforensics-site.log* 2>/dev/null | wc -l
grep -nE '可疑文件名' /mnt/df/www/wwwlogs/digiforensics-site.log.1 | head -20

# ===== 5. 优先级 3：持久化 =====
ls -l /mnt/df/var/spool/cron/crontabs/ /mnt/df/etc/cron.d/ 2>/dev/null
ls -l /mnt/df/etc/systemd/system/*.service 2>/dev/null
cat /mnt/df/etc/ld.so.preload 2>/dev/null                # 存在即高度可疑

# ===== 6. 优先级 4：账户与 SSH =====
cut -d: -f1,3,6,7 /mnt/df/etc/passwd
awk -F: '$3==0 || $2==""' /mnt/df/etc/shadow
find /mnt/df/root/.ssh /mnt/df/home -name authorized_keys -exec ls -l {} \; 2>/dev/null
last -f /mnt/df/var/log/wtmp 2>/dev/null | head -30

# ===== 7. 优先级 5：面板 =====
ls -l /mnt/df/www/server/panel/logs/ 2>/dev/null
grep -nE '可疑IP' /mnt/df/www/server/panel/logs/request.log | head
ls -l /mnt/df/www/server/panel/data/default.db /mnt/df/www/server/panel/data/db/ 2>/dev/null
ls -l /mnt/df/www/backup/ 2>/dev/null                    # 宝塔自动备份，勿遗漏

# ===== 8. 优先级 6：命令历史 =====
for h in /mnt/df/root/.bash_history /mnt/df/home/*/.bash_history \
         /mnt/df/root/.zsh_history /mnt/df/home/*/.zsh_history; do
  [ -f "$h" ] && { echo "== $h"; grep -nE 'curl|wget|chmod|base64|crontab' "$h" | head -20; }
done

# ===== 9. 固定与校验 =====
cp --preserve=all "可疑文件" /evidence/
sha256sum /evidence/* | tee -a /evidence/hashes.txt
find /mnt/df/www/wwwroot -printf '%y %m %u:%g %s %TY-%Tm-%Td %TH:%TM  %p\
' \
  | sort -k7 > /evidence/site-manifest.txt
umount /mnt/df && sha256sum -c /evidence/evidence.sha256
```

> **本篇延伸**：`disable_functions` 是否被清空（PHP 配置篡改）与 `log_format` 字段逐项含义见[第 05 篇](../server-web/server-web-nginx-apache.md)；access.log 的可疑流量分析见[第 07 篇](../server-web/server-web-webshell-traffic-patterns.md)。

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 服务器与 Web 取证 — Linux 服务器取证工件地图」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《Linux 服务器取证工件地图》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-mem.raw` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
