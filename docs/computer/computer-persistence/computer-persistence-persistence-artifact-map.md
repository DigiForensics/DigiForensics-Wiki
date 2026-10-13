---
title: "取证工件地图"
slug: "computer-persistence-persistence-artifact-map"
canonical: "https://www.digiforensics.cn/wiki/computer-persistence-persistence-artifact-map"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:52+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "computer"
space: "计算机取证"
node_path: ["持久化机制"]
---

# 取证工件地图

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/computer-persistence-persistence-artifact-map)

<a id="section-1"></a>

## 一、概述

Linux 取证最反直觉的一点是**它没有集中入口**。Windows 上 `Security.evtx` 一个文件就能回答「谁在什么时候登录了什么」，Linux 没有等价物：同样的信息被拆散在文本日志、文件时间戳、utmp 二进制库、shell 历史、包管理器账本，以及只有运行中才存在的 `/proc` 里。

这个结构直接导致两种失败模式，而且**都很隐蔽**：

- **只看日志会漏掉一半证据。** 文件创建时间、SUID 位、用户 crontab、`authorized_keys` 里的公钥——这些**不写在任何日志里**。清理日志能挡住一部分攻击痕迹，但完全挡不住配置文件类的证据。
- **只看文件时间戳会误判。** Linux 有四个时间戳，`atime` 还受挂载选项影响，「文件在某时被访问过」推不出「某人某天读过它」。

还有一个更隐蔽的错误：**把 Debian 系的路径套到 RHEL 系上**。`/var/log/auth.log` 在 CentOS 上根本不存在，去那里找认证日志会得到「这台机器没有日志」的错误结论——而真相是它叫 `secure`。

按「谁记录了它」可以把工件分成六类，下面这张速查表就是按这个维度组织的：

| 类别 | 典型路径 | 记录什么 |
|---|---|---|
| 系统服务记录 | `/var/log/`、`/var/log/journal/<machine-id>/`、`/run/utmp` | 谁登录过、哪个服务发生了什么 |
| 账户体系 | `/etc/passwd`、`/etc/shadow`、`/etc/group` | 账户清单与口令哈希（**只复制不破解**） |
| 应用配置 | `/etc/ssh/sshd_config`、`/etc/cron.d/`、`/etc/systemd/system/` | 服务如何被配置、如何被自动拉起 |
| 用户私有数据 | `/home/<user>/.bash_history`、`.zsh_history`、`.ssh/` | 交互行为、登录凭据材料 |
| 包管理器账本 | `/var/lib/dpkg/status`、`/var/lib/rpm/`、`/var/log/apt/history.log` | 装过什么、什么时候装、哪些是手动装的 |
| 运行时状态 | `/proc/`、`/tmp/`、`/var/tmp/` | 活系统才有的进程与连接快照 |

配套的判定信息有两处容易被忽略：`/etc/os-release` 与 `/etc/machine-id` 决定家族判定与 journal 子目录定位；`/etc/fstab` 决定 `atime` 是否可信。

关于 `/etc/shadow`：取证对它**只做复制与哈希记录，不做破解**。离线镜像里它就是一个普通文件，权限位记在 inode 里。

动手之前要先有东西可看。**上游是镜像制作与接入**——你得先有一份哈希可验证的镜像（见[镜像制作](../../imaging/imaging-acquire/imaging-acquire-disk-imaging-and-evidence-preservation.md)），并以只读方式挂载（见[只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md)），否则后面每一次「读一下」都会改掉你要证明的东西。这一步要产出三样：发行版家族判定、关键目录的存在性清点、接入未污染证据的验证。下游是按类展开的日志、持久化、SSH、包清单、Shell 痕迹与运行时状态，有了地图才知道哪个方向是空的、哪个方向有料。

**「某目录不存在」本身就是结论**，而且往往是重要结论。它可能意味着这台机器上从未配置过该服务、被清理过、或路径被人为改写。

答得出来的是这台机器属于哪个发行版家族、哪些关键工件实际存在、哪些路径的缺失本身值得追问、账户体系与自动启动机制的整体轮廓、以及一次接入操作有没有污染原始卷。

答不出来的同样明确：

- **任何具体行为。** 地图只告诉你「去 `/var/log/apt/history.log` 看装了什么」，不解释那行记录的含义。
- **时间线的完整形态。** 时间戳的语义、精度与可信度分层需要专门方法，见[时间线重建](../computer-log/computer-log-linux-timeline-reconstruction.md)。
- **运行时状态。** `/proc` 在离线镜像里是空的，这不是「没有进程」，而是「这个证据形态不适用于离线分析」，见[proc 虚拟文件系统取证](../computer-shell/computer-shell-proc.md)。
- **已删除内容。** `/tmp` 与 `/var/tmp` 里已经 unlink 的文件不再出现在目录中，地图层面看不见。
- **跨主机的东西。** 单台主机的地图无法回答「它连着谁」，那需要网络侧或服务器侧材料。

走这套流程需要已经完成镜像制作与完整性校验，知道为什么要先验证哈希再分析；能区分 Debian 系与 RHEL 系的基础差异，至少知道认证日志路径在这两族里不同；了解 ext4 的基本概念（inode、目录项、挂载选项），否则无法判断 `atime` 是否可信，见[ext4 结构与 inode](../../filesystem/filesystem-unix/filesystem-unix-ext4-inode.md)；

会使用只读挂载与 loop 设备，理解为什么「先复制再分析」和「直接挂载只读」是两种不同的操作。这份地图是清点清单性质的，具备基本的命令操作能力即可，不需要深度解析能力。

<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 Linux 证据按"记录者"分为六类

理解 Linux 取证的关键不是背路径，而是记住**每类痕迹由谁写入、什么时候写入**。这决定了它的可信度和清除难度。

| 类别 | 记录者 | 典型工件 | 清除难度 |
|---|---|---|---|
| **系统服务日志** | rsyslog / journald | `/var/log/auth.log`、`/var/log/messages`、journal | ★★★ 可 `truncate -s 0` |
| **文件系统元数据** | 内核 VFS 层 | atime/mtime/ctime/crtime、SUID 位、目录 mtime | ★★★★ 需改系统时间或卸载卷 |
| **用户行为痕迹** | Shell 自身 | `~/.bash_history`、`.viminfo`、`.mysql_history` | ★★ 用户一键 `history -c` |
| **子系统账本** | 包管理器 / 登录记账 | `dpkg` 状态、`/var/lib/rpm`、utmp/wtmp/btmp | ★★～★★★ 需 root 且会留不一致 |
| **运行时状态** | 内核 `/proc` | 进程命令行、环境变量、打开的 fd、网络连接 | ★★ 进程退出即消失 |
| **配置与自启** | 管理员 / 攻击者 | crontab、systemd unit、`ld.so.preload` | ★★ 写入成本低，清理动作通常不涉及 |

> **实战推论**：反取证通常是**从上往下**清的——先 `history -c`，再清日志文件，最后删自启项。而篡改 `ld.so.preload`、在 crontab 里留后门的写入成本几乎为零，且不写任何日志。所以「配置与自启」这一类不随日志与 history 的清理而消失，仍需逐项排查，见[第 04 篇](computer-persistence-scheduled-tasks-and-persistence.md)。

<a id="section-4"></a>

### 2.2 关键目录速查表

拿到镜像后按图索骥：

| 路径 | 内容 | 取证价值 | 参见 |
|---|---|---|---|
| `/var/log/` | 系统与服务日志 | ★★★★★ | [02](../computer-log/computer-log-system-log-analysis.md) |
| `/var/log/journal/` | systemd journal（**二进制**） | ★★★★★ | [02](../computer-log/computer-log-system-log-analysis.md) |
| `/var/log/wtmp` / `/var/log/btmp` | **成功 / 失败**登录记录 | ★★★★★ | [05](computer-persistence-ssh.md) |
| `/run/utmp` | **当前在线会话**（重启即清空） | ★★★★ | [05](computer-persistence-ssh.md) |
| `/var/log/apt/history.log` | **谁在何时装/卸/升级了什么** | ★★★★★ | [07](computer-persistence-package-manager-and-software-inventory.md) |
| `/etc/passwd`、`/etc/shadow` | **账户与口令哈希** | ★★★★★ | 本篇 3.2 |
| `/etc/ssh/sshd_config` | SSH 服务端配置 | ★★★★★ | [05](computer-persistence-ssh.md) |
| `/etc/cron.d/` | 系统级 crontab **片段**（无用户字段） | ★★★★★ | [04](computer-persistence-scheduled-tasks-and-persistence.md) |
| `/var/spool/cron/crontabs/<user>` | **各用户 crontab** | ★★★★★ | [04](computer-persistence-scheduled-tasks-and-persistence.md) |
| `/var/spool/cron/atjobs/` | `at` / `batch` 一次性任务队列 | ★★★★ | [04](computer-persistence-scheduled-tasks-and-persistence.md) |
| `/etc/systemd/system/` | **管理员自定义 unit**（含 `.wants/`） | ★★★★★ | [04](computer-persistence-scheduled-tasks-and-persistence.md) |
| `/etc/ld.so.preload` | **动态链接器劫持**（存在即高度可疑） | ★★★★★ | [04](computer-persistence-scheduled-tasks-and-persistence.md) |
| `/home/<user>/.bash_history` | **命令历史**（默认无时间戳） | ★★★★★ | [03](../computer-shell/computer-shell-shell.md) |
| `/home/<user>/.zsh_history` | zsh 历史（**带时间戳**） | ★★★★★ | [03](../computer-shell/computer-shell-shell.md) |
| `/home/<user>/.ssh/` | `authorized_keys`、`known_hosts`、`config` | ★★★★★ | [05](computer-persistence-ssh.md) |
| `/root/.ssh/authorized_keys` | **root 的授权公钥**（含密钥植入） | ★★★★★ | [05](computer-persistence-ssh.md) |
| `/tmp/`、`/var/tmp/` | 临时文件，`/var/tmp` **常驻盘** | ★★★★★ | 本篇 2.5 |
| `/proc/` | **运行时快照，离线读不到** | ★★★★★ | [06](../computer-shell/computer-shell-proc.md) |
| `/var/lib/dpkg/status` | Debian 已安装软件清单 | ★★★★★ | [07](computer-persistence-package-manager-and-software-inventory.md) |
| `/var/lib/rpm/` | RHEL 已安装软件清单 | ★★★★★ | [07](computer-persistence-package-manager-and-software-inventory.md) |

> ⚠️ `/etc/shadow` 只能以 root 读取。 离线分析时它只是一个普通文件，权限位记录在 inode 里；**取证不需要破解它，只需要复制并记录哈希**。在线取证用 `sudo cp` 而不要 `cat`，避免终端滚屏泄漏。

<a id="section-5"></a>

### 2.3 发行版差异：最常见的错误来源

**拿到镜像第一件事是判断发行版家族。** 判错会导致整条证据链走错目录。判定方法按可靠度排序：

1. **读标识文件**（最可靠）：`/etc/os-release` 字段标准化，`/etc/debian_version` 与 `/etc/redhat-release` 各自明确。
2. **看包管理器数据库**：`/var/lib/dpkg/` 存在即 Debian 系，`/var/lib/rpm/` 存在即 RHEL 系。
3. **看认证日志文件名**：`auth.log` vs `secure`（**辅助判据**——管理员可自定义 rsyslog 位置，见[第 02 篇](../computer-log/computer-log-system-log-analysis.md)）。

| 对比项 | **Debian / Ubuntu** | RHEL / CentOS / Rocky / Alma |
|---|---|---|
| 认证日志 | `/var/log/auth.log` | `/var/log/secure` |
| 系统总日志 | `/var/log/syslog` | `/var/log/messages` |
| 包管理数据库 | `/var/lib/dpkg/status` | `/var/lib/rpm/Packages` |
| 安装历史 | `/var/log/apt/history.log` | `/var/log/dnf.log`、`/var/log/yum.log` |
| init 脚本（遗留） | `/etc/init.d/` | `/etc/rc.d/init.d/`（软链到 init.d） |
| 安装器 | `apt` / `apt-get` / `dpkg` | `dnf`（8+）/ `yum`（7）/ `rpm` |

> 登录成功/失败账本（`wtmp`/`btmp`/`utmp`）与自定义 unit 目录（`/etc/systemd/system/`）两系相同。**其他家族**：`Arch`/`Alpine`（`/var/log/messages`、`apk`）、`SUSE`（`/var/log/messages`、`zypper`）。以 `/etc/os-release` 为准，不要靠猜。

<a id="section-6"></a>

### 2.4 时间戳在 Linux 上的特殊性

Linux 有**四个**时间戳，Windows 只有三个：

| 时间戳 | 含义 | 什么时候变 |
|---|---|---|
| `atime` | 访问/读取时间 | 文件被**读**时（受 `relatime`/`noatime` 影响） |
| `mtime` | 内容修改时间 | 文件**数据**被写时 |
| `ctime` | inode 状态变更 | 权限、属主、链接数、mtime 任一变化时 |
| `crtime` | **创建时间**（ext4 特有） | 文件创建时写入，此后不变 |

**取证含义**：

- `ctime` 变**不等于**内容被改。`chmod`、`chown` 都会更新它——改权限不改内容会留下 ctime 但不动 mtime，这是识别该手法的判据。
- `atime` 的可信度受挂载选项支配：`relatime` 下若 atime 与 mtime/ctime 相差超过 24 小时则不更新；`noatime` 下完全不更新。**读一次 `stat` 就可能改掉证据**。详见[第 08 篇](../computer-log/computer-log-linux-timeline-reconstruction.md)。

<a id="section-7"></a>

### 2.5 `/tmp` 与 `/var/tmp`：两个都要查

`/tmp` **可能是 tmpfs（内存）**，`systemd-tmpfiles` 会按 age 清理；若是 tmpfs，**重启即全部丢失**。`/var/tmp` **通常是磁盘**，同样受 tmpfiles age 约束，但**重启不丢**，是更常见的持久暂存地。

**判定 `/tmp` 是否为 tmpfs**（离线镜像上从 `/etc/fstab` 判断，不能靠「通常是内存」的经验）：

```bash
grep -E ' /tmp | /var/tmp ' /mnt/df/etc/fstab
# tmpfs /tmp tmpfs defaults,noatime,mode=1777 0 0    ← 内存，重启丢失
# /var/tmp 无独立行 → 属根分区，持久
```

> `/tmp` 的 `mode=1777`（world-writable + sticky bit）意味着**任何用户可写**。这使它成为恶意载荷的首选暂存地，也是「文件属主为 `root` 但 `mtime` 很新」这类异常的高发区。

<a id="section-8"></a>

### 2.6 取证环境准备：dd 后的只读挂载

**镜像制作完成后，第一步是建立只读接入环境。** 挂载本身会写盘（更新 atime、可能回放 journal），必须控制住。

```bash
# 步骤 1：确认 ext4 分区起始扇区（示例：Slot 03, Start 1181696）
mmls /work/DigiForensics.dd

# 步骤 2：只读挂载——ro / noload / noatime 三项缺一不可
sudo mkdir -p /mnt/df
sudo mount -o loop,ro,offset=1181696,noload,noatime /work/DigiForensics.dd /mnt/df
#                        │      │   │          │        └─ 禁止更新 atime（否则 stat 本身就在改证据）
#                        │      │   │          └─ 禁止回放 ext journal，保持崩溃现场原始状态
#                        │      │   └─ 只读
#                        └──────┴─ 建立 loop 设备

# 步骤 3：验证 + 记录镜像哈希（证据链要求）
findmnt -no OPTIONS /mnt/df
sha256sum /work/DigiForensics.dd | tee /evidence/evidence.sha256
```

**为什么 `noload` 是关键**：`ext4` 有 journal，操作系统挂载时会**回放未提交事务以修复文件系统**——这会改变 inode 时间戳和目录结构。取证要的是**原始的崩溃现场**，不是修复后的整洁状态。

| 需求 | 方式 | 说明 |
|---|---|---|
| **完整浏览**（首选） | `mount -o ro,noload,noatime` | 看不到已删 inode，但目录树完整 |
| **查已删除 inode** | `debugfs` 离线，不挂载 | 直接读镜像，见[《ext4 结构与 inode》](../../filesystem/filesystem-unix/filesystem-unix-ext4-inode.md) |
| **需要 inode 号对照** | `fls` / `istat` 直接读镜像 | 不挂载，inode 号天然对应 |

> ⚠️ **绝不**使用 `mount -o rw` 或 `debugfs -w`。也**不要**用 GUI 文件管理器浏览挂载点——它会生成缩略图、访问文件（改 atime）。

---

<a id="section-9"></a>

## 三、操作步骤

<a id="section-10"></a>

### 3.1 第 1 步：确认发行版家族（决定后续所有路径）

```bash
# 已挂载到 /mnt/df
grep -E '^(NAME|VERSION_ID|ID)=' /mnt/df/etc/os-release
ls /mnt/df/etc/*release /mnt/df/etc/debian_version 2>/dev/null

# 包管理器侧交叉验证（两条命令只有一条会成功）
ls -d /mnt/df/var/lib/dpkg 2>/dev/null && echo "→ Debian 系"
ls -d /mnt/df/var/lib/rpm  2>/dev/null && echo "→ RHEL 系"

# 认证日志路径由上一步决定
ls -l /mnt/df/var/log/auth.log 2>/dev/null   # Debian 系
ls -l /mnt/df/var/log/secure   2>/dev/null   # RHEL 系
```

<a id="section-11"></a>

### 3.2 第 2 步：账户与口令材料清点

```bash
# 账户清单（含 UID、GECOS、登录 shell）—— 非敏感，可直接读
cut -d: -f1,3,4,6,7 /mnt/df/etc/passwd

# 口令哈希文件（只记录元数据与哈希，不尝试破解）
stat -c '%n  size=%s  mtime=%y  mode=%a' /mnt/df/etc/shadow
sha256sum /mnt/df/etc/shadow /mnt/df/etc/passwd | tee /evidence/acct-hash.txt

# UID 0 的账户 —— 除 root 外出现即异常
awk -F: '$3==0 {print $1": UID 0"}' /mnt/df/etc/passwd
# 空口令账户（字段 2 为空 = 无口令）
awk -F: '$2=="" {print $1": 空口令"}' /mnt/df/etc/shadow
```

| 检查项 | 期望 | 异常信号 |
|---|---|---|
| 非 `root` 的 UID 0 | 不存在 | **权限完全等同 root，最高优先级排查** |
| 空口令账户 | 仅少数服务账户 | `nologin` 账户被设空口令 = 后门入口 |
| 重复 UID | 不存在 | 同 UID 多个账户 = 身份混淆/隐藏账户 |
| `/etc/shadow` 权限 | `640`/`600`，属主 `root:root` | 其他属主 = 可被篡改 |
| 交互式 shell 的服务账户 | 无 | 系统服务账户被赋予 `/bin/bash` = 可登录账户 |

<a id="section-12"></a>

### 3.3 第 3 步：SUID / SGID 全盘清点

```bash
# SUID：运行时以文件属主身份执行
find /mnt/df -xdev -perm -4000 -type f -printf '%m %u:%g %TY-%Tm-%Td %TH:%TM  %p\
' 2>/dev/null

# SGID
find /mnt/df -xdev -perm -2000 -type f -printf '%m %u:%g %p\
' 2>/dev/null

# 世界可写的文件（排除 /tmp /run /dev 等伪文件系统目录）
find /mnt/df -xdev -perm -0002 -type f \
  -not -path '*/tmp/*' -not -path '*/run/*' -not -path '*/dev/*' \
  -printf '%m %u:%g %p\
' 2>/dev/null | head -50
```

**判定逻辑**：`SUID` 位本身**不是**恶意标志（`/usr/bin/sudo`、`/usr/bin/passwd` 等系统文件必须有）。**可疑的是**：

| 信号 | 说明 |
|---|---|
| SUID 文件在 `/tmp`、`/var/tmp`、`/home` 下 | 位置与包管理区系统工具的常态位置不符，属高危信号 |
| SUID 文件属主为普通用户 | 极罕见 |
| SUID 文件**不在任何包管理器清单中** | 意味着是被直接写入盘的，见[第 07 篇](computer-persistence-package-manager-and-software-inventory.md) |
| SUID 文件的 `ctime` 远晚于 `mtime` | 只改了权限位，典型的改权限不改内容 |

<a id="section-13"></a>

### 3.4 第 4 步：`/tmp`、`/var/tmp` 清点

```bash
# 清单按时间排序，异常时间优先
find /mnt/df/tmp /mnt/df/var/tmp -xdev -printf '%T@ %TY-%Tm-%Td %TH:%TM  %m %u:%g %s  %p\
' \
  2>/dev/null | sort -n | tail -60
# 临时目录里的可执行文件 —— 优先取证对象
find /mnt/df/tmp /mnt/df/var/tmp -xdev -type f -executable -printf '%m %u:%g %p\
' 2>/dev/null
```

<a id="section-14"></a>

### 3.5 第 5 步：验证接入未污染证据

**不要假定**，逐项验证：

| 验证对象 | 命令 | 通过标准 |
|---|---|---|
| 挂载确为只读 | `findmnt -no OPTIONS /mnt/df` | 输出含 `ro`、`noload`、`noatime` |
| journal 未回放 | `debugfs -R stats` 的 `Filesystem state` | 与镜像制作时的状态一致 |
| 镜像哈希未变 | `sha256sum -c` | 卸载后复校，仍为 `OK` |

```bash
umount /mnt/df && sha256sum -c /evidence/evidence.sha256
# DigiForensics.dd: OK   ← "分析过程未污染证据"的最强证明
```

---
<a id="section-15"></a>

## 四、常见陷阱

本章按采集接入 → 环境判定 → 痕迹判读 → 结论表述归组，每条给出：现象、为什么会误判、误判代价、正确做法。
★ 标记表示该操作会导致原始检材永久灭失或不可逆改变，执行前必须停下来确认。

本章的一条主线：**Linux 上「目录不存在」本身就是一个结论**，而且它往往有多种互不相同的成因（见陷阱 3）。把「没找到」写成「没发生」时，报告里读起来和真正的阳性发现一模一样。

<a id="section-16"></a>

### 4.1 采集与接入

<a id="section-17"></a>

#### 陷阱 1：★ 用读写方式挂载镜像，或在挂载点里跑系统命令

**现象**：为了「看得全一点」，用 `mount -o loop,rw,offset=...` 挂上原始镜像，然后在里面执行 `find`、`dpkg -l`、`systemctl` 之类需要写临时文件的命令；或者干脆把 `DigiForensics.dd` 挂成系统根。

**原因**：**挂载动作本身就会改动文件系统元数据。**

以 rw 挂载 ext4，内核会写 superblock 计数、`/etc/mtab`（或 `/proc/self/mounts` 的持久化副本），可能触发 `relatime` 更新 atime。如果镜像没加 `noload`，内核还会**回放 journal**，把崩溃瞬间未落盘的事务补齐——于是你看到的「文件系统状态」已经不是断电瞬间的状态了。

更进一步，挂载点的绝对路径是 `/mnt/df`，镜像内的配置却仍指向真实根 `/etc/...`，任何解析路径的库都可能写到不该写的地方。

**影响**：不可逆污染，且事后无法自证。

你之后拿 `atime` 论证「文件被访问过」时，无法区分哪些 atime 是现场留下的、哪些是 `find` 遍历出来的；拿 superblock 论证文件系统状态时，你展示的是回放后的状态而不是现场状态。

在质证环节，对方只需主张「检材在接手前后的完整性无法保证」，你基于元数据的全部结论都会被牵连。

**核查**：

```bash
sudo mount -o loop,ro,offset=1181696,noload,noatime /work/DigiForensics.dd /mnt/df
findmnt -no OPTIONS /mnt/df     # 必须含 ro, noload, noatime
```

`noload` 阻止 ext4 journal 回放，`noatime` 阻止读取更新访问时间，`ro` 保证无法写入。3.5 节的收尾动作不能省：**卸载后对镜像重新计算哈希并与入库哈希比对**，把「分析过程未污染证据」写成可验证的事实而不是声明。

<a id="section-18"></a>

#### 陷阱 2：把「挂载成功」当成「只读接入成功」

**现象**：`mount` 命令返回 0，就认为证据保护到位，继续后续所有操作。中间某步因为空间不足 `umount` 失败、或改用了另一个挂载点，报告里仍写「全程只读接入」。

**原因**：`mount` 成功只说明建立了挂载关系，**保护是否生效完全取决于挂载参数**。

分析者常在需要跑工具时（`dpkg` 要写 `/var/lib/dpkg/lock`、`systemctl` 要写 `/run`）改用 `sudo` 重挂或另开一个 rw 挂载点，而这件事通常不会被记录。

另外 `noload` 也不是默认行为——不写这个参数时内核**会**回放 journal，事后无法从文件系统内部看出曾经回放过。

**影响**：报告里「全程只读」这句话如果被证伪，受影响的不是这一条方法论，而是整份报告的可信度。

委托方和法庭都无法区分「哪些结论来自干净检材、哪些来自污染检材」，于是所有结论一起降级。

**核查**：**每个挂载点建立后立即记录参数**，`findmnt -no OPTIONS` 的输出直接粘进证据处理记录；全程用 `mount | grep /mnt/df` 复查是否存在第二个 rw 挂载。

收尾必须执行 `umount` 后 `sha256sum -c` 复校镜像哈希（3.5 节命令）。若中途确实做过写操作，如实写明「某步骤在写模式副本上执行」，并说明结论分别来自原件还是副本。

<a id="section-19"></a>

#### 陷阱 3：把「目录不存在」直接当成「该机制未启用」

**现象**：`ls /mnt/df/etc/cron.d/` 报 `No such file or directory`，报告写「该系统未配置 cron 服务，无计划任务」。

**原因**：目录不存在至少有五种成因，其中只有两种能推出「未启用」：

| 成因 | 如何区分 | 结论强度 |
|---|---|---|
| 机制未启用，包未安装 | `/var/lib/dpkg/status`（或 rpm 数据库）里查不到对应包 | 可写「未启用」 |
| 目录被删（入侵者清理或自身维护） | **父目录 `mtime` 落在案发窗口内**，或同层有 `.dpkg-dist` 备份残留 | 本身是一条发现 |
| 路径被改写 | 该机制的配置文件指向非默认路径（见陷阱 4） | 需回溯配置才能定 |
| 从容器/快照导出时的裁剪 | 采集脚本只 `tar` 了部分子树 | 属采集局限，责任在采集 |
| 文件系统损坏导致目录项丢失 | 该分区其它目录也大面积读不出 | 是完整性问题，不是本案结论 |

在磁盘上，「从没配过」和「被删掉了」可能长得一模一样。区分线索是父目录的时间戳与包管理器账本。

**影响**：这是**结论方向相反**的一类误判。若真实成因是「被入侵者删除」，写成「未启用」等于替攻击者解释掉了痕迹，而且这个错误会连带影响整条持久化结论——委托方会认为这一层不需要再看。

**核查**：**目录缺失必须带三件套**，缺一件就不能定性。

```bash
# ① 父目录时间戳：被删会在父目录留下近期 mtime
stat -c '%n mtime=%y ctime=%z' /mnt/df/etc /mnt/df/var/spool/cron 2>/dev/null

# ② 包管理器账本：包里没有 = 真未启用
grep -E '^Package: (cron|anacron|systemd)$' /mnt/df/var/lib/dpkg/status 2>/dev/null
ls -l /mnt/df/var/lib/rpm/Packages 2>/dev/null

# ③ 配置改写：查是否有非默认路径
grep -rnE 'CRON_|CRONPATH|run-parts' /mnt/df/etc/default/ /mnt/df/etc/cron* 2>/dev/null
```

报告表述分三档：包账本无记录 → 「本机未安装 cron，机制未启用」；包账本有记录而目录缺失 → 「**cron 已安装但目录缺失，疑被删除**，父目录 `mtime` 为 `<时间>`」；采集裁剪 → 「本次采集未包含该路径，属采集局限」。**中间那档必须写成发现，不能写成结论。**

<a id="section-20"></a>

### 4.2 发行版与环境判定

<a id="section-21"></a>

#### 陷阱 4：只凭 `auth.log` / `secure` 判断发行版家族

**现象**：镜像里只看到 `/var/log/auth.log`，就断定是 Debian 系，开始按 Ubuntu 的路径全盘排查。实际那是一台被人为改名过的 RHEL。

**原因**：认证日志路径是 rsyslog 配置的产物，不是发行版的身份证明。

本篇 2.3 明确写了可靠度排序：`/etc/os-release` 与 `/etc/debian_version`、`/etc/redhat-release` 才是可靠判据，认证日志文件名只是**辅助判据**——管理员可以在 `/etc/rsyslog.conf` 或 `rsyslog.d/` 里把 `auth.*` 写到任意路径。

入侵者修改这个配置来误导调查，本身就是一种反取证手法。此时「文件名判断家族」恰好踩进对方设的套。

**影响**：判错家族意味着后续所有路径、账号体系、软件清单格式全部走错分支。

你会在 RHEL 机器上找不到 `/var/lib/dpkg`，得出「该机软件清单不可查」的结论，而真实的清单在 `/var/lib/rpm` 里好好躺着。第五章 5.1 的 SUID 归属反查正是靠 `rpm -qf` 完成的——判错家族这一步就会让它跑不起来。

**核查**：按 2.3 的三条判据交叉验证，至少两条一致才定家族：

```bash
grep -E '^(NAME|VERSION_ID|ID)=' /mnt/df/etc/os-release
ls -d /mnt/df/var/lib/dpkg 2>/dev/null; ls -d /mnt/df/var/lib/rpm 2>/dev/null
```

包管理器数据库是第二条独立证据线（`dpkg` 目录 vs rpm 数据库目录），它不依赖日志配置，可靠性高于文件名。`os-release` 被删或被改写时（`NAME=` 与实际不符），按 2.3 的说法以包管理器账本为准，并把这条不一致本身记为一条发现。

<a id="section-22"></a>

#### 陷阱 5：把「相对路径」当成无害，把「绝对路径」当成可疑

**现象**：`/etc/ld.so.preload`、`crontab`、systemd unit 里出现 `/tmp/.x.sh` 这类绝对路径就直接定性；看到 `./agent.sh`、`$(dirname $0)/run` 这类相对路径或变量展开就放过去。

**原因**：路径的判据不在「是不是绝对」，而在「它从哪来、能不能被移动」。

相对路径在两类场景下是完全正常的：`crontab` 的工作目录默认是用户家目录，`cd /opt/app && ./deploy.sh` 里的 `./` 完全正常；`/etc/ld.so.preload` 里写相对路径则几乎必然异常，因为动态链接器解析它时不以任何业务工作目录为基准——所以**同一个形态在不同载体里的含义相反**。反过来，绝对路径在安装脚本、systemd 的 `ExecStart` 里是主流写法，`/usr/local/bin/` 下大量文件都是这样注册的。

**影响**：判据用反了，两边都错：真正的劫持因为写的是绝对路径被归为正常，而正常脚本因为用了相对写法被列进高危清单。第五章那种「清单里混着噪音」的状态一旦形成，真正要报的那一条会被淹没。

**核查**：**按载体分别定判据，不做统一判断。**

```bash
# ld.so.preload：任何非绝对路径的条目都极可疑（解析基准不存在）
grep -vE '^\s*(#|$)' /mnt/df/etc/ld.so.preload | while read -r p; do
  case "$p" in /*) echo "绝对路径: $p";; *) echo "★可疑相对路径: $p";; esac
done

# crontab / systemd：看命令的落地位置，不看写法
# 落地在 /tmp /var/tmp /dev/shm 下 → 高危；落地在 /usr/local/bin 或家目录 → 需看包归属
```

判定的落点统一为「这个可执行文件归不归包管理器管」：`dpkg -S` / `rpm -qf` 有输出就是包自带的，无输出才是需要解释的。这条命令的判别力高于路径形态。

<a id="section-23"></a>

#### 陷阱 6：把 SUID 位本身当成恶意标志

**现象**：扫出 40 多个 SUID 文件，其中包含 `/usr/bin/sudo`、`/usr/bin/passwd`、`/usr/bin/chsh`，报告把它们列成「发现 40 余个高危可执行文件」。

**原因**：SUID 是 Unix 的正常权限模型，不是攻击特征。

`sudo`、`passwd`、`su`、`newgrp`、`chsh`、`chfn`、`gpasswd`、`mount`、`umount` 以及大量发行版打包的系统工具都**必须**带 SUID 才能工作，它存在的意义就是让普通用户完成需要 root 权限的操作。

**影响**：这类报告一旦被对方专业分析员看到，「把系统自带工具列为高危」会成为质疑你专业性的第一个把柄。

更实际的问题是**信噪比崩溃**——真正该查的那个 `/tmp/.kworkerd` 会淹没在 40 条噪音里。

**核查**：SUID 清点的判据是 3.3 节的四条组合信号，而不是位本身：① 位置在 `/tmp`、`/var/tmp`、`/home` 下；② 属主为普通用户；③ **不在任何包管理器清单中**（这是最强的一条，直接用 `dpkg -S <路径>` 或 `rpm -qf <路径>` 验证）；④ `ctime` 远晚于 `mtime`（只改权限不改内容）。

`ctime` 晚于 `mtime` 这一条尤其好用——它正是「改权限」这个动作留下的痕迹，因为改权限会更新 `ctime` 而不更新 `mtime`。

<a id="section-24"></a>

### 4.3 痕迹判读

<a id="section-25"></a>

#### 陷阱 7：把「某工件不存在」写成「该行为没有发生」

**现象**：镜像里没有 `crontabs/<user>` 文件，报告写「该账户无计划任务，无定时执行痕迹」。

**原因**：用户 crontab 的载体是 `/var/spool/cron/crontabs/<user>`，但同一个行为有多个互不相同的落点：系统级片段在 `/etc/cron.d/`（无用户字段）、`/etc/crontab`（有用户字段）、`/etc/cron.daily|weekly|monthly/`（走 run-parts）、一次性任务在 `/var/spool/cron/atjobs/`（配合 `at` 命令）、systemd 定时器在 `/etc/systemd/system/*.timer` 及其 `.timer` 触发的 `.service`。

攻击者用一个就足够，五个全查才完整。

**影响**：「没找到」是缺少限定范围的阴性结论。

你给出的「无定时执行痕迹」会被反问「你查了哪几处」——如果只查了用户 crontab 目录，这个反问无法回答，报告的整条持久化结论随之失效。

**核查**：按 2.2 的表格**逐个路径**确认存在性，把「查过哪些、结果如何」列成表；判定「无持久化」时必须五类都覆盖：

```bash
ls -l /mnt/df/etc/cron.d/ /mnt/df/etc/crontab /mnt/df/etc/cron.daily/ 2>/dev/null
ls -l /mnt/df/var/spool/cron/crontabs/ /mnt/df/var/spool/cron/atjobs/ 2>/dev/null
find /mnt/df/etc/systemd/system -name '*.timer' 2>/dev/null
```

若某类路径缺失，也要写清是「路径不存在」还是「目录存在但内容为空」——前者要接陷阱 3 的三件套判断，后者才需要逐条审内容。

<a id="section-26"></a>

#### 陷阱 8：把 systemd timer 与 cron 当成两条独立机制，分别归因

**现象**：在 `/etc/cron.d/` 里发现一条每 5 分钟的任务，同时在 `/etc/systemd/system/` 下发现一个 `.timer` 指向另一个脚本，报告写「攻击者布置了**两套**独立的定时执行机制」。

**原因**：**这两套机制在执行路径上会重叠，且重叠是静默的。**

`/etc/cron.d/` 与 `/etc/cron.daily/` 里的脚本最终都由 `run-parts` 执行，而 systemd 环境下这些路径里的一批脚本同时被 `*.timer` 的 `ExecStart` 引用；反过来，`/etc/systemd/system/` 下的 `.service` 也可以被 `cron` 直接调起。当两者指向同一个脚本时，**它会被触发两次**，而在日志里两条记录的来源前缀不同（`CRON[1234]` 与 `systemd[1]`），看起来像是两个不同的行为。

另一半原因是**触发时间与执行时间不是一回事**：`.timer` 的 `OnCalendar=` 决定触发时刻，`Persistent=true` 会让错过的触发在开机后补跑一次——于是**一次配置改动可能导致开机时突然出现一批执行记录**，看起来像新增行为，实际是补跑。

**影响**：把同一个行为数成两个，会让「攻击者布置了几套机制」这个数字虚高，报告的威胁评估随之膨胀。反过来，只查一套机制而漏掉另一套，则会漏掉实际唯一在跑的那个。

**核查**：先建「脚本 ↔ 触发源」的双向映射，再谈机制数量。

```bash
# ① 列出所有触发源
grep -rn . /mnt/df/etc/cron.d/ /mnt/df/etc/crontab /mnt/df/etc/cron.daily/ 2>/dev/null
find /mnt/df/etc/systemd/system -name '*.timer' -o -name '*.service' 2>/dev/null

# ② 每个触发源的目标路径归一，看是否指向同一个脚本
#    cron:  取第 5~6 字段；systemd: 取 ExecStart= 后的路径
# ③ 命中同一路径 → 记为「同一目标，多触发源」；并核对 .timer 的 Persistent= 与实际执行时刻
grep -rn 'Persistent=' /mnt/df/etc/systemd/system/ 2>/dev/null
```

结论写成「目标脚本 `<路径>` 由 cron（`<周期>`）与 systemd timer（`<OnCalendar>`）两处触发，案发时段执行记录见 `<日志源>`」。`Persistent=true` 造成的补跑要在时间线里单独标出，否则「开机后突然密集执行」会被读成攻击者在那一刻集中活动。

<a id="section-27"></a>

#### 陷阱 9：用 `find -perm -4000` 的结果直接推断「文件是攻击者放的」

**现象**：发现 `/tmp/.kworkerd` 是 SUID root，于是报告直接写「攻击者创建了该 SUID 后门文件」。

**原因**：归属推断需要独立证据，权限位只回答「它以什么身份运行」。

要证明「这是攻击者放的」，至少要拿到：文件不属于任何软件包（`dpkg -S` / `rpm -qf` 无输出）、`ctime` 与 `mtime` 都晚于案发窗口、其内容经分析确为恶意、并且能对应到一条执行或写入记录（如 auth.log 的 `sudo ... COMMAND=/bin/chmod 4755 /tmp/.kworkerd`）。

案例里第 5 步正是靠「不在包清单中 + auth.log 的 chmod 命令」两条才定案的。

**影响**：单靠 SUID 位置下「攻击者创建」的结论，在质证时会被「你怎么排除这是某个安装包解压时产生的临时文件」直接问倒。

而这类文件恰恰是最有价值的目标，结论一旦被推翻，损失最大。

**核查**：把归属证明拆成可独立验证的几条并全部写进报告：包归属查询结果、三个时间戳、内容哈希与行为分析、执行记录。

任何一条缺失，就在结论里降级为「存在未纳入软件包清单的 SUID 可执行文件，来源待定」。

<a id="section-28"></a>

#### 陷阱 10：把 `/etc/ld.so.preload` 的存在本身当作定案

**现象**：发现 `/etc/ld.so.preload` 里写了一个可疑 `.so` 路径，报告写「确认存在动态链接器劫持」。

**原因**：**这个文件本身可以是完全合法的内容**：安全加固工具（如某些 EDR/防 rootkit 的模块）、`faketime` 之类的调试辅助、容器镜像里的 `libnss_wrapper`、图形环境的字体缓存模块，都可能合法地出现在 preload 列表里。

它是**逐行**生效的，一个文件里可以有合法项和恶意项并存。

**影响**：把「存在」当成「恶意」，一旦举证不出该 `.so` 的实际功能，报告的定性就被削弱为推测。

更糟的是，如果你因此判定「已确认 rootkit」，却拿不出可复现的验证步骤，整份报告的可信度都会被这条草率结论拖累。

**核查**：逐行读内容并对每个条目独立定性：这个路径是绝对路径还是相对路径（`ld.so.preload` 中相对路径无解析基准，属异常，见陷阱 5）、指向的 `.so` 是否存在于镜像内、其字符串与导出符号是否与进程劫持相关（`dlsym`、`getenv`、网络符号等）、`mtime`/`ctime` 是否异常。

结论分层：**存在非常规 preload 项**（事实）→ **该项在系统启动时被注入到所有动态链接进程**（机制）→ **具体行为需动态分析确认**（结论边界）。

<a id="section-29"></a>

#### 陷阱 11：把 `.bashrc` 与 `.bash_profile` 的生效顺序搞反

**现象**：在 `~/.bashrc` 里发现一条可疑的 `export`，判定为「该用户登录后会自动执行」；或者在 `~/.bash_profile` 里没找到预期内容，判定「该账户家目录未配置」。

**原因**：这两个文件的加载是分层的，而且分层点不是「登录时」。

bash 启动时先读 `~/.bash_profile`（若不存在则退回 `~/.bash_login`，再退回 `~/.profile`），`~/.bashrc` 不是被 `bash_profile` 自动带进来的——各家发行版靠 `/etc/skel/.bash_profile` 里手写一行 `[ -f ~/.bashrc ] && . ~/.bashrc` 来串起来，而**这一行是可以不存在的**。后果是对称的两个错误：登录走的是 `bash_profile` 分支而 `.bashrc` 从未被 source，于是 `.bashrc` 里的东西实际不生效；反过来，`.bashrc` 里有配置但登录路径根本没读它，你把它当成反取证证据就完全站不住。

另一半是加载时机：`~/.bashrc` 在每次启动交互式 shell 时都会读（包括子 shell），而 `~/.bash_profile` 只在登录 shell 读。所以「一条只对非登录 shell 生效的命令」和「一条对所有 shell 生效的命令」写在不同文件里，效果完全不同。

**影响**：把未生效的配置当成有效载荷，或把有效载荷判成无害。第五章 5.1 里 `HISTFILE` 那类配置的取证价值完全建立在「它当时确实生效」这个前提上——前提错了，整条时间线论证就塌了。

**核查**：**先确定该账户走的是哪条启动路径，再谈配置内容。**

```bash
# ① 登录 shell 的第一层：profile 文件是否存在、内容是什么
ls -l /mnt/df/home/deploy/.bash_profile /mnt/df/home/deploy/.bash_login /mnt/df/home/deploy/.profile 2>&1

# ② 关键：有没有把 .bashrc 串进来
grep -nE '\.bashrc' /mnt/df/home/deploy/.bash_profile /mnt/df/home/deploy/.profile /mnt/df/etc/profile 2>/dev/null

# ③ 串联存在才可断言 .bashrc 生效
grep -nE '^\s*(export\s+)?(HISTFILE|HISTSIZE|HISTCONTROL|PATH)=' /mnt/df/home/deploy/.bashrc
```

结论按两档写：`.bash_profile` 存在且含 `.bashrc` 串联 → 「`.bashrc` 内容对登录与交互式 shell 均生效」；`.bash_profile` 存在但**不含**串联 → 「`.bashrc` 仅对交互式非登录 shell 生效，登录会话不加载」。**这一档差别必须在报告里写出来**，因为 `scp`、`ssh host "cmd"`、cron 这类非交互执行走的正是登录 shell 分支。

<a id="section-30"></a>

### 4.4 结论表述

<a id="section-31"></a>

#### 陷阱 12：把「账户层无异常」写成「未入侵」

**现象**：`/etc/passwd` 检查通过——无 UID 0 异常账户、无空口令、权限正确，报告结论写「账户层无异常，系统未被入侵」。

**原因**：**账户层检查的覆盖面极窄。** 案例第 3 步自己就点明了这一点：攻击者更倾向使用**合法账户**（`deploy`、`svc-backup` 这类已有账号），通过窃取口令或植入 SSH 公钥进入，账户清单上完全看不出异常。UID 0 异常账户只是最粗糙的一种后门形式，**它在现代攻击里反而是少数**。

**影响**：这是把一个窄结论当成全局结论的典型。委托方拿着「未入侵」这份结论去做后续处置（不换口令、不下补丁、不轮换密钥），等于把已建立的访问通道留在原地。

**核查**：结论必须限定范围。写成：「账户清单层未发现明显异常账户（已检查：UID 0 重复、重复 UID、空口令、shadow 权限与属主）。**该结论不覆盖凭据泄露与合法账户滥用**，需结合日志、命令历史与 SSH 工件判断。」后面这半句是必须的。

<a id="section-32"></a>

#### 陷阱 13：把「未找到某类痕迹」直接写成「无该行为」

**现象**：某类工件在镜像里不存在（例如镜像里没有 `/var/log/journal`，或没有 `wtmp`），报告写「该机未记录登录历史」。

**原因**：**工件不存在至少有五种成因，每一种的结论强度都不同**：该机制本来就没启用（`/run/utmp` 本来就是重启即清空、journald 可能被 mask）；内容随内存丢失（journal 只在 `/run/log/journal`，断电后不在盘上）；机制存在但队列为空（`/var/spool/cron/atjobs/` 正常就是空的）；被清理；采集时未包含该区域（镜像做了分区选择性采集）。

在磁盘上，「没启用」和「被清掉」可能长得一模一样。

**影响**：这是缺少成因限定的阴性结论。

若真实成因是「内容随内存丢失」或「被清理」，你给出了一份不存在的「干净」结论；若真实成因是「采集范围未覆盖」，委托方会认为你在现场就没有采全证据，责任在你。

**核查**：区分**四种表述**，不要混用：

| 情形 | 正确表述 |
|---|---|
| 机制未启用（配置文件/目录缺失可证） | 「该机制在本机未启用」 |
| 内容随内存丢失或队列本就为空 | 「该工件在检材中为空/不存在，**因机制特性（易失）导致不可得**」 |
| 存在但被清空/截断 | 「该工件存在但已被清空，**清空时间可由文件 ctime 界定**」 |
| 采集范围未覆盖 | 「本次采集未包含该区域，**属采集局限**」 |

判定「被清空」的具体手段是看文件还在不在、大小是否为 0、以及它的 `ctime`——文件存在且大小为 0，与文件不存在，是两条完全不同的证据。

<a id="section-33"></a>

#### 陷阱 14：只查了 `/etc/passwd`，漏掉 passwd 之外的身份载体

**现象**：确认 `/etc/passwd` 无异常账户后，报告写「已确认无隐藏账户」。

**原因**：Linux 的身份不只存在于 passwd 文件里。

至少还有：LDAP/AD 集中认证（`/etc/nsswitch.conf` 的 `passwd:` 行决定用户解析顺序，passwd 只是最后一个本地兜底）、`/etc/passwd-`（备份文件，攻击者改动后不会同步）、PAM 配置（`/etc/pam.d/` 决定认证链路，可被改去劫持）、`~/.ssh/authorized_keys`（不新增账户就能建立持久访问）。

「passwd 里没多账户」和「没有隐藏访问方式」是两个完全不同的命题。

**影响**：漏掉 `authorized_keys` 影响尤其明显——它是不新增账户、不改 passwd、就能获得 root 登录权限的最常见手段。

案例里 SSH 痕迹是独立的一篇，正是因为它的价值和 passwd 层不重叠。

**核查**：身份层的完整检查至少包含四项，`passwd`/`shadow`（账户本体）、`authorized_keys` 与 `~/.ssh/config`（免密访问）、`/etc/nsswitch.conf` 与 `/etc/pam.d/`（认证链路本身）、`/etc/passwd-`（改动残留）。

```bash
# 身份载体一次性覆盖：所有用户的家目录都要查，不限于 uid>=1000
find /mnt/df/root /mnt/df/home -name authorized_keys -printf '%p %TY-%Tm-%Td %u\
' 2>/dev/null
# passwd 与 passwd- 的差异 —— 改动残留的直接判据
diff /mnt/df/etc/passwd /mnt/df/etc/passwd- 2>&1 | head
```

每一项在报告里单列结论，不要用「账户层」一个词概括。`passwd` 与 `passwd-` 的 `diff` 有输出，就是一条独立的发现（改过 passwd 却没同步备份文件，或反之）。
<a id="section-34"></a>

## 五、案例示例

<a id="section-35"></a>

### 5.1 SUID 文件的包归属反查与 ctime 定序

**场景**

Ubuntu Server 22.04 Web 服务器 `web01`（ext4，2 TB SATA）。委托方要求确认该机是否被入侵、是否存在持久化机制。检材 `DigiForensics.dd`（raw，全盘），ext4 分区起始扇区 1181696，现场为断电状态。**本篇起 8 篇共用这一台主机与同一条时间线。**

「取证工件地图」的作用主要在于**系统性地排除什么**，而不只是找到什么。账户层、包归属、SUID 这三类基线没跑完，任何一个冒出来的异常项都只是异常，不是发现。

**处置过程**

第 1 步，定位与只读接入：

```bash
mmls /work/DigiForensics.dd
# Slot 00  Start 0        (引导)
# Slot 03  Start 1181696  (Linux ext4)  ← 目标

mount -o loop,ro,offset=1181696,noload,noatime /work/DigiForensics.dd /mnt/df
findmnt -no OPTIONS /mnt/df
# ro,noatime,noload,loop,offset=1181696   ✓ 只读 + 未回放 journal
```

第 2 步，确认发行版家族（决定后续全部路径）：

```bash
grep -E '^(NAME|VERSION_ID)' /mnt/df/etc/os-release
# NAME="Ubuntu"    VERSION_ID="22.04"
ls -d /mnt/df/var/lib/dpkg && echo "→ Debian 系"
ls -l /mnt/df/var/log/auth.log                # 存在 → 认证日志在 auth.log
ls -l /mnt/df/var/log/secure 2>&1 | head -1  # No such file（预期，RHEL 路径不适用）
```

第 3 步，账户层异常检查：

```bash
awk -F: '$3==0 {print $1": UID 0"}' /mnt/df/etc/passwd
# root: UID 0        ← 仅 root，正常
awk -F: '$2=="" {print $1": 空口令"}' /mnt/df/etc/shadow
# （无输出）        ← 无空口令账户
stat -c '%n mode=%a owner=%U:%G' /mnt/df/etc/shadow
# /mnt/df/etc/shadow mode=640 owner=0:0   ✓ 权限正常
```

第 4 步，工件存在性清点（缺失本身就是发现）：

```bash
find /mnt/df/var/log/journal -name '*.journal' -printf '%s %TY-%Tm-%Td %p\
'
# 12058624 2024-03-18 /var/log/journal/3a7f.../system.journal
# → 持久化 journal 存在，覆盖到 2024-03-18

ls -l --time-style=long-iso /mnt/df/var/log/auth.log*
# auth.log     2024-03-18 09:41
# auth.log.1   2024-03-04 23:59   ← logrotate 轮转，有约两周历史

ls -l /mnt/df/var/spool/cron/crontabs/
# -rw------- 1 root root  383 2024-03-17 09:12  deploy
# -rw------- 1 root root  182 2024-03-18 08:40  svc-backup
```

第 5 步，全盘 SUID 清点并做包归属反查：

```bash
find /mnt/df -xdev -type f -perm -4000 -printf '%m %u:%g %TY-%Tm-%Td %p\
' 2>/dev/null | sort -k4
# 4755 root:root 2022-03-15 /usr/bin/sudo                       ← 正常
# 4755 root:root 2022-03-15 /usr/bin/passwd                     ← 正常
# 4755 root:root 2024-03-17 /tmp/.kworkerd                      ← ★ 异常

grep -l '^/tmp/.kworkerd$' /mnt/df/var/lib/dpkg/info/*.list 2>/dev/null
# （无输出）   ← 不属于任何已安装包

stat -c '%n  mode=%a  mtime=%y  ctime=%z' /mnt/df/tmp/.kworkerd
# mode=4755  mtime=2024-03-17 22:47:59  ctime=2024-03-17 22:48:20
```

第 6 步，固定证据并扩大元数据异常扫描：

```bash
cp --preserve=all /mnt/df/tmp/.kworkerd /evidence/suspicious-kworkerd
file /evidence/suspicious-kworkerd     # ELF 64-bit LSB pie executable, x86-64
sha256sum /evidence/suspicious-kworkerd | tee -a /evidence/hashes.txt
find /mnt/df/usr/local /mnt/df/tmp -xdev -newerct '2024-03-17' -printf '%m %u:%g %p\
' | sort
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 系统为 Ubuntu 22.04（Debian 系），认证日志在 `/var/log/auth.log` | `os-release` + `dpkg` 目录 + 文件存在性三源确认 | 强 |
| 账户层无植入后门账户 | UID 0 唯一、无空口令、shadow 权限正常 | 强（**仅限账户层**） |
| 存在本地提权入口 | `/tmp/.kworkerd`：root 属主 + SUID + 非包管理器内容 | 强（机制层面可解释） |
| 其 SUID 位在 2024-03-17 22:48:20 被赋予 | 文件 `ctime` 与 auth.log 的 `sudo COMMAND=/bin/chmod 4755` 行时间一致 | 强（**双源印证**） |
| 文件内容在 22:47:59 已落地 | `mtime`，早于 `chmod` 约 21 秒 | 中（无独立时间源） |

**不能证明的**：不能仅凭 SUID 位证明该文件被实际利用过提权。机制上「普通用户执行它即以 root 权限运行」成立，但**是否有人执行过**需要命令历史、审计日志或该文件自身的行为痕迹支撑。

**误判对照**

最省事也最容易错的推论是：`/tmp/.kworkerd` 的 mtime 是 22:47:59，`chmod 4755` 是 22:48:20，所以这是两次独立操作——先投放文件，另外有人又给它加了 SUID。顺着这个方向走下去，报告里就会凭空多出「存在第二个未查明的人」。

真实情况就落在那 21 秒里。ext4 写内容时会同时推进 `mtime` 和 `ctime`，两者几乎相同；随后 `chmod` 单独推进 `ctime`，只动 inode 不动数据。本案 `mtime` 22:47:59 与 `ctime` 22:48:20 相差 **21 秒**，而 auth.log 里 `sudo COMMAND=/bin/chmod 4755 /tmp/.kworkerd` 的时间戳正是 **22:48:20**——`ctime` 与日志行秒级一致，这就是同一次 `chmod` 的两个视角，不是两次独立动作。

**这个区分决定了责任归属**。读成「两个操作」，SUID 的赋予就被归给一个未查明的第三方，怀疑面凭空扩大；读成「同一次 chmod」，则能确认提权执行者就是 22:43 登录的那个 `deploy` 会话，攻击链在此闭合。

**按错误判据走的代价**：多出一个虚构的行为人，嫌疑人范围扩大，真正的攻击链被拆成两段。委托方还可能拿这个不存在的名字去追查。

第二个易错点：把「账户层无后门账户」写成「攻击者没建账户，所以可能只是内部人员误操作」。 正确判据是这个阴性结论的**范围只限账户层**。`/tmp/.kworkerd` 的存在说明攻击者走的是「合法账户 + 提权工具」这条路，不新建账户恰恰是这类攻击的典型特征，不是排除入侵的理由。报告必须并列写：「未发现后门账户，但发现本地提权入口」，不能用前者去弱化后者。

---

<a id="section-36"></a>

### 5.2 sh 层的 passwd 改写：日志时间戳与 inode ctime 的取舍

**场景**

同系列另一台主机 `db05`（Debian 12），委托方在另一案里翻出一份 `passwd` 副本，说上面「创建了一个 uid=0 的隐藏账号」，要求确认这台机器是不是同一手法。检材 `DigiForensics.dd`。**账户层工件和日志对同一事件的记述可能对不上**，而**该信哪一个，本身就是要回答的问题**。

**处置过程**

第 1 步，取账户文件的三个时间戳：

```bash
stat -c '%n  crtime=%w  mtime=%y  ctime=%z  size=%s' /mnt/df/etc/passwd /mnt/df/etc/shadow
# /mnt/df/etc/passwd  crtime=2022-05-11 09:30:00  mtime=2024-03-17 22:50:11  ctime=2024-03-17 22:50:11  size=1842
# /mnt/df/etc/shadow  crtime=2022-05-11 09:30:00  mtime=2024-03-17 22:50:11  ctime=2024-03-17 22:50:11  size=1120
```

第 2 步，看 `passwd` 的 UID 0 条目数与内容差异：

```bash
awk -F: '$3==0 {print NR": "$1}' /mnt/df/etc/passwd
# 1: root
awk -F: 'NF<7 {print NR": 字段不足 → "$0}' /mnt/df/etc/passwd
# （无输出）  ← 无结构残缺的行
wc -l /mnt/df/etc/passwd     # 31 行，与 Ubuntu 22.04 基础镜像一致
```

第 3 步，在日志里找改写账户的对应动作：

```bash
grep -iE 'usermod|useradd|groupadd|chpasswd|passwd\[' /evidence/auth-merged.txt | sed -n '/Mar 17 22:5/p'
# （无 usermod/useradd/chpasswd 行）
```

第 4 步，区分改写账户文件与读取账户文件——`authorized_keys` 那条链已经证明 22:50 有过写操作：

```bash
stat -c '%n  mtime=%y' /mnt/df/root/.ssh/authorized_keys
# /mnt/df/root/.ssh/authorized_keys  mtime=2024-03-17 22:50:12
# 与 passwd 的 mtime 22:50:11 相差 1 秒，但两者是不同文件
```

第 5 步，确认 `passwd` 内容确实无隐藏账号（逐行核 UID 唯一性）：

```bash
awk -F: '{print $3}' /mnt/df/etc/passwd | sort | uniq -d
# （无输出）  ← 无重复 UID
grep -nE '::|:0:|:1000:' /mnt/df/etc/passwd | head
# 1:root:x:0:0:root:/root:/bin/bash
# 31:svc-backup:x:999:999::/var/lib/svc-backup:/usr/sbin/nologin
```

**结论**

- **未发现 uid=0 的隐藏账号**。`/etc/passwd` 共 31 行、UID 无重复、没有字段数不足的行、只有 `root` 一个 UID 0 账户；`svc-backup` 是 UID 999 的系统服务账户，登录 shell 为 `nologin`。委托方说的「隐藏账号」在本机**不成立**。
- `passwd` 与 `shadow` 的 `mtime` 都是 2024-03-17 22:50:11，**说明那一刻这两个文件被写过**。但 `auth.log` 在对应时段没有任何 `usermod`/`useradd`/`chpasswd`/`passwd[` 记录。
- 于是本机 22:50 的 `passwd` 写入**成因不明，且没有造成内容变化**（UID 集合无重复、无异常账号）。最可能的解释是某个备份或同步类工具以 root 身份重写了内容相同的文件——注意 `authorized_keys` 的 mtime 是 22:50:12，只差 1 秒，两者同属一个 22:50 的批量写入动作。
- **结论强度限定**：本结论只能到「当前 `passwd` 文件中不存在 uid=0 隐藏账号」。它不能证明 22:50 那次写入没有做过修改后又改回——当前内容与 22:50 之前是否一致，本机没有快照可比对。

**误判对照**

这个案子的陷阱在于，一条听起来完整的推论链条：passwd 的 mtime 是 22:50:11，auth.log 里查不到任何账户变更命令，所以一定是有人绕过日志机制直接改了账户文件，存在隐蔽的账号篡改。动机合理、链条完整，因此极易被采纳。

撑住这个案子的，是三个具体事实叠在一起：

1. **文件当前内容没有任何异常。** UID 无重复、只有一个 UID 0、没有字段数不足的行，行数与基础镜像一致。**一次成功的账号篡改必然留下内容痕迹**——auth.log 没有对应命令，说明这次没走标准工具路径。
2. **`mtime` 只证明被写过，不证明被改过。** 任何以 root 身份打开并回写该文件的程序——备份、同步、配置管理工具、某些守护进程的状态保存——都会推进 `mtime` 而不改变内容。**把写入时间读成内容变更时间，是本案的核心错误。**
3. **1 秒内两个不相关文件同时被写**（`passwd` 22:50:11、`authorized_keys` 22:50:12）更像批量操作的指纹，而不是精确定向篡改。真正的定向篡改通常只动一个文件。

**按错误判据走的代价**：会凭空认定存在绕过日志的隐蔽篡改，把调查方向从「查清 22:50 那次写入到底是谁的程序干的」引向「追查隐匿行为人」。后者在本案毫无证据支撑，委托方可能因此把怀疑扩大到不该怀疑的人。正确的下一步是顺着 22:50 那个 1 秒窗口去找同批被写的其他文件（`authorized_keys` 已经是同批证据），把成因定位到具体程序。

第二个易错点：**用「日志里没有记录」直接推出「行为不存在」。** 日志缺失有多种成因：审计未启用、该服务日志不覆盖 `auth.*` facility、事件发生在日志被清空的窗口。正确判据的方向正好相反：先确认内容无异常，再用日志缺失作为「未通过标准工具路径」的旁证。顺序一反，就等于把证据缺口当成了正面发现。

---

<a id="section-37"></a>

### 5.3 反例：noload 挂载下 ext4 状态位表明 journal 未回放

**场景**

一台 ext4 工作站 `wks12`，委托方要求恢复最近一次开机前 24 小时内的活动。检材 `DigiForensics.dd`，机器在一次异常断电后被送检。**取证的接入方式本身会改变证据状态**，而这个副作用可以被检测、被量化、也可以提前避开。

**处置过程**

第 1 步，**在两种挂载方式下分别读取文件系统状态**（这是本案例的核心动作）：

```bash
# 方式 A：带 noload（不触发 journal 回放）
mount -o loop,ro,offset=1181696,noload,noatime /work/DigiForensics.dd /mnt/df-a
debugfs -R "stats" /work/DigiForensics-part3.dd 2>/dev/null | grep -iE 'state|features'
# state: clean with errors
# features: has_journal ext_attr resize_inode dir_index filetype extent 64bit

# 方式 B：若误用可回放的挂载，journal 会被内核写回
# mount -o loop,ro,offset=1181696 /work/DigiForensics.dd /mnt/df-b
# → 内核检测到 has_journal 且状态非 clean，会尝试回放并写入镜像
```

第 2 步，量化 journal 未回放造成的证据不可见范围：

```bash
ls -l --time-style=full-iso /mnt/df-a/var/log/journal/*/system.journal
# -rw-r----- 1 root root 8388608 2024-06-11 09:52:14+08:00 system.journal
# 断电时刻 09:52，之后未再写入 → 断电前最后 30 分钟无 journal 记录

stat -c '%n  mtime=%y' /mnt/df-a/var/log/auth.log
# /mnt/df-a/var/log/auth.log  mtime=2024-06-11 09:47:02+08:00
# 与 journal 差 5 分钟 → 断电前最后的写入点
```

第 3 步，用纯文本日志补齐这 5 分钟的可查性：

```bash
tail -5 /mnt/df-a/var/log/auth.log
# Jun 11 09:46:58 wks12 sshd[2201]: session closed for user kmartin
# Jun 11 09:47:02 wks12 systemd-logind[812]: New session 41 of user kmartin
# → 09:47:02 是最后落盘点，之后到 09:52 断电之间无任何日志源
```

第 4 步，确认未回放 journal 的原因（正常行为还是异常）：

```bash
grep -rnE 'System clock|recover|journal' /mnt/df-a/var/log/auth.log /mnt/df-a/var/log/syslog 2>/dev/null | tail -5
# Jun 11 09:12:03 wks12 systemd-logind[812]: System clock is set forward by 2.114000 seconds
# → 断电前 40 分钟发生过一次时钟校正，非断电成因
```

**结论**

- 文件系统状态 `clean with errors` + `has_journal` 特征位，说明这是一次未正常卸载的断电现场，journal 中存在尚未回放的事务。本分析全程使用 `noload` 挂载，原始 journal 内容在镜像中保持原状，这是正确的接入方式。
- **可查范围**：`auth.log` 覆盖到 2024-06-11 09:47:02，journal 覆盖到 09:52:14。因此断电前 09:47:02 至 09:52:14 这 5 分 12 秒内，没有任何日志源留下记录——这不是「无活动」，而是**该窗口的日志尚在未回放的 journal 里**。
- 该窗口的证据**理论上可恢复**，前提是**在受控环境下让内核回放 journal**（对镜像副本操作，绝不在原件上）。这属于进阶操作；本篇的 `noload` 策略**主动放弃了这一窗口**，换取原始状态的零污染。这是取证中的显式取舍，必须写进报告，而不是默默略过。
- 委托方问题的答复：「2024-06-11 09:47:02 之前的活动可完整重建；09:47:02–09:52:14 存在证据缺口，成因是未回放的 ext4 journal；若需覆盖该窗口，须在副本上执行 journal 回放。」

**误判对照**

这里有个只差一步的错误结论：机器 09:52 断电，journal 文件的 mtime 是 09:52:14，说明断电前的日志都完整保存了，那段时间可查。推理链条看着没问题，错在把文件被写到的最后时刻，当成了日志内容覆盖到的最后时刻。

真正的判据是 `state: clean with errors` 这个状态位，它的含义正是**文件系统有未回放的 journal**。这个位存在时：

- journal **文件本身**存在且被内核持续写入，所以 `mtime` 会一直跟到断电那一刻（09:52:14）；
- 但文件里最新的、已完成的事务记录，其时间戳是 09:47:02 那个事件；
- 09:47:02–09:52:14 之间的事务**在 journal 中处于未提交状态**，常规只读路径（`noload` 挂载）**看不到它们**。

换句话说，`mtime` 是 journal 最后被写的时间，auth.log 最后一行是最后一条已提交事件的时间，**两者相差 5 分钟，正是未回放事务量的直接体现**。这个差值不是误差，是待恢复数据的体量指标。

**按错误判据走的代价**：报告向委托方承诺一个实际不存在的证据覆盖范围。若委托方据此认为断电前 5 分钟无异常，而该窗口内恰好有一次关键的外接设备接入，就会造成实质性的错误排除——**更糟的是这类错误在质证环节几乎无法被发现**，因为报告里所有引用的时间戳都真实存在，只是覆盖边界被夸大了 5 分钟。

第二个易错点：看到 `clean with errors` 就断定文件系统被破坏、数据不可信。 正确判据是：ext4 的 journal 机制本来就是为崩溃一致性设计的，`clean with errors` 表示**已提交的数据是完整的、可以完全信赖**，只是未提交的那部分还没被应用。写成「文件系统损坏、数据不可信」，会导致整台机器的证据被无谓地降级。

---
<a id="section-38"></a>

## 六、扩展阅读方向

<a id="section-39"></a>

### 前置基础：地图成立的前提

- [只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md) —— loop 设备挂载与 `noload` 语义。**本篇所有清点动作的前提**，读之前必须先确认是只读接入。
- [镜像制作](../../imaging/imaging-acquire/imaging-acquire-disk-imaging-and-evidence-preservation.md) —— 写入阻断与哈希校验。**证据地图的起点是一份可验证的镜像**，跳不过去这一步，后面所有结论都缺保管链支撑。
- [ext4 结构与 inode](../../filesystem/filesystem-unix/filesystem-unix-ext4-inode.md) —— 目录项分离、inode 字段与挂载选项。**本篇的路径判断要落到 inode 层才准确**，「目录里看不到」不等于数据不存在。
- [证据文件格式](../../fundamentals/fundamentals-chain/fundamentals-chain-dd-e01-aff4-evidence-formats.md) —— 镜像与哈希的标准化承载格式，决定清点结果能否被复核。

<a id="section-40"></a>

### 同层深入：把地图上的每一类展开成可操作的方法

- [系统日志深度分析](../computer-log/computer-log-system-log-analysis.md) —— 日志这一类的完整链路：落盘确认、格式判别、轮转归档。**读本篇前先确知路径由发行版家族决定**。
- [计划任务与持久化痕迹](computer-persistence-scheduled-tasks-and-persistence.md) —— 自动启动机制的逐项排查清单。**地图上标了「参见 04」的那几行是本篇的落点。**
- [SSH 痕迹与密钥取证](computer-persistence-ssh.md) —— `authorized_keys`、`known_hosts` 与登录记账三库。
- [包管理器与软件清单](computer-persistence-package-manager-and-software-inventory.md) —— 从账本反推主机功能，并发现非包管理的文件。
- [Shell 痕迹与命令历史](../computer-shell/computer-shell-shell.md) —— `.bash_history` 与 `.zsh_history` 的定位与解析。
- [时间线重建](../computer-log/computer-log-linux-timeline-reconstruction.md) —— 把散落的时间点收敛成可对齐的一条线。**本篇提供时间字段，可信度判断在那一篇。**

<a id="section-41"></a>

### 相邻议题：别的系统上的同类问题

- [取证工件地图](../computer-registry-log/computer-registry-log-windows-artifact-map.md) —— Windows 侧。两边对照看，能立刻理解「有集中入口」和「没有集中入口」对排查成本的影响——Windows 的地图可以按 hive 与 evtx 分类，Linux 只能按记录者分类。
- [取证工件地图](../computer-security/computer-security-security-artifact-map.md) —— macOS 侧。`~/Library` 的分层逻辑与 Linux 的 `/var` 分层并不对应，路径直觉不能直接搬。
- [proc 虚拟文件系统取证](../computer-shell/computer-shell-proc.md) —— 地图上唯一标注「离线读不到」的一类。**它决定了你能否回答「案发当时有哪些进程在跑」**，这是地图本身给不了的能力。

<a id="section-42"></a>

### 工具与规范：清点动作的操作边界

- [远程勘验与在线取证](../../imaging/imaging-acquire/imaging-acquire-remote-evidence-collection.md) —— 活系统上清点与离线镜像清点的能力差异。**在线清点会写访问时间，破坏的正是你要测的对象。**
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 保全优先与黄金规则。

<a id="section-43"></a>

### 判据与反例：哪些「找不到」必须写成限定结论

- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— 工件缺失本身就是痕迹的另一种形态。**该篇讲的是痕迹被清之后如何识别**，与本篇「清点后如何解读缺失」是同一个问题的两半。
<a id="section-44"></a>

## 七、命令速查

```bash
# ===== 环境（Ubuntu 22.04 分析机）=====
sudo apt install sleuthkit e2fsprogs file xxd util-linux

# ===== 1. 确认发行版家族（第一步，不可跳过）=====
grep -E '^(NAME|VERSION_ID|ID)=' /mnt/df/etc/os-release
ls /mnt/df/etc/debian_version /mnt/df/etc/redhat-release 2>/dev/null
ls -d /mnt/df/var/lib/dpkg /mnt/df/var/lib/rpm 2>/dev/null
ls -l /mnt/df/var/log/auth.log /mnt/df/var/log/secure 2>&1

# ===== 2. 只读挂载（核心：ro + noload + noatime）=====
mmls /work/DigiForensics.dd
sudo mount -o loop,ro,offset=1181696,noload,noatime /work/DigiForensics.dd /mnt/df
findmnt -no OPTIONS /mnt/df          # 必须含 ro / noload / noatime

# ===== 3. 账户层 =====
cut -d: -f1,3,4,6,7 /mnt/df/etc/passwd
awk -F: '$3==0 {print $1": UID0"}' /mnt/df/etc/passwd
awk -F: '$2=="" {print $1": 空口令"}' /mnt/df/etc/shadow
stat -c '%n size=%s mode=%a mtime=%y' /mnt/df/etc/shadow
sha256sum /mnt/df/etc/shadow /mnt/df/etc/passwd

# ===== 4. 权限位异常 =====
find /mnt/df -xdev -perm -4000 -type f -printf '%m %u:%g %TY-%Tm-%Td %TH:%TM  %p\
'
find /mnt/df -xdev -perm -2000 -type f -printf '%m %u:%g %p\
'
find /mnt/df -xdev -perm -0002 -type f -not -path '*/tmp/*' -not -path '*/run/*' \
  -printf '%m %u:%g %p\
'

# ===== 5. /tmp 与 /var/tmp =====
grep -E ' /tmp | /var/tmp ' /mnt/df/etc/fstab     # 判断 tmpfs
find /mnt/df/tmp /mnt/df/var/tmp -xdev -printf '%TY-%Tm-%Td %TH:%TM %m %u:%g %s %p\
' | sort | tail -60
find /mnt/df/tmp /mnt/df/var/tmp -xdev -type f -executable -printf '%m %u:%g %p\
'

# ===== 6. 关键目录批量存在性清点 =====
for p in /var/log/journal /var/log/btmp /var/log/wtmp /run/utmp \
         /var/log/apt/history.log /var/spool/cron/crontabs \
         /etc/cron.d /etc/systemd/system /etc/ld.so.preload \
         /root/.ssh/authorized_keys; do
  [ -e "/mnt/df$p" ] && echo "存在  $p" || echo "缺失  $p"
done
find /mnt/df/var/log -maxdepth 1 -name '*.gz' -printf '%TY-%Tm-%Td %p\
'   # logrotate 归档

# ===== 7. 校验 =====
umount /mnt/df
sha256sum -c /evidence/evidence.sha256
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — Linux 取证 — 取证工件地图」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《取证工件地图》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-mem.raw` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
