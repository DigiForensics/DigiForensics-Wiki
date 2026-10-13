---
title: "计划任务与持久化痕迹"
slug: "computer-persistence-scheduled-tasks-and-persistence"
canonical: "https://www.digiforensics.cn/wiki/computer-persistence-scheduled-tasks-and-persistence"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:51+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "computer"
space: "计算机取证"
node_path: ["持久化机制"]
---

# 计划任务与持久化痕迹

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/computer-persistence-scheduled-tasks-and-persistence)

<a id="section-1"></a>

## 一、概述

"开机自动运行"这件事被分散在十几个互不相干的位置，每个位置有各自的格式、不同的加载时机、不同的日志记录方式。

**由此产生一个取证上的特点**：攻击者建立持久化时几乎不写任何日志。

结果是"日志沉默、痕迹清晰"——要判断有没有被植入持久化，不能等日志，而要直接读配置。

这一层处在**分析环节的主机侧行为认定层**，在 [取证工件地图](computer-persistence-persistence-artifact-map.md) 之后、[时间线重建](../computer-log/computer-log-linux-timeline-reconstruction.md) 之前完成输入准备。它与其他两类的差别在三个属性上：

| 证据类型 | 是否依赖日志 | 依赖断电保护 | 清理成本 |
|---|---|---|---|
| `auth.log` 登录记录 | ✅ 强依赖 | ✅ 是 | 低（可截断） |
| `bash_history` 命令 | ✅ 强依赖 | ✅ 是（正常退出才落盘） | 低（可删） |
| **持久化配置** | ❌ **不依赖** | ❌ **不依赖** | **高（改了要逐个恢复）** |

只要攻击者建立了持久化，痕迹就躺在 `/etc`、`/var/spool`、`/home` 的某个目录里等着被读。 攻击者清理它的成本远高于留下它的成本。

具体要过的检查项有这些，每一类给出「位置 → 格式 → 排查命令 → 异常判据」，照着逐项过一遍即可，通读没有意义：

- **cron 五类位置** —— `/etc/crontab`（系统级）、`/etc/cron.d/`（片段式，**含用户名字段**）、`/var/spool/cron/crontabs/<用户>`（用户级）、`/etc/cron.{hourly,daily,weekly,monthly}/`（目录式）、`at` / `batch`（`/var/spool/cron/atjobs/`）。**五处格式不同，混读会漏**
- cron 的环境变量行 `SHELL=` / `PATH=` —— **攻击者常在这里改 `PATH` 劫持相对路径命令**，格式上只是一行环境变量，不看内容会漏
- systemd unit 与 `.wants` 软链 —— 只有存在 `.wants/` 下的软链才算"已启用"，unit 文件放在 `/etc/systemd/system/` 但没被 enable 的不算
- systemd `drop-in` 覆盖（`*.d/`） —— 在原 unit 基础上追加指令。**只看主 unit 文件会漏掉这部分**
- **profile 注入系列** —— `~/.bashrc`、`~/.bash_profile`、`/etc/profile`、`/etc/profile.d/*.sh`、`/etc/environment`。`profile.d` 下的任意 `.sh` 都会被每个登录 shell 执行
- **`BASH_ENV` 与 `ENV`** —— **不写进任何配置文件的注入**。由用户在环境里指定，指向任意脚本；**只看配置文件永远发现不了**
- motd 脚本 `/etc/update-motd.d/` —— 登录显示提示前执行。命名可任意伪装成 `88-sshfp` 这类像系统组件的名字
- `/etc/rc.local`、`/etc/init.d/` —— 传统启动脚本
- `/etc/modules-load.d/*.conf` 与内核模块 —— 内核级加载
- **`/etc/ld.so.preload`** —— **影响面最大的隐蔽持久化**：指定动态链接器预加载的 .so，对几乎所有动态链接程序生效，且不在任何进程列表里出现。文件不存在是重要阴性发现
- **SUID / SGID 位** —— 权限位本身即痕迹。`chmod 4755` 会更新 `ctime` 而不动 `mtime`，时间戳差值能定位赋值时刻
- **包管理器清单** —— `dpkg` / `rpm` 的已安装列表。"文件不属于任何已安装包"是判定清单外文件的一条客观判据（成立条件见 3.6 与陷阱 15）
- **载荷文件本身** —— cron 命令、unit 的 `ExecStart`、`pam_exec.so` 参数指向的脚本。`/usr/local/bin/.cache/` 这类伪装路径的共用性是自动化工具的典型特征
- `/home/<user>/.ssh/authorized_keys` —— 公钥持久化。追加公钥时 `crtime` 保持原值而 `mtime` 更新，据此可区分"新建"与"篡改"

走完这张表能回答的是：这台机器上存在哪些持久化配置、每条配置指向什么载荷、哪些文件不属于任何已安装包、**以及攻击者建立了哪几类持久化、用了什么统一路径**。

不能回答的必须说清：

- **"配置存在"不等于"已实际执行过"** —— **这是最重要的一条边界**。持久化配置证明的是"已建立"，运行记录要看 journal；机器断电时**只有配置证据、没有运行证据**
- **"排查为空"不等于"确定没有"** —— 阴性发现的强度只能到"未见"，第五章案例里 `rc.local`、自定义模块、`at` 任务三项都标注为"中（阴性，仅'未见'非'确定无'）"
- **载荷是否可执行、是否仍在磁盘** —— 配置指向的路径可能已被删除，**路径存在性要单独确认**
- **是谁建立的** —— 配置文件的属主与时间戳能给方向，**但没有用户身份记录**。要归因靠 [SSH 痕迹与密钥取证](computer-persistence-ssh.md) 与 [系统日志深度分析](../computer-log/computer-log-system-log-analysis.md)
- **容器与编排层面的持久化** —— Docker restart 策略、`--privileged`、K8s CronJob 属另一层机制，不在文本排查范围内
- **内核级与 UEFI 变种** —— initramfs 篡改、UEFI 启动项需要专用工具，同样不在文本排查范围内

前提有三项：知道 Linux 目录结构与文件权限语义（`/etc` 属 root、`-rwsr-xr-x` 每一位的含义）、理解 systemd 单元的基本概念，以及**先完成只读接入再排查**。

最后一条是硬性的：`/etc`、`/var/spool/cron`、`/home` 全部需要 root 才能读，**很多操作又会写访问时间或生成新文件**。直接对原始分区或错误的挂载方式动手，会在排查开始前就污染痕迹。

排查项很多，实际委托里时间往往不够，**必须能判断哪些项可以略过**。2.1 那张"按加载时机分类"的表就是排序依据——**登录时执行 > 定时执行 > 开机执行**，越靠前的位置触发频次越高、留痕越难。

<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 持久化位置全景（按"何时被加载"分类）

| 加载时机 | 机制 | 位置 | 是否需要 root |
|---|---|---|---|
| **登录 shell 启动时** | profile 系列 | `~/.bashrc`、`~/.bash_profile`、`/etc/profile`、`/etc/profile.d/*.sh`、`/etc/environment` | 部分 |
| **非登录 shell 启动时** | `BASH_ENV` / `ENV` | 指向任意可执行脚本 | 否（由用户自己设） |
| **登录时显示提示前** | motd 脚本 | `/etc/update-motd.d/`、`/etc/motd` | 是 |
| **定时（周期）** | cron | `/etc/crontab`、`/etc/cron.d/`、`/var/spool/cron/crontabs/`、`/etc/cron.{hourly,daily,weekly,monthly}/` | 是 |
| **定时（一次性）** | at / batch | `/var/spool/cron/atjobs/` | 是 |
| **服务启动时** | systemd unit | `/etc/systemd/system/`（含 `.wants/`）、`/lib/systemd/system/`、`/usr/lib/systemd/system/` | 是 |
| **定时（systemd）** | systemd timer | `*.timer` + 对应 `*.service` | 是 |
| **系统引导（旧机制）** | init 脚本 / rc.local | `/etc/init.d/`、`/etc/rc.local`、`/etc/rc*.d/` | 是 |
| **每次动态链接时** | **`ld.so.preload`** | `/etc/ld.so.preload` | 是 |
| **内核加载时** | 内核模块 | `/etc/modules-load.d/`、`/etc/modules` | 是 |
| **执行文件时** | SUID / SGID 位 | 任意可执行文件的权限位 | 是 |

> **读法**：从下往上，隐蔽性递增。`crontab` 是明文、显眼；`ld.so.preload` 和 `BASH_ENV` **在正常运维中几乎不会被检查**，但影响面最大——`ld.so.preload` 作用于**每一个动态链接的进程**。

<a id="section-4"></a>

### 2.2 cron：五类位置与各自格式

**cron 是文本可读、无需专用工具的持久化载体**，它有五个不同的位置，**格式各不相同**。

混淆它们是常见错误。

| 位置 | 格式 | 触发者 | 说明 |
|---|---|---|---|
| `/etc/crontab` | **有用户字段**（7 字段含 user） | 系统 | 唯一的"系统主"crontab |
| `/etc/cron.d/` | **有用户字段** | 系统 | **文件名规则因发行版而异**：Debian 系 cron 只接受 `[A-Za-z0-9_-]`，**含 `.` 会被忽略**；部分 RHEL 系（cronie）版本允许 `.`。**以目标系统实测为准** |
| `/etc/cron.hourly/` | **无用户字段、无时间字段** | 系统 | run-parts 每天执行目录内脚本 |
| `/etc/cron.daily/`（weekly/monthly 同理） | 同上 | 系统 | 同上 |
| `/var/spool/cron/crontabs/<user>` | **有用户字段**（**冗余**，字段是用户名） | `crond` | **各用户自己的 crontab**；`crontab -l` 读的就是它 |

**三种带用户字段的格式**（空格分隔，注意 `user` 位置不同）：

```
# /etc/crontab 格式：分 时 日 月 周  user  命令
17 2   * * *   root   /usr/bin/find /var/spool -mtime +30 -exec rm {} \;

# /etc/cron.d/fragment 格式：同 /etc/crontab
*/5 * * * *   deploy  /usr/local/bin/sync-job.sh

# /var/spool/cron/crontabs/deploy 格式：分 时 日 月 周  命令（**user 字段被省略**）
*/10 * * * *  /usr/local/bin/sync-job.sh
```

> ⚠️ **用户 crontab 不写用户字段**，因为文件名就是用户名。把 `/var/spool/cron/crontabs/` 里的文件按 `/etc/crontab` 解析会错位一列。

**环境变量陷阱**：`crontab` 的环境是**极简的**（几乎只有 `HOME`、`LOGNAME`、`PATH`、`SHELL`），**没有 `TERM`，很多交互程序会报错**。

因此攻击者常用两条规避写法：`.* * * * * /dev/shm/payload` 或在命令前加 PATH 赋值。

看到 crontab 里有 `.` 作为时间字段、或命令里带绝对路径/`env`，都值得多看一眼。

**日志**：cron 的执行记录在 `/var/log/syslog`（Debian 系）/ `/var/log/cron`（RHEL 系），关键字是 `CRON[...]`。

**但只有 cron 服务本身在跑时才有**——如果攻击者顺手停了 rsyslog，cron 日志也没了。不要把"cron 日志缺失"当"cron 没跑"。

<a id="section-5"></a>

### 2.3 systemd unit 与 timer

现代持久化主要走 systemd。有三个目录，**优先级和归属不同**：

| 目录 | 归属 | 用途 |
|---|---|---|
| `/etc/systemd/system/` | **管理员**（本地） | 自定义 unit 放这里；也是启用自启（`.wants/` 软链）的位置 ★ |
| `/run/systemd/system/` | 运行时 | 重启后消失，不持久（**若此目录有 unit，说明是当次启动注入的**） |
| `/lib/systemd/system/`（新版 `/usr/lib/systemd/system/`） | **发行版包提供** | 随包安装；**出现在此目录但不属于任何已安装包 = 可疑** ★ |

`.wants` 目录是 systemd 启用机制的核心：

```
/etc/systemd/system/multi-user.target.wants/
├── ssh.service -> /lib/systemd/system/ssh.service        ← 正常
├── nginx.service -> /lib/systemd/system/nginx.service    ← 正常
└── sysupdate.service -> /etc/systemd/system/sysupdate.service  ← ★ 可疑：指向 /etc 下的自定义 unit
```

**判定规则**：软链目标在 `/etc/systemd/system/` 且**该 unit 不属于任何已安装软件包**（用第 07 篇的包清单方法核对）→ **高度可疑的自定义自启服务**。

**timer 与 service 是配对的**：

```
# /etc/systemd/system/sysupdate.timer
[Unit]
Description=System Update
[Timer]
OnBootSec=5min
OnUnitActiveSec=1h          # 每小时触发
[Install]
WantedBy=timers.target

# /etc/systemd/system/sysupdate.service（被 timer 唤起）
[Unit]
Description=System Update
[Service]
Type=oneshot
ExecStart=/usr/local/bin/.cache/sysupdate
```

> **取证要点**：`OnCalendar=` 形式（如 `OnCalendar=*-*-* 00,12:00:00`）比 `OnUnitActiveSec=` 更隐蔽——**不写就看不出触发周期**。查 timer 时必须同时看对应的 `.service` 的 `ExecStart`，那才是真正执行的命令。

**日志**：`systemd` 单元的启动/停止在 journal 里，**关键字是单元名**（`journalctl -u <unit>`）。但同样，journal 在哪、是否被清，取决于[第 02 篇](../computer-log/computer-log-system-log-analysis.md)说的存储模式。

<a id="section-6"></a>

### 2.4 profile 注入：最容易被忽略的一类

**每次用户登录 bash 都会读一批文件**。

在这些文件里加一行，就是"登录即执行"。这类持久化**不留任何 cron/systemd 痕迹**，且在海量文件中极易漏检。

| 文件 | 何时被读 | 适用 |
|---|---|---|
| `/etc/profile` | **登录 shell** 启动 | 系统级，所有用户 |
| `/etc/profile.d/*.sh` | 同上（被 `/etc/profile` 逐个 source） | 系统级，**推荐按服务分文件，排查时逐个过** |
| `/etc/bash.bashrc` | **交互式非登录** shell | Debian/Ubuntu 系统级 |
| `~/.bashrc` | 交互式非登录 shell | 用户级 |
| `~/.bash_profile` / `~/.profile` | **登录 shell** | 用户级（Ubuntu 默认 `~/.profile`） |
| `~/.bash_login` / `~/.bash_logout` | 登录 shell / 登出 | 用户级（少见） |
| `/etc/environment` | **PAM 环境**（不是 shell 读） | 系统级；改环境变量 |

> ⚠️ 登录 shell 与非登录 shell 读的文件不同：SSH 登录进来是**登录 shell**，读 `~/.bash_profile` / `~/.profile`（不是 `~/.bashrc`，除非被 source）；而 `ssh host "command"` 形式是**非登录 shell**，只读 `~/.bashrc`。**排查时两类都要看。**

**`/etc/environment` 值得单独说**：它由 PAM（不是 shell）读取，只接受简单的 `KEY=VALUE` 格式。**它的存在会让"环境变量持久化"生效**，包括 `LD_PRELOAD`（见 2.7）。

<a id="section-7"></a>

### 2.5 `BASH_ENV` 与 `ENV`：不写进任何配置文件的注入

这是**技术上最隐蔽**的一类，因为**痕迹不在文件里，在环境变量里**。

- **`BASH_ENV`**：当 bash 作为**非交互式 shell**（执行脚本 `bash script.sh`）启动时，会 source 这个变量指向的文件。
- **`ENV`**：对 POSIX `sh`（及某些 shell）的等价机制。

**取证含义**：如果 `/etc/environment`、某个 `~/.bashrc`、或某个进程的 `/proc/<pid>/environ` 里出现 `BASH_ENV=/path/to/script`，那么执行任何非交互式 bash 脚本都会先跑那个脚本。判定方法：搜配置里的 `BASH_ENV` / `ENV=` 赋值，**并**在 `/proc/*/environ` 里找（在线取证时，见[第 06 篇](../computer-shell/computer-shell-proc.md)）。

<a id="section-8"></a>

### 2.6 SUID / SGID 与内核模块

**判定 SUID 恶意性的三条规则**（缺一不可）：

1. **不在包管理器清单里**（用 `*.list` / RPM 数据库核对，见[第 07 篇](computer-persistence-package-manager-and-software-inventory.md)）——这一条可独立验证，且不受文件位置影响。
2. 位置在 `/tmp`、`/var/tmp`、`/dev/shm`、`/home`、`/var/www` 等可写目录——系统 SUID 文件从不出现在这里。
3. **`ctime` 远晚于 `mtime`**——只改了权限位（`chmod +s`）而未改内容，是"赋权"而非"安装"的特征。

**内核模块**：`/etc/modules-load.d/*.conf`（Debian/Ubuntu）、`/etc/modules`（RHEL）、`/etc/modprobe.d/`。检查是否有**非常规 `.ko` 文件**（同样用包清单核对——内核模块几乎都来自 `linux-modules-*` 包）。加载的模块在 `/proc/modules`（仅在线）和 `lsmod` 可见。

<a id="section-9"></a>

### 2.7 `ld.so.preload`：影响面最大的隐蔽持久化

**机制**：动态链接器（`ld.so`）在启动**每个**动态链接的可执行文件时，都会读取 `/etc/ld.so.preload`，把里面列出的每个 `.so` 文件**预先加载**到这个新进程里。

**它的四个特征**：

- **作用于每一个动态链接进程**（包括 `ls`、`ps` 等几乎所有命令行工具本身）。
- **不需要任何 root 之外的配合**——写一次 `/etc/ld.so.preload` 就够了。
- **在正常运维中几乎不被检查**——它是一个"编译期优化"配置文件，管理员很少看。
- **容易漏检**——`.so` 文件可伪装成正常库名，且不在包清单里，很容易被忽略。

**取证判定**：

1. `/etc/ld.so.preload` **存在且非空** → 高度可疑（干净系统上这个文件通常不存在，或为空）。
2. 文件里列的 `.so` 路径**是否在包清单里**——**列出系统 lib 目录之外的路径 = 恶意**。
3. 该文件自身的 `mtime`/`ctime`/属主（`root:root`，权限 644）也是独立证据。

> ⚠️ **本篇只讲检测。** 不复现劫持手法，不给出绕过方法。

<a id="section-10"></a>

### 2.8 motd / init 脚本 / rc.local

| 位置 | 触发时机 | 要点 |
|---|---|---|
| `/etc/motd` | 登录时显示提示前 | 应是纯文本；若含 `$(...)` 或可疑命令需警惕 |
| `/etc/update-motd.d/` | 登录时（Debian/Ubuntu） | 目录下是**可执行脚本**（`00-`、`50-` 编号）；**多出的、不属任何包的脚本 = 可疑** |
| `/etc/update-motd.conf` | 同上 | 配置里 `ENABLED=` 引用了哪些脚本 |
| `/etc/init.d/` | 引导时（SysV 遗留） | **RHEL 系**在 `/etc/rc.d/init.d/`（软链至此）。**清单外脚本 = 可疑** |
| `/etc/rc.local` | 引导末期 | `#!/bin/sh` + 命令；若发行版不用它，**非空即可疑** |
| `/etc/rc*.d/` | 引导时 | SysV 的 runlevel 软链目录（Debian 系） |

> `/etc/update-motd.d/` 值得强调：这个目录里的脚本在**每次 SSH 登录时执行**，且**它的存在不写在任何"自启"配置里**——`systemctl list-unit-files` 看不到。排查时必须单独 `ls` 这个目录并与包清单核对。

---

<a id="section-11"></a>

## 三、操作步骤：逐项排查清单

> **用法**：把下面每一项当作一个检查点逐条跑。每项给出「位置 / 排查命令 / 异常判据」。建议把输出统一重定向到 `/evidence/persistence-*.txt` 留档。

<a id="section-12"></a>

### 3.1 cron 全面排查

```bash
# (1) 系统主 crontab
cat /mnt/df/etc/crontab

# (2) 系统级片段 /etc/cron.d/（注意文件名合法性）
ls -la /mnt/df/etc/cron.d/
for f in /mnt/df/etc/cron.d/*; do echo "== $f =="; cat "$f"; done

# (3) 所有用户 crontab
ls -la /mnt/df/var/spool/cron/crontabs/
for f in /mnt/df/var/spool/cron/crontabs/*; do echo "== $f =="; cat "$f"; done

# (4) 周期目录脚本（hourly/daily/weekly/monthly）
ls -la /mnt/df/etc/cron.{hourly,daily,weekly,monthly}/
for d in hourly daily weekly monthly; do
  for f in /mnt/df/etc/cron.$d/*; do [ -f "$f" ] && echo "$f"; done
done

# (5) 一次性别漏：cron 的其它 spool
ls -la /mnt/df/var/spool/cron/
```

**异常判据**：

| 判据 | 说明 |
|---|---|
| crontab 里的命令在 `/tmp`、`/dev/shm`、`/var/tmp` | 载荷暂存地，强烈可疑 |
| **`.` 作为分/时/日/月/周字段**（`.* * * * * cmd`） | 借"每分钟"语义但写成通配，**常见于刻意伪装** |
| **cron.d 里有含 `.` 的文件名** | Debian 系 cron 会**静默忽略**（不执行、不报错）——可能是被停用的旧任务，也可能是"写了但根本没生效"的伪装 |
| 用户 crontab 里的命令属 root 但用户是普通账户 | 提权残留 |
| **cron.d 片段里的命令不在任何包清单** | 载荷 |
| **周期目录脚本的 mtime 与其他脚本明显不同** | 后期加入 |

<a id="section-13"></a>

### 3.2 at / batch 一次性任务排查

```bash
# Debian 系 / RHEL 系位置相同
ls -la /mnt/df/var/spool/cron/atjobs/
# 文件名即 job id，内容是待执行脚本
for f in /mnt/df/var/spool/cron/atjobs/*; do
  [ -f "$f" ] || continue
  echo "== job $f =="; cat "$f"
  stat -c 'mtime=%y owner=%U' "$f"
done

# spools 目录（at/batch 各一个）
ls -la /mnt/df/var/spool/cron/ | grep -E 'atjobs|atspool'
```

**异常判据**：`atjobs` 目录**非空** = 有排定的未来任务。**攻击者常用 `at` 一次性执行**（不留 crontab 常驻痕迹）。**注意区分** `atjobs`（待执行脚本）与 `atspool`（已执行完但结果未取走的输出）。

<a id="section-14"></a>

### 3.3 systemd 自启与 timer 排查

```bash
# (1) 所有 unit 文件（系统 + 自定义 + 运行时）
find /mnt/df/etc/systemd/system /mnt/df/lib/systemd/system /mnt/df/usr/lib/systemd/system \
     -name '*.service' -o -name '*.timer' 2>/dev/null | sort

# (2) ★ 关键：所有自启软链，标注目标
for d in /mnt/df/etc/systemd/system/*.wants /mnt/df/etc/systemd/system/*.requires; do
  [ -d "$d" ] || continue
  ls -l "$d"
done 2>/dev/null

# (3) 关注指向 /etc 的软链（自定义服务）
find /mnt/df/etc/systemd/system -name '*.wants' -type d -exec ls -l {} \; \
  | grep -E '\-> /etc/'

# (4) 所有 timer 及其配对 service
find /mnt/df/etc/systemd/system -name '*.timer' 2>/dev/null | while read t; do
  echo "== $t =="; cat "$t"
  s="${t%.timer}.service"; [ -f "$s" ] && { echo "-- ExecStart --"; grep -A5 '\[Service\]' "$s"; }
done

# (5) 运行时注入（重启即失）
ls /mnt/df/run/systemd/system/ 2>/dev/null

# (6) 全盘 ExecStart 汇总，快速看有没有指向临时目录的
grep -rhE '^Exec(Start|Pre|StartPost)=' \
  /mnt/df/etc/systemd/system /mnt/df/lib/systemd/system /mnt/df/usr/lib/systemd/system 2>/dev/null \
  | sort -u | grep -E '/tmp/|/dev/shm/|/var/tmp/|/home/'
```

**异常判据**：

| 判据 | 说明 |
|---|---|
| `.wants` 软链目标在 `/etc/systemd/system/` | 自定义服务启用 ★ |
| **该 unit 不属于任何已安装包** | 非发行版自带 = 自定义（用第 07 篇核对） |
| `ExecStart` 指向 `/tmp`、`/dev/shm`、`/home` | 载荷路径 |
| timer 用 `OnCalendar=` 隐藏触发周期 | 需看 service 才知道执行什么 |
| `/run/systemd/system/` 非空 | 当次启动注入，重启消失（**说明有人做过临时注入**） |

<a id="section-15"></a>

### 3.4 profile 注入排查

```bash
# (1) 系统级 profile 全家桶
for f in /mnt/df/etc/profile /mnt/df/etc/bash.bashrc; do
  echo "== $f =="; grep -vE '^\s*#|^\s*$' "$f" 2>/dev/null
done

# (2) profile.d 每个文件都要看
ls -la /mnt/df/etc/profile.d/
for f in /mnt/df/etc/profile.d/*.sh; do echo "== $f =="; cat "$f"; done

# (3) /etc/environment（PAM 读，含 LD_PRELOAD 等）
cat /mnt/df/etc/environment

# (4) 所有用户 profile 系列文件
for d in /mnt/df/home/* /mnt/df/root; do
  [ -d "$d" ] || continue
  for f in .bashrc .bash_profile .bash_login .profile .zshrc .zprofile .zshenv; do
    [ -f "$d/$f" ] && { echo "== $d/$f =="; grep -nE 'BASH_ENV|ENV=|LD_PRELOAD|curl|wget|base64|/tmp/|/dev/shm|eval|nc |chmod \+s' "$d/$f"; }
  done
done

# (5) ★ 全文搜危险注入模式
grep -rnE '(BASH_ENV|LD_PRELOAD)[[:space:]]*=|^ENV=|curl [^|]*\|[[:space:]]*(ba)?sh|base64[[:space:]]+-d[^|]*\|[[:space:]]*(ba)?sh' \
  /mnt/df/etc /mnt/df/home /mnt/df/root 2>/dev/null
```

**异常判据**：

| 判据 | 说明 |
|---|---|
| `profile.d/` 里有**不属于任何包**的 `.sh`** | 清单外脚本 = 自定义注入 |
| 任何 profile 文件里出现 `curl ... \| sh`、`base64 -d \| sh` | 下载执行链 |
| 出现 `BASH_ENV=` / `ENV=` / `LD_PRELOAD=` | 环境变量持久化 ★ |
| `.bashrc` 末尾有**与本机业务无关**的网络请求 | 后门 |
| profile 文件的 `ctime` 晚于 `mtime` 且差很多 | 后期插入的行（append 不改 mtime，改 ctime） |

<a id="section-16"></a>

### 3.5 motd / init / rc.local / 模块 / ld.so.preload 排查

```bash
# (1) motd 系列
echo "== /etc/motd =="; cat /mnt/df/etc/motd 2>/dev/null
echo "== /etc/update-motd.d/ =="; ls -la /mnt/df/etc/update-motd.d/
cat /mnt/df/etc/update-motd.conf 2>/dev/null | grep -vE '^\s*#|^\s*$'

# (2) init 脚本（RHEL 在 /etc/rc.d/init.d/，Debian 在 /etc/init.d/）
ls -la /mnt/df/etc/init.d/ /mnt/df/etc/rc.d/init.d/ 2>/dev/null

# (3) rc.local / rc*.d
echo "== /etc/rc.local =="; cat /mnt/df/etc/rc.local 2>/dev/null
ls -la /mnt/df/etc/rc*.d/ 2>/dev/null

# (4) 内核模块
ls -la /mnt/df/etc/modules-load.d/ /mnt/df/etc/modprobe.d/ 2>/dev/null
grep -rhvE '^\s*#|^\s*$' /mnt/df/etc/modules-load.d/*.conf /mnt/df/etc/modules 2>/dev/null
# 找非发行版的 .ko 文件
find /mnt/df/lib/modules /mnt/df/usr/lib/modules -name '*.ko*' 2>/dev/null \
  | grep -vE 'kernel/drivers|kernel/fs|kernel/net|kernel/arch'

# (5) ★ ld.so.preload（存在且非空 = 强信号）
ls -l /mnt/df/etc/ld.so.preload 2>/dev/null
cat /mnt/df/etc/ld.so.preload 2>/dev/null
# preload 的 .so 是否在包清单里？
grep -oE '^\s*/[^ ]+\.so' /mnt/df/etc/ld.so.preload 2>/dev/null | tr -d ' ' | while read s; do
  echo "check: $s"
  grep -rlx "$s" /mnt/df/var/lib/dpkg/info/*.list 2>/dev/null | head -1 || echo "  → 不在任何包清单（可疑）"
done
```

**异常判据**：

| 位置 | 判据 |
|---|---|
| `/etc/ld.so.preload` | **存在且非空** = 强信号；所列 `.so` **不在包清单** = 强信号 |
| `/etc/update-motd.d/` | 有**不属于任何包**的可执行脚本；或 `update-motd.conf` 的 `ENABLED=` 引用了可疑脚本 |
| `/etc/rc.local` | 发行版默认不用它（`rc-local.service` masked）时，**非空即可疑** |
| `/etc/init.d/` | 清单外脚本 |
| `modules-load.d/*.conf` | 引用非发行版的 `.ko`；或配置文件本身 mtime 异常 |
| `/etc/environment` | 含 `LD_PRELOAD` |

<a id="section-17"></a>

### 3.6 SUID / SGID 复查（与包清单交叉）

```bash
# SUID
find /mnt/df -xdev -perm -4000 -type f -printf '%m %u:%g %TY-%Tm-%Td %TH:%TM %p\
' 2>/dev/null | sort
# SGID
find /mnt/df -xdev -perm -2000 -type f -printf '%m %u:%g %p\
' 2>/dev/null
# 可写目录下却有 SUID/SGID —— 强信号
find /mnt/df/tmp /mnt/df/var/tmp /mnt/df/dev/shm /mnt/df/home /mnt/df/var/www \
  -perm /6000 -printf '%m %u:%g %p\
' 2>/dev/null
```

**用包清单判定"是否官方文件"**（RHEL 系把 `*.list` 换成 `rpm -qf` 的离线等价：查 `/var/lib/rpm`）：

```bash
# Debian 系：这个 SUID 路径属于哪个包？无输出 = 不属于任何包
for p in $(find /mnt/df/tmp /mnt/df/var/tmp /mnt/df/dev/shm -perm /6000 -type f 2>/dev/null); do
  rel="${p#/mnt/df}"
  echo -n "$rel → 包: "
  grep -lx "$rel" /mnt/df/var/lib/dpkg/info/*.list 2>/dev/null | head -1 || echo "★ 不属于任何已安装包"
done
```

<a id="section-18"></a>

### 3.7 验证环节

| 验证对象 | 方法 | 通过标准 |
|---|---|---|
| cron 格式正确性 | 逐项对照 2.2 的三种格式 | 字段数与位置正确，无歧义 |
| unit 归属 | 包清单核对（见[第 07 篇](computer-persistence-package-manager-and-software-inventory.md)） | 清单外 = 标注为自定义 |
| ld.so.preload 的 `.so` 归属 | 同上 | 清单外 = 强信号 |
| 时间戳一致性 | `stat` 的 `mtime`/`ctime`/`crtime`（见[第 08 篇](../computer-log/computer-log-linux-timeline-reconstruction.md)） | 与入侵时间窗吻合才构成关联 |
| 与日志独立印证 | journal 的 `systemctl` 记录、auth.log | 至少一个独立源佐证 |

---
<a id="section-19"></a>

## 四、常见陷阱

本章按载体解析 → 加载机制 → 归属判定 → 结论表述 → 工具行为与环境前提归组，每条给出：现象、为什么会误判、误判代价、正确做法。
★ 标记表示该操作会导致原始检材永久灭失或不可逆改变，执行前必须停下来确认。

<a id="section-20"></a>

### 4.1 载体与格式解析

<a id="section-21"></a>

#### 陷阱 1：把用户 crontab 按 `/etc/crontab` 的格式解析

**现象**：读 `/var/spool/cron/crontabs/deploy`，看到 `*/15 * * * *  /usr/local/bin/sync-job.sh`，判断"每 15 分钟执行"，并据此认为第二条 `30 3 * * *  /usr/local/bin/.cache/rotate-logs.sh` 是 root 的任务。

**原因**：**用户 crontab 少一个字段。** `/etc/crontab` 和 `/etc/cron.d/` 里的片段是"分 时 日 月 周 **user** 命令"六段式，而 `/var/spool/cron/crontabs/<user>` 是"分 时 日 月 周 命令"五段式——**用户名写在文件名里，字段被省略了**。按六段式解析会整体错位一列：把 `30`（时）当成日、`3`（月）当成周，把 `/usr/local/bin/.cache/rotate-logs.sh` 当成 `user` 字段。

**影响**：错位后得到的时间调度完全错误（变成"每月 3 日的某星期"），更糟的是执行身份判断失效——你会以为这是 `rotate-logs.sh` 用户跑的任务，而实际执行身份是 `deploy`（文件所属用户）。

**攻击者正是靠这个错位隐藏自己**。

**核查**：按位置选择解析器，解析前先确认路径属于哪一类（`/etc/crontab` 与 `/etc/cron.d/` 有用户字段，`crontabs/<user>` 无用户字段）。读出后**把执行身份显式写进报告**——用户 crontab 的执行身份 = 文件名里的用户名。判据可以落到字段计数上：`/var/spool/cron/crontabs/` 下的文件，非注释非空行的字段数应为 5（`分 时 日 月 周 命令`），出现 6 个及以上字段就该怀疑多了一列或命令里含未转义空格：

```bash
# 按位置分类，逐个打印非注释行的字段数，便于快速发现格式错位
for f in /mnt/df/etc/crontab /mnt/df/etc/cron.d/* /mnt/df/var/spool/cron/crontabs/*; do
  [ -f "$f" ] || continue
  echo "== $f =="
  grep -vE '^\s*(#|$)' "$f" | awk '{print NF" 字段: "$0}'
done
# /etc/crontab 与 /etc/cron.d/*  → 6 字段起（含 user）
# /var/spool/cron/crontabs/*    → 5 字段起（无 user，身份=文件名）
```

<a id="section-22"></a>

#### 陷阱 2：把 `.cache` 之类的隐藏目录当成无害的临时目录

**现象**：`/usr/local/bin/.cache/` 下有 `rotate-logs.sh`、`sysd` 两个文件，命名完全像系统组件（轮转日志、系统守护），报告把它们归入"系统工具，正常"。

**原因**：命名伪装的前提就是"名字看起来合理"，隐藏性本身就是可疑信号。 `/usr/local/bin/.cache/` 兼具三重可疑属性：点开头的隐藏目录（正常运维不需要在 `bin` 下放隐藏目录）、不在任何包管理器清单里（系统组件必然由包提供）、载荷命名直接撞上系统领域词汇（`rotate-logs` 蹭 logrotate、`sysd` 蹭 systemd）。判读时容易被"名字像系统工具"这一层带着走。

**影响**：这类载荷藏在最常见的排查盲区里——分析者按"找异常文件"的思路去搜时，会用 `ls -l`（不含 `-a`）或者按扩展名过滤，隐藏目录直接被跳过。

案例里 `ExecStart` 指向同目录的 `sysd` 正是靠"路径一致性"这条线索才串起来的，而这条线索完全建立在"注意隐藏目录"之上。

**核查**：清点时必须用 `find` 而非 `ls`（`find` 递归且不因点开头而跳过），并把"**载荷路径是否一致**"作为一条独立检查——多条持久化共用同一目录是很强的关联信号。命名与功能不符（名字说 logs 内容是 `sleep 15`）要单独记为可疑点。展开隐藏目录的正向清点：

```bash
# /usr/local/bin 与 /opt、/srv 下的隐藏条目（-name '.*' 匹配点开头）
find /mnt/df/usr/local/bin /mnt/df/opt /mnt/df/srv -xdev -name '.*' -printf '%M %u:%g %TY-%Tm-%Td %p\
' 2>/dev/null
# 再按"可执行 + 不在任何包清单"过滤，路径一致性在这一步通常已经显现
for p in $(find /mnt/df/usr/local/bin -name '.*' -type f -perm -u+x 2>/dev/null); do
  rel="${p#/mnt/df}"
  grep -lx "$rel" /mnt/df/var/lib/dpkg/info/*.list 2>/dev/null || echo "★ 清单外且可执行: $rel"
done
```

<a id="section-23"></a>

### 4.2 加载机制与隐蔽性

<a id="section-24"></a>

#### 陷阱 3：只查 cron 和 systemd，漏掉 profile / motd 类登录时持久化

**现象**：全盘 cron 五类位置 + systemd unit + timer 全部查完，未发现异常，报告写「未发现计划任务类持久化」。

**原因**：**"计划任务"只是持久化的一种加载时机。** 2.1 的全景表按"何时被加载"分了十一类，其中至少四类不在 cron/systemd 体系内：登录 shell 启动时（profile 系列）、非登录 shell 启动时（`BASH_ENV`/`ENV`）、登录显示提示前（`/etc/update-motd.d/`）、每次动态链接时（`ld.so.preload`）。案例第 4 步的 `88-sshfp` 就在第三类里——它每次 SSH 登录都执行，却完全不出现在任何自启列表、也不写 cron。

**影响**："未发现计划任务类持久化"这个表述会让读者以为持久化面已扫全。

实际上覆盖面缺失是可被质证的：只要对方指出一个你漏掉的位置，你基于"已全面排查"的表述建立的所有排除结论一起失效。

**核查**：把"加载时机"当作检查清单的维度而非按工具分类，逐类确认：① 登录 shell（`/etc/profile`、`/etc/profile.d/*.sh`、各用户 `~/.bash_profile`/`~/.profile`）；② 交互式非登录 shell（`/etc/bash.bashrc`、`~/.bashrc`）；③ 非交互式 shell（`BASH_ENV`/`ENV`）；④ 登录显示前（`/etc/update-motd.d/`、`/etc/motd`）；⑤ 周期（cron 五位置）；⑥ 一次性（`at`）；⑦ 服务启动（systemd unit + `.wants`）；⑧ 定时（`*.timer`）；⑨ 引导（`init.d`、`rc.local`、`rc*.d`）；⑩ 每次动态链接（`ld.so.preload`）；⑪ 执行时（SUID/SGID）。**每类都要有一句"已查/未查及结果"。**

<a id="section-25"></a>

#### 陷阱 4：只查登录 shell 的 profile 文件，漏掉非登录 shell 那套

**现象**：检查了 `~/.bash_profile` 和 `~/.profile` 均无异常，认定"该用户无 profile 注入"。攻击者实际把 `BASH_ENV` 写进了 `~/.bashrc`。

**原因**：登录 shell 与非登录 shell 读的是不同的文件集合。 SSH 交互式登录进来是登录 shell，读 `~/.bash_profile`/`~/.profile`；而 `ssh host "command"` 这种非交互式调用是非登录 shell，只读 `~/.bashrc`（受 `BASH_ENV` 影响）。两者互不覆盖，所以"查了登录 shell 的文件没异常"完全不能推出"非登录 shell 的文件也干净"。

**影响**：这类注入专门躲在这个差异里。

它的作用面反而更大——**任何以非交互方式执行的 bash 脚本都会被劫持**，包括 cron 任务、Makefile、CI 脚本这类"看起来不像登录"的地方。

**核查**：两个方向都查：**文件侧**grep 所有 profile 类文件里的 `BASH_ENV`、`ENV=`、`LD_PRELOAD` 赋值；**运行态侧**在线取证时查 `/proc/<pid>/environ`（离线镜像里 `/proc` 是空的，见[第 06 篇](../computer-shell/computer-shell-proc.md)，必须明确写出这是离线检材的固有局限）。案例第 4 步用的正是 `grep -rnE '(BASH_ENV|LD_PRELOAD)[[:space:]]*='` 一次覆盖 `/etc/profile.d/` 与 `/etc/environment`。

<a id="section-26"></a>

#### 陷阱 5：看到 `*.timer` 文件就报告触发周期

**现象**：读到 `/etc/systemd/system/sysupdate.timer`，看到 `[Timer] OnBootSec=5min`，报告写"该服务每 5 分钟执行一次"。

**原因**：timer 文件描述的是"何时唤起"，真正执行什么在被它唤起的 `.service` 里。 而且触发方式不止一种：`OnUnitActiveSec=` 是"上次激活后间隔多久"（周期），`OnCalendar=` 是"日历时间点"（不写就完全看不出周期），`OnBootSec=` 只是"开机后多久首次触发"（可能之后再无触发）。案例里那个 unit 用的是 `OnUnitActiveSec=1h`，而分析者只看了 `OnBootSec` 就得出周期结论。

**影响**：触发周期判错会直接影响"攻击者能运行多久、能造成多少影响"的风险评估，也会让"清理时该先停哪个"这类建议给错。

**核查**：读 timer 必须同时读被 `Unit=` 指向的 `.service` 的 `ExecStart=`，那才是真正的载荷；`WantedBy=` 说明它被谁拉起，`Restart=`（`always`/`on-failure`）说明崩溃后会不会自己回来。周期结论只接受 `OnUnitActiveSec=`/`OnCalendar=` 的显式值，`OnBootSec` 只能说"开机后 X 秒首次触发"。三条触发指令可以一次问全：

```bash
for t in /mnt/df/etc/systemd/system/*.timer; do
  [ -f "$t" ] || continue
  echo "== $t =="
  grep -nE '^(OnCalendar|OnBootSec|OnUnitActiveSec|OnUnitInactiveSec|Unit|WantedBy)=' "$t"
  s="${t%.timer}.service"
  [ -f "$s" ] && grep -nE '^(ExecStart|Restart)=' "$s"
done
```

<a id="section-27"></a>

#### 陷阱 6：把 `/run/systemd/system/` 里的 unit 当成持久化证据

**现象**：在 `/run/systemd/system/` 发现 `evil.service`，报告写「发现攻击者植入的服务单元」。

**原因**：**`/run` 是 tmpfs，重启即清空。** 它是 systemd 的运行时状态目录，里面的 unit 是当次启动由某个动作注入的（例如现场处置时用 `systemd-run` 临时跑的分析命令、systemd-generator 生成的瞬态单元）。**它不构成跨重启的持久化。** 反过来，如果想找"重启后仍然生效"的单元，应该看 `/etc/systemd/system/`（管理员自定义，持久）。

**影响**：把瞬态单元当成持久化，会虚增"攻击者已建立长期驻留"的严重性评级。

而真正的持久化如果在 `/etc` 下，你又可能因为注意力被 `/run` 占用而漏掉。

**核查**：先按**存储位置**分类再谈持久性：`/etc/systemd/system/`（持久，管理员级）→ 重点排查对象；`/lib` 与 `/usr/lib/systemd/system/`（持久，包提供，需用包清单核对是否清单外）→ 清单外可疑；`/run/systemd/system/`（易失）→ 只能证明"本次启动期间存在过"。三类的结论强度在报告里必须区分。

<a id="section-28"></a>

### 4.3 归属判定与可执行性

<a id="section-29"></a>

#### 陷阱 7：把 `ld.so.preload` 缺失写成"未植入 preload 劫持"而不做进一步确认

**现象**：`ls /mnt/df/etc/ld.so.preload` 返回 No such file，报告结论「本机未被植入 `ld.so.preload` 劫持（阴性发现，强）」。

**原因**：这个阴性结论本身是对的标准格式，但它的强度取决于检查是否穷尽。 `ld.so.preload` 的判定还有第二条路径：`/etc/ld.so.preload` 之外，环境变量 `LD_PRELOAD` 同样能让动态链接器预加载库（2.4 提到 `/etc/environment` 由 PAM 读取，会让这种设置持久生效）。只查了文件没查环境变量赋值，结论就不完整。案例第 4 步是两者一起 grep 的。

**影响**：更常见的问题是把这类阴性发现直接给"强"评级。案例结论表里自己写了另一个阴性发现——"`rc.local`、自定义内核模块、`at` 任务均无异常"——标注为"中（阴性，仅'未见'非'确定无'）"。这个分级才是对的：文件不存在可以强，但"路径存在、内容为空、机制未启用"这几种情形的阴性强度完全不同。

**核查**：阴性发现按三档标注强度：① **强**（目标文件/路径确定不存在，且该机制在此环境正常应有）——如 `ld.so.preload` 不存在；② **中**（机制存在但队列/目录为空，或该机制在本环境本就可能未启用）——如 `atjobs/` 为空；③ **弱**（只查了一处，其余位置未覆盖）。每条阴性发现旁边写清"查了哪里、为什么查这里"。

<a id="section-30"></a>

#### 陷阱 8：把"痕迹存在"直接等同于"该机制实际被触发过"

**现象**：发现 `/etc/update-motd.d/88-sshfp`，报告写「攻击者在每次登录时执行了此脚本」。

**原因**：文件存在只说明"下次登录会执行"，不说明"曾经执行过"。 该脚本是 Debian 的 `update-motd` 机制的一部分，机制本身正常存在；它是**何时被加入**、**登录时是否真的被执行了**（比如脚本内部有条件判断、或 `update-motd.conf` 的 `ENABLED=` 列表里没有它就会被跳过）、**是否产生了输出**，这三件事都需要各自的证据。案例结论表里对这一条的标注很准确：「强（但**其是否实际产生过输出需结合 journal 验证**）」。

**影响**：如果脚本在加入之后从未有用户再登录过（机器断电停用），那么"每次登录执行"这个描述会暗示一个不存在的执行历史。

委托方可能据此推断"攻击者持续掌握该机数月"。

**核查**：把三层分开表述——① **配置事实**：该文件在 `/etc/update-motd.d/` 中且不属于任何包；② **机制后果**：按 update-motd 机制，下一次 SSH 登录时会被执行；③ **实际执行证据**：需要在 journal 或 `/var/log/` 的 motd 相关输出里找痕迹，若无则写"未见执行痕迹"。**不要把机制后果写成历史事实。**

<a id="section-31"></a>

### 4.4 结论表述

<a id="section-32"></a>

#### 陷阱 9：把"六个痕迹时间接近"直接当作"攻击者一次性完成建设"

**现象**：六个痕迹的 `mtime` 全部落在 22:47–22:53，报告写「攻击者在 6 分钟内建立了三条独立持久化」。

**原因**：`mtime` 相同只说明"这几个文件在相近时间被写"，不说明是同一个人、同一目的、同一动作写的。 连续动作会自然产生相近的 mtime，但也可能是一次批量操作（如 `tar` 解包、rsync 同步、镜像恢复）的结果，或者是某个脚本一次性铺开的。而且 `mtime` 是**可伪造字段**——`cp -p`、`tar -p` 解包都会保留原始 mtime，`touch -d` 可任意设定。

**影响**：把"时间接近"升格为"攻击者主动建设"，是在给一个相关性证据加上行为归因。

若真实成因是一次恢复操作，报告就会指责一个没做过这件事的人。

**核查**：时间聚集是**关联性证据**，用来提升可疑度，不用来完成归因。归因需要独立证据：auth.log 里的 `sudo ... COMMAND=` 行、命令历史、时间戳的 `ctime` 链（`ctime` 无法被 `cp -p` 伪造，它随元数据变更而更新）。案例里 22:47–22:53 的聚集之所以能升到"强"，靠的是与 auth.log 中 22:44–22:48 的 sudo 命令序列相互印证，而不只是六个时间戳彼此接近。

<a id="section-33"></a>

#### 陷阱 10：把"未见运行态证据"省略掉，直接给发现定级

**现象**：确认了多条持久化痕迹，报告逐条给出"强"评级，**没有提及机器强制断电这件事对结论的限制**。

**原因**：**痕迹的存在性与痕迹的生效性是两个不同的命题。** 机器强制断电意味着：没有最后一次运行的日志、journal 可能只存在内存、`utmp` 已被清空、systemd 从未有机会拉起那些自定义 unit。在没有运行态证据的情况下，你只能证明"攻击者放置了持久化配置"，**不能证明"这些持久化曾经生效"**。案例第 6 步的结论表最后一行专门写了这一点：「因机器强制断电，**无法确认这些持久化在最后一次运行中实际被触发过** | 无运行态证据 | **局限，须明示**」。

**影响**：委托方会据此决定清理动作的优先级——把"从未生效的残留"和"持续生效的后门"排在同一优先级上，前者可能根本不需要清理，后者必须立刻下线。

省略局限等于让对方基于错误的紧急度做决策。

**核查**：报告的发现表必须有一列「局限/未验证项」，与「强度」并列。对持久化类发现，这一条几乎总是存在：写明"因断电/取证时点限制，未获得运行态证据证明其已生效；本结论基于文件系统静态证据"。这句话本身不会削弱报告，它证明你知道结论的边界在哪。

<a id="section-34"></a>

### 4.5 工具行为与环境前提

这一组讲的是另一类失误：分析工具在你的环境里正常工作，但它读的根本不是检材，或者它对某个字段有覆盖边界而输出不提示。

<a id="section-35"></a>

#### 陷阱 11：用 `crontab -l`、`systemctl`、`journalctl` 去"验证"离线检材

**现象**：在分析机上执行 `crontab -l` 想核对镜像里 `deploy` 的任务，`systemctl list-timers` 想看有哪些定时器，输出被写进报告作为佐证。

**原因**：**这三个命令都只读分析机自己的状态。** `crontab -l` 读的是本机 `/var/spool/cron/crontabs/$USER`，`systemctl` 连的是本机的 systemd（离线镜像上通常根本连不上，报 `Failed to connect to bus`），`journalctl` 读的是本机的 journal。**它们的输出格式完全正常**，有列表有状态，看起来毫无异常，因此比"命令报错"更容易被当成证据。SSH 篇的陷阱 5 是同一类问题的 `last` 版本。

**影响**：报告里会出现一份与检材毫无关系的自启清单，而委托方无法从报告本身分辨它来自哪里。更麻烦的是，如果分析机恰好装了某个定时任务，它会被当成"检材上存在该持久化"写进发现表——这是一个凭空产生的、看起来有据可查的发现。

**核查**：离线分析时这些命令一律不用，全部换成直接读镜像文件：

| 想得到 | 不要用 | 改用 |
|---|---|---|
| 某用户的 crontab | `crontab -l` / `crontab -u deploy -l` | `cat /mnt/df/var/spool/cron/crontabs/deploy` |
| 启用的自启单元 | `systemctl list-unit-files` | `ls -l /mnt/df/etc/systemd/system/*.wants/` |
| 定时器与周期 | `systemctl list-timers` | 读 `*.timer` 的 `OnCalendar=`/`OnUnitActiveSec=` + 配对 `.service` |
| 单元运行记录 | `journalctl -u <unit>` | `/var/log/syslog` 或 `/var/log/cron` 里的关键字 |
| 服务是否在跑 | `systemctl is-active` | 断电检材上一律不可得，记为局限 |

<a id="section-36"></a>

#### 陷阱 12：把 cron 命令里的 `%` 当普通字符

**现象**：crontab 里出现 `0 * * * * /usr/local/bin/.cache/w --tag $(date +\%s)` 这类写法，或者看到 `date +%s` 就直接判成"载荷在生成时间戳"，没有意识到这条任务的实际行为与字面不同。

**原因**：Vixie cron 及派生实现把 `%` 当作命令与标准输入的分隔符：命令字符串里第一个未转义的 `%` 及其后所有内容，会被换成换行并作为该命令的**标准输入**。所以 `date +%s` 实际执行的是 `date +`（`%s` 变成喂给它的空输入），而 `%` 之后的内容根本不在命令行里。要写字面的 `%` 必须写成 `\%`。这条规则在日志里的表现很隐蔽——**cron 会照常执行，只是执行的是被截断后的命令**，任务不会报错。

**影响**：你读到的命令与实际执行的命令不是同一个。你会基于 `$(date +%s)` 推断载荷在做时间戳采集或定时同步，而实际执行的 `date +` 什么也没做。**这类推断属于凭空建构**，一旦委托方按"载荷有定时回连逻辑"去排查网络侧，会查错方向。

**核查**：逐条检查 cron 命令里的 `%`，并按 cron 规则还原真实执行的命令：

```bash
# 打印所有 cron 文件里的命令字段，标出含 % 的行
grep -rnE '^[^#].*%' /mnt/df/etc/crontab /mnt/df/etc/cron.d/* /mnt/df/var/spool/cron/crontabs/* 2>/dev/null
# 判定：未转义的第一个 % 之后的内容不进命令行，而是变成该命令的 stdin
```

命令里确实需要传百分号时（`date +\%s`、`printf '%s\
'`），**写成 `\%` 才是这个 cron 实现下的正确形式**。反过来说，看到未转义的 `%` 本身就是一条可疑线索——正常运维脚本在 crontab 里几乎不会忘记转义，而攻击者从网上抄来的命令常常没转。

<a id="section-37"></a>

#### 陷阱 13：把 `/etc/cron.d/` 里存在但文件名不合规的片段当成生效的任务

**现象**：`/etc/cron.d/` 下有一个 `sysupdate.conf`，内容看起来完全正常（字段数对、有用户字段、命令路径合理），被写进报告的"已启用周期任务"表里。

**原因**：Debian 系 cron 对 `/etc/cron.d/` 的文件名有字符集要求，只接受 `[A-Za-z0-9_-]`；含 `.` 的文件名会被**静默忽略**——不执行、不报错、不在日志里留任何痕迹。部分 RHEL 系（cronie）版本的实现更宽松。**这个"静默"是本条陷阱的核心**：配置写对了、路径也放对了，但 cron 根本没把它读进来。攻击者用这种方式可以让一个片段"看起来存在、实际不生效"，而防守方读到它时会以为攻击者留了个失效的半成品，从而降低警惕。

**影响**：把未生效的片段算进"攻击者建立了周期任务"，会让持久化条数虚增。而真正需要解释的问题——"这个片段为什么不执行"——被跳过了。报告里"存在 cron 持久化任务 N 条"这个数字可能是错的。

**核查**：**判定生效性看文件名是否合法，而不是看内容是否正确**，两者独立。逐个列出文件名与字符集判定：

```bash
for f in /mnt/df/etc/cron.d/*; do
  b=$(basename "$f")
  case "$b" in
    *[!A-Za-z0-9_-]*) echo "★ 文件名含非法字符，Debian 系 cron 静默忽略: $b" ;;
    *)                 echo "  文件名合法: $b" ;;
  esac
done
# 内容侧同时查时间字段，确认字段数与用户字段位置
grep -nvE '^\s*(#|$)' /mnt/df/etc/cron.d/* 2>/dev/null
```

跨发行版时这一条要写明依赖：文件名规则随 cron 实现而异，**Debian 系与部分 RHEL 系行为不同**，以目标系统的实测或 cron 包版本为准。不同发行版上"生效"是不同的事实，不能跨环境照搬结论。

<a id="section-38"></a>

#### 陷阱 14：用 `mtime` 代替 `crtime`，把"覆盖已有文件"读成"新建文件"

**现象**：`/usr/local/bin/.cache/w` 的 `mtime` 是 2024-03-17 22:47，报告写「攻击者于 22:47 新建了该载荷文件」，并据此把它与其他新建痕迹并列。

**原因**：`mtime` 记录的是"内容最后一次被写"的时间，不是"文件是什么时候出现在这个文件系统里的"时间。 攻击者投放载荷的常见手法恰恰是**覆盖已存在的文件**——写到一个系统里本来就有的路径上（哪怕那个文件只是个空壳或之前被别的工具用过），此时 `crtime`（inode 创建时间）远早于 `mtime`，`mtime` 只能说明"内容在 22:47 被改过"。反过来，`cp -p`、`tar -p` 解包会**保留原始 mtime**，此时 `mtime` 会比入侵时间早得多，看起来像"系统自带文件"。两个方向都会出错，而 `ls -la` 只显示三个时间戳，看不到第四个。

**影响**：mtime 被当成创建时间，会同时造成两类错误结论：把"篡改已有文件"读成"新投放"（时间线整体前移，破坏与入侵窗口的对应关系），把"保留了原始时间的覆盖写"读成"与本案无关"（真阳性被过滤掉）。这一条直接动摇你把痕迹与入侵时间窗对齐的全部前提。

**核查**：`mtime`、`ctime`、`crtime` 三个一起读，并明确各自的语义分工：

```bash
# %w = 出生时间(crtime)，%y = mtime，%z = ctime；不可得时 %w 显示 "-"
stat -c '%n  crtime=%w  mtime=%y  ctime=%z  size=%s' /mnt/df/usr/local/bin/.cache/w

# 需要从镜像里直接读 inode 时（不经 FUSE，出生时间更可靠）
debugfs -R "stat /usr/local/bin/.cache/w" /mnt/df/DigiForensics.dd 2>/dev/null | grep -iE 'crtime|mtime|ctime'
```

判读规则：① `crtime` 落在入侵窗口内 → **新建**，这是最干净的情形；② `crtime` 远早于 `mtime` → **篡改已有文件**，写入时刻取 `mtime`；③ `mtime` 早于入侵窗口且 `crtime` 也早 → 可能是保留时间的覆盖（`cp -p`/`tar -p`）或与本案无关，**不能仅凭时间排除，需回到内容与包清单**。出生时间不可得时（文件系统未记录、镜像经无元数据转存），要在报告里记为字段缺失，不要用 `mtime` 顶替。

<a id="section-39"></a>

#### 陷阱 15：把包卸载后残留的配置片段算成"清单外文件 = 攻击者投放"

**现象**：`/etc/cron.daily/` 下有一个 `e2scrub_all` 脚本，`grep -l` 在 `info/*.list` 里找不到它，于是和 `/tmp/.kworkerd` 一起被列进"非包管理安装的可疑文件"清单。

**原因**：Debian 包的卸载会保留配置文件，而配置文件里就包括 cron 片段。 `/etc/crontab`、`/etc/cron.d/`、`/etc/cron.daily/` 这类路径对许多包来说是 conffile（`cron` 包本身就把它们登记为 conffile，`e2scrub-all`、`logrotate` 等也各有自己的 `/etc/cron.d/` 片段）。执行 `apt remove` 而不是 `apt purge` 之后，**程序文件被删、配置留下**，于是这个脚本在磁盘上存在，却不在任何 `.list` 里——**"不在清单"这个判据在这里会稳定地误报**。判别方法在包账本里：`/var/lib/dpkg/info/<pkg>.conffiles` 列出的正是这类路径。

**影响**：这类噪音会淹没真信号。它与"清单外可执行文件"共用同一个判据输出，不做区分地混在一张表里，报告的读者无法判断哪几条是同一种机制产生的。**更实际的风险是反向的**：如果分析者已经认定"清单外 = 攻击者"，看到一堆 conffiles 残留后可能会觉得"这台机器环境不干净、判据不可靠"，从而把判据整体降级。

**核查**：把"清单外文件"再分成两支，分别定性：

```bash
# 支一：conffiles 残留（包被 remove 但配置留下）
cat /mnt/df/var/lib/dpkg/info/*.conffiles 2>/dev/null | sort -u > /evidence/dpkg-conffiles.txt
# 支二：真正没有任何包归属的路径
cat /mnt/df/var/lib/dpkg/info/*.list | sort -u > /evidence/dpkg-files-all.txt
# 命中支一 → 标注"配置残留，程序已卸载"，并去 status 里核对该包的 Status 是否为 config-files
awk '/^Package: /{p=$2} /^Status: /{print p"\	"$0; p=""}' /mnt/df/var/lib/dpkg/status \
  | grep -i 'config-files'
```

**判据顺序**：先查是否在 `*.conffiles` 里（是 → 卸载留配置，走 `deinstall ok config-files` 那条线解释），不在 conffiles 再查是否在 `*.list` 里（不在 → 才进入"清单外"集合）。案例里 `/tmp/.kworkerd` 的定性之所以站得住，靠的是它**同时**满足 SUID + 临时目录 + 清单无归属 + `conffiles` 里也没有 + auth.log 里有 `chmod` 命令，而不是"不在 `.list` 里"这一条。

<a id="section-40"></a>

#### 陷阱 16：解析 `/etc/ld.so.preload` 时漏掉行内路径导致包清单核对假阴性

**现象**：把 `ld.so.preload` 里的内容抽出来去包清单里比对，得出"该 `.so` 属于已安装的 nss 包"，于是排除 preload 劫持。

**原因**：`/etc/ld.so.preload` 的语法是"每行一个以空白分隔的路径"，`#` 之后是注释。 用 `cut -d' ' -f1` 或只取首个 token 的写法，遇到行内多路径、行尾注释、行首缩进等情况就会抽出错误甚至为空的字符串，`grep -lx "$s"` 拿一个残缺路径去比对，**必然匹配不上**，而"匹配不上"正是判据期待的结论方向。**这类错误的方向是系统性的**——提取环节出错的产物几乎总是"不在清单里"，于是假阳性；反过来若提取时误把别的路径拼在一起，则可能假阴性，即本条现象。

**影响**：preload 是影响面最大的一类持久化（对几乎所有动态链接进程生效），对它的判定一旦出错就是全盘判定出错。"该 `.so` 属于已安装包"这个结论会把整条 preload 检查从阳性翻成阴性，而后续所有"未发现链接器级劫持"的排除结论都建立在这个翻转之上。

**核查**：先把文件内容规范化——去掉注释、逐个空白切分——再逐个路径比对，并把"提取到几个路径"这个数字记下来：

```bash
sed 's/#.*//' /mnt/df/etc/ld.so.preload 2>/dev/null \
  | tr -s '[:space:]' '\
' | grep -v '^$' | sort -u > /evidence/preload-paths.txt
wc -l < /evidence/preload-paths.txt          # 提取到的路径条数，应与文件目视结果一致
while read -r s; do
  printf '%s → ' "$s"
  if grep -lx "$s" /mnt/df/var/lib/dpkg/info/*.list 2>/dev/null | head -1; then :; else echo "★ 不在任何包清单"; fi
done < /evidence/preload-paths.txt
```

**自检判据**：文件非空但 `wc -l` 得到 0，说明提取规则写错了，此时任何"未发现异常"的结论都必须作废重来——**这是提取环节的失败，不是数据的阴性**。

<a id="section-41"></a>

#### 陷阱 17：`stat` 解析不出属主就把该文件的属主字段跳过

**现象**：批量 `stat` 持久化候选文件时，`%U`/`%G` 输出的是数字 UID/GID（如 `1000 1000`）而不是 `root`/`deploy`，于是属主这一列被当作"不可用"从排查表里删掉。

**原因**：属主显示为数字，是解析环境缺 `/etc/passwd` 映射，不是检材里没有这个用户。 离线镜像通过 FUSE 或 loop 挂载时，若分析机侧的 UID→用户名映射表里没有对应的 GID，解析出来的就是裸数字。**数字本身就是有效信息**——它精确地告诉你文件的属主 UID 是多少，而这个 UID 在镜像内的 `/etc/passwd` 里通常能查到对应的用户名。删掉这一列，等于丢掉了把文件与某个具体账户关联起来的唯一系统侧证据。

**影响**：属主是把持久化痕迹归到某个账户的唯一系统侧锚点（时间戳只能给"什么时候"，属主能给"谁的"）。丢掉它，案例里"三个持久化文件全部属主为同一 UID"这类路径一致性证据就无从建立，跨痕迹的关联分析也失去一个维度。

**核查**：**永远同时打印数字 ID 与名字**，数字是权威值，名字是派生值：

```bash
stat -c '%n  uid=%u(%U)  gid=%g(%G)  mode=%a' /mnt/df/etc/update-motd.d/* 2>/dev/null

# 再把镜像内的 UID 翻译成用户名（ID→名称的权威来源是检材自己的 /etc/passwd）
awk -F: '$3>=1000 || $1=="root" {print $3"\	"$1}' /mnt/df/etc/passwd | sort -n
```

两者对照后可能出现三种情况，各有不同含义：**名字与数字一致** → 映射正常；**数字存在但名字为空** → 该 UID 在镜像的 `/etc/passwd` 里查不到（账户已被删除或来自外部域/LDAP），**这本身是一条发现**，不是解析错误；**名字显示为分析机上的用户** → 映射串了，此时**只采信数字**。报告里写属主一律用 `UID 1000 (镜像内 /etc/passwd 未登记此 UID)` 这样的形式，把"查不到名字"和"属主为空"区分开。

<a id="section-42"></a>

## 五、案例示例

<a id="section-43"></a>

### 5.1 五分钟内建成三条持久化的时间线对齐

**场景**

Ubuntu Server 22.04 Web 服务器 `web01`（ext4，2 TB）。委托方要求全面排查持久化机制。检材 `DigiForensics.dd`（raw），ext4 分区起始扇区 1181696，**强制断电**。已知 2024-03-17 22:43 `deploy` 账户被爆破登录并提权。

持久化痕迹的定性关键不是"有多少个"，而是"它们在什么时间窗口内建立"——密集出现在登录后的几分钟内，与零散分布在数月之间，指向的结论强度完全不同。

**处置过程**

第 1 步，cron 五个位置一次跑完：

```bash
# (1)(2)(3)
cat /mnt/df/etc/crontab
ls -la /mnt/df/etc/cron.d/ /mnt/df/var/spool/cron/crontabs/
cat /mnt/df/var/spool/cron/crontabs/deploy
# SHELL=/bin/bash
# PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# */15 * * * *  /usr/local/bin/sync-job.sh          ← 表面正常
#
# 30 3 * * *   /usr/local/bin/.cache/rotate-logs.sh   ← ★ 隐藏目录，凌晨3:30

# (4) 周期目录
ls -la /mnt/df/etc/cron.daily/
# 50-wordpress                     ← 正常（Debian 包）
# 90-cleanup                       ← 正常

# (5) at
ls -la /mnt/df/var/spool/cron/atjobs/
# （空）  ✓ 无 at 一次性任务
```

第 2 步，验证 cron 载荷是否属于任何包，并看内容：

```bash
grep -l 'rotate-logs' /mnt/df/var/lib/dpkg/info/*.list 2>/dev/null
# （无输出）  ← 不属于任何已安装包

cat /mnt/df/usr/local/bin/.cache/rotate-logs.sh
# #!/bin/bash
# /usr/local/bin/.cache/w >/dev/null 2>&1
# sleep 15

stat -c '%n mtime=%y ctime=%z size=%s' /mnt/df/usr/local/bin/.cache/rotate-logs.sh
# mtime=2024-03-17 22:47:50  ctime=2024-03-17 22:47:50  size=118
```

这是一个极短的包装脚本：调用同目录的另一个文件 `w`，把输出丢弃，`sleep 15`。

重定向到 `/dev/null` 是本案的关键行为特征——它说明调用方**不关心载荷的输出，只关心它被执行**。

第 3 步，systemd 自启软链检查：

```bash
ls -l /mnt/df/etc/systemd/system/multi-user.target.wants/
# ssh.service        -> /lib/systemd/system/ssh.service          ← 正常
# nginx.service      -> /lib/systemd/system/nginx.service        ← 正常
# sysupdate.service  -> /etc/systemd/system/sysupdate.service    ← ★ 指向 /etc

grep -l 'sysupdate' /mnt/df/var/lib/dpkg/info/*.list 2>/dev/null | head
# （无输出）  ← 不属于任何已安装包

cat /mnt/df/etc/systemd/system/sysupdate.service
# [Unit]
# Description=System Update Service
# [Service]
# Type=simple
# ExecStart=/usr/local/bin/.cache/sysd
# Restart=always
# [Install]
# WantedBy=multi-user.target
```

第 4 步，profile 注入与 motd 类痕迹：

```bash
ls /mnt/df/etc/profile.d/
grep -rnE '(BASH_ENV|LD_PRELOAD)[[:space:]]*=' /mnt/df/etc/profile.d/ /mnt/df/etc/environment 2>/dev/null
# （无输出）  ✓ 这两处干净

ls /mnt/df/etc/update-motd.d/ | grep -vE 'motd-news|landscape|esm|updates-available'
# 88-sshfp                       ← ★ 清单外
cat /mnt/df/etc/update-motd.d/88-sshfp
# #!/bin/sh
# /usr/local/bin/.cache/w >/dev/null 2>&1
```

`/etc/update-motd.d/88-sshfp` 伪装成"SSH 指纹提示"，**但调用的是同一个 `w`，同样丢弃输出**。它不在任何自启列表、不写 cron，**却在每次 SSH 登录时执行**——这是"配置与自启类"痕迹里最难用 `systemctl`/`crontab` 排查的一类。

第 5 步，收尾检查（阴性发现也要记录）：

```bash
ls -l /mnt/df/etc/ld.so.preload 2>/dev/null
# ls: cannot access '/mnt/df/etc/ld.so.preload': No such file or directory
# ✓ 本机未被植入 preload 劫持

cat /mnt/df/etc/rc.local 2>/dev/null
# #!/bin/sh -e     ← 仅 shebang，无命令（Debian 默认空）

find /mnt/df/etc/modules-load.d/ -name '*.conf' -exec grep -lhvE '^\s*#|^\s*$' {} \; 2>/dev/null
# （仅发行版默认模块，无自定义）
```

第 6 步，按时间排序全部痕迹：

| 痕迹 | 类型 | mtime（+08:00） |
|---|---|---|
| `/usr/local/bin/.cache/rotate-logs.sh` | cron 任务载荷 | 2024-03-17 22:47:50 |
| `/usr/local/bin/.cache/sysd` | systemd 服务载荷 | 2024-03-17 22:49:12 |
| `/etc/systemd/system/sysupdate.service` | 自定义自启 unit | 2024-03-17 22:49:30 |
| `multi-user.target.wants/sysupdate.service` | 启用软链 | 2024-03-17 22:49:31 |
| `/etc/update-motd.d/88-sshfp` | 登录时执行脚本 | 2024-03-17 22:52:07 |
| `deploy` crontab 文件本身 | crontab 变更 | 2024-03-17 22:53:15 |

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 攻击者在提权后 10 分钟内建立了**至少 3 条**独立持久化（cron / systemd 服务 / motd 脚本） | 六个痕迹的 mtime 全部落在 22:47–22:53，且晚于 22:43 登录 | 强 |
| 三条持久化共用同一载荷 `w`，且全部丢弃输出 | 三个文件内容均调用 `/usr/local/bin/.cache/w >/dev/null 2>&1` | 强 |
| 全部持久化载荷集中在 `/usr/local/bin/.cache/`（隐藏目录） | 路径一致 + 命名伪装成系统组件 | 强 |
| `sysupdate` 服务**不属于任何已安装包** | `.wants` 目标在 `/etc` + 包清单无匹配，双源印证 | 强 |
| 本机**未**被植入 `ld.so.preload` 劫持 | 文件不存在 | 强（阴性发现） |
| `rc.local`、自定义内核模块、`at` 任务**均无异常** | 逐项排查为空 | 中（阴性，仅"未见"非"确定无"） |
| **无法确认**这些持久化在最后一次开机中实际被触发过 | 机器断电，无运行态记录 | **局限，须明示** |

**误判对照**

本案最容易得出的错误结论是「发现了 6 个持久化文件、分布在 cron、systemd、motd 三个不同位置，说明攻击者做了周密的反检测设计，技术水平很高」。

**正确判据是时间戳的密集程度，恰恰指向相反的方向**。

六个痕迹的 mtime 全部落在 22:47:50 至 22:53:15 这 5 分 25 秒内，且晚于 22:43:07 登录成功、22:44:01 提权。

这种密度是**自动化投放**或**交互式脚本批量执行**的典型特征——人类手工操作在三个不同机制体系里各建一条持久化，通常要跨越较长时间且伴随大量试错。

第二个判据是**载荷的复用**。

三个入口（`rotate-logs.sh`、`sysupdate.service` 的 `ExecStart`、`88-sshfp`）调用的是**同一个文件 `w`**，且都写成 `>/dev/null 2>&1`。

三条"精心设计"的持久化共用一个载荷，说明设计者根本没打算让它们各有功能——它们只是同一个东西的三个触发器。所谓"周密"，实际是"用最省事的方式挂三个触发点"。

**按错误判据走的代价**：把攻击者能力高估，会引导委托方采取与实际不匹配的对策（比如假设面对的是定制化高级工具，投入资源做特征检测，而真正的威胁是"低成本、多触发点、随时可重建"）。

**能力评估错位会直接影响响应策略的合理性**——过度的反制措施在资源有限时反而挤占了更有价值的工作。

第二个易错点：把 `88-sshfp` 写成"SSH 指纹伪装程序，功能是显示指纹"。

正确判据是文件内容——它不显示任何指纹，**只有一个调用 `w` 并丢弃输出的动作**。

命名与功能完全脱节，这正是它"每条 SSH 登录都跑却从不出现在任何自启列表"却仍需被排查的原因。按内容判定、按名称定罪，是这一类痕迹最常见的翻车点。

---

<a id="section-44"></a>

### 5.2 profile.d 与 BASH_ENV：登录即执行但不在任何自启清单

**场景**

同系列主机 `app02`（Ubuntu 22.04，Web 应用服务器），委托方追问"攻击者是否在我每次登录时都能拿到 root 权限"。检材 `DigiForensics.dd`。此前已在 `app01` 上发现 `88-sshfp` 型痕迹，本案要查的是同一族手法的其他变体。

这类痕迹的行为等价于"每次登录自动执行"，触发频次高于开机型后门，但不落在任何自启清单里。

**处置过程**

第 1 步，遍历 `profile.d` 全部脚本并区分包归属：

```bash
ls -l /mnt/df/etc/profile.d/
# -rw-r--r-- 1 root root  1466 2022-05-11 09:30  /mnt/df/etc/profile.d/0apt.list.sh
# -rw-r--r-- 1 root root  2201 2022-05-11 09:30  /mnt/df/etc/profile.d/bash_completion
# -rw-r--r-- 1 root root   77 2022-05-11 09:30  /mnt/df/etc/profile.d/export_editor.sh
# -rw-r--r-- 1 root root   92 2024-03-17 22:51:40  /mnt/df/etc/profile.d/zz-telemetry.sh   ← ★

grep -l 'zz-telemetry' /mnt/df/var/lib/dpkg/info/*.list 2>/dev/null
# （无输出）  ← 不属于任何包
```

第 2 步，看 `zz-` 前缀脚本的内容（**文件名的 `zz-` 前缀意味着最后执行**）：

```bash
cat /mnt/df/etc/profile.d/zz-telemetry.sh
# #!/bin/sh
# [ -f /usr/local/bin/.cache/w ] && /usr/local/bin/.cache/w >/dev/null 2>&1
# export EDITOR=vim
#                                 ← 末行是正常导出，起掩护作用
stat -c '%n mtime=%y ctime=%z' /mnt/df/etc/profile.d/zz-telemetry.sh
# mtime=2024-03-17 22:51:40  ctime=2024-03-17 22:51:40
```

**关键**：脚本里那句无害的 `export EDITOR=vim` 是典型的**掩护行**。只看文件大小或扫可疑命令很容易放过它；真正要判的是**它调用了哪个可执行文件**。

第 3 步，检查 `BASH_ENV` 与 `/etc/environment`（非交互 shell 的注入面）：

```bash
grep -rnE 'BASH_ENV|ENV=|LD_PRELOAD|LD_LIBRARY_PATH' \
  /mnt/df/etc/profile.d/ /mnt/df/etc/environment /mnt/df/etc/bash.bashrc /mnt/df/root/.bashrc 2>/dev/null
# （无输出）  ✓ 未发现非交互 shell 注入
```

第 4 步，检查 root 与目标用户的 shell 配置文件：

```bash
for u in root deploy app; do
  f=/mnt/df/home/$u/.bashrc; [ -f "$f" ] && stat -c '%n mtime=%y' "$f"
done
# /mnt/df/root/.bashrc  mtime=2022-05-11 09:30        ← 原始
grep -rnE '(curl|wget|nc |/dev/tcp)' /mnt/df/home/*/.bashrc /mnt/df/root/.bashrc 2>/dev/null
# （无输出）  ✓ 用户级 rc 未被投毒
```

第 5 步，把本机全部 profile 类痕迹按时间并排：

```bash
find /mnt/df/etc/profile.d /mnt/df/etc/update-motd.d /mnt/df/etc/rc.local \
     -type f -newermt '2024-03-01' -printf '%T+ %p\
' 2>/dev/null | sort
# 1774374700.2218841 /mnt/df/etc/update-motd.d/88-sshfp
# 1774374700.3310288 /mnt/df/etc/profile.d/zz-telemetry.sh
# → 1 秒内两个不同执行面被写入
```

**结论**

- **确认存在登录时自动执行**：`/etc/profile.d/zz-telemetry.sh` 于 2024-03-17 22:51:40 被创建，`mtime` 与 `ctime` 相同（一次性新建），**不属于任何已安装包**，内容是条件调用 `/usr/local/bin/.cache/w` 并丢弃输出。
- **`zz-` 前缀是有意义的**：profile.d 里的脚本按文件名字典序执行，`zz-` 保证它在所有其他 profile 片段之后运行，即使前面的脚本已经 `return` 或设了 `set -e` 也仍会执行。这不是随手起的名字。
- `BASH_ENV`、`/etc/environment`、`LD_PRELOAD`、用户 `.bashrc` **均未被投毒**。这一族手法的其他变体在本机不存在。
- 因此对委托方问题的直接答复：「**是的，每次登录都会触发一次载荷执行**。触发点在 `zz-telemetry.sh`，载荷为 `/usr/local/bin/.cache/w`，输出被丢弃。**但该脚本以当前登录用户身份运行，自身不提供提权**——提权能力取决于 `w` 内部是否读取了 root 可读的凭据文件（如 `deploy` 的 `~/.ssh/id_ed25519`），这一点需结合 payload 本身分析。**」

**误判对照**

本案最容易得出的错误结论是「`zz-telemetry.sh` 里有 `export EDITOR=vim`，而且文件在 `profile.d` 目录里，说明它只是系统的一个编辑器配置脚本，可以排除」——该误判容易发生，因为它**几乎命中了所有"快速过滤"条件**：名字像配置文件、有合理的 shell 语句、在系统目录里。

**正确判据是这个脚本调用了哪个可执行文件**。判读要点有三层：

1. **文件名前缀**。`telemetry` 这类名字暗示"数据采集"，而 `zz-` 前缀是**绕过前面脚本提前退出的手法**。包管理器安装的 profile 脚本几乎不会用 `zz-` 前缀——系统自带的几个（`0apt.list.sh`、`bash_completion`、`export_editor.sh`）要么无前缀、要么用功能名。
2. **调用链**。脚本里唯一的"有效动作"是 `/usr/local/bin/.cache/w >/dev/null 2>&1`。`>/dev/null 2>&1` 是本案的核心行为特征：正常系统配置脚本不会丢弃自己的全部输出，因为它的目的就是把状态设置给后续 shell。丢弃输出意味着**调用方只关心"它跑过了"，不关心它说了什么**。
3. **时间戳基线**。系统自带脚本的 mtime 是 2022-05-11 09:30（与 `/etc/passwd` 的 crtime 同日，即系统初始化），而本文件是 2024-03-17 22:51:40，**差了将近两年**。同目录内文件的 mtime 形成两个明显的时间簇，**异常项就在少数派里**。

**按错误判据走的代价**：把这条痕迹排除，等于漏掉"每条 SSH 登录都触发一次"这一事实。

委托方会认为"攻击者只在开机时自启，登录行为无影响"，从而**不修改登录策略、不轮换部署用的密钥凭据**——而下一次任何人登录（包括管理员日常运维）都会再次触发载荷。

第二个易错点：「`profile.d` 是用户级配置，不可能拿到 root，所以威胁等级低」。

正确判据是这个结论混淆了两件事：脚本**以谁的身份执行**决定它不能提权，但**它能读什么**决定它的危害。

`profile.d` 对所有登录用户生效，包括 root——**root 登录时该脚本以 root 身份运行**。所以准确表述是"对非 root 登录用户不提供提权"，而非"威胁等级低"。

本案的定案依据是载荷 `w` 的能力，而那需要单独分析。

---

<a id="section-45"></a>

### 5.3 反例：残留 crontab 空壳与已停用单元的识别

**场景**

某台退役的测试机 `old05`，委托方提供了另一案中的可疑 crontab 内容，要求确认本机是否存在同类持久化。检材 `DigiForensics.dd`，机器已于两周前正常关机、退役。

这条路径值得写，因为退役机器上的持久化痕迹会大量"看起来还在、实际已失效"，而把两者混为一谈会直接导致误报。

**处置过程**

第 1 步，逐个 crontab 读内容并按 mtime 排序：

```bash
ls -l --time-style=long-iso /mnt/df/var/spool/cron/crontabs/
# -rw------- 1 root root  383 2024-03-17 09:12  deploy
# -rw------- 1 root root  182 2024-03-18 08:40  svc-backup
# -rw------- 1 root root   96 2023-08-11 14:22  jenkins

cat /mnt/df/var/spool/cron/crontabs/jenkins
# 0 4 * * *  /opt/jenkins/backup-artifacts.sh
# → 路径属 jenkins 部署目录，mtime 2023-08-11，与本案无关
```

第 2 步，**关键动作：验证 cron 载荷文件是否还存在**：

```bash
ls -l /mnt/df/opt/jenkins/backup-artifacts.sh 2>&1
# ls: cannot access '/mnt/df/opt/jenkins/backup-artifacts.sh': No such file or directory
# → 载荷已删除，任务必然失败

# 全量交叉检查：所有 crontab 行的可执行目标是否都在
awk '/^[^#]/ && NF>6 {print $NF}' /mnt/df/var/spool/cron/crontabs/* 2>/dev/null | sort -u | while read p; do
  [ -e "/mnt/df$p" ] || echo "载荷缺失: $p"
done
# 载荷缺失: /opt/jenkins/backup-artifacts.sh
# 载荷缺失: /usr/local/bin/.cache/rotate-logs.sh    ← ★ deploy 的 cron 载荷也不在
```

第 3 步，检查 systemctl 单元的启用软链是否已断开：

```bash
ls -l /mnt/df/etc/systemd/system/multi-user.target.wants/ | grep -i sysupdate
#（无输出）  ← 软链已不存在：单元文件可能还在，但已不再自启

ls -l /mnt/df/etc/systemd/system/sysupdate.service
# -rw-r--r-- 1 root root 231 2024-03-17 22:49:30  sysupdate.service
# → 文件仍在，但无 .wants 软链 → 未被 enable

ls -l /mnt/df/usr/local/bin/.cache/ 2>&1
# ls: cannot access '/mnt/df/usr/local/bin/.cache/': No such file or directory
# → 整个目录已被删除
```

第 4 步，区分"载荷缺失"与"任务失败但曾成功过"：

```bash
grep -iE 'CRON|rotate-logs|sysd' /mnt/df/var/log/syslog 2>/dev/null | tail -6
# Jun 24 03:30:01 old05 CRON[2211]: (root) CMD (/usr/local/bin/.cache/rotate-logs.sh)
# Jun 24 03:30:01 old05 CRON[2211]: (/usr/local/bin/.cache/rotate-logs.sh): No such file or directory
# → 最后一次执行尝试在 2024-06-24（关机日），且失败
```

第 5 步，确定关机时间作为时间线终点：

```bash
last -f /mnt/df/var/log/wtmp reboot shutdown | head -3
# old05    system boot  2024-06-12 09:14
# old05    system down  2024-06-24 18:02   ← 正常关机（未断电）
```

**结论**

- `/usr/local/bin/.cache/` 整个目录已不存在。因此 `deploy` crontab 里的 `rotate-logs.sh` 调用、`sysupdate.service` 的 `ExecStart` 指向的 `sysd`、以及 `88-sshfp` 与 `zz-telemetry.sh` 引用的 `w`，**全部指向已不存在的文件**。
- 日志证实这些入口最后一次尝试执行是在 2024-06-24 03:30:01，且失败（`No such file or directory`）。因此：载荷在 2024-06-24 03:30 之后、2024-06-24 18:02 关机之前的某个时刻被删除，删除后未再有成功执行。
- **这台机器当前不具备该持久化的执行能力。** 但必须同时写明：① crontab 条目、`.service` 单元文件、profile 脚本**本身仍留在磁盘上**，未被清理；② `multi-user.target.wants/` 下的软链已被删除（`sysupdate.service` 文件在但未 enable），说明删除动作是有选择的、针对软链和载荷的，而不是一次全盘清理。
- **对委托方问题的答复**：「本机存在同类持久化的**配置残留**，但**载荷已被删除、自启软链已断开**；日志证实 2024-06-24 03:30 之后的执行尝试全部失败。该机已于 2024-06-24 18:02 正常关机并退役，因此当前无实际威胁；但配置残留应作为清理项记录，因为 `deploy` 账户的 crontab 一旦被恢复或该账户被重新启用，残留配置会立即复活。」

**误判对照**

本案最容易得出的错误结论有两个方向，第二个更隐蔽：

误判 A：「载荷文件不存在，所以这台机器没有被入侵过，配置是历史遗留的正常运维脚本。」 依据是所有可疑路径都指向不存在的文件。

正确判据是**配置文件的 mtime**。`sysupdate.service` 的 mtime 是 2024-03-17 22:49:30，`deploy` 的 crontab 是 2024-03-17 09:12——**与另案主机的时间戳完全一致**，说明这不是"历史遗留的正常运维"，而是**同一批攻击者在 2024-03-17 建立的痕迹**。载荷后来被删除，只说明**清理动作发生在入侵之后**，不说明入侵没发生。删除痕迹本身就是行为人的行为，是入侵成立的证据而非反证。

误判 B（更隐蔽）：「日志里 `rotate-logs.sh` 反复执行了 100 多天，说明它一直在正常工作，是生产任务。」

正确判据是 syslog 里那两行**成对出现**的记录：

```
CRON[2211]: (root) CMD (/usr/local/bin/.cache/rotate-logs.sh)
CRON[2211]: (...): No such file or directory
```

同一 PID 连续两行，第一行是 cron 记录"我要执行"，第二行是执行失败。计数 100 多次统计的是**尝试次数，不是成功次数**——`rotate-logs.sh` **一次都没有成功执行过**（在保留的日志窗口内）。

**按误判 B 走的代价**：最直接的后果是**把"删除载荷"这个动作漏掉**。如果分析者认为它在正常工作，就不会去追查"谁在 2024-06-24 前后删除了 `/usr/local/bin/.cache/`"——而这个删除动作，连同同时被删除的 `multi-user.target.wants/sysupdate.service` 软链，**恰恰是本案最有价值的行为人痕迹**：它证明有人在退役前主动清理了自启能力，但故意留下了 crontab 条目和 unit 文件。

按误判 A 走的代价则是方向性错误：把入侵主机写成"干净"，委托方会把这台机器排除出调查范围，**而它仍是同批受控主机之一**（时间戳完全对得上）。

**判据小结**：cron/systemd 的"存在性"要拆成三层看——**配置项在不在**（在）、**自启软链在不在**（`sysupdate` 已断）、**载荷在不在**（已删）。三层里只要有一层缺，就不能笼统说"有持久化"或"无持久化"。执行能力的判据是三者与日志中最后一次执行尝试的结果，而本次执行是失败的。

---
<a id="section-46"></a>

## 六、扩展阅读方向

按"排查完一个点之后往哪跳"分成五组，不按主题。

<a id="section-47"></a>

### 前置基础

- [取证工件地图](computer-persistence-persistence-artifact-map.md) —— **解决"只读接入怎么做、这台机器是什么发行版"**。`/etc/os-release` 的读法、`/tmp` 与 `/var/tmp` 为什么两个都要查、SUID 全盘清点的入口都在那篇。**本篇的所有命令都建立在"接入已完成"这个前提上。**
- [ext4 结构与 inode](../../filesystem/filesystem-unix/filesystem-unix-ext4-inode.md) —— 解决"`ctime` 晚于 `mtime` 21 秒这个判据从哪来"。四个时间戳的字段位置与语义在那篇，**没有它就无法解释"权限被单独赋予"这类发现**。

<a id="section-48"></a>

### 同层深入

- [SSH 痕迹与密钥取证](computer-persistence-ssh.md) —— 解决"`authorized_keys` 里的公钥是谁的"。本篇能确认"公钥被追加"，**归属与来源 IP 要靠那篇的认证记录**。
- [包管理器与软件清单](computer-persistence-package-manager-and-software-inventory.md) —— **解决"这个文件是不是系统自带的"**。"不属于任何已安装包"是本篇多处依赖的一条判据，而那条判据的实现全在那篇。清单比对不做，所有"异常文件"都会沦为主观判断。
- [时间线重建](../computer-log/computer-log-linux-timeline-reconstruction.md) —— 解决"六条痕迹的 mtime 怎么合成一条攻击时间线"。本篇产出的是**带时间戳的痕迹清单**，合并与收敛在那篇。

<a id="section-49"></a>

### 相邻议题

- [Shell 痕迹与命令历史](../computer-shell/computer-shell-shell.md) —— 解决"这条 cron 的命令当初是从哪个 shell 里敲下去的"。本篇给配置侧，**那篇给执行侧**，两者交叉才能把"配置"和"操作"连起来。
- [系统日志深度分析](../computer-log/computer-log-system-log-analysis.md) —— **解决"这些持久化有没有真的运行过"**。cron 执行与 systemd 单元启动的运行态记录在 journal 里，**这是"配置存在"升级为"已执行"的唯一途径**。
- [proc 虚拟文件系统取证](../computer-shell/computer-shell-proc.md) —— **解决"运行态的痕迹怎么读"**。断电或已关机的机器上 `/proc` 无内容，**但它能解释哪些痕迹来自运行中而非磁盘**。
- [统一日志与 LaunchAgents](../computer-log-persistence/computer-log-persistence-macos-unified-logs-and-launch-agents.md) —— **横向对照读**。macOS 上同类问题由 launchd 与登录项承担，两边位置与格式完全不同，放在一起看能快速判断攻击者用的是哪套习惯。

<a id="section-50"></a>

### 工具与规范

- 逐项排查的完整命令链见[命令速查](#section-52)——**建议按 3.x 的顺序一次性跑完再回头看**，边跑边查容易漏项。
- **只读接入是硬前提**。`debugfs`、`fls`、只读挂载、`mount -o ro,noload` 四种方式的安全边界见 [取证工件地图的接入章节](computer-persistence-persistence-artifact-map.md#section-8)——**用错方式会在排查开始前就改动证据**。
- 阴性发现必须写成"逐项排查为空"并列出具体项名，见[案例示例](#section-42)的结论表最后两行。"未见"与"确定无"在报告里是两句话，混淆会削弱整个结论的可信度。
- 包清单与文件哈希的固定见[取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md)——**载荷文件先 `sha256sum` 再分析**，顺序反了就没法证明分析对象是证据。

<a id="section-51"></a>

### 判据与反例

- **判据一**：**"配置存在"与"已执行"必须分开表述。**断电状态下只有前者，用 `mtime` 代替"已执行"的证明是最常见的越界。
- **判据二**：`ctime` 晚于 `mtime` 是"权限位被单独赋予"的判据。**`chmod 4755` 只动 `ctime`** —— 这个差值能把"创建"与"提权后赋权"两种情形分开。
- **判据三**：`crtime` 老而 `mtime` 新 = **篡改已有文件**。`authorized_keys` 靠这一条被判定为"追加公钥"而非"新建后门文件"。
- **判据四**：**载荷路径的集中性是强判据。**多条痕迹全部落在同一个伪装目录（如 `/usr/local/bin/.cache/`）且命名风格统一，符合自动化工具特征而非手工操作。

六条反例的共同点：把某个位置或某个文件的存在，当成了它所代表的那个机制已经生效。

- **反例一**：看到 `/etc/systemd/system/` 下有 unit 就写"已建立自启"。没有 `.wants/` 软链的 unit 不会被加载，这是两件事。
- **反例二**：只看主 unit 文件。**`drop-in`（`*.d/`）会追加指令**，忽略它等于漏掉一半配置。
- **反例三**：只看配置文件，宣称"未发现 `BASH_ENV` 注入"。**它由用户在环境里指定，不落在任何配置文件里**，这类注入靠读文件是发现不了的。
- **反例四**：把某项排查为空写成"该机制未被利用"。正确写法是"未见"，并注明是仅"未见"非"确定无"。
- **反例五**：把"载荷文件路径存在"当成"载荷被执行过"。**路径存在与执行是两件事**，执行证据在 journal。
- **反例六**：只看 `ld.so.preload` 之外的位置就宣称"未发现链接器级劫持"。**它对几乎所有动态链接程序生效且不在进程列表出现**，这一项必须单独确认；文件不存在是有价值的阴性发现，但只说明"未见该文件"，不等于"未被劫持过"。
<a id="section-52"></a>

## 七、命令速查

```bash
# ===== 1. cron 五位置（一次跑完）=====
cat /mnt/df/etc/crontab
ls -la /mnt/df/etc/cron.d/ && for f in /mnt/df/etc/cron.d/*; do echo "== $f =="; cat "$f"; done
ls -la /mnt/df/var/spool/cron/crontabs/ && for f in /mnt/df/var/spool/cron/crontabs/*; do echo "== $f =="; cat "$f"; done
ls -la /mnt/df/etc/cron.{hourly,daily,weekly,monthly}/
ls -la /mnt/df/var/spool/cron/atjobs/          # at/batch 一次性任务

# ===== 2. systemd 自启（.wants 才是"已启用"）=====
ls -l /mnt/df/etc/systemd/system/*.wants/ /mnt/df/etc/systemd/system/*.requires/ 2>/dev/null
# 重点：软链目标是否在 /etc（下标 custom）
find /mnt/df/etc/systemd/system -name '*.wants' -type d -exec ls -l {} \; 2>/dev/null | grep '\-> /etc/'
# timer + 配对 service 的 ExecStart
find /mnt/df/etc/systemd/system -name '*.timer' 2>/dev/null | while read t; do
  echo "== $t =="; cat "$t"; grep -A5 '\[Service\]' "${t%.timer}.service" 2>/dev/null; done
# 全局搜危险 ExecStart
grep -rhE '^Exec(Start|Pre|StartPost)=' /mnt/df/{etc,lib,usr/lib}/systemd/system 2>/dev/null \
  | sort -u | grep -E '/tmp/|/dev/shm/|/var/tmp/|/home/'

# ===== 3. profile 注入 =====
for f in /mnt/df/etc/profile /mnt/df/etc/bash.bashrc /mnt/df/etc/environment; do
  echo "== $f =="; grep -vE '^\s*#|^\s*$' "$f" 2>/dev/null; done
for f in /mnt/df/etc/profile.d/*.sh; do echo "== $f =="; cat "$f"; done
# 搜环境变量型注入 + 下载执行链
grep -rnE '(BASH_ENV|LD_PRELOAD)[[:space:]]*=|^ENV=|curl[^|]*\|[[:space:]]*(ba)?sh|base64[[:space:]]+-d[^|]*\|[[:space:]]*(ba)?sh' \
  /mnt/df/etc /mnt/df/home /mnt/df/root 2>/dev/null

# ===== 4. motd / init / rc.local / 模块 =====
ls -la /mnt/df/etc/update-motd.d/ ; cat /mnt/df/etc/update-motd.conf 2>/dev/null
ls -la /mnt/df/etc/init.d/ /mnt/df/etc/rc.d/init.d/ 2>/dev/null
cat /mnt/df/etc/rc.local 2>/dev/null ; ls -la /mnt/df/etc/rc*.d/ 2>/dev/null
grep -rhvE '^\s*#|^\s*$' /mnt/df/etc/modules-load.d/*.conf /mnt/df/etc/modules 2>/dev/null

# ===== 5. ★ ld.so.preload（存在且非空 = 强信号）=====
ls -l /mnt/df/etc/ld.so.preload 2>/dev/null
cat /mnt/df/etc/ld.so.preload 2>/dev/null
# 其中的 .so 是否属于任何包？（Debian 系）
grep -oE '^\s*/[^ ]+\.so' /mnt/df/etc/ld.so.preload 2>/dev/null | tr -d ' ' | while read s; do
  echo -n "$s → "; grep -rlx "$s" /mnt/df/var/lib/dpkg/info/*.list 2>/dev/null | head -1 || echo "★ 不属于任何包"; done

# ===== 6. SUID / SGID 复查 =====
find /mnt/df -xdev -perm -4000 -type f -printf '%m %u:%g %TY-%Tm-%Td %TH:%TM %p\
' 2>/dev/null | sort
find /mnt/df -xdev -perm -2000 -type f -printf '%m %u:%g %p\
' 2>/dev/null
# 可写目录里的 setuid/setgid = 强信号
find /mnt/df/tmp /mnt/df/var/tmp /mnt/df/dev/shm /mnt/df/home -perm /6000 2>/dev/null
# 用包清单判定"是否官方"（Debian 系；RHEL 用 rpm 离线数据库）
for p in $(find /mnt/df/tmp /mnt/df/var/tmp -perm /6000 -type f 2>/dev/null); do
  echo -n "${p#/mnt/df} → "; grep -lx "${p#/mnt/df}" /mnt/df/var/lib/dpkg/info/*.list 2>/dev/null | head -1 || echo "★ 不属于任何包"; done
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — Linux 取证 — 计划任务与持久化痕迹」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《计划任务与持久化痕迹》（CC BY-SA 4.0）`

文中 `DigiForensics.dd` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
