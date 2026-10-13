---
title: "包管理器与软件清单"
slug: "computer-persistence-package-manager-and-software-inventory"
canonical: "https://www.digiforensics.cn/wiki/computer-persistence-package-manager-and-software-inventory"
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

# 包管理器与软件清单

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/computer-persistence-package-manager-and-software-inventory)

<a id="section-1"></a>

## 一、概述

多数 Linux 取证只读 `auth.log` 和文件时间戳，**很少系统性地读包管理器的账本**。

但账本能回答一批其它工件回答不了的问题，而且是结构化答案：

- **这台机器上装没装某个软件？** 账本比「目录里有没有」可靠得多，原因见下。
- **谁在什么时候装、卸、升级了它？** Debian 系的 `apt/history.log` 把**时间、操作者、包名、版本变更**四要素记全了，格式还是结构化纯文本，比 `auth.log` 的自由文本好解析得多。
- **这个文件是系统自带的，还是后来放上去的？** 每个包都有完整文件路径清单，逐条比对就能定性。
- **这个包是管理员有意装的，还是依赖自动带进来的？** `Auto-Installed` 标记能回答，**这决定了该包的出现是否说明管理员有明确意图**。
- **这台机器的用途是什么？** 软件组合反推。

账本比「目录里有没有」可靠，靠的是三条机制：

- **卸载不删干净文件。** `apt remove` / `rpm -e` 只改数据库，`/etc` 下的配置、缓存、日志、数据目录经常留下。所以「`/etc/nginx` 还在」**推不出「nginx 还装着」**；反过来「账本里没有 nginx」**能推出「官方渠道没装 nginx」**。
- **安装会覆盖系统路径。** 装包时同名文件会落到 `/usr/bin` 等位置，可能顶替原有文件。定性方法见 3.3 的全盘归属比对。
- **账本本身是普通文件。** `/var/lib/dpkg/status` 与 `/var/lib/rpm/` 随镜像被复制，**不需要在原机器上跑任何命令**。

账本在流程里的定位是**分析**环节的「定性工具」——它本身通常不产出新发现，而是**为其它发现定性**。

**上游依赖**发行版家族判定。Debian 系与 RHEL 系是两套完全不同的账本结构，判错则后面全错，判定方法见[取证工件地图](computer-persistence-persistence-artifact-map.md)。

**下游支撑**四处，都很关键：为[计划任务与持久化痕迹](computer-persistence-scheduled-tasks-and-persistence.md)里发现的 SUID 文件判断「是包自带的还是人为放的」；为可疑二进制的来源定性；为时间线提供包级的时间锚点（**装包时间可以作为校验其它时间戳是否合理的基准**）；为报告里的主机画像提供软件清单。

它的方法论价值超出 Linux：「查文件归属」这个动作在任何装了包管理器的系统上都成立，容器镜像、macOS 的 Homebrew、Windows 的程序清单都属同一思路。

账本的形态与位置：

| 形态 | 位置 | 关键结构 |
|---|---|---|
| Debian 状态库 | `/var/lib/dpkg/status` | RFC822 风格段落，`Status:` 行的状态位有七种组合，其中「已卸载但配置残留」与「完全不存在」是两个状态 |
| Debian 文件清单 | `/var/lib/dpkg/info/<pkg>.list` | **每个包安装的全部文件路径，逐行一条** —— 归属比对的依据 |
| Debian 安装历史 | `/var/log/apt/history.log`（及其归档 `.gz`） | 分块结构，含 `Start-Date` / `Commandline` / `Install:` / `Upgrade:` / `Remove:` |
| 安装者标记 | `/var/lib/apt/extended_states` | `Auto-Installed` 标记在此，不在 `status` 里 —— 读错文件会得到完全相反的结论 |
| RHEL 账本 | `/var/lib/rpm/Packages`（Berkeley DB）、`/var/lib/rpm/rpmdb.sqlite`（较新版本） | 二进制数据库，需专用工具离线读取 |
| RHEL 历史 | `/var/log/dnf.log`、`/var/log/yum.log` | 文本，含事务 ID 与动作列表 |
| 其它生态 | snap（`/var/lib/snapd`）、Flatpak、容器镜像层 | 各自独立账本，**不在 dpkg/rpm 体系内，不比对就会漏** |
| 校验工具 | `dpkg --verify` / `rpm -V` | 校验已安装文件的完整性与属主，是发现文件被改的手段 |

答得出来的是：完整软件清单及其版本、每个文件的包归属、装卸升级的时间与操作者、手动装与依赖装的区分、**哪些文件不属于任何包**（这是发现人为放置文件的关键）、以及通过软件组合反推的主机角色。

答不出来的：

- **装过但已完全卸载的包**。账本不留卸载记录的历史细节，`history.log` 只在启用 APT 日志的机器上有，**未配置的主机上这个答案是「查不到」而非「没装过」**。
- **非包管理安装的文件的创建时间与操作者**。归属比对只能说「不属于任何包」，**要拿到时间与操作者，需要靠时间线与认证日志**。
- **装软件的人的意图**。`Auto-Installed: 1` 说明是依赖带进来的，不说明为什么需要它。
- **未被账本覆盖的生态**。snap、Flatpak、手工编译安装的二进制、自行下载的脚本，**都不在 dpkg/rpm 账本里**，只查这两个库会系统性地漏。
- **文件内容是否被改过**。归属比对回答「这个路径该属于谁」，**「内容是否与包提供的一致」是另一件事**，需要完整性校验。

走这套方法需要能区分 Debian 系与 RHEL 系的基础差异，至少知道两者包管理器不同；熟悉 Linux 目录结构，理解 `/usr`、`/etc`、`/var` 的分工——**归属比对本质上是路径与包的对应关系**；会读 RFC822 风格的段落文本，能分辨 `status` 文件里七种状态位的含义；了解时间戳的基本语义，用于把安装时间与文件 `mtime` 做对照；具备批量检索能力，3.3 的全盘归属比对需要遍历整卷路径清单。

<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 两大家族的账本结构

| 对比项 | **Debian / Ubuntu** | RHEL / CentOS / Rocky / Alma |
|---|---|---|
| 数据库文件 | `/var/lib/dpkg/status`（**纯文本**） | `/var/lib/rpm/Packages`（**Berkeley DB 或 sqlite**）★ |
| 每包文件清单 | `/var/lib/dpkg/info/<pkg>.list` ★★ | RPM 数据库同样含文件列表（需 `rpm -ql` 离线读或解析 DB） |
| 包元数据 | `/var/lib/dpkg/info/<pkg>.md5sums`、`conffiles` | RPM header 内含 |
| **安装历史** | `/var/log/apt/history.log` ★★ | `/var/log/dnf.log`、`/var/log/yum.log` |
| 单次事务日志 | `/var/log/dpkg.log` | 同 `dnf.log` |
| 手动/自动标记 | `/var/lib/apt/extended_states`（`Auto-Installed: 1`）★ | `dnf history user installed` |
| 查询工具 | `dpkg -l`、`dpkg -S`、`apt list` | `rpm -qa`、`rpm -qf` |
| 发行版标识 | `/etc/dpkg/origins/` | `/var/lib/rpm/repodata/` |

> ⚠️ RHEL 系的 `/var/lib/rpm/Packages` 是 Berkeley DB 或 SQLite 二进制，不是纯文本。**不能 `grep`/`cat` 解析**。要么用 `rpm` 工具在分析机上指向镜像（`rpm --dbpath`），要么用专门的解析器。这与 Debian 系的纯文本 `status` 有本质差异，是两系操作方式不同的根源。

> ⚠️ **判断数据库格式**：`file /var/lib/rpm/Packages`。Berkeley DB 会显示 `Berkeley DB (BTree, ...)`, sqlite 显示 `SQLite 3.x database`。**两者解析器不同。**

<a id="section-4"></a>

### 2.2 `dpkg` 的三层数据结构

`dpkg` 的账本是分层的，理解这个结构就理解了它的全部取证能力：
| 层 | 位置 | 内容 |
|---|---|---|
| **① 已安装状态** | `/var/lib/dpkg/status` | **纯文本**，分段结构，每段一个包：包名、版本、架构、状态、依赖 |
| **② 每包文件清单** | `/var/lib/dpkg/info/<pkg>.list` | **该包安装的每一个文件路径，一行一个** ★★ |
| **③ 每包校验和** | `/var/lib/dpkg/info/<pkg>.md5sums` | 文件 → md5，用于完整性验证 |
| **③ 每包配置文件** | `/var/lib/dpkg/info/<pkg>.conffiles` | 该包的配置文件路径（卸载时保留的） |
| **附加信息** | `/var/lib/dpkg/info/<pkg>.postinst` 等 | 卸载时会执行的脚本（`postrm` 值得看） |

**`status` 文件的段结构**（Stanza）：

```
Package: nginx
Status: install ok installed
Priority: optional
Section: web
Installed-Size: 643
Maintainer: Jose Parrella <bureado@debian.org>
Architecture: amd64
Version: 1.18.0-6ubuntu14.4
Depends: libc6, libpcre2-8-0, zlib1g
Description: small, powerful, scalable web server
```

**关键字段**：

| 字段 | 取证意义 |
|---|---|
| `Package` | 包名 |
| `Version` | **含发行版修订号**（`1.18.0-6ubuntu14.4`），**比"软件版本"更精确**——同一上游版本的不同修订说明"打过安全补丁" |
| `Status` | `install ok installed` = 已装；`deinstall ok config-files` = **只删了程序、留了配置** ★（强信号：有人在清理但保留配置） |
| `Architecture` | `amd64`/`arm64`/`all`（`all` = 架构无关，如 `bash`） |

> ★ `deinstall ok config-files` 是Linux 取证里的一个高质量信号：它意味着有人执行了 `apt remove`（不是 `purge`），**明确保留了配置文件**。这在"管理员正常卸载"和"攻击者清理工具但可能还想回来"之间需要结合其它证据判断。**必须逐包检查是否有这个状态。**

`/var/lib/dpkg/info/*.list` 的三项用途：

```bash
# 列出某包安装的所有文件
cat /mnt/df/var/lib/dpkg/info/nginx.list
# /etc/nginx/...
# /usr/sbin/nginx
# /usr/share/nginx/...
```

- **★ 反查：这个文件属于哪个包？** `dpkg -S /usr/bin/sudo` 离线等价为 `grep -lx '/usr/bin/sudo' /var/lib/dpkg/info/*.list`。
- **★ 全盘文件比对**：把所有 `*.list` 合并成一个"官方文件全集"，然后凡是磁盘上存在、但不在这份全集里、且又不属于已知手动部署路径的文件，都是"非包管理安装"的文件——**这是发现被直接写入磁盘的文件的系统化方法**（第 01 篇案例中判定 `/tmp/.kworkerd` 属此类，用的就是这个方法）。
- **★ 判断文件是否被顶替**：若某文件的路径**在**某包清单里，但文件本身的 `mtime`/`ctime` 与包安装时间不符，**说明文件被改过**。

<a id="section-5"></a>

### 2.3 ★ `/var/log/apt/history.log`：四要素齐全的事务日志

`apt`（不只是 `dpkg`）会把每一次事务（install/upgrade/remove/purge）记录成一个结构化条目：

```
Start-Date: 2024-03-17 22:47:33 UTC
Install: netcat [1.10-41]:amd64 (1.10-41ubuntu1)
Install: netcat-openbsd [1.219-1ubuntu1]:amd64 (1.219-1ubuntu1 -> 1.219-1ubuntu1.1)
End-Date: 2024-03-17 22:47:35 UTC
```

| 字段 | 含义 | 取证价值 |
|---|---|---|
| `Start-Date` / `End-Date` | 事务起止（**带时区标注**） | 精确时间锚点 |
| `Commandline` | 触发命令（如 `apt-get install -y netcat`） | **可含参数** |
| **`Install:`** | 安装/升级的包 + `[版本]`，升级用 `旧 → 新` | **★ 版本变更一目了然** |
| `Remove:` | 卸载的包 + 版本 | 卸载了防护软件 = 信号 |
| `Purge:` | 彻底清除的包 | 需与其它证据交叉印证，见陷阱 10 |
| `Upgrade:` | 升级 | |
| **`Requested-By:`** | **谁触发的**（`$` 后面是用户名） | **★ 操作者身份！** |
| `Error:` | 失败的事务 | 失败的尝试也有价值 |

**这四项优势的成立条件**：

1. **四要素齐全**——**时间**（Start-Date）、**操作者**（`Requested-By`）、**包名**、**版本变更**（`旧 → 新`）。单个日志文件同时回答"谁、何时、做了什么、改了哪个版本"。
2. **结构化**——比 `auth.log` 的自由文本好解析得多（`:` 分隔、`旧 → 新` 固定模式）。
3. **带时区标注**——但标注的是系统本地时间，缩写含义须按陷阱 14 逐条判定，时间线对齐见[第 08 篇](../computer-log/computer-log-linux-timeline-reconstruction.md)。
4. **不依赖其它工件**——即使 `auth.log` 被清、shell 历史被删，`history.log` 仍独立记着"装了 netcat"这个事实（除非也被删）。

两条读表时的警告：

- `Requested-By` 的用户名只在该用户自己跑 apt 时出现。若 `root` 跑 `apt`，通常是 `root`。但 `Commandline` 里的细节（如 `-y`、`--allow-downgrades`）往往比用户名更能说明意图。
- 系统自动更新（unattended-upgrades）也会写 `history.log`，条目里 `Requested-By: <root>`（或 `_apt`）且 `Commandline: unattended-upgrade`。**必须把自动更新条目和人工操作区分开**——否则会把系统自动打的补丁误判为"管理员装了什么"。判据是包名 + `Requested-By` + `Commandline` 三者。

**多个文件配合**：

| 文件 | 粒度 | 说明 |
|---|---|---|
| `/var/log/apt/history.log` | **每次事务一条** | ★★ 本篇重点 |
| `/var/log/apt/history.log.*.gz` | 归档 | logrotate 轮转，**必须一并提取** |
| `/var/log/dpkg.log` | **每个包动作一行** | 粒度更细，含 unpack/install/configure/status 等阶段 |
| `/var/log/alternatives.log` | 软链切换 | 改了系统默认工具（如 `editor`） |

> ⚠️ `history.log` 也被 logrotate 轮转，所以历史可能分散在 `history.log`、`history.log.1.gz` 等。**必须合并后再分析**（方法同[第 02 篇](../computer-log/computer-log-system-log-analysis.md)的 3.2）。

<a id="section-6"></a>

### 2.4 `apt-mark`：区分"手动装的"与"依赖带进来的"

这解决一个常见误判：很多包是安装别的包时被依赖自动带进来的，不代表管理员"想要"它。
| 命令 | 含义 |
|---|---|
| `apt-mark showmanual` | **标记为"手动安装"**的包（管理员/脚本显式安装的） |
| `apt-mark showauto` | **标记为"自动安装"**的包（作为依赖被带进来的） |
| `apt-mark showhold` | 被 hold（锁定不升级）的包 |

> ⚠️ 关键事实：手动/自动标记不在 `/var/lib/dpkg/status` 里，而在 `/var/lib/apt/extended_states`。
>
> - `/var/lib/dpkg/status` 只有 `Status: install ok installed` 这类**安装状态**，**没有**"是否自动安装"的字段。分析时不要在 status 里找 `Auto-Installed`，找不到是正常的。
> - `/var/lib/apt/extended_states` 是 APT 自己的扩展数据库，**只有自动安装的包才会被写进去**，字段形如：
>
> ```
> Package: libssl3
> Architecture: amd64
> Auto-Installed: 1
> ```
>
> - 因此判定规则是：在 `extended_states` 里且 `Auto-Installed: 1` → 自动安装（依赖带入）；不在其中 → 手动安装。 注意该文件里也可能出现 `Auto-Installed: 0`（曾被标记为自动、后被 `apt-mark manual` 改回）。
> - 用 `dpkg -i` 直接装的包不会写 `extended_states`，APT 一律视为手动安装——这一条在取证中很有用：它意味着"绕过 apt 直接 dpkg 安装"会留下"看起来像手动安装"的痕迹。
> - `apt-mark showauto/showmanual` 读的就是这个文件（`-f` 可指定其他文件）。离线分析时直接解析 `extended_states` 即可，无需 `apt-mark` 参与。

**取证价值**：

| 观察 | 判读 |
|---|---|
| `netcat` 在 `showmanual` 里 | 管理员/攻击者**显式**装的 → 强信号（系统默认不装 netcat） |
| 某大量 Web 库在 `showauto` 里 | 是装 web 框架时**依赖带进来的**，不单独说明问题 |
| 某个防护工具在 `showauto` 且已被 remove | 可能是被卸载时顺带移除的 |

> **本篇只讲痕迹识别，不涉及规避手法的实现。**

<a id="section-7"></a>

### 2.5 RHEL 系：RPM 数据库与 dnf 历史

RHEL 系的结构和 Debian 系不同，操作方式也不同：
| 项目 | 位置/命令 | 注意事项 |
|---|---|---|
| 包数据库 | `/var/lib/rpm/Packages`（**Berkeley DB 或 SQLite**） | **二进制，不能 grep** |
| 查已装 | `rpm -qa`（在线）；离线用 `rpm --dbpath <镜像>/var/lib/rpm -qa` | ⚠️ dbpath 指向镜像，**不写**（加 `--justdb --nodeps` 只读） |
| 查某文件属哪个包 | `rpm -qf <path>`（在线）；离线同上 | |
| **安装历史** | **`/var/log/dnf.log`**（或 yum 的 `/var/log/yum.log`） | **是自由格式文本，不是结构化的 history** |
| 事务历史 | `dnf history list`（在线） | 离线解析难度较高 |
| repo 元数据 | `/var/lib/rpm/repodata/` | |

> ⚠️ RHEL 系没有 Debian 系那样"单文件结构化 history"。`dnf.log`/`yum.log` 是**混合自由文本**，需要 grep 关键字（`Installed:`、`Installed:`、`Complete!`、`Error:`）。**这是两系在取证效率上的实质差距**——Debian 系的 `history.log` 明显更适合作为证据。

<a id="section-8"></a>

### 2.6 其它包管理生态

| 生态 | 查询 | 位置 | 取证意义 |
|---|---|---|---|
| **snap** | `snap list` | `/var/lib/snapd/snaps/`、`/snap/*/` | snap 包**沙箱运行、自更新**；**常驻后台**（snapd 服务） |
| **flatpak** | `flatpak list` | `/var/lib/flatpak/`、`~/.local/share/flatpak/` | 同上 |
| **pip** | `pip list` | `/usr/lib/python3/dist-packages/`、`~/.local/lib/` | **含 `~/.local` 的手动装包**（`pip install --user`） |
| **npm 全局** | `npm -g ls` | `/usr/lib/node_modules/` | |
| **docker** | `docker ps -a` | `/var/lib/docker/`（**overlay2** 分层） | 见"容器"提示 |
| **conda** | `conda env list` | `/opt/conda/` | |

> **snap / flatpak 的特殊性**：它们**在系统包之外另起一套**，所以 **`dpkg -l` 看不到 snap 装的软件**。而且它们**会自动更新**（除非企业版策略禁用），意味着"某个 snap 的版本是某天的"这类推论不成立。**这是一个容易导致时间线误判的点。**

<a id="section-9"></a>

### 2.7 从软件清单反推主机功能

**软件组合是主机用途的强证据**，比任何单一文件都有说服力：
| 软件组合 | 推断的主机功能 | 佐证方向 |
|---|---|---|
| `nginx` + `php-fpm` | **网站服务器** | `/var/www`、`nginx` 访问日志 |
| `docker`/`containerd` + `docker-compose` | **容器化应用主机** | `/var/lib/docker/overlay2` |
| `mysql-server`/`postgresql` + `php` | **数据库驱动的应用** | 数据库数据目录、连接日志 |
| `openssh-server` + `fail2ban` + `ufw` | 有防护的远程运维主机 | 见[第 05 篇](computer-persistence-ssh.md) |
| `auditd` + `rsyslog` + 集中转发配置 | **合规审计环境**（日志留存要求高） | `/etc/rsyslog.d/`、logrotate 策略 |
| 多个 `*-server` + 无桌面环境 | 纯服务器（无 X11/图形栈） | 包清单里无 `xorg` |
| `tcpdump`/`wireshark`/`nmap` | **有抓包/扫描工具**（安全人员，或攻击者） | ★ 结合其他证据判断意图 |
| `telnet` | 存在明文远程登录（高危配置） | 见[第 05 篇](computer-persistence-ssh.md) |
| 无 `*-server` 且只装了基础工具 | 容器基础镜像 / 最小化系统 | `/etc/os-release` 交叉 |

> **反推的使用纪律**：软件组合只能作为"这台机器具备某功能"的证据，不能作为"某行为已发生"的证据。装了 `tcpdump` ≠ 抓过包；装了 `nmap` ≠ 扫过别人。**必须与日志/时间戳交叉才能定性行为。**

---

<a id="section-10"></a>

## 三、操作步骤

<a id="section-11"></a>

### 3.1 第 1 步：确认家族与账本格式

```bash
# 家族判定
cat /mnt/df/etc/os-release | grep -E '^(NAME|VERSION_ID)='
ls -d /mnt/df/var/lib/dpkg /mnt/df/var/lib/rpm 2>/dev/null

# RHEL 系：确认 RPM 后端格式（Berkeley DB vs sqlite）
file /mnt/df/var/lib/rpm/Packages
# Berkeley DB (BTree, native byte-order, version 8, format 62)  → Berkeley DB 后端
# SQLite 3.x database ...                                   → sqlite 后端（解析器不同！）
```

<a id="section-12"></a>

### 3.2 第 2 步：提取已安装软件清单

**Debian 系（纯文本，可直接解析）**：

```bash
# 提取包名 + 版本 + 状态（从 status 文件）
awk '/^Package: /{p=$2} /^Status: /{s=$2" "$3" "$4} /^Version: /{v=$2}
     /^$/{if(p)print p"\	"v"\	"s; p=s=v=""} END{if(p)print p"\	"v"\	"s}' \
  /mnt/df/var/lib/dpkg/status | sort > /evidence/dpkg-installed.tsv

# 看总数与关键包
wc -l /evidence/dpkg-installed.tsv
grep -iE 'nginx|openssh|netcat|nmap|tcpdump|docker|audit' /evidence/dpkg-installed.tsv

# ★ 只删了程序、保留了配置的状态（强信号）
awk '/^Package: /{p=$2} /^Status: /{s=$0} /^$/{if(s ~ /config-files|deinstall/)print p"  "s; s=""}' \
  /mnt/df/var/lib/dpkg/status
```

**RHEL 系（二进制，需 rpm 工具）**：

```bash
# 离线读镜像里的 RPM 数据库（--justdb --nodeps = 只读，不触发脚本）
rpm --dbpath /mnt/df/var/lib/rpm --justdb --nodeps -qa 2>/dev/null | head -40
rpm --dbpath /mnt/df/var/lib/rpm --justdb --nodeps -qf /usr/bin/bash 2>/dev/null
# ⚠️ 一定加 --justdb --nodeps，避免触发脚本 / 写入
```

<a id="section-13"></a>

### 3.3 第 3 步：★ 全盘文件归属比对（发现"非包管理安装"的文件）

```bash
# 1) 汇总"官方文件全集"（所有包安装的文件路径）
cat /mnt/df/var/lib/dpkg/info/*.list | sed 's#^\./##' | sort -u > /evidence/official-files.txt
wc -l /evidence/official-files.txt

# 2) 拿一个可疑文件，查它是否属于任何包
check_file() { grep -qx "$1" /evidence/official-files.txt && echo "属于某个包" || echo "★ 不属于任何包"; }
check_file /usr/bin/sudo
check_file /tmp/.kworkerd

# 3) 批量：找出 /usr/bin /usr/sbin 下不属于任何包的可执行文件
find /mnt/df/usr/bin /mnt/df/usr/sbin /mnt/df/bin /mnt/df/sbin -type f 2>/dev/null \
  | sed 's#^/mnt/df##' | sort > /tmp/on-disk.txt
comm -23 /tmp/on-disk.txt /evidence/official-files.txt | head -40
# ↑ 这些是"磁盘上有、包清单里没有"的可执行文件 → 值得逐个看
```

> **排除项**：`/usr/local/bin`、`/opt`、`/snap`、`/home` 下的文件**本就不该在包清单里**（属手动部署区），**不能直接当异常**。异常集中在 `/usr/bin`、`/usr/sbin`、`/lib`、`/bin` 等"包管理区"。 这一点务必注意，否则会大量误报。

<a id="section-14"></a>

### 3.4 第 4 步：★ 解析 `apt/history.log`（含归档）

```bash
# 1) 合并当前 + 归档（最旧 → 最新）
cd /mnt/df/var/log/apt
{
  ls -1tr history.log.*.gz 2>/dev/null | while read f; do zcat "$f"; done
  cat history.log 2>/dev/null
} > /evidence/apt-history-merged.txt
wc -l /evidence/apt-history-merged.txt

# 2) 找出所有装/卸/升级了安全相关工具的事务
grep -nE '^(Install|Remove|Purge|Upgrade):.*(netcat|nmap|tcpdump|audit|ufw|fail2ban|sudo|openssh)' \
  /evidence/apt-history-merged.txt

# 3) 找出时间接近入侵窗口的事务（Start-Date 在窗口内）
grep -A8 '^Start-Date: 2024-03-17' /evidence/apt-history-merged.txt

# 4) 看谁触发的 + 命令行
grep -E '^(Requested-By|Commandline):' /evidence/apt-history-merged.txt | tail -20
```

**`history.log` 解析示例**（本案真实形态）：

```
Start-Date: 2024-03-17 22:47:33 CST
Install: netcat [1.10-41]:amd64 (1.10-41ubuntu1)
Install: netcat-openbsd [1.219-1ubuntu1]:amd64 (1.219-1ubuntu1 -> 1.219-1ubuntu1.1)
End-Date: 2024-03-17 22:47:35 CST
Start-Date: 2024-03-17 22:49:20 CST
Commandline: apt-get install -y jq
Requested-By: root
Install: jq [1.6-2.1ubuntu3]:amd64 (1.6-2.1ubuntu3)
End-Date: 2024-03-17 22:49:22 CST
```

**读法**：第一条无 `Requested-By` 行 = 由一个已存在的 apt 进程以调用者身份触发（通常是 `sudo apt` 后的普通 `apt` 调用）；第二条有 `Requested-By: root` + `Commandline` 明文。两条都在 22:47–22:49 落地，与[第 02 篇](../computer-log/computer-log-system-log-analysis.md) auth.log 里 22:47:33 的 `sudo COMMAND=/usr/bin/apt-get install -y netcat` 精确吻合——**双源印证**。

> ⚠️ **`Start-Date` 的时区必须逐条看。** `apt` 写的是**系统本地时间 + 时区缩写**（`UTC` / `CST` / `+0800` 等），**并非总是 UTC**。`CST` 是个陷阱——它同时指"中央标准时间"和"中国标准时间"，必须靠 `/etc/timezone` 或 `/etc/localtime` 判定实际偏移。跨源对齐前先确认基准（见[第 08 篇](../computer-log/computer-log-linux-timeline-reconstruction.md)）。
>
> ⚠️ **必须区分自动更新**：`unattended-upgrades` 的条目形如 `Commandline: unattended-upgrade` 且 `Requested-By: <root>`，通常在**固定时段**（如每天 06:00）批量升级一批包。人工操作通常是零散、时段随机、且有 `Commandline` 明文。

<a id="section-15"></a>

### 3.5 第 5 步：手动 vs 自动标记（读 `extended_states`，不是 `status`）

```bash
# 全部已安装包（从 dpkg status）
awk '/^Package: /{p=$2} /^$/{if(p)print p; p=""}' /mnt/df/var/lib/dpkg/status > /evidence/all-pkgs.txt
wc -l /evidence/all-pkgs.txt

# ★ 自动安装的包 = extended_states 里 Auto-Installed: 1 的那些
awk '/^Package: /{p=$2} /^Auto-Installed: 1/{print p}' \
    /mnt/df/var/lib/apt/extended_states > /evidence/auto-pkgs.txt
wc -l /evidence/auto-pkgs.txt        # 通常占已装包的三分之一以上

# 手动安装的包 = 全部已装 − 自动安装
grep -vxF -f /evidence/auto-pkgs.txt /evidence/all-pkgs.txt > /evidence/manual-pkgs.txt

# 关键查询：netcat 是手动还是自动？
grep -qx 'netcat' /evidence/auto-pkgs.txt && echo "自动（依赖带入）" || echo "手动 ★"
# → 手动 ★   系统默认不装 netcat，属显式安装
```

> **判读规则**：`extended_states` 中有 `netcat` 且 `Auto-Installed: 1` → 自动；**不在该文件中 → 手动**。若文件里出现 `netcat` 但 `Auto-Installed: 0`，说明曾被当依赖装入、后被 `apt-mark manual` 提升为手动——**这个转变本身是人为动作，值得追查**。
>
> ⚠️ `extended_states` 缺失时不要默认"全部手动"。 该文件可能被删除或从未由 apt 写过（纯 dpkg 安装的系统就没有）。此时应写"**自动/手动标记不可得**，仅能给出已安装包全集"，并把结论强度降级。

<a id="section-16"></a>

### 3.6 第 6 步：其它生态与容器

```bash
# snap / flatpak（包管理之外的系统，dpkg 看不到）
ls -la /mnt/df/var/lib/snapd/snaps/ 2>/dev/null     # snap 镜像文件
ls -la /mnt/df/snap/ 2>/dev/null
ls -la /mnt/df/var/lib/flatpak/ 2>/dev/null          # flatpak

# pip（含 --user 手动装到 ~/.local 的）
ls -la /mnt/df/usr/lib/python3/dist-packages/ 2>/dev/null | head
ls -la /mnt/df/root/.local/lib/python*/site-packages/ 2>/dev/null
find /mnt/df -xdev -name 'METADATA' -path '*dist-packages*' 2>/dev/null | head

# npm 全局
ls /mnt/df/usr/lib/node_modules/ 2>/dev/null

# docker（overlay2 分层 = 容器文件系统证据）
ls -la /mnt/df/var/lib/docker/overlay2/ 2>/dev/null | head
# 另见 /mnt/df/var/lib/docker/containers/ 下的 config.v2.json（含容器启动命令）
```

<a id="section-17"></a>

### 3.7 验证环节

| 验证对象 | 方法 | 通过标准 |
|---|---|---|
| 清单解析正确 | 包数量与 `dpkg -l`/`rpm -qa` 一致（在线对照） | 数量合理，无解析遗漏 |
| 文件归属判定 | `grep -qx <path> official-files.txt` | 归属明确；异常文件逐个人工确认 |
| 时间戳 | 磁盘上该文件 `stat` 的 `crtime`（ext4） | 落在入侵窗口 → 关联成立 |
| 自动 vs 人工 | `Requested-By` + `Commandline` + 时段分布 | 区分 unattended-upgrades 与人工 |
| 交叉印证 | `history.log` 时间 vs auth.log 的 `sudo COMMAND` | 二者吻合 → 强关联 |

---
<a id="section-18"></a>

## 四、常见陷阱

本章按账本读取 → 状态判读 → 安装历史 → 结论表述归组，每条给出：现象、为什么会误判、误判代价、正确做法。
★ 标记表示该操作会导致原始检材永久灭失或不可逆改变，执行前必须停下来确认。

<a id="section-19"></a>

### 4.1 账本读取

<a id="section-20"></a>

#### 陷阱 1：把 RHEL 系的 `/var/lib/rpm/Packages` 当文本解析

**现象**：在 Rocky Linux 镜像上 `cat /var/lib/rpm/Packages` 输出一堆乱码，或者 `grep 'nginx'` 在二进制文件上只报 "Binary file matches"，于是写「软件清单不可解析」。

**原因**：Debian 与 RHEL 两系的账本格式有本质差异。 Debian 的 `/var/lib/dpkg/status` 是纯文本分段结构，可以直接 `cat`/`awk`；RHEL 的 `/var/lib/rpm/Packages` 是 **Berkeley DB 或 SQLite 二进制**，必须用 `rpm` 工具（配 `--dbpath`）或专门的解析器。用文本手段读二进制，"乱码"是工具不适用的表现，不是文件损坏。

**影响**：这是"工具静默失败"的典型：`grep` 对二进制默认只输出一行 "Binary file matches" 而不报错，**退出码仍然是 0**。

分析者容易把它当成"解析成功但内容为空"，进一步得出"该机未安装 nginx"之类的结论。

**核查**：先判格式再选工具，两系分流：

```bash
ls -d /mnt/df/var/lib/dpkg /mnt/df/var/lib/rpm 2>/dev/null    # 家族判定
file /mnt/df/var/lib/rpm/Packages
# Berkeley DB (BTree, ...)  → 需 rpm --dbpath 或 bdb 解析器
# SQLite 3.x database ...   → 需 sqlite 解析器
```

Debian 系才用 `awk`/`grep` 直接解析 `status`；RHEL 系用 `rpm --dbpath /mnt/df/var/lib/rpm -qa` 指向镜像内的数据库目录，不要把镜像内的 rpm 数据库拷到分析机的系统 rpm 库里——版本不匹配会解析失败或误判，且可能污染分析机环境。

<a id="section-21"></a>

#### 陷阱 2：把 `dpkg -l` / `dpkg -S` 直接指向镜像路径

**现象**：在分析机上执行 `dpkg -l`，输出的是**分析机自己**的软件清单；执行 `dpkg -S /usr/bin/sudo` 得到的归属也是分析机的。

**原因**：`dpkg` 默认只读本机的 `/var/lib/dpkg`，它没有 `--dbpath` 这类指向异地数据库的选项（这与 `rpm --dbpath` 不同）。想让它读镜像，唯一途径是在挂载点/chroot/容器环境下运行。分析者以为在查检材，实际一直在查自己的机器。

**影响**：与 SSH 篇 `last` 不加 `-f` 是同一类错误，只是更隐蔽——`dpkg -l` 的输出格式完全正常、包名看起来合理，如果分析机的软件组合恰好与目标机接近，几乎不可能被发现。

报告里会出现一份与检材毫无关系的软件清单。

**核查**：Debian 系在离线场景下**直接解析 `status` 文件**，不走 `dpkg`：

```bash
# 提取"包名 + 状态 + 版本"三元组
awk '/^Package: /{p=$2} /^Version: /{v=$2} /^Status: /{print p"\	"$2"\	"v; p=v=""}' \
  /mnt/df/var/lib/dpkg/status

# 反查某文件属于哪个包（dpkg -S 的离线等价）
grep -lx '/usr/bin/sudo' /mnt/df/var/lib/dpkg/info/*.list
```

包文件清单在 `info/<pkg>.list`（一行一个路径），**离线场景下不需要 `dpkg` 就能用**。

<a id="section-22"></a>

### 4.2 状态与文件判读

<a id="section-23"></a>

#### 陷阱 3：忽略 `deinstall ok config-files` 状态

**现象**：`dpkg -l` 的输出被按"包名前面是 `ii`（已安装）还是 `rc`（仅配置）"扫了一眼，没有逐包细看 `Status` 字段，把三个 `deinstall ok config-files` 状态的包当成"未安装，不重要"跳过。

**原因**：`deinstall ok config-files` 意味着有人执行了 `apt remove` 而不是 `apt purge`，明确保留了配置文件。 这个状态本身就是一条独立于日志的静态发现——它说明有主体在这台机器上做过"卸载程序但不清配置"的动作。而管理员的正常卸载习惯与攻击者的清理习惯都会落到这个状态上，二者需要结合其他证据区分，但不能因为"包没装"就跳过。

**影响**：跳过的代价是丢掉一整类"清理行为"的证据。

案例第 2 步正是靠逐包扫 `config-files` 状态，挖出 `dump`、`tcpdump`、`wireshark-common` 三个网络分析类包被卸载但留配置——这个发现完全独立于日志，即使 auth.log 被清、shell 历史被删也依然成立。

**核查**：把 `Status` 字段的完整值作为必查项，而不是看两字符缩写：

```bash
awk '/^Package: /{p=$2} /^Status: /{s=$0} /^$/{if(s~/config-files|deinstall/)print p"  "s; s=""}' \
  /mnt/df/var/lib/dpkg/status
```

对每个命中的包补三项信息：① 残留的配置文件在哪（`<pkg>.conffiles` 列出路径，直接看文件内容）；② 该包的 `dpkg.log` 记录何时被移除；③ 移除时间是否落在入侵窗口内。"卸载留配置"是要写进报告的独立发现，不是过滤条件。

<a id="section-24"></a>

#### 陷阱 4：把"文件不在任何包清单里"直接等同于"攻击者放置"

**现象**：全盘比对 `info/*.list` 合并出的"官方文件全集"，发现几十个不在其中的文件，报告写「发现 N 个攻击者植入的文件」。

**原因**：不在包清单里只说明"不是通过包管理器装的"，来源至少有四种：① 攻击者直接写入；② 管理员手动 `make install` / 从源码编译安装 / `pip install` / `gem install`（这些都绕过包管理器，本机就装着 Python 生态的工具）；③ 容器运行时写入的数据文件（`docker`、`containerd` 的数据目录完全是手工布局的）；④ snap/flatpak 管理的软件文件——`dpkg -l` 根本看不到 snap 装的软件，所以它们的文件天然不在 `dpkg` 清单里。

**影响**：把"非包管理安装"整体归为恶意，会把运维手工装的工具、容器卷、Pip 装的 Python 库全部标红。

真信号（`/tmp/.kworkerd`、隐藏目录里的载荷）会淹没在几十条噪音里。

**核查**：把判据做成多层的，并按可信度分档：

```bash
# 第一步：合并官方文件全集
cat /mnt/df/var/lib/dpkg/info/*.list | sort -u > /evidence/dpkg-files-all.txt

# 第二步：磁盘上存在但不在全集里的可执行文件
find /mnt/df -xdev -type f -executable -printf '%p\
' 2>/dev/null \
  | sort -u > /evidence/disk-exec.txt
comm -13 /evidence/dpkg-files-all.txt /evidence/disk-exec.txt > /evidence/nonpkg-exec.txt
```

对 `nonpkg-exec.txt` 的每一项，按以下顺序分层定性：① 路径是否在已知的手工部署路径（`/usr/local/bin`、`/opt`、`/srv`、`/home/*/.local/bin`、`/usr/local/lib/python*/dist-packages`）——是则降级；

② 是否有对应包管理痕迹（pip 的 `RECORD`、`node_modules`、`/var/lib/snap`）——是则降级；③ 是否在可写临时目录（`/tmp`、`/var/tmp`、`/dev/shm`）、是否点开头隐藏、是否不在任何包清单——三者叠加才升到"可疑"。案例中 `/tmp/.kworkerd` 之所以定性，靠的是"SUID + 临时目录 + 包清单无归属 + auth.log 里有 chmod 命令"四条齐备，不是单靠"不在清单里"。

<a id="section-25"></a>

#### 陷阱 5：把"路径在包清单里"当作"文件未被改动"

**现象**：`/usr/bin/sudo` 的路径出现在 `sudo.list` 里，于是把它排除在篡改嫌疑之外。

**原因**：包清单记录的是"这个路径应该有这个文件"，不包含内容校验。 攻击者替换掉 `/usr/bin/sudo` 这个二进制后，包管理器数据库不会有任何变化——`status` 里的 `Status: install ok installed` 依然成立，`sudo.list` 里依然有这个路径。**清单回答"路径归属"，不回答"内容完整"。**

**影响**：路径级归属检查是最容易被当成完整性验证的步骤，误以为它覆盖了内容。`/usr/bin/sudo`、`/usr/bin/sshd` 这类被替换后的二进制是极高价值的入侵证据，而这种检查会完全漏掉。

**核查**：路径归属与内容校验是**两件独立的事**，都要做。内容侧有两个来源：① `info/<pkg>.md5sums` 记录了包内文件的 md5，可直接比对；② 即使没有 md5sums，也可比对该文件与其余同包文件的 `mtime`/`ctime` 是否同批——包安装时所有文件会获得接近的 mtime，个别文件显著偏晚即被改过（案例第 3.2 节的判据就是这个）。要说明的是：`md5sums` 不覆盖配置文件（配置文件由 `conffiles` 单独管理，且管理员的正常修改也会让 md5 失配），所以失配不等于恶意，要结合该文件是否属于 `conffiles` 清单来解释。

<a id="section-26"></a>

### 4.3 安装历史判读

<a id="section-27"></a>

#### 陷阱 6：把系统自动更新（unattended-upgrades）当成管理员操作

**现象**：`history.log` 里出现大量 `Upgrade: openssl [...]` 条目，报告写「管理员在该时段批量升级了多个组件」，并把其中一条与入侵时间关联。

**原因**：`unattended-upgrades` 是系统自动更新服务，它自己也会写 `history.log`，条目特征是 `Commandline: unattended-upgrade` 加 `Requested-By: <root>`（或 `_apt`）。它产生的事务与管理员手工 `apt-get upgrade` 在条目结构上高度相似，都是 `Upgrade: <包> [旧 -> 新]`。案例里 2024-03-17 06:00 的 openssl 升级就是这一类，判据是 `包名 + Requested-By + Commandline` **三者合看**。

**影响**：自动更新条目数量通常远多于人工操作，混在一起会让安装历史失去分析价值——真正的人工动作（安装 netcat、安装 strace）被淹没。

更糟的是，如果你把自动更新的时间聚集当成"管理员在入侵时段还在正常运维"，就会用它来反驳入侵结论（"当时管理员还在打补丁，说明一切正常"），而这个反驳建立在一堆自动条目上。

**核查**：先分类再分析，判据是三项组合：

```bash
grep -B1 -A6 '^Start-Date: 2024-03-17' /evidence/apt-history-merged.txt
```

对每条事务标注类型：`Commandline: unattended-upgrade` → **自动**；`Commandline: apt-get ...` 或 `/usr/bin/apt-get ...` → **人工**（此时 `Requested-By` 的用户名是最有价值的字段）；`Commandline` 缺失 → **由已存在的 apt 进程以调用者身份触发**（案例里 netcat 那条正是如此——`Requested-By` 缺失应作为观察项写进报告）。**只对人工类事务做行为归因。**

<a id="section-28"></a>

#### 陷阱 7：只看 `history.log` 当前文件，漏掉轮转归档

**现象**：`/var/log/apt/history.log` 里最近三天的事务齐全，报告写「该机近期的软件安装记录完整」。而真正案发那天的记录在 `history.log.2.gz` 里。

**原因**：`history.log` 同样受 logrotate 管控，归档为 `history.log.1`、`history.log.N.gz`。`compress` 之后的档位必须 `zcat` 才能读，直接 `ls`/`cat` 会被当成不存在。当前文件只保存最近一个轮转周期。

**影响**：案发时刻的软件安装记录（这是本主题最核心的证据）恰好在最早的归档里。

只读当前文件等于系统性丢掉案发时段，`Commandline` 与 `Requested-By` 都拿不到，报告只能停留在"装了 netcat"而说不出"谁装的、什么时候装的"。

**核查**：按轮转顺序由旧到新合并：

```bash
cd /mnt/df/var/log/apt
{ ls -1tr history.log.*.gz 2>/dev/null | while read f; do zcat "$f"; done
  cat history.log; } > /evidence/apt-history-merged.txt
```

用 `ls -1tr` 确认顺序（`dateext` 配置下后缀是日期序，字典序等于时间序）；合并后检查首尾 `Start-Date` 是否覆盖预期区间。若归档编号不连续（缺中间档），这是被删除的信号，要单独记录。

<a id="section-29"></a>

#### 陷阱 8：把"装了什么工具"直接推成"用工具做了什么"

**现象**：软件清单里有 `tcpdump`、`nmap`、`wireshark`，报告写「攻击者使用抓包与扫描工具进行了内网侦察」。

**原因**：软件清单只能证明"这台机器具备某功能"，不能证明"某行为已发生"。 装了 `tcpdump` 不等于抓过包，装了 `nmap` 不等于扫过别人。这些包也可能是管理员日常运维工具、安全团队的常备工具，或者是本篇 2.7 表格里说的那样——`tcpdump`/`wireshark`/`nmap` 属于"意图不明"类，需要结合其他证据判断。

**影响**：这是"能力 → 行为"的跳跃。

它给出的结论（"实施了内网侦察"）需要被举证，而软件清单完全无法支撑。一旦被质疑，报告里所有基于"行为已发生"的推演都失去起点。

**核查**：把软件清单的结论**严格限定在能力层面**：「镜像中发现 `tcpdump`（版本 x），该机具备抓包能力」。行为侧需要各自的独立证据：抓包需要输出文件（`/tmp/*.pcap`、进程 fd、流量记录）、扫描需要目标记录（防火墙日志、`auth.log` 里的批量 `Invalid user`、被扫主机的告警）。案例里 22:47 安装 netcat 之所以能定性，不是因为 netcat 本身，而是因为同一条 auth.log 时间线上还有 `chmod 4755 /tmp/.kworkerd` 这条具体动作——能力与行为被日志串在了一起。

<a id="section-30"></a>

### 4.4 结论表述

<a id="section-31"></a>

#### 陷阱 9：把"dpkg 清单里没有"写成"该软件未安装"

**现象**：报告列出"未发现 X 软件"，依据是 `dpkg -l` 无该条目。

**原因**：**`dpkg` 只覆盖系统包这一套账本。** 至少五类安装完全在它之外：① **snap**（`/var/lib/snap`、独立的 snapd 日志，会自动更新——"某个 snap 的版本是某天的"这类推论根本不成立）；② **flatpak**（`~/.local/share/flatpak`、系统级 `/var/lib/flatpak`）；③ **pip / npm / gem / cargo** 等语言级包管理器，装在 `/usr/local/lib/python*/`、`~/.local/`、`node_modules` 下；④ **从源码 `make install`** 的手工部署；⑤ **容器镜像内自带的软件**（`/var/lib/docker/overlay2` 里的完整根文件系统，`dpkg` 完全看不到）。案例第 5 步专门查了 `snap list` 和 `docker images` 来补这一块。

**影响**：一份基于 `dpkg -l` 的"未发现"清单，在 snap/容器环境里可能漏掉整机软件。

委托方若据此认为"该机没有 Python 环境/没有容器化应用"，会做出错误的处置决策。

**核查**："未安装"这个结论必须限定在账本范围内：「**`dpkg` 账本内**未发现 X」。同时补查另外四条路径（`snap list` 的元数据、`flatpak list`、`pip`/`npm` 的包记录目录、容器数据目录），并把查过哪些写进报告的"分析范围"章节。案例的做法是把这四类并列列出，这样"未发现"才有边界清晰的含义。

<a id="section-32"></a>

#### 陷阱 10：把"没有卸载记录"当成"没有清理行为"

**现象**：`history.log` 里没有 `Remove:`/`Purge:` 条目，报告写「攻击者未清理自身安装的软件」。

**原因**：清理行为在包账本上留下的痕迹不止一处，而且都有可能被绕过：① 直接 `rm` 删掉包安装的文件（`dpkg` 数据库会变成"文件缺失"状态而不是"已卸载"）；② 直接编辑 `/var/lib/dpkg/status` 移除 stanza；③ 攻击者更常用的做法是**根本不走包管理器**——工具本来就是从源码或直接复制到 `/usr/local/bin/.cache/` 的，**清理时 `rm` 掉即可，不会在任何包历史里留痕**（案例里 `rotate-logs.sh`、`sysd` 正是这类，完全不来自包管理器）；④ 清理时直接 `truncate` 掉 `history.log`（此时你会看到文件"完整但突然截断"）。

**影响**：这条阴性结论会被用来论证"攻击者不专业/清理不彻底"。

而真实情况很可能相反——攻击者用的是不产生日志的方式，**恰恰因为专业才没有包历史**。

**核查**：阴性发现要回答"我用什么方法确认没清理"。至少三条独立路径：① `history.log` 及其归档有无 `Remove`/`Purge`/`Requested-By` 相关条目；② `status` 文件里有没有 `deinstall ok config-files` 或 `not-installed` 状态残留；③ **文件时间线本身**——把所有非包管理文件的 `mtime` 排序，看有没有"安装后被删"的可疑空洞（配合 `dpkg.log` 的 unpack 时间与 `ctime` 链）。三者都无，才可以写「包管理渠道内未见卸载记录」，并明确**这个结论只覆盖包管理渠道**。

<a id="section-33"></a>

### 4.5 工具行为与环境前提

前四组讲的是判读，这一组讲**工具默认行为与环境差异**——它们制造的假阳性或假阴性不会留下任何提示，而判据的方向往往是系统性的。

<a id="section-34"></a>

#### 陷阱 11：`grep -lx` 反查包归属时把相对路径写错

**现象**：查 `/usr/bin/sudo` 属于哪个包，`grep -lx '/usr/bin/sudo' /var/lib/dpkg/info/*.list` 无输出，于是把它列入"清单外文件"。

**原因**：`*.list` 里记的是相对于根文件系统的路径（以 `/` 开头、无挂载点前缀），而分析时手上的路径几乎总是带挂载点前缀。 前者是 `/usr/bin/sudo`，后者是 `/mnt/df/usr/bin/sudo`。**`grep -x` 要求整行完全匹配**，多一个挂载点前缀就匹配不上，输出为空——而"无输出"恰好是判据期待的"清单外"方向。批量场景下更隐蔽：`comm` 比对两侧文件一边带前缀一边不带，**整份清单的匹配全部失败**。

**影响**：这是本篇覆盖面最广的一处判据失效——它不止影响一个文件，而是让"清单外文件"这个全集失真。系统自带的 `/usr/bin/*`、`/bin/*` 会大量涌入可疑清单，而真正的清单外文件淹没在其中。反过来更糟的情况是：把包文件标成"清单外"会导致报告指控一个**从未被篡改的系统二进制**，这是无依据的严重指控。

**核查**：**两侧路径统一剥到根相对形式再比对**：

```bash
# ① 建立官方文件全集（.list 本身就是根相对）
cat /mnt/df/var/lib/dpkg/info/*.list | sed 's|^\./||' | sort -u > /evidence/dpkg-files-all.txt

# ② 磁盘上可执行文件，剥掉挂载点前缀
find /mnt/df -xdev -type f -executable -printf '%p\
' 2>/dev/null \
  | sed 's|^/mnt/df||' | sort -u > /evidence/disk-exec-rel.txt

# ③ 比对：comm 的两个输入必须同为根相对且已排序
comm -13 /evidence/dpkg-files-all.txt /evidence/disk-exec-rel.txt > /evidence/nonpkg-exec.txt

# 自检：整套系统文件应在全集里，抽样验证匹配确实生效
grep -cx '/usr/bin/sudo' /evidence/dpkg-files-all.txt   # 应 = 1，若 = 0 说明路径口径错了
```

**那条抽样自检不能省**——它一步就能发现整份比对失效。任何 `comm`/`grep -x` 的路径比对，先用一个已知属包文件验证匹配能力，再信它的阴性输出。

<a id="section-35"></a>

#### 陷阱 12：把 `md5sums` 失配一律当作文件被篡改

**现象**：`/etc/ssh/sshd_config` 的 md5 与包内 `md5sums` 记录不一致，报告写「`sshd_config` 已被篡改」。

**原因**：`md5sums` 记录的是"安装那一刻的哈希"，而配置文件在被安装之后被修改是系统设计的正常结果。 包管理器把这类文件单独登记在 `*.conffiles` 里，并且刻意不把它们纳入 `md5sums` 的覆盖范围——正是为了避免正常配置修改被当成损坏。除此之外还有几种合法失配：包升级时配置文件被合并更新（Debian 会把原文件存成 `.dpkg-dist`/`.dpkg-old`，新文件哈希随版本变化）；管理员按自己的需要调过参数并**用 `dpkg-divert` 分流**；文件被编辑器换行符转换后保存（Windows 环境下的 CRLF/LF 差异是常见的哈希失配原因）。

**影响**：这条误判的分量很重——被指控的是 SSH 配置文件，而 SSH 配置正是入侵检测与横向移动的核心入口。报告若写「`sshd_config` 已被篡改」，委托方会立刻认定 SSH 认证策略被改，而真相可能只是管理员调了 `ClientAliveInterval`。**更实际的问题是这条结论会引导整改**：委托方可能去恢复一份"原始"配置，从而覆盖掉管理员的合法调整，甚至覆盖掉攻击者真正改动的那部分之外的所有现场配置。

**核查**：先判断该文件是否在 `conffiles` 里，再决定失配的解释方式：

```bash
# ① 该路径是否被登记为配置文件
grep -l '^/etc/ssh/sshd_config$' /mnt/df/var/lib/dpkg/info/*.conffiles

# ② 旁证：包管理器留存的原版本是否还在（正常修改/升级会留下它们）
ls -l /mnt/df/etc/ssh/sshd_config.* 2>/dev/null
#   sshd_config.dpkg-dist = 升级前版本（未被替换，说明无人改过）
#   sshd_config.dpkg-old  = 升级时被替换下来的旧版本
#   .dpkg-new            = 新版安装但未覆盖成功（冲突残留，本身值得解释）

# ③ 配置文件的 mtime vs 该包安装/升级的时间
stat -c '%n mtime=%y ctime=%z' /mnt/df/etc/ssh/sshd_config
grep -E 'ssh|openssh' /mnt/df/var/log/dpkg.log | tail -5
```

**判读规则**：① 路径在 `conffiles` 里 → 哈希失配是**预期的正常状态**，要写的是"配置文件内容与包内版本不同（系统正常允许）"，并把差异本身作为分析对象（**内容变了什么才是取证重点**）；② 不在 `conffiles` 也不在 `md5sums` 里 → 属未覆盖范围，**不能判定篡改**；③ 在 `md5sums` 覆盖范围内且失配 → 才是篡改判据成立。**配置文件的内容差异要走 diff，而不是走哈希。**

<a id="section-36"></a>

#### 陷阱 13：把 `dpkg.log` 的时间当成动作发生时间

**现象**：`/var/log/dpkg.log` 里某条记录的时间是 22:47:33，报告写「该时刻发生了安装动作」，并把它作为入侵窗口的锚点。

**原因**：**`dpkg.log` 的时间粒度与语义都受限。** 三点具体问题：① 它记的是事务内各个步骤的时间，一条记录不必然等于"用户发起了这个动作"的时刻——解包、配置、触发 postinst 脚本是不同步骤，时间可能相差数十秒，而后处理脚本的耗时可能更长；② `apt` 的动作与 `dpkg` 的动作有时间差，`history.log` 的 `Start-Date`/`End-Date` 才是事务边界，`dpkg.log` 只覆盖 `dpkg` 自身那部分，两者不一致时以 `history.log` 为事务口径；③ **日志轮转会造成缺口**，`dpkg.log` 与 `history.log` 的保留周期通常不同（`history.log` 轮转更快），更早的操作可能在 `dpkg.log` 里还在、`history.log` 里已丢，于是你会看到"有 dpkg 记录、无 history 记录"的孤立条目。

**影响**：用 `dpkg.log` 的时间做精确对齐，会在跨源比对时产生分钟级甚至小时级的偏差。偏差的直接后果是把一个本该落在入侵窗口内的动作判成"与之无关"，或反过来把一个无关的系统自动更新拉进攻击时间线。

**核查**：事务口径用 `history.log`，`dpkg.log` 只作步骤级补充，两源都要在报告里标注：

```bash
# 事务边界（口径来源）
grep -E '^(Start-Date|End-Date|Commandline|Requested-By):' /evidence/apt-history-merged.txt | tail -20
# 步骤细节（补充来源，注意粒度更细）
grep -E 'netcat' /mnt/df/var/log/dpkg.log | tail -10
```

**表述模板**：「事务 `<包名>` 的边界为 `<Start-Date>` 至 `<End-Date>`（来源 `history.log`）；`dpkg.log` 显示解包完成于 `<时刻>`、配置触发于 `<时刻>`，该日志的粒度为 dpkg 步骤级，不等同于用户发起时刻。」

<a id="section-37"></a>

#### 陷阱 14：把 `Start-Date` 里的 `CST` 当成已确定含义

**现象**：`history.log` 里的时间是 `2024-03-17 22:47:33 CST`，报告直接按 UTC+8 与 auth.log 的时间对齐，两条时间线吻合，于是把安装动作与入侵关联。

**原因**：`CST` 这个缩写同时指"中央标准时间（北美，UTC−6）"和"中国标准时间（UTC+8）"，相差 14 小时。 而 `apt` 写什么缩写取决于系统配置，`CST` / `CDT` / `IST` / `BST` 这类缩写在不同语境下含义不同。**判定的唯一权威来源是检材自身的时区配置**——`/etc/timezone` 的内容、或者 `/etc/localtime` 这个符号链接指向哪个 zoneinfo 文件。若系统时区配置为 `Asia/Shanghai`，则该 `CST` 是 UTC+8；配置缺失或被改动时，**日志里的缩写可能与当前实际时区不一致**（夏令时调整、改过时区又改回、日志是旧配置下写的），这时只能靠与其它时间源交叉验证来定基准。

**影响**：14 小时的误判会把一次关键动作完全移出入侵窗口，**或者把一个无关动作拉进窗口**。前者让真阳性丢失，后者让报告出现一个看似合理、实则凭空的时间关联。**在时间线重建的专题里，这种偏差是严重的**，因为后续所有跨日志的顺序判断都建立在同一时间基准上。

**核查**：**时区基准在分析开始时就要定下来并写入报告**：

```bash
# ① 检材声明的时区
cat /mnt/df/etc/timezone 2>/dev/null
ls -l /mnt/df/etc/localtime 2>/dev/null        # 指向哪个 zoneinfo
# ② 日志行自身的时区标注（逐条看，可能不一致）
grep -oE 'Start-Date: .*' /evidence/apt-history-merged.txt | tail -5
# ③ 与 auth.log 的时间交叉校准（auth.log 通常带明确时区或用本地时间）
grep -E 'COMMAND=/usr/bin/apt-get' /evidence/auth-merged.txt | tail -3
```

**判读规则**：① 以 `/etc/timezone` + `/etc/localtime` 为第一依据；② 该配置缺失时，用**两条独立时间线在同一事件上的相对差值**倒推（例如 auth.log 的 `sudo` 与 `history.log` 的 `Start-Date` 应在数秒内）；③ 仍不能确定时，**在报告里把时区作为一条显式不确定性写明**，并给出"若为 UTC+8 则…、若为 UTC−6 则…"两种情形下的对齐结果，**不要单选一种而不说明**。

<a id="section-38"></a>

#### 陷阱 15：把 `Auto-Installed: 0` 当成"管理员安装过"

**现象**：`extended_states` 里查到 `netcat` 且标记为 `Auto-Installed: 0`，报告写「该包由管理员手动安装」。

**原因**：`Auto-Installed` 记录的是 apt 对该包来源的标记，而它可以被独立改变。 三条路径：① `apt-mark manual <包>` 会把标记从 1 改成 0，**这个动作不修改包的安装记录**，`history.log` 里没有对应条目；② `apt-mark auto <包>` 反向操作同理；③ 关键的一点——`Auto-Installed: 0` 只表示"apt 不认为它是依赖带入的"，并不表示"有人主动安装它"。包可以从多种途径进入系统而不经过 apt 的依赖解析：直接下载 `.deb` 后 `dpkg -i`、从源码 `make install`、**从别处拷贝的二进制**、甚至攻击者直接放置文件而根本不用包管理器。这几种情形在 `extended_states` 里的表现可能完全相同。

**影响**：把标记状态读成行为归因，会给出一个具体的、听起来可靠的行为结论：「管理员主动安装了 netcat」。委托方可能据此去追查管理员的操作，或反过来认为"既然是管理员装的、那就不是攻击者"——后者尤其危险，它会直接否掉一条真实的攻击痕迹。

**核查**：**标记只用于分类，不用于归因**。三源分别取证：

```bash
# ① apt 的标记状态（分类用，不归因）
awk '/^Package: /{p=$2} /^Auto-Installed: 1/{print p}' /mnt/df/var/lib/apt/extended_states

# ② apt 的事务记录（有人走 apt 渠道的证据）
grep -B2 -A4 'netcat' /evidence/apt-history-merged.txt
#   有条目 → 该包经 apt 安装，看 Requested-By / Commandline
#   无条目 → 该包不来自 apt 事务（可能是 dpkg -i、源码编译、或根本不是包）

# ③ dpkg.log 的 unpack 记录（dpkg 层面的动作，粒度更细）
grep 'netcat' /mnt/df/var/log/dpkg.log | tail -5
```

**表述模板**：「`netcat` 在 `extended_states` 中标记为 `Auto-Installed: 0`（apt 不视其为依赖带入）。`history.log` **有/无**对应事务条目，**`Requested-By` 为 `<值>`**；`dpkg.log` 显示 unpack 于 `<时刻>`。」——注意这里没有一句"由管理员安装"，因为这三个字段都不足以支撑它。 行为归因要靠 auth.log 的 `sudo COMMAND=` 行，那才是"谁执行了"的证据。

<a id="section-39"></a>

#### 陷阱 16：用 `rpm -qf` 在分析机上查检材里的文件

**现象**：在分析机上执行 `rpm -qf /mnt/df/usr/bin/python3`，报错或返回了分析机自己的包名，报告里引用了这个结果。

**原因**：`rpm -qf` 接受一个路径，但查询的是"本机数据库里谁拥有这个路径"，它不会因为你给了镜像路径就去读镜像里的数据库。 `rpm --dbpath` 指向的是**数据库目录**，不是文件搜索的根——用 `--dbpath` 配合镜像路径时可行，但**前提是数据库格式与本机 rpm 版本兼容**。RPM 数据库从 BDB 到 SQLite 的演进、以及不同发行版对数据库格式的改写，都会让高版本 rpm 无法读低版本的库，或反之；而 `rpm` 在读库失败时**可能给出部分结果而不是明确失败**，输出看起来是正常的包名列表。

**影响**：错误分两向发生，且都很难发现：**读到空结果时**会把正常的系统文件判成"不属于任何包"（同陷阱 11 的失效方向）；**读到部分结果时**会给出错误的包归属，而输出格式完全正常。这类归属错误会直接影响"这个文件是否被替换"的判断——若被替换的文件恰好被误判为"包提供、版本正常"，篡改就会被放过。

**核查**：RHEL 系的包归属判定优先走"文件清单比对"而不是 `rpm -qf`，并先确认数据库格式与工具版本匹配：

```bash
# ① 先判数据库格式与本机 rpm 能力
file /mnt/df/var/lib/rpm/Packages
rpm --version
rpm --dbpath /mnt/df/var/lib/rpm -qa 2>&1 | head -5     # 观察有无告警

# ② 可靠路径：让 rpm 导出全量文件清单，再在文本层比对
rpm --dbpath /mnt/df/var/lib/rpm -qa --qf '[%{FILENAMES}\
]' 2>/dev/null \
  | sort -u > /evidence/rpm-files-all.txt
find /mnt/df -xdev -type f -executable -printf '%p\
' | sed 's|^/mnt/df||' | sort -u \
  > /evidence/disk-exec-rel.txt
comm -13 /evidence/rpm-files-all.txt /evidence/disk-exec-rel.txt
```

**与 Debian 系同一条纪律**：两侧路径统一剥到根相对形式，**并用已知属包文件做抽样自检**（如 `/usr/bin/python3` 应在清单里），确认比对生效后再采信阴性输出。rpm 报出的任何告警都要读原文，不要只看退出码。

<a id="section-40"></a>

#### 陷阱 17：把 `apt-get install` 的事务时间当成载荷投放时间

**现象**：`history.log` 显示 22:47:33 安装了 netcat，报告写「攻击者于 22:47:33 投放了 netcat 载荷」，并据此把 22:47 之后的所有文件动作都归因于该次安装。

**原因**：`history.log` 记的是包管理器的事务，而"安装这个包"和"用这个包做什么"之间没有任何因果关系的记录。 具体地：① 事务的 `End-Date` 与动作完成时刻可能相差很久（依赖多、配置脚本慢、或有交互式提示）；② 包被安装后可能长期未被调用，**首次使用发生在几周之后**；③ 更关键的是**方向问题——很多工具是预先安装、案发时才被使用的**，本篇案例里 netcat 的价值恰恰在于它与 auth.log 里 22:47:33 的 `sudo COMMAND=/usr/bin/apt-get install -y netcat` 精确吻合，也就是**靠的是双源印证而非时间接近**。

**影响**：把"安装时刻"当成"行为时刻"，会让时间线看起来精确而实际上全是推断。更实际的伤害是把整段后续文件动作都挂到这一次安装上，**形成一个"安装即投放、投放即使用"的叙事**，而这个叙事没有任何独立证据支撑。若该叙事被写入报告，委托方会据此认为攻击链的起点就是 22:47:33，而真实的起点可能早得多（工具早就预置在镜像里）。

**核查**：安装时间、首次使用时间、行为发生时间是三个不同的字段，必须分别取证：

```bash
# ① 安装时刻（包管理器事务口径）
grep -A6 'netcat' /evidence/apt-history-merged.txt | grep -E 'Start-Date|End-Date|Commandline|Requested-By'
# ② 首次使用时刻：从执行痕迹侧取，而非安装侧
#    命令历史（有落盘才有）、sudo 日志、进程记账、或相关产出文件
grep -iE 'nc |ncat|netcat' /mnt/df/root/.bash_history /mnt/df/home/*/.bash_history 2>/dev/null
grep -iE 'netcat|\bnc\b' /mnt/df/var/log/auth.log 2>/dev/null
# ③ 行为时刻：产出物或动作痕迹
stat -c '%n mtime=%y' /mnt/df/tmp/*.pcap 2>/dev/null
```

**表述模板**：「`<包名>` 于 `<Start-Date>` 经 `<Commandline>` 安装（`Requested-By: <值>`）。**本条记录仅证明包的安装时刻**；该工具的首次使用时刻/实际使用行为需由 `<执行痕迹来源>` 另行认定，本次 `<已查/未见>`。」——这三层分开写，是「能力 ≠ 行为」这条判据（陷阱 8）在时间维度上的落实。
<a id="section-41"></a>

## 五、案例示例

<a id="section-42"></a>

### 5.1 apt 历史三源印证与卸载留配置状态

**场景**

Ubuntu Server 22.04 Web 服务器 `web01`（ext4，2 TB）。委托方要求查明攻击者安装了哪些工具、是否有清理卸载行为。检材 `DigiForensics.dd`（raw），ext4 起始扇区 1181696，**强制断电**。已知攻击者 `deploy` 于 2024-03-17 22:43 提权。

在账本覆盖范围内，包管理账本能回答"装了什么、卸了什么"，且它的记录独立于认证日志——即使 `auth.log` 被清空，`status` 里的残留状态依然指向行为。

**处置过程**

第 1 步，确认账本格式与家族：

```bash
cat /mnt/df/etc/os-release | grep -E '^(NAME|VERSION_ID)='
# NAME="Ubuntu"  VERSION_ID="22.04"
ls -d /mnt/df/var/lib/dpkg && echo "→ Debian 系，status 是纯文本"
file /mnt/df/var/lib/rpm/Packages 2>/dev/null || echo "（无 rpm 目录）"
```

第 2 步，找"只删程序留配置"的状态：

```bash
awk '/^Package: /{p=$2} /^Status: /{s=$0} /^$/{if(s~/config-files|deinstall/)print p"  "s; s=""}' \
  /mnt/df/var/lib/dpkg/status
# dump              Status: deinstall ok config-files    ★ 程序已删，配置保留
# tcpdump            Status: deinstall ok config-files    ★ 抓包工具被卸载但留配置
# wireshark-common   Status: deinstall ok config-files    ★
```

三个网络分析/抓包类包处于 `deinstall ok config-files`——程序已卸载、配置文件刻意保留。

第 3 步，合并解析 `apt/history.log`（**必须先合并归档**）：

```bash
cd /mnt/df/var/log/apt
{ ls -1tr history.log.*.gz 2>/dev/null | while read f; do zcat "$f"; done
  cat history.log; } > /evidence/apt-history-merged.txt
grep -B1 -A6 '^Start-Date: 2024-03-17' /evidence/apt-history-merged.txt
```

```
Start-Date: 2024-03-17 06:00:12 CST
Commandline: unattended-upgrade
Requested-By: <root>
Upgrade: openssl [3.0.2-0ubuntu1.15]:amd64 (3.0.2-0ubuntu1.10 -> 3.0.2-0ubuntu1.15)
End-Date: 2024-03-17 06:04:51 CST

Start-Date: 2024-03-17 22:47:33 CST
Install: netcat [1.10-41]:amd64 (1.10-41ubuntu1)
Install: netcat-openbsd [1.219-1ubuntu1]:amd64 (1.219-1ubuntu1 -> 1.219-1ubuntu1.1)
End-Date: 2024-03-17 22:47:35 CST

Start-Date: 2024-03-18 08:55:02 CST
Commandline: /usr/bin/apt-get install -y strace
Requested-By: <root>
Install: strace [6.1-0ubuntu1]:amd64 (6.1-0ubuntu1)
End-Date: 2024-03-18 08:55:04 CST
```

第 4 步，跨源对齐（**先确认时区基准，不能凭 `CST` 缩写猜**）：

```bash
cat /mnt/df/etc/timezone                 # → Asia/Shanghai
ls -l /mnt/df/etc/localtime              # → /usr/share/zoneinfo/Asia/Shanghai
```

时区为 `Asia/Shanghai`（UTC+8），因此 `auth.log`（无时区标记的本地时间）与 `history.log`（标 `CST`）**同基准，可直接比较**。

| 源 | 记录 | 本地时间 | 统一到 UTC |
|---|---|---|---|
| `apt/history.log` | `Start-Date` 安装 netcat | 2024-03-17 **22:47:33 CST** | 14:47:33 UTC |
| `auth.log` | `sudo COMMAND=/usr/bin/apt-get install -y netcat` | 2024-03-17 **22:47:33** | 14:47:33 UTC |
| `dpkg.log` | `status installed netcat` | 2024-03-17 **22:47:34** | 14:47:34 UTC |

**三源精确到秒吻合**（history.log 与 auth.log 同秒，dpkg.log 晚 1 秒，符合"事务开始→落盘"的顺序）。
第 5 步，全盘文件归属比对：

```bash
cat /mnt/df/var/lib/dpkg/info/*.list | sed 's#^\./##' | sort -u > /evidence/official-files.txt

check_file() { grep -qx "$1" /evidence/official-files.txt && echo "属于某个包" || echo "★ 不属于任何包"; }
check_file /usr/local/bin/.cache/sysd       # → ★ 不属于任何包
check_file /tmp/.kworkerd                    # → ★ 不属于任何包
check_file /usr/bin/sudo                     # → 属于 sudo 包（对照组）

# 注意：/usr/local、/opt 本就不在包清单中，不能据此判异常
# 重点查包管理区：
find /mnt/df/usr/bin /mnt/df/usr/sbin -type f 2>/dev/null | sed 's#^/mnt/df##' | sort > /tmp/ondisk.txt
comm -23 /tmp/ondisk.txt /evidence/official-files.txt
# /usr/bin/xxx-agent    ← ★ 落在包管理区却不属于任何包
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 2024-03-17 22:47:33 攻击者安装了 `netcat` / `netcat-openbsd` | `history.log` + `auth.log` + `dpkg.log` 三源秒级吻合 | 强 |
| 2024-03-18 08:55:02 以显式命令行 `apt-get install -y strace` 安装了 `strace` | `history.log` 有 `Commandline` 行 | 强 |
| `dump`/`tcpdump`/`wireshark-common` 处于卸载但留配置状态 | `status` 的 `Status: deinstall ok config-files` | 强（**独立于日志的静态发现**） |
| 存在多个不属于任何包的文件 | `info/*.list` 全集比对 + SUID 发现 | 强（双源） |
| 本机**无** snap/flatpak/容器层 | 目录不存在或为空 | 中（阴性发现） |

**不能证明的**：`config-files` 状态只能证明"卸载时保留了配置"，**不能证明卸载者是攻击者**——运维卸载临时装的抓包工具同样会留下这个状态。

本案能给出强结论，靠的是它与 `netcat` 卸载发生在同一时间窗这一旁证。

**误判对照**

本案最容易得出的错误结论是「`dump`、`tcpdump`、`wireshark-common` 都是 `deinstall ok config-files`，说明攻击者装了抓包工具分析流量、然后卸载隐藏痕迹」。

这个推断在行为逻辑上很顺，但它**跳过了时间这一环**。

**正确判据是这三个包的卸载时间是否落在入侵窗口内**。

`config-files` 状态本身**不含任何时间戳**——`/var/lib/dpkg/status` 是纯文本状态数据库，记录当前状态，不记录变迁历史。要拿到卸载时间必须去 `dpkg.log`（或 `history.log`）：

```bash
grep -E 'remove|purge' /evidence/dpkg-merged.txt | grep -E 'tcpdump|dump|wireshark'
# 2024-02-11 09:22:14 status removed tcpdump
# 2024-02-11 09:22:14 remove tcpdump [1.10-2]:amd64 (1.10-2ubuntu1)
```

本案这三个包的卸载时间是 2024-02-11，比入侵早 5 周。 因此正确的归类是："**这是入侵前的运维卸载行为，与本案无关**"。把它们并入攻击链是错误的关联。

**按错误判据走的代价**：这条错误关联会**改变行为人的画像**——"装抓包工具、卸载隐藏痕迹"意味着**有反取证意识、技术水平较高**；而实际情形是"用 netcat 反弹shell、留下 SUID 和 cron 载荷"，是**快速操作、不清理痕迹**的行为。

画像错了，委托方对这台机器上其他系统的风险评估、以及对"是否还有未发现的潜伏工具"的判断都会跟着偏。

第二个易错点：把 06:00:12 的 `openssl` 升级当成攻击痕迹。

正确判据是那一段事务带了 `Commandline: unattended-upgrade` 和 `Requested-By: <root>` 两个字段，而 22:47:33 安装 netcat 的那段**两个字段都没有**。

有 `Commandline` 说明是有人（或计划任务）显式调用了 apt；无 `Commandline` 说明是**某个已在运行的 apt 进程以其调用者身份执行**。

`unattended-upgrade` 是 Ubuntu 的自动安全更新机制，06:00 正是其默认触发时段，这条升级记录必须从攻击时间线里剔除，否则会在委托方的时间线上制造一个假的"凌晨有活动"。

---

<a id="section-43"></a>

### 5.2 包管理区清单外文件与手动部署区的判别

**场景**

同系列主机 `app03`（Ubuntu 22.04），委托方要求"确认这台机器上运行的二进制是否都来自官方渠道"。检材 `DigiForensics.dd`。

"文件不属于任何包"这句话在不同目录下含义完全相反——在 `/usr/bin` 是强信号，在 `/usr/local` 是常态。

**处置过程**

第 1 步，建立官方文件全集（Debian 侧的正确做法是遍历 `info/*.list`）：

```bash
cat /mnt/df/var/lib/dpkg/info/*.list | sed 's#^\./##' | sort -u > /evidence/official-files.txt
wc -l /evidence/official-files.txt        # 41288 行，覆盖全部已安装包的文件
```

第 2 步，分区做差集——**这一步是本案的核心，不能合并成一次全盘比对**：

```bash
# ① 包管理区：清单外 = 高度可疑
find /mnt/df/usr/bin /mnt/df/usr/sbin /mnt/df/usr/local/sbin \
     -type f 2>/dev/null | sed 's#^/mnt/df##' | sort > /tmp/managed.txt
comm -23 /tmp/managed.txt /evidence/official-files.txt
# /usr/bin/xxx-agent
# /usr/local/sbin/df-sync
# → 2 项，落在包管理区却不属于任何包

# ② 手动部署区：清单外 = 正常
comm -13 /evidence/official-files.txt \
     <(find /mnt/df/usr/local /mnt/df/opt /mnt/df/srv -type f 2>/dev/null | sed 's#^/mnt/df##' | sort) | head
# /usr/local/bin/.cache/sysd
# /usr/local/bin/.cache/rotate-logs.sh
# /opt/app-4.2.0/bin/app-server
# /opt/app-4.2.0/config/application.yml
# → 全部正常或已知，不构成"异常"判据
```

第 3 步，对 ① 的两个文件做归属与时间取证：

```bash
for f in /usr/bin/xxx-agent /usr/local/sbin/df-sync; do
  echo "== $f =="; stat -c '  mode=%a %U:%G size=%s mtime=%y' "/mnt/df$f"; file "/mnt/df$f"
done
# == /usr/bin/xxx-agent ==
#   mode=755 root:root size=1843200 mtime=2024-03-17 22:51:22
#   ELF 64-bit LSB pie executable, x86-64, stripped
# == /usr/local/sbin/df-sync ==
#   mode=755 root:root size=2411008 mtime=2024-03-17 22:51:19
#   ELF 64-bit LSB pie executable, x86-64

# 包归属反查（确认没被装过又被删）
grep -lE '^/(usr/bin/xxx-agent|usr/local/sbin/df-sync)$' /mnt/df/var/lib/dpkg/info/*.list 2>/dev/null
# （无输出）  ← 从未属于任何包
```

第 4 步，做 SHA256 归并查是否与已知载荷同源：

```bash
sha256sum /mnt/df/usr/bin/xxx-agent /mnt/df/usr/local/sbin/df-sync /evidence/suspicious-kworkerd \
  | tee -a /evidence/hashes.txt
# a1b2...  /mnt/df/usr/bin/xxx-agent
# c3d4...  /mnt/df/usr/local/sbin/df-sync
# e5f6...  /evidence/suspicious-kworkerd
# → 三者互不相同，但都落在 22:51:19–22:51:22 这 3 秒内
```

第 5 步，查这两个文件是否被任何服务引用（确认"已启用"而非"已投放"）：

```bash
grep -rl 'xxx-agent\|df-sync' /mnt/df/etc/systemd/system/ /mnt/df/etc/cron* 2>/dev/null
# /mnt/df/etc/systemd/system/sysupdate.service   ← sysupdate.service 引用了其中一个
# /mnt/df/etc/cron.d/telemetry                    ← 另一个被 cron 引用
cat /mnt/df/etc/cron.d/telemetry
# */7 * * * *  /usr/local/sbin/df-sync >/dev/null 2>&1
```

**结论**

- `/usr/bin/xxx-agent`（22:51:22）与 `/usr/local/sbin/df-sync`（22:51:19）是两个落入包管理区、且不属于任何包的 ELF 可执行文件，mtime 均落在入侵窗口内，**且都被实际启用**（前者被 `sysupdate.service` 的 `ExecStart` 链引用，后者被 `/etc/cron.d/telemetry` 每 7 分钟执行一次）。
- 两者 SHA256 互不相同，也与 `/tmp/.kworkerd` 不同，**说明是三个不同的载荷而非同一份文件的副本**。但三者集中在 22:47–22:52 的 5 分钟内投放，**构成同一波投放行为**。
- 对委托方问题的准确答复：「该机上运行的二进制中，包管理区有 2 个不属于任何已安装包的文件，且均已被持久化机制引用为执行目标；`/usr/local`、`/opt` 下的非包文件属正常手动部署，不计入异常。」
- **必须写明的方法学边界**：`/usr/local`、`/opt`、`/srv` 本就不受 dpkg 管理，**"不属于任何包"在这三个目录下不构成任何异常判据**。本案把它们从异常清单中排除，是为了让 `/usr/bin/xxx-agent` 这类真异常不被噪声淹没。

**误判对照**

本案最容易得出的错误结论是「全盘比对出 `/usr/local/bin/.cache/sysd`、`/opt/app-4.2.0/bin/app-server` 等文件都不属于任何包，说明这台机器被大面积污染」——这会导致一个**淹没真信号**的结论。

**正确判据是目录的属性，不是比对的通用规则**。dpkg 的 `info/*.list` 只登记**包管理器安装时写入的路径**，而 `/usr/local`、`/opt`、`/srv`、`/home` 按 Debian 的约定就是留给管理员手动部署的位置。在没有包的文件，在这些目录下是设计使然，不是异常。

区分要点：

| 目录 | 归属 | 清单外文件的含义 |
|---|---|---|
| `/usr/bin`、`/usr/sbin`、`/usr/lib` | 包管理区 | **强异常信号**——正常情况下这里只该有包 |
| `/etc` | 配置区 | 需按内容判断（配置文件多为手写） |
| `/usr/local/bin`、`/opt`、`/srv` | 手动部署区 | **中性**——不属于任何包是常态 |

**按错误判据走的代价**：报告里会出现一长串"可疑文件"，其中大部分是正常的应用部署。

委托方拿到这份清单后要么无法判断优先级而全部排查（成本失控），要么因为噪声太大而对真正重要的 `/usr/bin/xxx-agent` 也一并忽略——而后者恰恰是唯一落在本应纯净的包管理区里的东西。

异常判据的价值来自它的低误报率，一旦噪声淹没信号，这项证据就等于没有。

第二个易错点：看到 `/usr/bin/xxx-agent` 不属于任何包，就认定"攻击者上传了它"。

严格判据要加一步：确认它**从未被装过又删**（`grep` 所有 `info/*.list` 无匹配，说明它不是"装过再卸"的残留），以及确认 mtime 落在入侵窗口内。

"不属于任何包"只说明来源不受包管理，不说明它是攻击者放的——一个手工编译安装到 `/usr/bin` 的自研工具同样满足这个条件。

本案能给出强结论，靠的是mtime + 从未被包管理 + 位于包管理区 + 已被持久化引用四个条件同时成立。

---

<a id="section-44"></a>

### 5.3 反例：dpkg 状态字段被误当作安装证据

**场景**

某台 Ubuntu 18.04 开发机 `dev02`，委托方在 `/var/lib/dpkg/status` 中发现大量条目，怀疑"攻击者批量安装了软件"。检材 `DigiForensics.dd`，机器为开发人员日常使用，非生产环境。

`status` 文件是"当前状态快照"而非"安装流水"，把它当流水读会得出大量虚假的安装行为。

**处置过程**

第 1 步，先看 `status` 的字段结构（**这是判读的前提**）：

```bash
head -12 /mnt/df/var/lib/dpkg/status
# Package: bash
# Status: install ok installed
# Priority: required
# Section: shells
# Installed-Size: 6470
# Maintainer: Matthias Klose <doko@debian.org>
# Architecture: amd64
# Version: 4.4.19-1ubuntu2
# Depends: base-files (>= 2.1.12), debianutils (>= 2.15)
```

**注意：这些字段全是"现状描述"，没有任何时间戳。** `Status: install ok installed` 只说明"**现在**是已安装状态"。

第 2 步，统计状态分布：

```bash
awk '/^Package: /{p=$2} /^Status: /{print $2, $3, $4}' /mnt/df/var/lib/dpkg/status \
  | sort | uniq -c | sort -rn | head
#   1842 install ok installed        ← 正常已安装
#    214 deinstall ok config-files   ← 卸载留配置
#     37 deinstall ok half-installed ← ★ 需单独看
```

第 3步，追查那 37 个 `half-installed`（**其他状态都是当前状态描述，只有该状态指向一次中断过的事务**）：

```bash
awk '/^Package: /{p=$2} /^Status: /{if($2=="deinstall"&&$4=="half-installed")print p}' \
  /mnt/df/var/lib/dpkg/status | head -10
# docker-ce
# containerd.io
# docker-ce-cli

grep -E 'docker-ce|containerd' /evidence/dpkg-merged.txt | tail -8
# 2024-01-08 03:11:22 install docker-ce [5:24.0.7-1~ubuntu.22.04~ls1]:amd64 (...)
# 2024-01-08 03:14:07 status half-configured docker-ce
# 2024-01-08 03:14:07 status half-installed docker-ce
# 2024-01-08 03:15:51 remove docker-ce [5:24.0.7-1~ubuntu.22.04~ls1]:amd64 (...)
```

第 4 步，确认这台机器是否有容器运行时残留（阴性结论要限定范围）：

```bash
ls -d /mnt/df/var/lib/docker /mnt/df/var/lib/containerd 2>&1
# /mnt/df/var/lib/docker: No such file or directory
# /mnt/df/var/lib/containerd: No such file or directory
# → 无容器层残留，本次卸载已清理干净

grep -c 'docker\|containerd' /mnt/df/etc/cron.d/* /mnt/df/etc/systemd/system/*.service 2>/dev/null | grep -v ':0'
# （无输出）  ✓ 无容器相关持久化
```

第 5 步，确认是否为开发人员日常使用导致的状态堆积：

```bash
ls -l --time-style=long-iso /mnt/df/var/log/apt/history.log*
# history.log.1.gz  2024-03-01        ← 轮转保留
grep -c '^Start-Date' /evidence/apt-history-merged.txt   # 本机共 214 个 apt 事务
awk '/^Commandline: /{print $2, $3}' /evidence/apt-history-merged.txt | sort | uniq -c | sort -rn | head -5
#   188 apt
#    14 /usr/bin/apt-get
#     6 pip3
#     4 snap
#     2 unattended-upgrade
```

**结论**

- `status` 中的 1842 条 `install ok installed` 不构成任何"安装行为"证据。 它们是**状态快照**，描述的是"送检这一刻哪些包处于已安装状态"，**不包含任何安装时间**。把它们当成流水读，会得出"这台机器安装了 1842 个软件"的荒谬结论。
- 真正有信息量的是 37 条 `half-installed`：dpkg 记录的 `status half-configured` / `half-installed` 出现在 2024-01-08 03:14:07，而 `remove` 在 03:15:51——这是一次 1 分 44 秒内完成的 docker-ce 安装失败并被清理的过程，与本案无关。
- 本机共 214 个 apt 事务，其中 188 个是常规 `apt` 调用、6 个 `pip3`、4 个 `snap`，**分布特征与一台日常使用的开发机完全吻合**。214 个事务 / 1842 个包 = 平均 8.6 个包每次事务，**属于正常的增量安装节奏**。
- **对委托方问题的答复**：「在本机 `/var/lib/dpkg/status`、`/var/lib/apt/history.log` 全量及 `/var/log/dpkg.log` 保留窗口（2023-09 至 2024-03）内，**未发现与本案相关的异常包安装行为**。`half-installed` 状态的 3 个包为 2024-01-08 的 docker-ce 残留，已清理，无容器层目录残留、无容器相关持久化。阴性发现的限定范围：仅覆盖 dpkg/apt 管理的包，pip/npm/cargo 等非 dpkg 的软件不在本结论范围内，需另行核查。」

**误判对照**

本案最容易得出的错误结论是「`status` 里有 1842 个 `install ok installed`、214 个 `deinstall ok config-files`，说明这台机器上装了大量不明软件又被卸载隐藏」。

这个结论的每一项数字都是**从文件里正确读出来的**，但**因果关系完全虚构**。

**正确判据是 `status` 的字段性质**。三个具体事实：

1. **`status` 文件里没有任何时间字段**。`Package`、`Status`、`Version`、`Installed-Size`、`Maintainer` —— 全部是"当前状态"或"元信息"，没有一个字段记录"何时安装"。因此从 `status` 读出安装时间是不可能的，任何"某包于某时安装"的结论都必须来自 `history.log` 或 `dpkg.log`。
2. **`config-files` 状态不区分卸载动机**。它只表示"卸载时选择了保留配置文件"，这个动作可以是攻击者清理痕迹，也可以是运维卸载一个装错了的工具。本案 214 条里绝大多数的时间（2023-09 至 2024-03 均匀分布）与 `unattended-upgrade` 的自动升级记录混杂，**呈现的是正常使用节奏而非集中清理的节奏**。
3. **真正的异常信号应该是"集中的、突发的"**。本案中唯一符合该特征的是那 37 条 `half-installed`——时间高度集中（03:14:07 一次性全部进入该状态）且随后 1 分 44 秒内被清理。这个"集中突发"的形态才是该查的，而 `status` 的静态条目数不具备这个特征。

**按错误判据走的代价**：会把一台**干净的开发机**写成"存在大规模可疑软件安装与卸载活动"，直接触发对这台机器及其使用者的不当怀疑。

这类误报的代价不只是结论错——**它会指向一个具体的自然人**，而那个人可能从未做过任何事。

第二个易错点：用 `status` 的条目数推断"这台机器的利用率"或"用户画像"。 `Installed-Size` 字段确实能统计已安装体积，但**它只反映当前状态，不反映历史**。要回答"这台机器上发生过什么"必须读流水（`history.log` / `dpkg.log`）；要回答"现在装了什么"才读 `status`。**两个问题对应两个文件，混用会同时失去两个答案。**

---
<a id="section-45"></a>

## 六、扩展阅读方向

<a id="section-46"></a>

### 前置基础：账本要读对，先认准家族与落点

- [取证工件地图](computer-persistence-persistence-artifact-map.md) —— 发行版家族判定与 `/var/lib/dpkg/`、`/var/lib/rpm/` 的落点。本篇 3.1 的第一步就是确认家族，判错则整章读的是错误格式。
- [只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md) —— 全盘归属比对的执行前提。
- [ext4 结构与 inode](../../filesystem/filesystem-unix/filesystem-unix-ext4-inode.md) —— 文件权限与属主在 inode 中的存储。`dpkg --verify` 报的属主差异，只有理解了 mode 与 uid 字段才判得准。

<a id="section-47"></a>

### 同层深入：账本之外的安装面

- [计划任务与持久化痕迹](computer-persistence-scheduled-tasks-and-persistence.md) —— 归属比对最直接的用武之地：**清点出来的 SUID 文件有多少是包自带的**，这个比例本身就是异常信号。
- [Shell 痕迹与命令历史](../computer-shell/computer-shell-shell.md) —— `apt`、`pip`、`npm` 的调用记录在历史文件里，**能补上账本没记的操作者意图**。
- [时间线重建](../computer-log/computer-log-linux-timeline-reconstruction.md) —— 包安装时间作为校验基准。**装包时间是可信的外部锚点**，可以用它检验其它来源时间戳是否被改动过。

<a id="section-48"></a>

### 相邻议题：其它生态与其它系统的同类机制

- [Docker 与容器取证](../../server/server-panel/server-panel-linux-server-artifact-map.md) —— 容器镜像层的包清单是另一套账本。容器里「不属于任何包」的文件，恰恰是最需要检查的对象。
- [浏览器取证](../computer-browser-behavior/computer-browser-behavior-browser-forensics.md) —— 应用层软件痕迹的对照。浏览器配置目录与包清单是两种范式：前者是被使用改出来的状态，后者是安装动作的结果。

<a id="section-49"></a>

### 工具与规范：操作边界

- [证据文件格式](../../fundamentals/fundamentals-chain/fundamentals-chain-dd-e01-aff4-evidence-formats.md) —— 账本解析产出的归档格式。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md) —— 软件清单常用于推断主机用途并进一步界定调查范围，**范围扩张需要有授权支撑**。

<a id="section-50"></a>

### 判据与反例：哪些「不属于任何包」是真的可疑

- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— 包自带的文件被替换后，`mtime` 会偏离安装时间，**这个偏离是判断文件被改过的独立线索**，与完整性校验互为补充。
- [取证技能树](../../fundamentals/fundamentals-process/fundamentals-process-forensics-learning-path.md) —— 「查文件归属」是一类可迁移的方法，技能树能定位它属于哪一层能力。
<a id="section-51"></a>

## 七、命令速查

```bash
# ===== 1. 家族与账本格式 =====
cat /mnt/df/etc/os-release | grep -E '^(NAME|VERSION_ID)='
ls -d /mnt/df/var/lib/dpkg /mnt/df/var/lib/rpm 2>/dev/null
file /mnt/df/var/lib/rpm/Packages 2>/dev/null      # Berkeley DB / SQLite（解析器不同）

# ===== 2. 已装软件清单 =====
# Debian 系（纯文本，离线可解析）
awk '/^Package: /{p=$2} /^Status: /{s=$0} /^Version: /{v=$2} /^$/{if(p)print p"\	"v"\	"s;p=s=v=""}' \
  /mnt/df/var/lib/dpkg/status | sort > /evidence/dpkg-installed.tsv
# ★ 只删程序留配置（强信号）
awk '/^Package: /{p=$2} /^Status: /{s=$0} /^$/{if(s~/config-files|deinstall/)print p"  "s; s=""}' \
  /mnt/df/var/lib/dpkg/status
# RHEL 系（二进制，只读）
rpm --dbpath /mnt/df/var/lib/rpm --justdb --nodeps -qa | head
rpm --dbpath /mnt/df/var/lib/rpm --justdb --nodeps -qf /usr/bin/bash

# ===== 3. ★ 全盘文件归属比对（发现非包管理安装）=====
cat /mnt/df/var/lib/dpkg/info/*.list | sed 's#^\./##' | sort -u > /evidence/official-files.txt
check_file() { grep -qx "$1" /evidence/official-files.txt && echo "属于某个包" || echo "★ 不属于任何包"; }
# 只在包管理区找异常（/usr/local、/opt 本就不在清单内）
find /mnt/df/usr/bin /mnt/df/usr/sbin -type f | sed 's#^/mnt/df##' | sort > /tmp/ondisk.txt
comm -23 /tmp/ondisk.txt /evidence/official-files.txt

# ===== 4. ★ apt/history.log（最有价值的单一日志：时间+操作者+包+版本）=====
cd /mnt/df/var/log/apt
{ ls -1tr history.log.*.gz 2>/dev/null | while read f; do zcat "$f"; done
  cat history.log; } > /evidence/apt-history-merged.txt
grep -B1 -A6 '^Start-Date: 2024-03-17' /evidence/apt-history-merged.txt   # 入侵日事务
grep -E '^(Install|Remove|Purge|Upgrade|Requested-By|Commandline):' /evidence/apt-history-merged.txt | tail -30
# ★ 区分自动 vs 人工：Commandline=unattended-upgrade → 自动；具体 install -y X → 人工

# ===== 5. 手动 vs 自动标记（读 extended_states，不是 status）=====
awk '/^Package: /{p=$2} /^Auto-Installed: 1/{print p}' \
    /mnt/df/var/lib/apt/extended_states > /evidence/auto-pkgs.txt
grep -qx 'netcat' /evidence/auto-pkgs.txt && echo "自动（依赖带入）" || echo "手动 ★"
# → 手动 ★   在 extended_states 中找不到 netcat = 显式安装

# ===== 6. 其它生态（dpkg 看不到的）=====
ls /mnt/df/var/lib/snapd/snaps/ /mnt/df/snap/ /mnt/df/var/lib/flatpak/ 2>/dev/null   # snap/flatpak
find /mnt/df -xdev -name 'METADATA' -path '*dist-packages*' 2>/dev/null | head        # pip
ls /mnt/df/usr/lib/node_modules/ 2>/dev/null                                          # npm
ls -la /mnt/df/var/lib/docker/overlay2/ 2>/dev/null | head                           # 容器分层
# 容器启动命令：/mnt/df/var/lib/docker/containers/*/config.v2.json

# ===== 7. 完整性验证（与第 01 篇"文件被顶替"联动）=====
# Debian 系：校验某包内文件是否被改（需在分析机上对副本操作，勿动镜像）
#   dpkg --verify <pkg> 会列出 MD5 不匹配的文件
# RHEL：rpm -V <pkg>（需 rpm --dbpath 指向镜像 + --justdb）
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — Linux 取证 — 包管理器与软件清单」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《包管理器与软件清单》（CC BY-SA 4.0）`

文中 `DigiForensics.dd` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
