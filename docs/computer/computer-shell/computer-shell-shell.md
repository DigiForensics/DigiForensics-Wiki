---
title: "Shell 痕迹与命令历史"
slug: "computer-shell-shell"
canonical: "https://www.digiforensics.cn/wiki/computer-shell-shell"
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

# Shell 痕迹与命令历史

<a id="section-1"></a>

## 一、概述

`~/.bash_history` 是 Linux 取证里**最容易找到、也最容易误读**的工件。它看起来人畜无害——就是一串敲过的命令。

但三个机制特性决定了它记什么、漏什么、能被伪造到什么程度：

- **默认不记时间戳。** 只有 `~/.bashrc` 或 `/etc/bash.bashrc` 里设了 `HISTTIMEFORMAT`，历史文件里才会出现 `#<epoch>` 行。没有这些 `#` 行，就不能把命令绑定到任何时间点。
- **路径、长度、写入内容都可以被用户自己改。** `HISTFILE` 改路径、`HISTCONTROL=ignorespace` 让空格开头的命令不记录、`history -c` 随时清空。「没找到 `.bash_history`」完全不能推出「没有历史」。
- **只在 shell 正常退出时写盘。** `kill -9`、断电、崩溃都会丢掉当前会话的全部历史。**磁盘上的历史文件永远落后于内存。**

三条合起来会产生一个致命误判：看到历史里都是无害命令，就认定入侵者没用过这台机器。

实际情况可能是：他用了 `ignorespace`、把 `HISTFILE` 指到别处、或者 `kill -9` 掉自己的 shell 后登出。

这类证据属于**分析**环节的「行为类证据」，位置是「登录之后」这一段的起点。

**上游依赖**账户与家目录的确认。`HISTFILE` 可被改写意味着不能在默认路径找不到就收工，家目录清点方式见[取证工件地图](../computer-persistence/computer-persistence-persistence-artifact-map.md)；账户身份由[SSH 痕迹与密钥取证](../computer-persistence/computer-persistence-ssh.md)提供。

**下游支撑**四件事。命令内容解释了这个账户「实际做了什么」；命令里的时间戳是[时间线重建](../computer-log/computer-log-linux-timeline-reconstruction.md)的输入之一，但只在配置了 `HISTTIMEFORMAT` 时才可信；命令内容常直接指向落地的文件（`wget` 的 URL、`crontab` 的写入、`chmod` 的 SUID），这些是排查下一步的入口；与认证日志的交叉验证是**反伪造的核心手段**。

**第一步**得先回答「这份历史到底有没有时间戳」，这个判断决定了它能进时间线还是只能当静态文本用。

痕迹的形态与位置：

| 形态 | 位置 | 关键结构 |
|---|---|---|
| bash 历史 | `~/.bash_history`、`/root/.bash_history` | 纯文本行；带时间戳时格式为命令行后跟一行 `#<epoch>`，该时间戳标记的是「这条命令何时被读入历史列表」，不是执行时刻 |
| zsh 历史 | `~/.zsh_history` | **格式完全不同**，默认以 `: <epoch>:<elapsed>;<command>` 开头 |
| bash 配置 | `~/.bashrc`、`~/.bash_profile`、`~/.profile`、`/etc/bash.bashrc` | 决定 `HISTTIMEFORMAT`、`HISTCONTROL`、`HISTFILE`、`HISTSIZE` 四个变量 |
| 派生 shell 历史 | `~/.bash_sessions/`（部分发行版） | 记录每个登录会话的历史片段 |
| 应用自有历史 | 各应用目录下的独立历史文件 | **格式与位置各不相同，不遵循 bash 约定**，需要逐个确认 |
| 认证与提权日志 | `/var/log/auth.log`（Debian 系）/ `secure`（RHEL 系） | **独立时钟**，是反伪造的对照源 |
| 登录记账 | `/var/log/wtmp` | 给出「谁在什么时候登录过」，用于给无时间戳的历史定锚 |

关键判定：bash 历史**默认无时间戳**这件事是常态而非异常，**报告里不能因为「没有时间戳」就认为该文件不可用**，它仍然能证明命令内容的存在。

答得出来的是：某个账户执行过哪些命令、命令的顺序、命令中出现的文件路径与网络地址、以及在有 `HISTTIMEFORMAT` 的机器上命令与时间的粗略对应。

答不出来的，以及几个必须先纠正的误读：

- **命令的准确执行时刻。** 即使有 `#<epoch>`，它标记的是**命令何时被读入历史列表**，不是执行时刻；交互式 shell 里两者可能相差很远。
- **「历史里没有」等于「没执行」。** 上面三条机制（`ignorespace`、`HISTFILE`、非正常退出）每一条都足以造成缺失。
- **会话期间的全部命令。** 磁盘上的历史文件**永远落后于内存**，最后一次会话的内容在写入前就可能已经随会话消失。
- **「历史看起来正常」的证明力。** 这是代价很高的一类错误：历史里都是无害命令，不能推出入侵者没用过机器。 把它当正面证据，代价是漏掉整条攻击链。
- **同一时刻其它用户或其它终端做了什么**。历史是按账户分文件的，跨账户的时序推断必须靠认证日志。
- **命令是否真的生效了**。历史记录的是输入，**执行结果与副作用要靠文件系统变化来验证**。

要读懂这些，前提是熟悉 Linux 用户目录结构，知道家目录下有哪些隐藏配置文件；理解 Shell 环境变量的继承与覆盖关系，否则无法判断 `HISTFILE` 的实际取值来自哪一层；能读懂 syslog 格式的日志行作为交叉验证的对照源，见[系统日志深度分析](../computer-log/computer-log-system-log-analysis.md)；

掌握时间戳的基本语义与纪元换算——`#<epoch>` 是 Unix 时间戳，与其它时间基准的转换见[时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md)；会使用只读挂载后的镜像检索隐藏文件，能在指定目录下按名查找而非依赖目录列表。

<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 bash 历史的五个控制变量（机制核心）

bash 的历史行为由这五个变量决定。取证时要从"系统配置 + 用户配置"里反推当时生效的值。

| 变量 | 默认值 | 作用 | 取证意义 |
|---|---|---|---|
| `HISTFILE` | `~/.bash_history` | **历史文件路径** | **可被改成任意路径** → 找不到默认文件不代表无历史 |
| `HISTSIZE` | `1000`（多数发行版） | **内存中**保留的命令条数 | 超出的旧命令**退出时不会写入文件** |
| `HISTFILESIZE` | `HISTSIZE` | **写入文件**的条数上限 | 与 `HISTSIZE` 不同时，文件可能比内存历史短 |
| `HISTCONTROL` | `ignoredups` | 记录策略（见下） | `ignorespace` = **空格开头的命令不记录** |
| `HISTTIMEFORMAT` | **未设置** | 时间戳显示格式 | **不设就不写时间戳**（考点一） |
| `HISTIGNORE` | 未设置 | 按模式排除命令 | 可排除某些命令，可能是反取证配置 |

<a id="section-4"></a>

#### 考点一：默认无时间戳，`#<epoch>` 行从哪来

bash **默认只写命令本身**，不写时间。所以一个"正常"的 `.bash_history` 是一列裸命令：

```bash
ls -la /var/www
whoami
uname -a
```

只有当 `HISTTIMEFORMAT` 被设置后，bash 才会在每条命令前写一行 `#<Unix epoch>` 注释：

```bash
#1710700800
ls -la /var/www
#1710700860
whoami
#1710700920
uname -a
```

> **机制细节**：这些 `#` 行是 bash 自己加的**注释行**。`#` 后面是 **Unix epoch 秒**，可直接换算。`HISTTIMEFORMAT` 里的 `%F`（日期）和 `%T`（时间）**只是决定交互提示符怎么显示**，真正让 `#` 行落盘的条件是 `HISTTIMEFORMAT` 这个变量被设置过（哪怕值是空的）。发行版通常在 `/etc/bash.bashrc` 或 `/etc/skel/.bashrc` 里用条件语句设置：
> ```bash
> HISTTIMEFORMAT='%F %T '
> ```
> 所以"有没有时间戳"直接取决于该系统/用户的 bashrc 里这一行在不在。

**取证判定**：

| 观察 | 结论 |
|---|---|
| 历史文件**无** `#` 行 | 该用户/系统**未启用时间戳** → **不能给命令绑定时间**。这是"局限"，不是"无事发生" |
| 历史文件**有** `#` 行 | 时间戳可用，`#<epoch>` 逐条对应其后的命令 |
| **部分**条目有 `#`、部分没有 | 时间戳功能是**中途被启用**的（用户改了 bashrc 后重开 shell）→ 有 `#` 的才可定时间 |

> ⚠️ `#<epoch>` 只对紧随其后的第一条命令有效。 解析时不能把一个 `#` 行"套"给后面多条命令。bash 的格式是**严格一一对应**。

<a id="section-5"></a>

#### 考点二：`HISTCONTROL=ignorespace` —— 空格开头的命令不记录

`HISTCONTROL` 是一个**冒号分隔**的多值变量，常见取值：

| 取值 | 含义 |
|---|---|
| `ignoredups` | 忽略与上一条**完全相同**的连续命令（多数发行版默认） |
| `ignorespace` | **忽略以空格开头的命令** ★ |
| `ignoreboth` | 同时忽略重复和空格开头 |
| `erasedups` | 把重复命令从历史中**移除**（而非只不显示） |

**`ignorespace` 的机制**：若 `HISTCONTROL` 含 `ignorespace`，bash 遇到**第一个字符是空格**的命令时，既不加入内存历史、也不写入文件。

> **取证意义（也是本知识库反复强调的考点）**：一个交互式 shell 的提示符默认**本身就带尾随空格**（`user@host:~$ `）。攻击者只需在敲命令前**多加一个空格**，就能让命令完全不出现在任何历史文件里，而**对操作者来说几乎无感**。
>
> 这直接导致一条反直觉的结论：`.bash_history` 里"缺少某条命令"完全不能证明该命令没被执行过。 反过来，**历史里出现了某条本该需要空格才不被记录的敏感命令**（如 `HISTCONTROL=ignorespace` 环境下的下载/执行链），反而说明**该配置当时可能未生效**——这是一个可交叉验证的判据。

**如何知道 `ignorespace` 是否生效**：查 `/etc/bash.bashrc`、`/etc/profile`、`/etc/profile.d/*.sh`、`~/.bashrc`、`~/.bash_profile` 里的 `HISTCONTROL` 赋值。注意 `HISTCONTROL` 是在 shell 启动时读的，之后在会话内改它不影响已有历史。

<a id="section-6"></a>

#### 考点三：`HISTFILE` 可改路径 —— "找不到 .bash_history"不代表没有

`HISTFILE` 决定历史写到哪个文件。发行版默认 `~/.bash_history`，但用户可改成任意可写路径：

```bash
export HISTFILE=/dev/null        # 历史全部丢弃（等价于关掉历史）
export HISTFILE=~/.bash_hist     # 改到别的文件名
export HISTFILE=/tmp/.h           # 藏在 tmp
export HISTFILE=/var/tmp/hist    # 更隐蔽
```

**取证含义**：

- **默认路径没有文件** = 三种可能：用户从未交互式登录、历史被清、`HISTFILE` 被改。**必须全盘搜一遍**再下结论。
- 搜历史文件的正确方式是**按内容特征全盘搜**，而不是只 `ls ~/.bash_history`：

```bash
# 全盘搜 bash 历史特征的候选文件（含隐藏、非默认路径）
find / -xdev -type f \( -name '*hist*' -o -name '.*history*' \) 2>/dev/null
grep -rlE '^(cd|ls|vi|sudo|curl|wget|chmod)\b' /home /root /tmp /var/tmp 2>/dev/null
```

> ⚠️ 注意 `HISTSIZE`/`HISTFILESIZE` 的连带影响：即使 `HISTFILE` 指向正常位置，若 `HISTSIZE=0` 或 `HISTFILESIZE=0`，历史**同样为空**。判定"无历史"时把这两个变量一并查。

<a id="section-7"></a>

#### 考点四：bash 只在正常退出时写盘 —— `kill -9` 丢失当前会话

**这是四个考点里最容易在阴性结论中被漏掉的一个。**

bash 的历史机制分两层：

```
交互式输入命令  ──→  内存历史列表（HISTSIZE 控制条数）
                        │
                        └── 仅在 shell 退出时 ──→ 一次性写入 HISTFILE
```

- **正常退出**（`exit`、Ctrl-D、SSH 断开后 shell 收到 SIGHUP 而退出）：bash 在退出时把内存历史**一次性 append 写盘**。
- **`kill -9`（SIGKILL，不可捕获）**、**断电/崩溃**、**会话被 OOM Killer 杀掉**：bash **没有任何机会执行写盘**，**当前会话的全部历史丢失**。

> **取证推论**：
> 1. 磁盘上的 `.bash_history` 永远"落后"于最近一次交互。 如果攻击者登入后 `kill -9` 自己的 shell 再重登，他在这个 kill 之前的命令**不会落盘**。
> 2. `.bash_history` 的 `mtime` 不等于"最后一条命令的时间"——它可能因为某次退出（哪怕是很久之前的正常退出后接了很多 `kill -9` 会话）而很旧。要判断"最后一次交互"，更该看 `~/.bashrc` 的 atime、`/var/log/wtmp`/`lastlog` 的登录记录、bash 的 `.session` 痕迹。
> 3. 这解释了为什么"历史很干净"和"入侵者刚刚用过"可以并存。 一份 `.bash_history` 的缺失或无害内容，**在机制上完全不能排除同期的未落盘操作**。

**补充机制**：`HISTCONTROL=ignoredups` 意味着**连续重复的同一条命令在文件里只留一条**——所以文件里的命令条数 ≠ 实际敲过的次数。另有部分发行版的 bash 会在 `$HISTFILE` 所在目录维护 `.bash_sessions`（记录会话与历史改写情况）；它不是 bash 的通用核心机制，各版本差异较大，发现时按"辅助线索"对待即可。

<a id="section-8"></a>

### 2.2 zsh 历史：格式完全不同，且默认带时间戳

zsh（Oh My Zsh 在开发者群体中极常见）历史在 `~/.zsh_history`，**格式与 bash 完全不同**：
```
: 1710700800:0;ls -la /var/www
: 1710700860:0;whoami
: 1710700920:3;cd /tmp
```

**字段含义**：

| 字段 | 含义 |
|---|---|
| 冒号 + **epoch 秒** | 命令**开始执行**的时间（由 `EXTENDED_HISTORY` 启用，不需 `HISTTIMEFORMAT`）★ |
| 第二个数字（`0`/`3`） | **该命令的运行时长（秒）**——`3` 表示这条命令跑了约 3 秒 |
| 分号后 | **命令原文** |

**关键差异**：

- **zsh 默认就有时间戳**，bash 要 `HISTTIMEFORMAT` 才会写。所以机器上存在带时间戳的 `.zsh_history`，本身就是「该 shell 会话可提供时间基准」的正面信号。
- 历史能按时间排序，这就是 zsh 痕迹比无时间戳 bash 历史更易进入时间线的原因。
- ⚠️ **第二个数字恒为 `0` 不代表命令瞬间完成。** 启用 `INC_APPEND_HISTORY` 或 `SHARE_HISTORY` 时，zsh 在命令**提交时**就写入历史，**此时命令尚未结束、时长无从得知，一律记 `0`**；只有 `INC_APPEND_HISTORY_TIME`（等命令结束后再写）才记录真实时长。所以时长字段只能作「该命令是否超过 1 秒」的粗判据，不能当精确执行时间用。
- **解析规则**：取「行首第一个冒号到分号之间」的第一个整数作为 epoch，其余数字字段一律忽略。**这样即使格式扩展（多冒号）也不会解析错位。**

> **取证判定**：如果一台机器上**同时**有 `.bash_history`（无时间戳）和 `.zsh_history`（有），说明用户既用过 bash 也用过 zsh；**分析时必须两个都看**，只看 bash 会漏掉 zsh 里的时间线。

<a id="section-9"></a>

### 2.3 各应用自有的历史文件

这些**不是 shell 历史**，但记录了"用过什么、连过什么"，且各自有独立路径和格式：

| 文件 | 所属 | 记录内容 | 取证价值 |
|---|---|---|---|
| `~/.python_history` | Python 交互解释器 | 交互式输入的 Python 语句 | 脚本化操作的痕迹；**无时间戳** |
| `~/.mysql_history` | MySQL 客户端 | 逐条 SQL | **可含明文口令**（`CREATE USER ... IDENTIFIED BY`）；**无时间戳** |
| `~/.psql_history` | PostgreSQL psql | SQL + 历史命令 | 同上 |
| `~/.rediscli_history` | redis-cli | Redis 命令 | 可能含 `CONFIG SET`、`FLUSHALL` |
| `~/.sqlite_history` | sqlite3 | SQL | 少用但存在 |
| `~/.viminfo` | vim | **最近打开文件列表**、光标位置、寄存器 | **信息密度高**：记录编辑过的文件路径 |
| `~/.lesshst` | less | 历史搜索模式 | 辅助证据 |
| `~/.node_repl_history` | Node.js REPL | JS 语句 | 现代环境 |
| `~/.irb_history` | Ruby IRB | Ruby 语句 | 少见 |
| `~/.gnu_history` / `~/.history` | 某些 shell 的历史 | 命令 | 少见但存在 |

> ⚠️ **这批文件绝大多数默认不记时间戳。** 和 bash 历史一样，只能当"内容证据"，不能直接定时间。要定时间，得和文件系统时间戳、auth.log、journal 交叉。

<a id="section-10"></a>

### 2.4 历史伪造：能改什么、怎么发现

**"能伪造"是历史证据的固有弱点**。

但伪造会留下可检出的痕迹。取证的关键不是"信不信历史"，而是"**这些历史自洽吗**"。

**攻击者能做的（用于理解局限，本篇不给出实现）**：

- 直接编辑 `.bash_history` 文件（增删改命令）
- `history -c` 清空内存 + 文件
- 设置 `HISTFILE=/dev/null` 彻底关掉
- 结束会话时 `kill -9` 当前 shell，让部分操作不落盘
- 事后**覆写时间戳**（bash 存的是可改的 epoch 文本）

**可检出的反伪造信号**（这是本节的重点）：

| 信号 | 判据 |
|---|---|
| 命令与 auth.log 的 `Accepted` 时刻矛盾 | 历史里有 `wget` 某 URL，但 auth.log 里该用户的登录/会话时间**不覆盖**该文件的 crtime |
| **顺序不自然** | 下载 → 执行 → 删除 的逻辑链断裂；或出现"先删后建" |
| 大量 `export HISTFILE` / `history -c` / `unset HISTFILE` 出现在历史里 | **攻击者自己留下了"清历史"的痕迹** |
| **时间戳被人为整齐化** | 大量 `#<epoch>` 呈规律间隔（如全在整点、全间隔相同）= 脚本批量生成，非人工输入 |
| **epoch 超出合理范围** | `#<epoch>` 换算后是未来时间 / 1970 / 明显不可能的年份 |
| 文件 mtime 与最后一条 `#epoch` 严重不符 | 最后一条命令的时间远早于文件 mtime 很久 → 有人在会话后大量编辑 |
| 同一用户历史里同时出现两套 `HISTFILE` 设置 | 说明中途切换过存储位置 |

> **核心方法论**：**永远不要单独用历史定性。** 历史文件是"最容易被伪造的工件之一"，它的价值在于与 auth.log、wtmp、文件系统时间戳、包管理器日志交叉印证。当三者矛盾时，**以独立于历史的日志为准**，并把矛盾本身作为发现写进报告。

---

<a id="section-11"></a>

## 三、操作步骤

<a id="section-12"></a>

### 3.1 第 1 步：确定用户列表与家目录

```bash
# 真实可登录用户（家目录存在 + 有 bash_history/zsh_history）
for d in /home/* /root; do
  [ -d "$d" ] || continue
  ls -la "$d"/.bash_history "$d"/.zsh_history 2>/dev/null
done

# 从 passwd 取家目录 + shell（判定 nologin 账户不会有 shell 历史）
awk -F: '$7 !~ /(nologin|false|sync)$/ {print $1"  home="$6"  shell="$7}' /mnt/df/etc/passwd
```

> 发行版可能把家目录放在 `/home`、`/export/home`（SUSE）、`/Users`（macOS 风格）等。以 `/etc/passwd` 的第 6 字段为准，不要假设 `/home`。

<a id="section-13"></a>

### 3.2 第 2 步：提取并解析 bash 历史（含时间戳判定）

```bash
# 提取
cp --preserve=all /mnt/df/home/deploy/.bash_history /evidence/bash_history_deploy

# 判定是否带时间戳（看有无 #<epoch> 行）
grep -cE '^#[0-9]{9,}$' /evidence/bash_history_deploy
# 0   → 无时间戳（不能定时间）
# >0  → 有时间戳

# 若有，按时间戳把 epoch 换算为可读时间（逐行解析）
python3 - <<'PY'
import re, datetime
cur = None
out = []
for line in open('/evidence/bash_history_deploy', encoding='utf-8', errors='replace'):
    m = re.match(r'^#(\d{9,})$', line.rstrip('\
'))
    if m:
        cur = datetime.datetime.fromtimestamp(int(m.group(1)),
              datetime.timezone.utc).isoformat()
    else:
        out.append((cur, line.rstrip('\
')))
for t, c in out:
    if t: print(f'{t}  {c}')
    else: print(f'[无时间戳]      {c}')
PY
```

> **解析要点**：`#<epoch>` 只对**紧随其后**的第一条命令生效，一一对应，不能跨多条套用。epoch 先用 **UTC** 换算，再按机器本地时区调整（见[第 08 篇](../computer-log/computer-log-linux-timeline-reconstruction.md)）。

<a id="section-14"></a>

### 3.3 第 3 步：判定 bash 是否配置了时间戳（找"为什么没有时间戳"）

```bash
# 查 HISTTIMEFORMAT 是否在任何 bashrc/profile 里被设置
grep -rnE 'HISTTIMEFORMAT' /mnt/df/etc/bash.bashrc /mnt/df/etc/profile \
  /mnt/df/etc/profile.d/ /mnt/df/home/*/.bashrc /mnt/df/root/.bashrc 2>/dev/null

# 查是否被明确关掉或清空
grep -rnE 'HISTTIMEFORMAT=(""|'"''"')' /mnt/df/etc /mnt/df/home 2>/dev/null

# 查其余四个控制变量
grep -rnE '^\s*(export\s+)?(HISTSIZE|HISTFILESIZE|HISTCONTROL|HISTFILE|HISTIGNORE)=' \
  /mnt/df/etc/bash.bashrc /mnt/df/etc/profile /mnt/df/etc/profile.d/ \
  /mnt/df/home/*/.bashrc /mnt/df/home/*/.bash_profile /mnt/df/root/.bashrc 2>/dev/null
```

| 配置发现 | 取证含义 |
|---|---|
| 有 `HISTTIMEFORMAT='%F %T '` | 该用户/系统**会写时间戳**；历史无 `#` 行 = **被人删过 `#` 行或历史被伪造** |
| 无 `HISTTIMEFORMAT` | 历史**本就不带时间戳**；无 `#` 行属正常，不是篡改 |
| 有 `HISTCONTROL=ignorespace` | **空格开头命令不记录**；历史"缺命令"不能证明未执行 |
| 有 `HISTSIZE=0` / `HISTFILESIZE=0` | 历史**本就是空的**；缺失非篡改 |
| `HISTFILE` 指向非常规路径 | **重点排查对象**——去那个路径找历史 |

<a id="section-15"></a>

### 3.4 第 4 步：全盘搜历史文件（因为 HISTFILE 可改）

```bash
# 1. 按文件名特征搜（含隐藏、非默认路径）
find /mnt/df -xdev -type f \( -name '*hist*' -o -name '.*history*' -o -name '.sh_history' \) \
  -printf '%TY-%Tm-%Td %TH:%TM  %u:%g  %8s  %p\
' 2>/dev/null | sort

# 2. 按内容特征搜（漏网之鱼：改名过的历史文件）
grep -rlE '^(#1[0-9]{9}|: 1[0-9]{9}:)' /mnt/df/home /mnt/df/root \
      /mnt/df/tmp /mnt/df/var/tmp 2>/dev/null

# 3. 应用自有历史
find /mnt/df/home /mnt/df/root -maxdepth 2 -type f \
  \( -name '.*history' -o -name '.viminfo' -o -name '.lesshst' -o -name '.node_repl_history' \) \
  -printf '%TY-%Tm-%Td  %u:%g  %8s  %p\
' 2>/dev/null | sort
```

> 内容特征 `^#1[0-9]{9}` 精确命中 bash 带时间戳的历史首行，`: 1[0-9]{9}:` 命中 zsh。**这一步是揪出"改名或改过路径的历史"的关键。**

<a id="section-16"></a>

### 3.5 第 5 步：解析 zsh 历史（带时间戳）

```bash
# 检查存在性
ls -l /mnt/df/home/*/.zsh_history /mnt/df/root/.zsh_history 2>/dev/null

# 解析：: <epoch>:<num>;<command>
python3 - <<'PY'
import datetime
for path in ['/evidence/zsh_history_deploy']:
    for line in open(path, encoding='utf-8', errors='replace'):
        line = line.rstrip('\
')
        if line.startswith(': '):
            meta, _, cmd = line[2:].partition(';')
            parts = meta.split(':')
            if parts and parts[0].isdigit():
                ts = datetime.datetime.fromtimestamp(int(parts[0]),
                      datetime.timezone.utc).isoformat()
                print(f'{ts}  {cmd}')
        else:
            print(f'[无时间戳]      {line}')
PY
```

<a id="section-17"></a>

### 3.6 第 6 步：与独立日志交叉验证（反伪造的核心）

```bash
# 取该用户的登录/会话时间窗口（auth.log 为例）
grep -iE "Accepted.* for <user> |session (opened|closed) for user <user>" \
  /evidence/auth-merged.txt

# 检查历史里的高危命令是否落在会话窗口内
grep -inE 'curl|wget|nc |ncat|socat|base64 -d|chmod \+s|chmod 4[0-9]{3}|/tmp/|/dev/shm' \
  /evidence/bash_history_deploy
```

| 交叉验证结果 | 结论 |
|---|---|
| 历史命令时间 ∈ 会话窗口 | 佐证历史可信 |
| 历史命令时间 **∉** 会话窗口（差距明显） | **历史可能被伪造/编辑**；以 auth.log 为准 |
| 历史里有 `wget`，但目标文件 crtime 晚于会话 | 时间线矛盾，需解释 |
| 历史里出现 `history -c` / `HISTFILE=/dev/null` | **攻击者清历史的直接痕迹** |

<a id="section-18"></a>

### 3.7 验证环节

| 验证对象 | 方法 | 通过标准 |
|---|---|---|
| 历史文件完整性 | `sha256sum` + `stat` | 提取长度/哈希与源一致 |
| 时间戳可用性 | 数 `#<epoch>` 行数 | >0 才可定时间；否则标注"无时间戳" |
| epoch 合理性 | 换算后范围检查 | 在合理年份区间、非未来、非 1970 |
| 顺序自洽 | 逻辑链检查 | 下载→执行→清理链完整或矛盾可解释 |
| 与日志一致 | auth.log 会话窗口 | 命令时间落在窗口内（无矛盾） |

---
<a id="section-19"></a>

## 四、常见陷阱

本章按历史文件定位 → 机制误读 → 时间归属 → 结论表述归组，每条给出：现象、为什么会误判、误判代价、正确做法。
★ 标记表示该操作会导致原始检材被不可逆改变或使某类证据本次无法再取，执行前必须停下来确认。

本章有一条贯穿的主线：shell 历史是「行为的部分采样」，而不是行为的完整记录。 它在四个方向上会漏记，而这四个方向在磁盘上的表现完全一样——就是「没有那条命令」。所以本主题里最常见的错误不是读错，而是把「没读到」当成「没发生」，或者把「这台机器没读到」当成「这台机器没有」。

<a id="section-20"></a>

### 4.1 历史文件定位

<a id="section-21"></a>

#### 陷阱 1：只查 `~/.bash_history`，找不到就写"无命令历史"

**现象**：镜像里 `/home/deploy/.bash_history` 大小为 0，报告结论写「该账户无命令历史记录，无法还原其操作」。

**原因**：bash 的历史路径由 `HISTFILE` 决定，用户可以改到任意可写位置。 常见改法有 `~/.bash_hist`（改名备份）、`/tmp/.h`、`/var/tmp/hist`（藏进常驻盘）、`/dev/null`（彻底丢弃）。更关键的是即使 `HISTFILE` 没改，`HISTSIZE=0` 或 `HISTFILESIZE=0` 也会让历史文件为空——这两个变量是内存/写盘条数上限，置 0 就等于关闭。案例第 3 步正是靠"按内容特征全盘搜"找到了非标准路径的 `.bash_hist.bak`（1847 字节，含时间戳），而默认路径那个是 0 字节。

**影响**：这是本主题代价最高的一类阴性结论。

命令历史是还原操作意图的直接来源之一（其余来源见扩展阅读中的认证日志与持久化工件）。案例里整个攻击链（下载载荷 → 赋 SUID → 改 HISTFILE 掩盖）都是从 `.bash_hist.bak` 里还原出来的。默认路径为空就下结论，等于把这条证据链排除在分析之外。

**核查**：**按内容特征全盘搜，不要按路径找**。搜索范围要覆盖隐藏文件与非默认目录：

```bash
# 候选文件名
find /mnt/df -xdev -type f \( -name '*hist*' -o -name '.*history*' \) \
  -printf '%TY-%Tm-%Td %TH:%TM %8s %p\
' 2>/dev/null | sort
# 内容特征：bash 带时间戳的 #<epoch> 行，或 zsh 的 : <epoch>:<dur>; 格式
grep -rlE '^(#1[0-9]{9}|: 1[0-9]{9}:)' /mnt/df/home /mnt/df/root /mnt/df/tmp /mnt/df/var/tmp 2>/dev/null
```

同时把 bash 侧的四个变量一并查（`HISTFILE`/`HISTSIZE`/`HISTFILESIZE`/`HISTCONTROL`），并在报告里写清"**已搜索的路径范围与判据**"。搜完仍无结果，结论才成立。

<a id="section-22"></a>

#### 陷阱 2：把 `HISTFILE=/dev/null` 当成"用户正常设置"

**现象**：在 `~/.bashrc` 里看到 `export HISTFILE=/dev/null`，报告写「该用户自行关闭了命令历史，属常规配置」。

**原因**：**这个配置出现在案发时间窗口内，本身就是痕迹。** 它的效果是"该用户从设置时刻起，所有交互式命令都不落盘"——代价极低（一行 export）。判断它是常规配置还是反取证，要看三件事：① 配置行的 `mtime`/`ctime`（案例里它是 22:44，正好在 22:43 登录成功之后一分钟）；② 同一 `.bashrc` 里是否还有 `HISTCONTROL=ignorespace`、`shopt -s histappend` 之类的配合项；③ 该用户此前是否有正常历史——此前有正常历史 + 突然被指向 `/dev/null` + 时间落在争议时段内，这个组合需要专门解释。

**影响**：把反取证配置写成"常规设置"，等于帮攻击者把配置解释掉了。

委托方会认为"该账户本来就关了历史"，从而不会去想"为什么这个账户的命令都看不到"。

**核查**：bash 配置文件的**时间戳**是这类判定的核心证据，必须采集并写入报告：

```bash
stat -c '%n mtime=%y ctime=%z' /mnt/df/home/deploy/.bashrc
grep -nE '^\s*(export\s+)?(HISTFILE|HISTSIZE|HISTFILESIZE|HISTCONTROL|HISTTIMEFORMAT|HISTIGNORE)=' \
  /mnt/df/home/deploy/.bashrc /mnt/df/etc/bash.bashrc /mnt/df/etc/profile
```

结论表述：「`~/.bashrc` 第 12 行将 `HISTFILE` 指向 `/dev/null`，该文件 `mtime` 为 2024-03-17 22:44:03，晚于该账户 22:43:07 的登录成功时间约 56 秒。该配置使此后所有交互命令不落盘。」——**时间关系是这条结论的承重墙，必须写出来。**

<a id="section-23"></a>

#### 陷阱 3：看到 zsh 历史里有时间戳，就照搬去给 bash 命令定时间

**现象**：机器上同时存在 `.bash_history`（无时间戳）和 `.zsh_history`（带时间戳），分析者用 zsh 的时间戳给 zsh 会话定序，然后把这个精度套用到同一用户的 bash 命令上，报告写「该用户在 22:47 前后执行了以下操作」。

**原因**：两个历史文件记录的是不同 shell 的会话，各自独立。 案例里 `deploy` 主要是 bash 用户，`.bash_history` 完全无时间戳，`.zsh_history` 的存在只说明**该用户在这个时刻也用过 zsh**。bash 会话的"先后顺序"没有时间基准可用。**zsh 有时间戳不等于 bash 也有**——这是两个文件的两种配置，不能互相借用。

**影响**：把 zsh 的时间精度套到 bash 上，会产出看似精确、实则无据的时间。案例第 1 步的正确定义是：bash 历史无时间戳 → **这是"局限"**；bash 的时间锚点只能从 auth.log 的 `Accepted`/`session` 行、wtmp、以及文件系统时间戳三处取。

**核查**：分 shell 独立处理，各给各的结论强度。bash 会话的定序用三源：① `auth.log` 的登录/会话时间窗（给出区间而非点）；② 历史文件自身 `mtime`/`ctime`（给出落盘时刻，不是执行时刻）；③ 涉及的文件/目录时间戳（给出对象的时间）。三种时间在报告里必须分列标注，不能合并成一个"时间"。

<a id="section-24"></a>

#### 陷阱 4：靠找文件名判断用户用的哪个 shell

**现象**：在 `/home/*` 下没找到 `.bash_history`，判断「该用户不用 bash 所以无历史」；或者反过来，看到 `.zsh_history` 就认定「该用户是 zsh 用户」，不去看 `/etc/passwd`。

**原因**：用户的默认 shell 记录在 `/etc/passwd` 第 7 字段，而各 shell 的历史文件路径差异极大，且与家目录根毫无关系。

fish 的历史在 `~/.local/share/fish/fish_history`，**不在 home 根目录**；而 fish 的文件名里根本没有 "hist" 的规律可用。第五章 5.3 里 `data` 用户用 fish，其历史路径无明显线索，正是「`ls ~/*hist*` 极易漏查」的对象。反过来的坑也存在：用户登录 shell 是 bash，但他在某个会话里用 `zsh` 跑过一段命令——此时 `.zsh_history` 属于他，`.bash_history` 也属于他，两者都有效。

**影响**：这是把「解析失败」误报为「证据缺失」，性质比路径漏查更严重。

第五章那条最像的误判是「`.zsh_history` 与 `fish_history` 用 bash 正则匹配数为 0，说明这两个 shell 没有启用时间戳功能，无法用于时间线重建」——实际上 `ops` 的 142 条与 `data` 的 88 条**全部带时间戳**，只是格式不同（zsh 是 `epoch:duration;cmd` 单行，fish 用 `- cmd:` 前缀作时间戳标记）。用 bash 的 `^#[0-9]{9,}$` 规则去扫它们，匹配数必然是 0。

两份可用的时间线证据因此被整体丢弃，而委托方看到的报告会说「无法重建时间线」——这是本篇唯一一处「数据在盘上却被写成不可得」的成因，它连搜索动作都没做对。

**核查**：shell 判定来自 `/etc/passwd` 第 7 字段，历史路径由格式判定，不由文件名判定。

```bash
# ① 每个用户的登录 shell（权威来源）
awk -F: '$3>=1000 || $1=="root" {printf "%s shell=%s home=%s\
",$1,$7,$6}' /mnt/df/etc/passwd

# ② 按 shell 分别定位历史路径，不靠通配符
#    bash: ~/.bash_history          zsh:  ~/.zsh_history
#    fish: ~/.local/share/fish/fish_history
#    ksh:  ~/.sh_history            tcsh: ~/.history
for u in $(awk -F: '$3>=1000 || $1=="root" {print $1}' /mnt/df/etc/passwd); do
  h=$(awk -F: -v u="$u" '$1==u {print $6}' /mnt/df/etc/passwd)
  for p in "$h/.bash_history" "$h/.zsh_history" "$h/.local/share/fish/fish_history" "$h/.sh_history" "$h/.history"; do
    [ -f "/mnt/df$p" ] && printf '%s shell=%s hist=%s\
' "$u" "$(awk -F: -v u="$u" '$1==u{print $7}' /mnt/df/etc/passwd)" "$p"
  done
done
```

**三条路径都要查，不按第 7 字段排除。** `/etc/passwd` 的第 7 字段给出的是**登录 shell**，而历史文件可能属于其它 shell——`deploy` 同时有 bash 与 zsh 历史就是这种结构。

<a id="section-25"></a>

#### 陷阱 5：把 `history` 命令的输出当成完整历史

**现象**：在检材上（或凭同事转述）执行 `history`，看到输出就认为「该用户的命令历史就是这些」，并按这个清单写报告。

**原因**：`history` 打印的是内存中的历史列表，不是文件，而这两者不一致是常态。

三个方向都会不一致：① 内存列表受 `HISTSIZE` 截断，**文件里可能有更多**（退出时是按 `HISTFILESIZE` 写的，两个值常常不同）；② **当前会话的命令还没写盘**——bash 只在正常退出时一次性 append，所以 `history` 能看到刚敲的、文件里没有；③ 通过 `history -c` 清空的只有内存，而文件内容是否同时被清取决于具体版本与是否启用 `histappend`。

另一半是**子 shell 的可见性**：`history` 只能看到当前 shell 的历史，从 `sudo`、`su` 后的 shell、以及子进程里执行过的命令都不在当前列表内。

**影响**：「以 `history` 输出为准」会把一个内存视图写成文件事实，而文件里可能恰恰有那些「没被记下来」的敏感命令——第五章 5.1 里整个攻击链是从 `.bash_hist.bak` 还原的，`history` 输出里根本没有这条文件。反过来若照抄 `history` 输出，报告里的命令清单会短于实际，且无法解释短在哪里。

**核查**：结论只以磁盘上的文件为准，`history` 输出只能作为辅助记录，且必须标明它不是证据。

```bash
# 唯一的取证对象：磁盘上的历史文件
ls -l /mnt/df/home/<user>/.bash_history
wc -l /evidence/bash_history_<user>            # 条数基线

# 若在检材上做过 history（仅工作副本），记录两条基线之差
# 差值 > 0 → 说明有「只在内存、未写盘」的会话，这本身就是一条结论
```

报告里若引用了 `history` 输出，必须写：「以下命令清单取自分析机上的 `history` 输出，**仅作辅助**；磁盘文件的权威版本共 `<N>` 条，两者差异 `<M>` 条，差异原因是 `<当前会话未落盘 / HISTSIZE 与 HISTFILESIZE 不同>`」。把辅助材料当证据提交，是本主题最容易被忽略的一处程序瑕疵。

<a id="section-26"></a>

#### 陷阱 6：把 `TMOUT` 与历史缺失联系起来

**现象**：`/etc/profile` 或 `~/.bashrc` 里配了 `TMOUT=1800`，历史文件里缺了后半段命令，报告写「会话超时退出导致后半段命令未落盘」。

**原因**：`TMOUT` 的作用是空闲超时退出，它在 bash 里走的是普通退出路径，与 `kill -9` 是两回事。

bash 收到 `SIGHUP`（`TMOUT` 触发的就是这一类）时会执行退出清理，**包括把内存历史写入 `HISTFILE`**——所以「因为 `TMOUT` 所以历史丢了」这个推理在机制上是错的。真正丢历史的退出方式只有两类：① 进程被 `SIGKILL` 终止（`kill -9`、OOM Killer），此时没有任何清理机会；② 断电、崩溃、内核 panic。

而 `TMOUT` 真正的取证价值在另一个方向：它解释了会话的结束方式，从而解释历史为什么"在某处断了"。配置了 `TMOUT` 且断点时间与登录时间的间隔接近 `TMOUT` 值，这条对应关系是有意义的观察。

**影响**：把 `TMOUT` 写成丢历史的原因，等于给出一个**机制上不成立但听起来合理**的解释。它会把这个阴性发现「解释掉」——委托方读到「会话超时导致历史丢失」，就认为这是正常现象而非取证缺口；而实际上若真是超时退出，历史本该落盘，**缺失就需要另找原因**。

**核查**：`TMOUT` 只用来解释退出方式，不用来解释历史缺失。

```bash
# ① TMOUT 的实际值与设置位置
grep -rnE '^\s*(export\s+)?TMOUT=' /mnt/df/etc/profile /mnt/df/etc/bash.bashrc \
  /mnt/df/etc/profile.d/ /mnt/df/home/*/.bashrc 2>/dev/null

# ② 会话结束时刻：与 TMOUT 值比对，判断退出方式
grep -E 'session (opened|closed)' /mnt/df/var/log/auth.log | grep '<user>'
# 间隔 ≈ TMOUT 值 → 符合超时退出，历史应已落盘，缺失需另解释
```

**判定分两档**：间隔接近 `TMOUT` 值 → 「会话于 `<时间>` 因空闲超时退出，**该退出路径会触发历史写盘**，因此缺失部分不能归因于超时」；会话无 `session closed` 记录而机器随后强制断电 → 「会话被中断（断电 / kill -9 类），未执行退出写盘，当前会话历史不可得」，此时 `TMOUT` 的值不参与解释。

<a id="section-27"></a>

### 4.2 机制误读

<a id="section-28"></a>

#### 陷阱 7：把"没有 `#` 行"直接当成"时间戳被清除"

**现象**：`grep -cE '^#[0-9]{9,}$' .bash_history` 返回 0，报告写「历史文件时间戳已被攻击者清除」。

**原因**：**bash 默认就不写时间戳。** 只有当 `HISTTIMEFORMAT` 这个变量被设置过（哪怕值为空），bash 才会为每条命令前加一行 `#<epoch>`。多数系统并未启用它，所以"无 `#` 行"是**默认状态**，不是被清除的痕迹。区分的方法是查配置——案例第 2 步查到 `/home/deploy/.bashrc:9: HISTTIMEFORMAT='%F %T '` **是设置了的**，这与磁盘上无 `#` 行构成矛盾，矛盾本身需要解释。

**影响**：把默认状态当篡改，会给出无依据的"证据被篡改"指控。

更常见的是反向失误：看到无 `#` 行就写"该机无历史可定时间"，**却不去查配置**。而案例恰恰是配置存在、文件异常，这才是真发现。

**核查**："无 `#` 行"是一个必须解释的观察，不是结论。 解释需要两个数据点：

```bash
grep -cE '^#[0-9]{9,}$' /evidence/bash_history_deploy     # 0 —— 观察
grep -rnE 'HISTTIMEFORMAT' /mnt/df/etc/bash.bashrc /mnt/df/etc/profile \
  /mnt/df/etc/profile.d/ /mnt/df/home/deploy/.bashrc      # /home/deploy/.bashrc:9 有 → 矛盾
```

组合判读：配置无 + 文件无 `#` = **未启用**，结论"该系统未记录历史时间"（局限）；配置有 + 文件无 `#` = **矛盾**，构成"历史文件被重写/清空"的信号（发现）；**部分条目有 `#`、部分没有** = 时间戳功能中途启用，**只有有 `#` 的那些才能定时间**。

注意「配置有 + 文件无」这个矛盾还有一个非恶意解释：用户设了 `HISTTIMEFORMAT` 但那个会话从未正常退出过（断电 / `kill -9`），于是新配置根本没机会写 `#` 行。第五章的机器正是强制断电。所以这个矛盾指向的是「某个时点之后的会话历史不可得」，而不是「历史被篡改」——两者的差别在于报告能不能指出断点。

<a id="section-29"></a>

#### 陷阱 8：把一个 `#` 行"套"给后面多条命令

**现象**：历史文件里只有一个 `#1710685755` 在头部，后面跟了 30 条裸命令，报告把这 30 条全部标为"1710685755 时刻执行"。

**原因**：bash 的 `#<epoch>` 与其后的命令是严格一一对应的——每条命令前面各有自己的 `#` 行（启用时间戳后写入的形态是 `#<epoch>` 与命令行交替出现）。如果只有一个 `#` 行而后面有 30 条命令，这本身就是**文件被编辑过**的形态（正常 bash 写出的文件里，两种形态不会这样混排），而不是"30 条命令共享一个时间"。

**影响**：给 30 条命令赋同一个时间戳，等于在时间线上造出一个虚假的"30 条命令同时执行"事件。

案例里 `.bash_hist.bak` 的形态是标准的交替（`#1710685755` / `ls -la /var/www` / `#1710685901` / `whoami`），解析脚本必须严格按交替配对。

**核查**：解析时**严格逐行状态机**——遇到 `#<epoch>` 就记住它，遇到非 `#` 行就把当前 epoch 赋给这条命令，遇到无 epoch 的命令标记为"时间未知"而不是继承上一条。同时统计三种行数的比例（`#` 行数 vs 命令行数），比例失衡本身就是格式异常的信号。

```bash
awk '
  /^#[0-9]{9,}$/ { ts=substr($0,2); next }
  /^#/            { next }                 # 其它注释行，忽略
  NF              { printf "%s\	%s\
", (ts==""?"NO_TS":ts), $0; ts="" }
' /evidence/bash_hist.bak
```

<a id="section-30"></a>

#### 陷阱 9：拿 zsh 的解析规则去读 fish 历史（反之亦然）

**现象**：机器上有 bash、zsh、fish 三种 shell 的历史，分析员统一用 zsh 规则（`: <epoch>:<dur>;cmd`）去解析所有文件，fish 与 bash 的历史输出零匹配，报告写「这两类历史不可解析」。

**原因**：四种格式的字段位置完全不同，而「解析不出时间」这个结果在任何格式下都表现为「匹配数为 0」。

| shell | 形态 | 时间字段 |
|---|---|---|
| bash | `#<epoch>` **独立行**，与其后 1 条命令交替 | 仅当 `HISTTIMEFORMAT` 被设置过 |
| zsh | `: <epoch>:<dur>;cmd` **单行** | `EXTENDED_HISTORY` 启用即有，不需 `HISTTIMEFORMAT` |
| fish | `- cmd: <原文>` 行内前缀 | **有 `- cmd:` = 已启用时间戳**；**无 `-` 的 `cmd:` = 未启用** |
| ksh / tcsh | 自有格式，无统一约定 | 需按实际形态判定 |

**fish 的判读方向最容易被搞反**：看到 `- cmd:` 说明时间戳功能开启，**看到无 `-` 的 `cmd:` 才是未启用**——两种形态含义完全相反，而笼统说「这个格式没有时间戳」会把前者一起否定掉。

**影响**：第五章 5.3 那份最容易得出的错误结论正是这个形态——「匹配数为 0 说明这两个 shell 没有启用时间戳功能」。而实际上 `ops` 的 142 条与 `data` 的 88 条**全部可用**，合计 230 条带时间戳的命令被整体丢弃。

**核查**：逐格式解析，匹配数为 0 只能作为「本规则不适用」，不能作为「无时间戳」。

```bash
# zsh：取行首第一个冒号到分号之间的第一个整数，其余数字字段忽略
awk -F'[;:]' '/^: [0-9]+:[0-9]+;/ {
  split($2,a,":"); print a[1]"\	"substr($0, index($0,";")+1)
}' /evidence/zsh_history_ops

# fish：时间戳在行内的 - cmd: 之后、原文之前
grep -E '^- cmd: [0-9]+' /mnt/df/home/data/.local/share/fish/fish_history | head
# 判读方向：有 - cmd: = 已启用；只有 cmd: = 未启用

# fish 路径不在家目录根，走一遍逻辑遍历
find /mnt/df/home -path '*/.local/share/fish/fish_history' 2>/dev/null
```

报告里每个 shell 单独给结论，并写明用的是哪条解析规则。「解析不出」和「没有」这两个词在这份报告里必须分开。

<a id="section-31"></a>

### 4.3 时间归属

<a id="section-32"></a>

#### 陷阱 10：把历史文件的 `mtime` 当成"最后一条命令的执行时间"

**现象**：`stat` 显示 `.bash_history` 的 `mtime` 是 2024-03-18 09:40，报告写「该用户最后一次操作在 09:40」。

**原因**：`mtime` 是"文件最后一次被写入的时间"，不是"最后一条命令被执行的时间"。 bash 的机制是**正常退出时一次性 append 写盘**——文件里最后一条命令可能在几天前就敲了，中间几次会话因 `kill -9`（SIGKILL 不可捕获）、OOM Killer、断电而完全没写盘。更极端的情形：一次很久之后的正常退出会把内存里所有命令一起落盘，把 `mtime` 推到很晚，而内容跨越很长时间。

**影响**：把落盘时刻当执行时刻，会在时间线上造出一个假的"近期活动"，并掩盖掉真正的执行时刻。

对断电检材尤其致命——案例的机器正是强制断电。

**核查**：三种时间必须分列，不可互换：

| 时间 | 含义 | 来源 |
|---|---|---|
| 命令执行时刻 | 真正敲下命令的时间 | **仅当有 `#<epoch>` 时可得**；否则不可得 |
| 文件 `mtime` | 最后一次落盘时刻 | `stat` 的 `%y` |
| 文件 `ctime` | 元数据最后一次变更时刻 | `stat` 的 `%z` |

无 `#` 行时，命令执行时刻**只能给出区间**——用 auth.log 的 `session opened` 到 `session closed` 作为区间边界，报告写「该账户在此会话区间内执行了以下命令，**具体时刻不可知**」。

**跨源比对时这三种时间不能混用。** `mtime` 与 auth.log 的 `Accepted` 时刻差值算出来很接近，不构成「同时发生」的证据——因为写盘发生在会话结束时，而 `Accepted` 发生在会话开始时。**这两者的差值天然等于一个会话的长度**。

<a id="section-33"></a>

#### 陷阱 11：★ 把攻击者的 shell 挂上去交互，或用 `kill -9` 试探历史落盘行为

**现象**：为"确认 bash 是否会写盘"，在挂载点内启动一个 bash 试运行；或为"看会不会有新历史"而在检材上执行会触发写盘的操作。

**原因**：bash 的写盘行为只影响 `HISTFILE` 指向的文件。 如果 `HISTFILE` 指向挂载点内的镜像路径（默认 `~/.bash_history` 在挂载点内），任何一次正常退出都会向检材写入。你以为在"观察"，实际上在**修改证据**。

**影响**：不可逆污染，写入的内容还会伪装成正常历史行。

更严重的是：`.bash_history` 是本主题的核心物证，混入分析动作产生的命令后，它的哈希不再代表检材原始状态，完整性链出现断点。

**核查**：**任何需要"运行一下看看"的动作都在工作副本上做**（`dd` 复制出的 `DigiForensics-work.dd`），并把 `HISTFILE` 显式指向证据目录：

```bash
cp --preserve=all /mnt/df/home/deploy/.bash_history /evidence/bash_history_deploy
sha256sum /evidence/bash_history_deploy | tee /evidence/hashes.txt
# 若必须实测行为：
export HISTFILE=/evidence/test_history
bash -i      # 绝不指向 /mnt/df 内的任何路径
```

只读挂载（`mount -o ro,noload,noatime`）是第一道防线，`--preserve=all` 复制 + 记录哈希是第二道，报告中"提取方式"一栏要写明用了哪两条。

**用 `kill -9` 试探更是双重错误**：它既污染不了证据（因为目标挂载是只读的），也测不出任何东西（只会杀掉你自己的测试 shell）。这类实验在只读环境下得到的永远是「操作失败」，而失败原因会被误读成「该机制不生效」。

<a id="section-34"></a>

#### 陷阱 12：把 zsh 历史的第二个数字当执行时长

**现象**：读到 `: 1710700920:3;cd /tmp`，报告写「该命令执行了 3 秒」，并据此推断操作节奏。

**原因**：第二个数字是"该命令的运行时长（秒）"，但它经常是假的。 启用 `INC_APPEND_HISTORY` 或 `SHARE_HISTORY` 时，zsh 在命令**提交时**就写入历史，**此时命令尚未结束、时长无从得知，一律记 0**；只有 `INC_APPEND_HISTORY_TIME`（等命令结束后再写）才记录真实时长。所以**看到 `0` 不代表命令瞬间完成**。

**影响**：把提交时刻与完成时刻混为一谈，会得出"命令瞬间完成→是脚本自动执行"或"耗时 3 秒→在手工逐条敲"这类无依据的推断。

**核查**：时长字段**只能作「该命令是否超过 1 秒」的粗判据**。**第一个 epoch 才是可靠的**——它是命令**开始执行**的时间（由 `EXTENDED_HISTORY` 启用，不需 `HISTTIMEFORMAT`，这是 zsh 相对 bash 的优势）。解析规则照 2.2 的写法：取行首第一个冒号到分号之间的第一个整数作为 epoch，其余数字字段一律忽略，这样格式扩展也不会错位。

```bash
awk -F'[;:]' '/^: [0-9]+:[0-9]+;/ {
  split($2, a, ":"); print a[1]"\	"substr($0, index($0,";")+1)
}' /mnt/df/home/deploy/.zsh_history
```

「手工敲」与「脚本执行」的判据不能建立在时长字段上，而应建立在这些地方：命令的语义是否适合手工执行（如一次性 `for` 循环）、同一时刻是否有多个 shell 会话（`auth.log` 的并发会话数）、以及这些命令在 auth.log 里能否对应上独立的登录记录。

<a id="section-35"></a>

### 4.4 结论表述

<a id="section-36"></a>

#### 陷阱 13：把"历史文件干净"写成"攻击者没有执行敏感操作"

**现象**：`.bash_history` 内容只有 `ls`、`whoami`、`uname -a` 这类无害命令，报告结论写「未见攻击者进行任何下载、执行或提权操作」。

**原因**：**bash 历史机制在四个方向上都会漏记**，且四个方向在磁盘上的表现完全一样（就是"没有那条命令"）：① `HISTCONTROL=ignorespace` 跳过空格开头的命令；② `HISTFILE` 指向别处或 `/dev/null`；③ `HISTSIZE=0`/`HISTFILESIZE=0`；④ **只在正常退出时写盘**——`kill -9`、OOM、断电都让当前会话全部丢失。案例的机器**正是强制断电**，这是最不利的组合。

**影响**：这是取证报告里最典型的一类假阴性。

它用一个"看起来干净"的负面前缀，否定了本可以通过其他工件（文件系统时间戳、auth.log 的 sudo、persistence 痕迹）证明的行为。案例里实际操作者在 auth.log 与文件系统时间戳里留下了痕迹，**只有命令历史是空的**。在这里下"未见敏感操作"的结论，就与同一份报告里其它章节的发现直接矛盾。

**核查**：这类结论必须**收敛到机制允许的最小命题**，并把限制条件写在同一句话里：

> 「该账户的 bash 历史文件不含时间戳行，且 `.bashrc` 配置 `HISTFILE=/dev/null`（配置时间 22:44:03，晚于登录成功 56 秒）。**因此本账户的命令历史在 22:44 之后不可得**；`kill -9` 与断电亦会导致当前会话历史丢失。**本节结论不覆盖 22:44 之后的操作**，该时段的行为以 auth.log 的 `sudo COMMAND=` 记录与文件系统时间戳为准。」

关键是把"证据不可得"写进结论，而不是把"未见"写成"未发生"。

前者是专业的边界声明，后者是需要承担举证责任的断言。

<a id="section-37"></a>

#### 陷阱 14：把"历史内容与登录时间矛盾"直接定性为"伪造"

**现象**：历史里有一条命令，而 auth.log 里该用户的会话时间窗不覆盖对应的文件创建时间，报告直接写「攻击者伪造了命令历史」。

**原因**：**矛盾只说明两者不能同时为真，成因至少四种**：① 历史被伪造；② auth.log 被截断/轮转掉（时间窗不完整）；③ 命令是通过非交互方式执行的（脚本、cron、`ssh host "cmd"`）——这类执行根本不写进 `.bash_history`；④ 时间基准差异（`#<epoch>` 是 UTC 秒，auth.log 是本地时间且无年份，补年出错就会产生假的矛盾）。

**影响**："伪造"是一个需要承担举证责任的定性（2.4 那节把它列在"攻击者能做的"里，是理解局限而非指控）。一旦写进报告，对方只需提出"你补错了年份"或"该命令由 cron 执行"就能推翻，而你建立的其他基于时间线自洽性的推演也会被牵连。

**核查**：矛盾是**信号，不是定性**。定级 **L2 存疑**，措辞用「命令记录与认证日志存在时间矛盾，需进一步确认」。要升到"伪造"必须有独立证据：文件系统 `ctime` 链与命令内容矛盾（例如命令说 `rm` 某文件但该文件 `mtime` 晚于命令声称的时段）、或历史文件的 `mtime`/`ctime` 与内容逻辑不符。报告里要把四种可能都列出来，这是 L2 与 L3 的分界线。

四种成因里第 ③ 项最容易被忽略，而它恰恰是最常见的一种：`cron`、`systemd` 的 `.service`、部署脚本里的 `ssh host "cmd"` 都不产生交互式历史。所以「历史里没有某条命令」与「该命令没被记录」之间没有推理关系——缺命令的默认解释应该是「没被记录」，而不是「没执行」。

要区分这两者，得去查 cron 与 systemd 的执行记录（见[计划任务与持久化痕迹](../computer-persistence/computer-persistence-scheduled-tasks-and-persistence.md)）。
<a id="section-38"></a>

## 五、案例示例

<a id="section-39"></a>

### 5.1 HISTFILE 指向 devnull 后的改名备份与自证关闭

**场景**

Ubuntu Server 22.04 Web 服务器（Debian 系）。委托方要求还原攻击者 `deploy` 账户在主机上的操作。

检材 `DigiForensics.dd`（raw），ext4 起始扇区 1181696，**强制断电**。前序分析已确认 2024-03-17 22:43 `deploy` 从 `203.0.113.77` 密码登录成功并提权。

这条路径值得走，本案的起点是一个"空的"证据——默认历史文件大小为 0。要解释这个空文件为什么不可信，只能去看配置。**证据的可信度判定本身就是一条完整的取证链。**

**处置过程**

第 1 步，提取默认历史文件并判定时间戳可用性：

```bash
cp --preserve=all /mnt/df/home/deploy/.bash_history /evidence/bash_history_deploy
stat -c '%n size=%s mtime=%y ctime=%z' /evidence/bash_history_deploy
# size=0 mtime=2024-03-17 22:44:03 ctime=2024-03-17 22:44:03

grep -cE '^#[0-9]{9,}$' /evidence/bash_history_deploy
# 0   ← ★ 无任何 #<epoch> 行，且文件大小为 0
```

**默认路径上的历史文件是 0 字节**。此时若就此写"无可用命令历史"，整个调查方向就断了。

第 2 步，查 bash 配置，判定"无时间戳/无内容"的成因（**这一步是关键区分**）：

```bash
grep -rnE 'HISTTIMEFORMAT' /mnt/df/etc/bash.bashrc /mnt/df/etc/profile \
  /mnt/df/etc/profile.d/ /mnt/df/home/deploy/.bashrc 2>/dev/null
# /mnt/df/home/deploy/.bashrc:9:  HISTTIMEFORMAT='%F %T '     ← 曾启用过

grep -rnE '^\s*(export\s+)?(HISTSIZE|HISTCONTROL|HISTFILE)=' /mnt/df/home/deploy/.bashrc
# :10: export HISTCONTROL=ignorespace
# :12: export HISTFILE=/dev/null           ← ★★
```

两个矛盾点同时出现：配置里有 `HISTTIMEFORMAT`（说明本可记时间戳），但文件里没有 `#` 行；配置里有 `HISTFILE=/dev/null`（说明历史被重定向丢弃）。

后者直接解释了 0 字节。

第 3 步，全盘搜历史文件（**不能只查默认路径**）：

```bash
find /mnt/df -xdev -type f -name '*hist*' -printf '%TY-%Tm-%Td %TH:%TM %8s %p\
' 2>/dev/null | sort
# 2024-03-17 22:44 03      0  /mnt/df/home/deploy/.bash_history
# 2024-03-18 09:41 12   1847  /mnt/df/home/deploy/.bash_hist.bak   ← ★ 含时间戳
```

第 4 步，解析备份（`#<epoch>` 配对；epoch 本身是 **UTC** 秒，本机本地时区为 `Asia/Shanghai`）：

```
#1710685755
ls -la /var/www
#1710685901
whoami
#1710686642
sudo apt-get install -y netcat
#1710686853
sudo chmod 4755 /tmp/.kworkerd
#1710686900
/tmp/.kworkerd
#1710726044
echo 'HISTFILE=/dev/null' >> ~/.bashrc     ← ★ 攻击者自己记录了关闭历史
```

| epoch | UTC | 本地（UTC+8） | 命令 |
|---|---|---|---|
| `#1710685755` | 2024-03-17T14:29:15Z | 03-17 22:29:15 | `ls -la /var/www` |
| `#1710685901` | 2024-03-17T14:31:41Z | 03-17 22:31:41 | `whoami` |
| `#1710686642` | 2024-03-17T14:44:02Z | 03-17 22:44:02 | `sudo apt-get install -y netcat` |
| `#1710686853` | 2024-03-17T14:47:33Z | 03-17 22:47:33 | `sudo chmod 4755 /tmp/.kworkerd` |
| `#1710686900` | 2024-03-17T14:48:20Z | 03-17 22:48:20 | `/tmp/.kworkerd` |
| `#1710726044` | 2024-03-18T01:40:44Z | 03-18 09:40:44 | `echo 'HISTFILE=/dev/null' >> ~/.bashrc` |

第 5 步，跨源双源印证：

```bash
# 历史（UTC→本地） vs auth.log（本地 CST）
# 22:47:33  sudo chmod 4755 /tmp/.kworkerd   ← 历史
# 22:48:20  sudo COMMAND=/bin/chmod 4755 /tmp/.kworkerd  ← auth.log
# 22:44:02  sudo apt-get install -y netcat   ← 历史
# 22:47:33  Start-Date: 2024-03-17 22:47:33 CST  ← apt/history.log
```

**三源经时区换算后相互吻合**，构成"下命令 → 执行 → 落盘"的链条；历史给出命令内容，`auth.log` 的 `sudo COMMAND=` 与 `apt/history.log` 给出执行侧记录，三者来源相互独立。

第 6 步，交叉验证会话窗口（**这一步发现了一个矛盾点**）：

```bash
grep -iE 'Accepted.* for deploy|session (opened|closed) for user deploy' /evidence/auth-merged.txt
# Accepted password for deploy from 203.0.113.77 port 40210   (22:43:07)
# session opened for user deploy                              (22:43:09)
# Accepted password for deploy from 203.0.113.77 port 44880   (次日 09:40:58)
# session closed for user deploy                              (09:41:07)

last -f /mnt/df/var/log/wtmp deploy | head
# deploy  pts/0  198.51.100.23  Sat Mar 16 21:15 - 21:40
# deploy  pts/0  203.0.113.77  Sat Mar 17 22:43 - 23:55
# deploy  pts/0  203.0.113.77  Sun Mar 18 09:40 - 09:41
#                ↑ 存在更早的合法运维会话
```

备份历史里最早的 `ls -la /var/www` 在本地 **22:29:15**，**早于 22:43:07 的入侵登录**。

但 `wtmp` 显示该用户在 03-16 21:15 有过合法登录（来自 `198.51.100.23`）。"登录窗口"必须对照 `wtmp` 全量，不能只盯入侵那一次。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 磁盘上默认 `.bash_history` 不可信/不完整 | 当前 0 字节 + `.bashrc` 有 `HISTFILE=/dev/null` + 全盘搜到 `.bash_hist.bak` | 强 |
| 该账户主动关闭了历史记录 | `.bashrc:12 export HISTFILE=/dev/null`，且该动作本身出现在 `.bash_hist.bak` 里（`echo 'HISTFILE=/dev/null' >> ~/.bashrc`） | 强（**行为自证**：关闭动作本身被记录下来） |
| 2024-03-17 22:47–22:48 对 `/tmp/.kworkerd` 设 SUID 4755 并执行 | `.bash_hist.bak`（`sudo chmod 4755` + 执行）**+** auth.log `sudo COMMAND` 行，时间吻合，两类工件来源独立 | 强 |
| 该账户的 bash 配置原本可记时间戳，但备份历史带 `#` 行、默认文件无 | `.bashrc` 有 `HISTTIMEFORMAT`；默认文件 0 字节且 `HISTFILE=/dev/null` | 强（成因已由配置解释，无需假设文件被改写） |
| 历史里 22:29 等早期命令属 `deploy` 更早的运维会话 | 早于争议时段登录，但符合 `wtmp` 里 03-16 的登录记录 | 中（需以 wtmp 全量为准） |

**必须明示的盲区**：2024-03-17 22:43 登录后、切换 `HISTFILE=/dev/null` 之前的那段会话，**因写盘时刻被改动而存在不可恢复的盲区**。备份历史里 22:44:02 之后到 22:47:33 之间只有三条命令，与实际执行的动作数量明显不符，**缺口不能补写**。

**误判对照**

本案最容易得出的错误结论是「`.bash_history` 大小为 0，且 `.bashrc` 里有 `HISTTIMEFORMAT='%F %T '` 但文件里没有 `#` 行，说明 bash 配置损坏/时间戳功能异常，历史记录机制不可靠，因此本机无有效命令历史证据」。

**正确判据是把两个矛盾点分别归因**：

1. **为什么没有 `#` 行**——不是"功能异常"，而是**历史根本没往这个文件里写**。`.bashrc:12` 的 `export HISTFILE=/dev/null` 意味着每次 shell 退出时 bash 把历史写到 `/dev/null`（黑洞）。0 字节 + 无 `#` 行是**这个指令的直接后果**，配置本身完全正常。
2. **为什么会有 `.bash_hist.bak`**——这不是标准文件名，是**非默认位置的历史文件**。它在 03-18 09:41 有 1847 字节，与 `HISTFILE=/dev/null` 生效的时刻（22:44 之后）逻辑自洽：关闭历史前先做了备份，第二次登录（03-18 09:40）时又执行了 `echo 'HISTFILE=/dev/null' >> ~/.bashrc`——这条命令本身被记进了备份，因为写 `.bashrc` 的动作发生在 `HISTFILE` 重定向生效的边界上。

**这个"自证"结构是本案最值得写进报告的部分**：为隐藏历史而执行的 `echo` 命令，恰好留下了关闭历史这一行为的记录。

**按错误判据走的代价**：结论会变成"本机无有效命令历史证据"，从而**放弃命令序列这条攻击链**。

委托方会失去"22:44 下命令 → 22:47 安装完成 → 22:48 执行载荷"这条时间线，而这条序列是本案中直接说明**操作意图**的证据（装 netcat、给文件加 SUID、执行它）。

更实际的问题是：丢失这条链后，`/tmp/.kworkerd` 的存在会变成一个孤立的文件发现，**无法与登录事件建立因果联系**。

第二个易错点：把备份里 22:29 的 `ls -la /var/www` 当成"有人在入侵前就已潜伏"的证据。

正确判据是 `wtmp` 里 `deploy` 账户在 03-16 21:15 从 `198.51.100.23`（与攻击者 `203.0.113.77` 不同的来源 IP）有过合法登录。

同一账户的历史命令跨越多次会话，不能按"落在入侵窗口内"一刀切。 按错误判据走，会虚构出一个"提前 14 分钟就开始潜伏"的行为人，而实际上那只是一个正常运维会话的遗留命令。

---

<a id="section-40"></a>

### 5.2 HISTCONTROL ignorespace 造成的命令缺失与误读为证据销毁

**场景**

同系列主机 `app07`（Ubuntu 22.04），委托方要求还原某次"配置被误改"事件的操作过程，怀疑有人执行了破坏性命令。检材 `DigiForensics.dd`。

这条路径值得走，因为前一个案例里的 `HISTCONTROL=ignorespace` 在本机同样生效。它的效果是**让一批命令静默地不进入历史**。

这类"选择性缺失"比整体缺失更难发现，也更容易被误判成有人动了手脚。

**处置过程**

第 1 步，读取历史控制配置（**五个变量要一起看，不能只看 HISTFILE**）：

```bash
grep -nE '^\s*(export\s+)?(HISTSIZE|HISTFILESIZE|HISTCONTROL|HISTFILE|HISTIGNORE)=' /mnt/df/home/app/.bashrc
# :8:  export HISTSIZE=1000
# :9:  export HISTFILESIZE=2000
# :10: export HISTCONTROL=ignorespace        ← ★
# :11: export HISTFILE=/home/app/.bash_history
# :12: export HISTIGNORE=""
```

第 2 步，验证 `ignorespace` 的实际效果（**用一条带前导空格的命令做对照**）：

```bash
grep -cE '^ [^ ]' /mnt/df/home/app/.bash_history
# 0   ← ★ 历史中零条前导空格命令，与 ignorespace 完全自洽

wc -l /mnt/df/home/app/.bash_history
# 842 行，HISTSIZE=1000 未触发截断
```

第 3 步，与系统级证据对照，量化"应有但缺失"的命令：

```bash
grep -c 'session opened for user app' /mnt/df/var/log/auth.log
# 186 次会话；842 条命令 / 186 次 ≈ 4.5 条每次 → 属正常运维量级
```

第 4 步，定位本次委托的具体事件（**关键一步：找出系统日志有、历史没有的命令**）：

```bash
grep -iE 'sudo.*COMMAND=' /mnt/df/var/log/auth.log | grep -E 'systemctl|vim'
# Mar 22 14:02:11 app07 sudo:  app : COMMAND=/usr/bin/systemctl restart nginx
# Mar 22 14:07:44 app07 sudo:  app : COMMAND=/usr/bin/vim /etc/nginx/sites-enabled/default

grep -nE 'systemctl|nginx' /mnt/df/home/app/.bash_history
# 238:systemctl status nginx                                     ← 附近有 status
# 241:/usr/bin/vim /etc/nginx/sites-enabled/default              ← 14:07 那条在
# → ★ restart nginx 完全不在历史里，而 vim 那条在
```

第 5 步，验证缺失模式是"选择性"而非"整体"：

```bash
stat -c '%n mtime=%y size=%s' /mnt/df/home/app/.bash_history
# mtime=2024-03-22 18:02:11  size=20114
# mtime = 当天用户正常登出时刻，非事后编辑时刻

tail -3 /mnt/df/home/app/.bash_history
# 末行时间与 auth.log.1 轮转边界连贯，未见断口
```

**结论**

- 确认 `HISTCONTROL=ignorespace` 在本机生效（配置存在 + 历史中零条前导空格命令，双源）。其效果是：**任何以空格开头的命令在会话结束时不写入历史**。
- 因此历史文件对"重启服务""改配置"这类高危命令的记录是不完整的。本案中 `systemctl restart nginx`（14:02:11，auth.log 有 `sudo COMMAND=` 明确记录）**在历史中完全不存在**，而相邻的 `vim /etc/nginx/sites-enabled/default`（14:07:44）在历史里。这条差异不能解释为"没执行"——auth.log 才是权威记录。
- 事件完整过程需靠 `auth.log` 的 `sudo COMMAND=` 行 + 文件时间戳补齐：`/etc/nginx/sites-enabled/default` 的 mtime 应为 2024-03-22 14:07 左右，`/var/log/nginx/error.log` 可佐证重启时刻。**这构成"系统日志补命令历史"的分工。**
- 历史文件本身**未被清空**：mtime 是当天正常登出时刻、`HISTSIZE=1000` 未触发截断（842 < 1000）、末尾与轮转边界连贯。**所以缺失是选择性的，不是整体性的。**
- 对委托方问题的答复：「在 `/home/app/.bash_history`（842 行，覆盖至 2024-03-22 18:02）范围内，未发现执行 `systemctl restart nginx` 的记录；但该账户启用了 `HISTCONTROL=ignorespace`，历史对前导空格命令系统性缺失，因此"历史里没有"不等于"没有执行"。本次事件已由 `auth.log` 的 `sudo COMMAND=` 行确认。」

**误判对照**

本案最容易得出的错误结论是「`systemctl restart nginx` 明明在 auth.log 里以 `sudo COMMAND=` 出现了，但 `.bash_history` 里没有，说明有人事后删除了这条历史记录以掩盖痕迹——这是有意的证据销毁，应作为加重情节」。

正确判据是 `HISTCONTROL=ignorespace` 这个配置本身，三个要点：

1. **配置语义决定缺失是系统性的**。`ignorespace` 的含义是"忽略以空格开头的命令"——**不是删除某一条，而是所有前导空格命令一律不记录**。本案历史中 `grep -cE '^ [^ ]'` 得 **0**，与该配置完全自洽。若真是人为删除，删除者不会恰好只删掉"带前导空格执行的那批"而保留其余全部 842 条。
2. **缺失的分布特征可验证**。人为删除会在历史里留下**不连续或缺口痕迹**；`ignorespace` 造成的是**均匀的、符合操作习惯的缺失**——本案 842 条与 186 次会话的比例（4.5 条/次）完全正常，**无可辨识的删除痕迹**。
3. **mtime 排除了事后编辑**。历史文件 mtime 是 18:02:11（用户登出时刻）。若有人在 14:07 之后专门编辑该文件删记录，mtime 会晚于登出时刻。本案 mtime 与登出时刻一致，说明**文件在最后那个会话结束时被正常写入，此后未被触碰**。

**按错误判据走的代价**：把一个**配置导致的可解释缺失**定性为"有意的证据销毁"，会产生三重后果——① 法律定性错误，影响后续处置尺度；② 归因错误，怀疑一个实际上只是习惯用空格开头的用户；③ **分析方向被误导**：认定是人为删除，接下来就会去找"谁删的"，而真正的答案是"没人删，是 bash 配置决定的"，这个方向会无限发散却得不出结论。

第二个易错点：反过来把 ignorespace 当成"有利的取证条件"，声称可以依赖历史还原完整操作。

正确判据是它**削弱**而非增强历史：**凡是需要保密的操作，执行者往往会主动加前导空格**，因此在 `ignorespace` 开启的环境里，**恰恰是最该被记录的那批命令最容易缺失**。

必须用系统日志（`sudo COMMAND=`）与文件时间戳做双重兜底，不能把历史文件当唯一来源。

---

<a id="section-41"></a>

### 5.3 反例：zsh 与 fish 历史格式差异导致的漏读

**场景**

开发人员工作机 `dev07`（Linux 桌面环境），委托方要求还原某次数据库误删操作。检材 `DigiForensics.dd`。该机存在三个用户：`app` 用 bash、`ops` 用 zsh、`data` 用 fish。

这条路径值得写，因为三种 shell 的历史格式完全不同，漏读任何一个都会造成"该用户没有历史"的错误结论。

而这种错误来自解析失败，与"证据不存在"在报告上无法区分。

**处置过程**

第 1 步，先确定每个用户实际使用的 shell（不能靠 `ls` 找 `.bash_history` 猜）：

```bash
awk -F: '$3>=1000 && $3<65534 {print $1"\	"$7}' /mnt/df/etc/passwd
# app    /bin/bash
# ops    /usr/bin/zsh
# data   /usr/bin/fish
```

第 2 步，zsh 历史（格式：每行 `epoch:duration;command`，时间戳在行内）：

```bash
ls -l /mnt/df/home/ops/.zsh_history
# -rw-r--r-- 1 ops ops 8842 2024-03-22 17:41:03
head -3 /mnt/df/home/ops/.zsh_history
# 1711091200:0;cd /srv/app
# 1711091320:12;tail -f /var/log/app.log
# 1711091685:0;psql -U app -d prod -c 'DELETE FROM orders WHERE created_at < now() - interval '90 days';'
```

**zsh 格式与 bash 完全不同**：没有独立的 `#epoch` 行，`epoch:duration;command` 挤在一行。bash 的解析脚本会把它整体当成一条"以数字开头的普通命令"，时间丢失。

第 3 步，fish 历史（**`- cmd:` 前缀是时间戳启用标记**）：

```bash
ls -l /mnt/df/home/data/.local/share/fish/fish_history
head -4 /mnt/df/home/data/.local/share/fish/fish_history
# - cmd: sqlite3 /srv/data/orders.db
# - cmd: .backup orders.db backup/orders-0322.db
```

**注意路径**：`~/.local/share/fish/fish_history` **不在 home 根目录**，靠 `ls ~/*hist*` 极易漏查。

第 4 步，用 bash 的正则扫这三个文件，验证漏读确实会发生：

```bash
for f in /mnt/df/home/app/.bash_history /mnt/df/home/ops/.zsh_history \
         /mnt/df/home/data/.local/share/fish/fish_history; do
  printf '%-52s bash正则匹配=%-4s 总行数=%s\
' "$f" \
    "$(grep -cE '^#[0-9]{9,}$' "$f")" "$(wc -l < "$f")"
done
# /mnt/df/home/app/.bash_history            bash正则匹配=428  总行数=842   ← 正常
# /mnt/df/home/ops/.zsh_history             bash正则匹配=0    总行数=142   ← ★ 格式不同
# /mnt/df/home/data/.local/.../fish_history  bash正则匹配=0    总行数=88    ← ★ 格式不同
# → 用 bash 解析器扫后两个得到 0 匹配
```

第 5 步，按 zsh 格式正确解析并换算（`ops` 用户的误删操作）：

```bash
awk -F';' '{split($1,a,":"); print a[1]"\	"substr($0,index($0,";")+1)}' \
  /mnt/df/home/ops/.zsh_history \
  | while IFS=$'\	' read ep cmd; do
      printf '%s  %s\
' "$(date -u -r "$ep" '+%Y-%m-%dT%H:%M:%SZ')" "$cmd"
    done | grep -iE 'DELETE|psql'
# 2024-03-22T09:41:25Z  psql -U app -d prod -c 'DELETE FROM orders WHERE created_at < ...'
# ↑ UTC 09:41:25 = 本地 Asia/Shanghai 17:41:25，与文件 mtime 17:41:03 同分钟 ✓
```

第 6 步，交叉验证是否真执行（**命令历史不等于执行成功**）：

```bash
grep -iE 'DELETE' /mnt/df/var/log/postgresql/postgresql-16-main.log | tail -2
# 2024-03-22 17:41:25 UTC [1234] LOG:  statement: DELETE FROM orders WHERE created_at < ...
# 2024-03-22 17:41:25 UTC [1234] LOG:  duration: 88421.331 ms  statement: DELETE ...
# → ✓ 实际执行，耗时 88 秒

stat -c '%n mtime=%y size=%s' /mnt/df/srv/data/backup/orders-0322.db
# 2024-03-22 17:39:12  size=184320000
# → 备份早于删除操作 2 分 13 秒 → 存在可回滚点 ✓
```

**结论**

- 三用户三种 shell，历史格式各异，必须逐格式解析：`app`（bash，`#epoch` 独立行，428 条带时间戳）、`ops`（zsh，`epoch:duration;command` 单行，142 条**全部可用**）、`data`（fish，`- cmd:` 前缀，88 条**全部可用**）。
- 用 bash 的 `^#[0-9]{9,}$` 规则扫 zsh/fish 会得到 0 匹配，若据此写"`ops` 与 `data` 无带时间戳的历史记录"，则是**把解析失败误报为证据缺失**。
- 误删操作定案：`2024-03-22T09:41:25Z`（本地 17:41:25）`ops` 用户执行 `psql -U app -d prod -c 'DELETE FROM orders ...'`，PostgreSQL 日志以 `statement:` 与 `duration: 88421.331 ms` 独立印证实际执行，耗时 88 秒。命令的执行者取自 zsh 历史所属账户，不等于操作系统层面的登录身份，两者在多账户共用场景下需要另行确认。
- **存在可回滚点**：`/srv/data/backup/orders-0322.db` 的 mtime 是 17:39:12，**早于删除操作 2 分 13 秒**，据此可判断存在删除前的恢复点；是否可回滚仍需实际校验备份可读性与完整性。
- **方法学结论**：shell 判定必须来自 `/etc/passwd` 第 7 字段，不能靠找文件名。`data` 用户的 fish 历史在 `~/.local/share/fish/fish_history`，路径无明显线索且不在 home 根目录，极易漏查。

**误判对照**

本案最容易得出的错误结论是「`/home/ops/.zsh_history` 和 fish_history 用 `#<epoch>` 格式一条都匹配不到（匹配数 0），说明这两个 shell **没有启用时间戳功能**，其历史不含时间信息，无法用于时间线重建」。

正确判据是逐格式验证，而不是"一条没匹配上就判为无时间戳"。三个具体事实：

1. **zsh 的时间戳在行内而非独立行**。默认格式 `1711091685:0;command` ——**时间戳是命令行的前缀字段**。用 `^#[0-9]{9,}$` 这种锚定行首 `#` 的正则去扫，**结构上不可能匹配**。正确做法是按 `;` 分割后取前半段冒号前的数字。
2. **fish 用 `- cmd:` 前缀作时间戳标记**。这个前缀是 fish 的语法约定。看到 `- cmd:` 说明时间戳功能开启，**看到无 `-` 的 `cmd:` 才是未启用**。两种形态含义完全相反，不能笼统说"没有时间戳"。
3. `HISTSIZE`/`HISTFILE` 这类 bash 变量对 zsh 和 fish 无效。fish 用 `fish_history` 变量。在 bash 的 `.bashrc` 里找不到 `HISTTIMEFORMAT`，不代表该用户的历史没有时间——他根本不用 bash。

**按错误判据走的代价**：把两个用户的可用历史误判为"无时间信息"，数据库误删事件只剩 `data` 用户那条无时间戳的 `.backup` 命令，**整条时间线塌掉**。

委托方将无法确定误删的**精确时刻与执行者**，而这个时刻正是评估数据损失范围、判断"备份是否早于删除"的关键信息。

本案正是靠 `ops` 的 zsh 时间戳与备份文件 mtime 的先后关系，才确认了数据可回滚。 丢掉它，结论会从"可恢复"退化成"损失待评估"，可能触发不必要的数据重建流程。

第二个易错点：把 zsh 历史里带时间戳的记录直接当作执行证据。

正确判据是 zsh 的第二个字段 `duration`——本案 `1711091200:0;cd /srv/app` 的 duration 为 0。zsh 历史只记录"命令被输入并提交"，不记录执行成功。

真正的执行确认必须来自 `postgresql-16-main.log` 的 `statement:` 行——本案正是靠这一条把"输入过"升级为"确实执行了 88 秒"。

---
<a id="section-42"></a>

## 六、扩展阅读方向

<a id="section-43"></a>

### 前置基础：历史文件的定位与交叉验证都依赖它们

- [取证工件地图](../computer-persistence/computer-persistence-persistence-artifact-map.md) —— 账户体系与家目录结构。「`HISTFILE` 可被改写」意味着不能在默认路径找不到就收工，全盘检索的范围依据在这一篇。
- [系统日志深度分析](../computer-log/computer-log-system-log-analysis.md) —— 认证与提权日志的读取。**这是本篇 3.6 反伪造的独立时钟来源**，没有它，历史文件的可信度只能靠自身判断。
- [时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md) —— `#<epoch>` 与其它时间基准的换算。
- [proc 虚拟文件系统取证](computer-shell-proc.md) —— 同一主题下的另一面。历史文件记录输入，进程命令行记录的是实际在跑的东西，活系统上两者对不上的地方往往就是关键。

<a id="section-44"></a>

### 同层深入：行为证据的其它来源

- [时间线重建](../computer-log/computer-log-linux-timeline-reconstruction.md) —— 历史的顺序有意义、时间不可靠，**把两者放在一起才能用**：顺序直接采信，时刻靠旁证。
- [SSH 痕迹与密钥取证](../computer-persistence/computer-persistence-ssh.md) —— 给历史定锚的账户身份与登录时段。
- [计划任务与持久化痕迹](../computer-persistence/computer-persistence-scheduled-tasks-and-persistence.md) —— 历史里的 `crontab`、`systemctl` 命令与磁盘上的实际条目可以互相印证，**两者一致说明是真做了，不一致本身就是发现**。
- [包管理器与软件清单](../computer-persistence/computer-persistence-package-manager-and-software-inventory.md) —— 历史里的安装命令与包账本对照，**能确认命令是否真的执行成功**。

<a id="section-45"></a>

### 相邻议题：Windows 侧与 macOS 侧的对应机制

- [用户行为痕迹](../computer-registry-log/computer-registry-log-user-activity-artifacts.md) —— Windows 的 UserAssist。同样是「最近用过什么」的记录，但 Windows 侧的编码（ROT13）、容量上限（固定 7 项）与时间语义规则完全不同，对照看能看清两个平台的取舍。
- [Keychain 与 Safari 痕迹](../computer-security/computer-security-keychain-safari.md) —— macOS 的浏览与凭据痕迹，「用某应用做过的操作」在 macOS 上主要落在数据库而非 shell 历史。

<a id="section-46"></a>

### 工具与规范：操作边界

- [只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md) —— 读取历史文件前必须先确认接入方式。**读取本身会更新 atime**，虽然 atime 在现代 Linux 上不可信，纪律仍要遵守。
- [证据保管链与委托证明](../../fundamentals/fundamentals-chain/fundamentals-chain-chain-of-custody-and-authorization.md) —— 命令历史常包含口令、令牌等敏感输入，**摘录进报告时必须脱敏**。

<a id="section-47"></a>

### 判据与反例：如何证明历史被改过

- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— 往历史里**追加**命令与**整文件替换**在时间戳上表现不同，这个差异是识别伪造的判据之一。该篇的核心结论同样适用于本篇：单一来源内部的一致性只能给出「存疑」，要坐实必须引入独立时钟。
<a id="section-48"></a>

## 七、命令速查

```bash
# ===== 1. 定位用户与家目录 =====
awk -F: '$7 !~ /(nologin|false|sync)$/ {print $1"  home="$6"  shell="$7}' /mnt/df/etc/passwd
ls -la /mnt/df/home/*/.bash_history /mnt/df/home/*/.zsh_history /mnt/df/root/.*history 2>/dev/null

# ===== 2. 判定时间戳可用性 =====
cp --preserve=all /mnt/df/home/deploy/.bash_history /evidence/bash_history_deploy
grep -cE '^#[0-9]{9,}$' /evidence/bash_history_deploy     # 0 = 无时间戳
head -4 /evidence/bash_history_deploy

# ===== 3. 查 bash 控制变量（解释"为什么这样"）=====
grep -rnE 'HISTTIMEFORMAT|^\s*(export\s+)?(HISTSIZE|HISTFILESIZE|HISTCONTROL|HISTFILE|HISTIGNORE)=' \
  /mnt/df/etc/bash.bashrc /mnt/df/etc/profile /mnt/df/etc/profile.d/ \
  /mnt/df/home/*/.bashrc /mnt/df/home/*/.bash_profile /mnt/df/root/.bashrc 2>/dev/null
# 关注：HISTCONTROL=ignorespace（空格命令不记）/ HISTFILE=/dev/null（历史关闭）/ HISTSIZE=0（空）

# ===== 4. 全盘搜历史（HISTFILE 可改，必须全盘找）=====
find /mnt/df -xdev -type f \( -name '*hist*' -o -name '.*history*' \) \
  -printf '%TY-%Tm-%Td %TH:%TM %8s %p\
' 2>/dev/null | sort
grep -rlE '^(#1[0-9]{9}|: 1[0-9]{9}:)' /mnt/df/home /mnt/df/root /mnt/df/tmp /mnt/df/var/tmp 2>/dev/null

# ===== 5. 应用自有历史 + viminfo（最近打开文件）=====
find /mnt/df/home /mnt/df/root -maxdepth 2 -type f \
  \( -name '.*history' -o -name '.viminfo' -o -name '.lesshst' -o -name '.node_repl_history' \) \
  -printf '%TY-%Tm-%Td %u:%g %8s %p\
' 2>/dev/null | sort
grep -aE "^'?/|^[0-9]+:" /mnt/df/home/deploy/.viminfo 2>/dev/null | head   # viminfo 里的文件路径

# ===== 6. 解析带时间戳的 bash 历史（#epoch 一一对应）=====
python3 - <<'PY'
import re, datetime
cur=None
for line in open('/evidence/bash_history_deploy', encoding='utf-8', errors='replace'):
    m=re.match(r'^#(\d{9,})$', line.rstrip())
    if m: cur=datetime.datetime.fromtimestamp(int(m.group(1)),datetime.timezone.utc).isoformat()
    else: print(f"{cur or '[无时间戳]':26} {line.rstrip()}")
PY

# ===== 7. 解析 zsh 历史（: <epoch>:<num>;<cmd>）=====
python3 - <<'PY'
import datetime
for line in open('/evidence/zsh_history_deploy', encoding='utf-8', errors='replace'):
    line=line.rstrip()
    if line.startswith(': '):
        meta,_,cmd=line[2:].partition(';')
        ts=meta.split(':')[0]
        if ts.isdigit():
            print(datetime.datetime.fromtimestamp(int(ts),datetime.timezone.utc).isoformat(), cmd)
PY

# ===== 8. 与 auth.log 交叉验证（反伪造核心）=====
grep -iE 'Accepted.* for deploy |session (opened|closed) for user deploy' /evidence/auth-merged.txt
grep -inE 'curl|wget|nc |base64 -d|chmod \+s|chmod 4[0-9]{3}|HISTFILE=|history -c|/tmp/|/dev/shm' \
  /evidence/bash_history_deploy
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — Linux 取证 — Shell 痕迹与命令历史」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《Shell 痕迹与命令历史》（CC BY-SA 4.0）`

文中 `DigiForensics.dd` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
