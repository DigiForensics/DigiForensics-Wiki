---
title: "SSH 痕迹与密钥取证"
slug: "computer-persistence-ssh"
canonical: "https://www.digiforensics.cn/wiki/computer-persistence-ssh"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:49+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "computer"
space: "计算机取证"
node_path: ["持久化机制"]
---

# SSH 痕迹与密钥取证

<a id="section-1"></a>

## 一、概述

SSH 是 Linux 取证里通常优先分析的服务，原因有三条：互联网可达的 Linux 主机几乎必有 SSH 端口；它默认开启、默认留痕，成功、失败、会话建立与结束、连接断开**服务端每一条都有日志**；更关键的是，**认证方式直接对应身份**——日志里的 `Accepted publickey for <user> ... RSA SHA256:XXXX` 那个指纹，能直接对应到某个 `authorized_keys` 文件里的某一行。

日志中的公钥指纹可用于查找授权文件中的对应公钥。

但真正的问题出在痕迹的不对称上。`~/.ssh/authorized_keys` 里的陌生公钥**删起来很容易**，`/var/log/auth.log` 里的 `Accepted` 记录**清掉代价很高**。清空它需要 root，会在文件层面留下明显痕迹：文件大小骤减、`.1` / `.gz` 归档断档、rsyslog 配置被改。

所以要解决的核心判断是：「`authorized_keys` 里没有可疑公钥」完全不能推出「没人用过公钥登录」。 指纹在日志里，不在文件里。

这类证据属于**分析**环节中的「身份类证据」，它的位置特殊：**公钥指纹可用于双向核对**——从文件可以查到身份，从日志指纹可以反查文件行号，其它多数工件只单向记录。

**上游依赖**服务配置确认。`sshd_config` 及其 `conf.d` drop-in 决定端口、认证方式、是否允许 root 登录，这些直接决定日志里可能出现哪些事件类型，配置结构见[系统日志深度分析](../computer-log/computer-log-system-log-analysis.md)对日志落点的判定。

**下游支撑**三件事。确认的登录时段是[时间线重建](../computer-log/computer-log-linux-timeline-reconstruction.md)的输入时间窗；确认的公钥归属要靠[计划任务与持久化痕迹](computer-persistence-scheduled-tasks-and-persistence.md)核对同一账户的其他自动启动机制；私钥材料的固定与识别则是后续凭据分析的前提，**这里只做离线固定与格式识别，不做口令攻击**。

**动手前**要先清点 `/etc/ssh/` 下的配置文件是否完整——配置被改过本身就是发现。

三类痕迹的分工与生命周期完全不同：

| 类别 | 落点 | 关键结构 | 生命周期 |
|---|---|---|---|
| 服务端配置 | `/etc/ssh/sshd_config`、`/etc/ssh/sshd_config.d/*.conf` | `Port`、`PermitRootLogin`、`PubkeyAuthentication`、`AuthorizedKeysFile`、`AllowUsers` | 改配置要 root，**改完需 reload 才生效**，易被遗留 |
| 认证日志 | `/var/log/auth.log`（Debian 系）/ `/var/log/secure`（RHEL 系） | `Accepted password` / `Accepted publickey` / `Failed password` / `Invalid user` / `Disconnected from authenticating user` | 受 logrotate 保留期限制 |
| 用户侧目录 | `~/.ssh/authorized_keys`、`known_hosts`、`config`、`*.pub` | 公钥行格式为「类型 + base64 + 注释」；`known_hosts` 可能是含主机名的哈希形式 | **随时可删，删除不留日志** |
| 登录记账 | `/var/log/wtmp`（成功）、`/var/log/btmp`（失败）、`/run/utmp`（当前） | utmp 结构二进制 | `utmp` **重启即清空**，只反映当前运行期 |
| 私钥材料 | `~/.ssh/id_rsa`、`id_ed25519` 及 `.pub` | 新旧两代格式：OpenSSH 新格式带加密头，旧格式为 PEM 的 `Proc-Type` 头 | 私钥本身即高敏感证据 |

配套的两个判定细节：公钥指纹要按算法分别算（`SHA256:` 与 `MD5:` 两种前缀都可能出现），以及 `ControlMaster` 复用连接会让「一次登录对应多条会话记录」，影响计数判读。

答得出来的是：哪个账户在什么时间从什么地址以什么方式登录成功过、失败登录的聚集特征、某个公钥指纹对应哪些授权文件、登录会话的起止时刻与来源地址、服务端的认证策略与实际开放端口、以及**某个私钥文件属于哪个用户**。

答不出来的，以及两个必须先纠正的误读：

- 日志里的 `port <数字>` 是客户端临时源端口，不是服务端口。 `Accepted password for deploy from 203.0.113.77 port 40210` 里的 `40210` 落在 32768–60999 这个临时端口范围，服务端口在 `sshd_config` 的 `Port` 项（默认 22）。把两者当成一回事是硬伤级误读，会直接得出「服务跑在 40210」的错误结论。
- 「`authorized_keys` 无可疑条目」不能推出「未发生公钥登录」。 必须回到日志查 `Accepted publickey` 的历史与它记录的指纹。
- **会话期间执行了什么**。SSH 日志记认证与断开，不记命令内容。
- **私钥的口令**。这里识别格式并固定文件，**不做口令恢复**；若委托确有授权需要，恢复须遵循最小化与脱敏要求。
- **未落盘的会话**。`utmp` 重启即清空，跨越重启的登录记录只能靠 wtmp。
- **连接是否成功建立到应用层**。`Accepted` 只到认证通过，后面的失败（磁盘满、fork 失败）要靠 `Disconnected` 与 `session` 行的组合判断。

要读懂这套东西，得先理解 SSH 协议基础：公钥认证的挑战应答流程、私钥加密私钥与公钥的关系；熟悉 Linux 用户目录结构与权限规则，知道 `authorized_keys` 为什么必须 600 权限、属主必须是该用户；能读懂 syslog 格式的日志行，理解其无年份、无时区标记的缺陷，见[系统日志深度分析](../computer-log/computer-log-system-log-analysis.md)；

会处理二进制结构（utmp），至少知道 `last` / `lastb` 读的是什么文件；掌握公钥指纹的计算方式（`ssh-keygen -lf`），否则无法核对日志与文件中的公钥。

<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 三类痕迹的分工与生命周期

| 类别 | 位置 | 记录什么 | 生命周期 | 清除难度 |
|---|---|---|---|---|
| **服务端配置** | `/etc/ssh/sshd_config`、`/etc/ssh/sshd_config.d/*.conf` | 认证策略、端口、允许的用户/网段 | 改配置**不重连也生效**（多数配置项） | ★ 需 root |
| **认证日志** | `auth.log`（Debian）/ `secure`（RHEL）/ journal | 每次认证尝试与会话开闭 | logrotate 周期（数天–数周） | ★★★ 需 root 且留痕 |
| **用户侧文件** | `~/.ssh/`（`authorized_keys`、`known_hosts`、`config`） | 谁能免密登录、连过哪些主机、连接配置 | 长期 | ★★ 用户自己就能删 |
| **登录记账** | `utmp`（当前）/ `wtmp`（成功）/ `btmp`（失败） | 二进制会话记录 | utmp 重启清空；wtmp/btmp 长期 | ★★～★★★ |

> **重要机制**：`sshd_config` 的**大多数配置项在每次新建连接时读取**（不是只在守护进程启动时读一次），所以改 `PasswordAuthentication` 无需重启 sshd 就能生效。这意味着攻击者可以临时改配置开一个后门窗口，然后改回去——`mtime`/`ctime` 仍会留下痕迹。

<a id="section-4"></a>

### 2.2 `sshd_config`：取证必看的配置项

现代 OpenSSH 支持 `Include` 指令，Ubuntu 22.04 默认有：

```
Include /etc/ssh/sshd_config.d/*.conf
```

这意味着 `sshd_config` 本身可能不是真正的生效配置。

排查时必须把 `/etc/ssh/sshd_config.d/` 目录一起看——很多机器的端口/认证设置就在这些 drop-in 文件里。

| 配置项 | 默认 | 取证意义 |
|---|---|---|
| `Port <n>` | `22` | **真实服务端口**。非 22 说明可能改过端口（也可能是运维主动） |
| `PermitRootLogin` | `prohibit-password`（多数发行版） | **`yes` = 允许 root 密码登录** = 高危配置；`no` = 最安全 |
| `PasswordAuthentication` | `yes` | `no` = 只允许密钥登录，此时出现的密码登录尝试全为失败 |
| `PubkeyAuthentication` | `yes` | 关掉则公钥登录不可用 |
| `AllowUsers` / `AllowGroups` / `DenyUsers` | 空 | **白/黑名单**；非空说明该主机做过访问限制 |
| `ListenAddress` | `0.0.0.0` | 限制监听地址/端口 |
| `PermitEmptyPasswords` | `no` | `yes` = 允许空口令登录，**极度高危** |
| `X11Forwarding` | `yes`（部分） | `no` = 禁转发（加固） |
| `MaxAuthTries` | `6` | 单次连接允许的尝试次数，**影响爆破窗口大小** |
| `LogLevel` | `INFO` | `VERBOSE`/`DEBUG3` 会记录**公钥路径等更多细节** |

> ⚠️ **`Include` 是取证陷阱。** 只 `cat /etc/ssh/sshd_config` 会漏掉 drop-in 里的实际配置。先读 `Include` 行，再逐个读被包含的文件。
>
> ⚠️ **匹配规则**：OpenSSH 对多数列表型指令采用**"首次出现即生效"**原则（first obtained value wins），所以 `Include` 放在文件开头还是结尾会改变最终生效值。**这是配置矛盾时的分析要点。**

<a id="section-5"></a>

### 2.3 认证日志：关键事件与指纹

`auth.log`（Debian）/ `secure`（RHEL）里 SSH 相关事件，详见[第 02 篇](../computer-log/computer-log-system-log-analysis.md)的总表。

本篇聚焦**能相互核对的记录**：

| 事件 | 格式要点 | 取证价值 |
|---|---|---|
| **公钥登录成功** | `Accepted publickey for <user> from <ip> port <pt> ssh2: RSA SHA256:<fingerprint>` | ★ 指纹可与 `authorized_keys` 里的公钥一一对应 |
| **密码登录成功** | `Accepted password for <user> from <ip> port <pt> ssh2` | 成功入侵的直接证据 |
| **密码失败** | `Failed password for [invalid user ]<user> from <ip> port <pt> ssh2` | 爆破；带 `invalid user` = 在猜用户名 |
| **无效用户** | `Invalid user <user> from <ip> port <pt>` | 扫描器行为 |
| **会话建立/关闭** | `session opened for user <user> by (uid=0)` / `session closed` | 会话窗口锚点 |
| **预认证断开** | `Disconnected from authenticating user <user> <ip> port <pt> [preauth]` | 扫描器探测后主动断开；**大量出现 = 端口扫描** |
| **正常断开** | `Connection closed by authenticating user <user> <ip> port <pt> [preauth]` | 同上 |
| **连接关闭** | `Connection closed by <user> <ip> port <pt>` | 会话正常结束 |
| **密钥协商失败** | `error: maximum authentication attempts exceeded for <user> from <ip> port <pt>` | 撞了 `MaxAuthTries` |

**公钥指纹字段是本篇的重点**。

`ssh2: RSA SHA256:xxxx` 中的 `SHA256:xxxx` 是**公钥的 SHA256 指纹**（base64），可以直接与 `authorized_keys` 文件里各行的指纹对应：

```bash
# 取某公钥的 SHA256 指纹
ssh-keygen -lf ~/.ssh/authorized_keys
# 256 SHA256:7Kx9mNpVqRtYwZaBcDeFgHiJkLmNoPqRsTuVwXyZ0 deploy@attacker (ED25519)
# ↑ 指纹              ↑ 与 auth.log 里 Accepted publickey 后的指纹完全对应
```

> **核对方法**：这是 Linux 取证里少见的"**日志中的指纹 → 磁盘上具体某一行公钥**"的直接映射。看到 `Accepted publickey` 就必须把指纹抄下来，到所有 `authorized_keys` 里逐一比对（格式与算法差异见陷阱 13）。

<a id="section-6"></a>

### 2.4 `~/.ssh/` 目录：文件与权限规则

| 文件 | 作用 | 取证价值 |
|---|---|---|
| `authorized_keys` | **允许免密登录本账户的公钥** | ★★★★★ **后门植入的经典位置** |
| `known_hosts` | 本机连过的远端主机及其主机密钥 | ★★★★ 反向线索：从内网连到过哪些主机 |
| `config` | 本机 SSH 客户端配置（`-i` 私钥、`ProxyJump`、`ControlMaster`） | ★★★★ **含私钥路径与跳板配置** |
| `id_rsa` / `id_ed25519` / `id_ecdsa` | **私钥** | ★★★★★ 高价值材料 |
| `id_rsa.pub` 等 | 对应公钥 | ★★ |
| `authorized_keys2` | 旧版 sshd 的备用文件 | ★★ 多数现代 sshd 已不读，但**存在本身值得记录** |
| `.ssh/` 目录权限 | **必须 700** | 权限不对会被 sshd 忽略 |

> ⚠️ **权限硬规则（常被误判为"配置错误"）**：`authorized_keys` **权限必须是 600**（`chmod 600`），`.ssh/` 目录**必须是 700**。若 `authorized_keys` 权限过宽（如 644），**sshd 会直接忽略该文件、拒绝所有公钥登录**（严格模式下会拒绝）。
>
> **取证含义**：**这既是"陷阱"也是"证据"**。攻击者植入 `authorized_keys` 后如果忘了 `chmod 600`，会**导致该公钥实际不生效**——此时 `authorized_keys` 文件**存在但从未被成功使用过**。

判断方法：查 auth.log 里是否真有与该指纹对应的 `Accepted publickey`。**文件存在 ≠ 生效过。**

> ⚠️ `authorized_keys` 还可被用于维持权限：文件末尾行、支持 `command="..."`、`from="..."`、禁用 PTY 等**选项前缀**。这些选项**不写进日志**，只能从文件内容发现。

<a id="section-7"></a>

### 2.5 登录记账三库：utmp / wtmp / btmp

Linux 把登录记录放在三个**二进制**数据库文件里（不是文本，`grep` 无效）：
| 文件 | 记录 | 读取工具 | 生命周期 |
|---|---|---|---|
| **`/var/run/utmp`** | **当前在线会话** | `who` / `w` | **★ 重启即清空**（tmpfs 或重建） |
| **`/var/log/wtmp`** | **成功登录历史** | `last` | 长期（`lastlog` 是其中每用户一条最近记录） |
| **`/var/log/btmp`** | **失败登录历史** | `lastb` / `last -f` | 长期 |
| `/var/log/lastlog` | 每用户**最近一次**登录 | `lastlog` | 长期 |

**三者互补的证据能力**：

| 问题 | 唯一能回答的库 |
|---|---|
| "这台机器**现在**有谁在线？" | `utmp`（且**仅在运行中有效**，断电机器的 utmp 是空的） |
| "过去 30 天谁成功登录过？从哪台机器？" | **`wtmp`**（`last`） |
| "过去 30 天有哪些登录失败尝试？" | **`btmp`**（`lastb`） |
| "用户 X 最后一次登录是什么时候？" | `lastlog` |

> ⚠️ **`/var/run/utmp` 不是历史记录。** 它只描述"当前在线"，**重启/断电后内容全部消失**。很多分析误把 utmp 当"登录历史"。**登录历史必须看 `wtmp`。**
>
> ⚠️ `last` 的输出有"仍在登录"（`still logged in`）的记录，这表示**会话从未被正常关闭**（崩溃、断电、或 wtmp 条目未更新）。**这本身是一个信号**，尤其与机器的断电状态吻合时。

**离线读法**：`last -f <文件>` 可指定文件，不必运行在原机器上。

```bash
last -f /mnt/df/var/log/wtmp              # 成功登录历史
lastb -f /mnt/df/var/log/btmp             # 失败登录历史（等价 last -f btmp）
lastlog -f /mnt/df/var/log/lastlog        # 每用户最近登录
who -a                                    # 需原机器运行态，离线无意义
```

> **`lastlog` 的格式注意**：部分系统上 `lastlog` 是**稀疏文件**（`/var/log/lastlog` 可能占用几十 MB 但内容很少），用 `icat` 导出时**会补零成完整声明大小**。参考[第 01 篇](computer-persistence-persistence-artifact-map.md)对稀疏流的处理提示。

<a id="section-8"></a>

### 2.6 SSH 连接复用：`ControlMaster` 及其取证意义

**OpenSSH 的连接复用机制**：`ControlMaster auto` + `ControlPath` 会让第一次连接建立的 TCP 连接被后续所有同目标连接复用，且第一次认证成功后，会在 socket 文件里缓存认证结果，后续连接无需重新认证。

```bash
# ~/.ssh/config 里的典型配置
Host bastion
  HostName bastion.example.com
  User deploy
  ControlMaster auto
  ControlPath ~/.ssh/cm-%r@%h:%p
  ControlPersist 10m
```

**取证意义**：

1. **一次认证，多条会话**。auth.log 里可能只有 **1 条** `Accepted`，但实际发生了 **10 次**会话活动（复用通道）。不能用 `Accepted` 计数来统计活动次数。
2. **连接复用的审计盲区**。后续复用连接**不再产生新的认证日志**，可能也不产生新的 `session opened` 记录（取决于 `sshd` 版本与配置）。**这是 SSH 取证的一个真实盲区。**
3. **`ControlPath` 指向的文件本身是痕迹**：`~/.ssh/cm-<user>@<host>:<port>` 这样的 socket 文件如果还在（未正常清理），**说明该复用通道未正常结束**。

注意 socket 文件通常在关机/退出后消失，断电机器上基本不留。

> **`ControlPersist` 的取值也有意义**：`ControlPersist 10m` 表示认证缓存 10 分钟；`ControlPersist yes` 则是无限期（直到会话结束）。**`yes` 意味着认证凭据被长期缓存在内存中**，是加固审计时值得关注的一项。

<a id="section-9"></a>

### 2.7 私钥格式：新旧两代

**识别私钥类型只需看第一行 PEM 头**：

| 首行 | 格式 | 特征 |
|---|---|---|
| `-----BEGIN OPENSSH PRIVATE KEY-----` | **OpenSSH 新格式**（7.8+ 默认生成） | 单一容器，内含私钥 + **公钥 + 注释**；`ssh-keygen -i -m pem` 可转旧格式 |
| `-----BEGIN RSA PRIVATE KEY-----` | **PKCS#1 / 传统 PEM** | 旧格式；OpenSSH 新版默认不再生成，但仍完全接受 |
| `-----BEGIN DSA PRIVATE KEY-----` / `-----BEGIN EC PRIVATE KEY-----` | 对应旧格式 | 同上 |
| `-----BEGIN ENCRYPTED PRIVATE KEY-----` | **PKCS#8 加密格式** | 常用于其它工具，**sshd 不接受**这种格式做 `IdentityFile` |

> ⚠️ `OPENSSH PRIVATE KEY` 头既不代表"加密"也不代表"未加密"。 OpenSSH 新格式是一种**容器格式**，是否受口令保护取决于**生成时是否设置了 passphrase**（`ssh-keygen` 会交互询问，用户可直接回车留空）。旧 PEM 格式同理。判断是否加密必须看容器内部字段 / 实测验证，绝不能仅凭 PEM 头下结论。

**取证要点**：

- **是否带口令与格式新旧无关**，只取决于生成时是否设置 passphrase。`ssh-keygen` 交互提示可直接回车留空，因此**新格式私钥同样可能是无口令的**。
- **实测验证（不修改原文件）**：`ssh-keygen -y -P "" -f <key>` —— 能输出公钥即**无口令保护**，报 `incorrect passphrase` 即**有口令保护**。
- 私钥文件权限应为 600；权限过宽时 ssh 客户端会拒绝使用。
- 私钥文件的 `mtime`/`ctime` 说明它何时生成或被改动，可与 `authorized_keys` 的时间对照，判断是"私钥与公钥同时植入"还是"先后两次动作"。

---

<a id="section-10"></a>

## 三、操作步骤

<a id="section-11"></a>

### 3.1 第 1 步：确认 SSH 服务配置（含 drop-in）

```bash
# 1. 确认主配置里有没有 Include（现代 OpenSSH 默认有）
grep -nE '^\s*Include' /mnt/df/etc/ssh/sshd_config

# 2. 列出 drop-in 目录内容
ls -la /mnt/df/etc/ssh/sshd_config.d/ 2>/dev/null
# 若为空（不存在该目录）→ 只看主配置；若非空 → 必须逐个读

# 3. 提取关键项（主配置 + 所有 drop-in，注意"首次出现生效"）
for f in /mnt/df/etc/ssh/sshd_config /mnt/df/etc/ssh/sshd_config.d/*.conf; do
  [ -f "$f" ] || continue
  echo "== $f =="
  grep -nE '^\s*(Port|ListenAddress|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AllowUsers|AllowGroups|DenyUsers|PermitEmptyPasswords|MaxAuthTries|LogLevel|AuthorizedKeysFile)\b' "$f"
done
```

| 配置组合 | 取证判读 |
|---|---|
| `PermitRootLogin yes` | **允许 root 密码直接登录**——高危；若日志有 `Accepted password for root`，直接定性 |
| `PasswordAuthentication no` | 只允许密钥登录；此时所有 `Failed password` 都是无效尝试（因为密码认证根本不会走） |
| `PermitEmptyPasswords yes` | **极度高危**；配合空口令账户 = 免密登录 |
| `AuthorizedKeysFile` 非默认 | 授权公钥读的是**别的路径**（`.ssh/authorized_keys` 里的内容可能根本没用） |
| drop-in 里有 `Port 2222` | 真实服务端口；与日志中的 `port` 字段**无关** |

<a id="section-12"></a>

### 3.2 第 2 步：授权公钥全面清点与指纹比对（本篇核心）

```bash
# 1. 找出所有 authorized_keys（root + 所有用户 + 可能的自定义路径）
find /mnt/df -xdev -type f -name 'authorized_keys*' \
  -printf '%m %u:%g %TY-%Tm-%Td %TH:%TM  %p\
' 2>/dev/null | sort

# 2. 逐个看内容与权限（权限必须 600，.ssh 必须 700）
for f in $(find /mnt/df -xdev -type f -name 'authorized_keys' 2>/dev/null); do
  echo "===== $f ====="
  stat -c '  mode=%a  owner=%U:%G  mtime=%y  ctime=%z' "$f"
  # 取每行的 SHA256 指纹（用于和 auth.log 比对）
  ssh-keygen -lf "$f" 2>/dev/null || echo "  (ssh-keygen 解析失败，可能格式异常)"
done

# 3. 目录权限检查（.ssh 必须 700）
find /mnt/df -xdev -type d -name '.ssh' -printf '%m %u:%g %p\
' 2>/dev/null

# 4. 从 auth.log 提取所有公钥登录成功记录里的指纹
grep -oE 'Accepted publickey for [^ ]+ from [^ ]+ port [0-9]+ ssh2: \S+ SHA256:[A-Za-z0-9+/=]+' \
  /evidence/auth-merged.txt | grep -oE 'SHA256:[A-Za-z0-9+/=]+' | sort | uniq -c
```

**交叉比对表**（手工核对，或用脚本）：

| auth.log 指纹 | `authorized_keys` 指纹 | 文件路径 | 权限 = 600 | 结论 |
|---|---|---|---|---|
| `SHA256:7Kx9...` | `SHA256:7Kx9...` | `/home/deploy/.ssh/authorized_keys` | 是 | **该公钥被实际使用过登录** ★（指纹+日志双源印证） |
| 无对应 | `SHA256:3nQ8...` | `/root/.ssh/authorized_keys` | 是 | 文件存在但**未见成功登录**（未使用 / 已轮转 / 痕迹已清） |
| `SHA256:7Kx9...` | `SHA256:7Kx9...` | `/home/svc-backup/.ssh/authorized_keys` | **否（644）** | **规则与日志矛盾**：权限过宽时 sshd 会拒绝该文件，故登录必发生在被 `chmod` 之前；须比对 `mtime` 与首次使用时间 |

<a id="section-13"></a>

### 3.3 第 3 步：`known_hosts` 与 `config` 分析

```bash
# known_hosts：本机曾连到过哪些远端主机
# 格式：<主机名/IP> <密钥类型> <公钥>   （旧版可能含明文主机名）
cat /mnt/df/root/.ssh/known_hosts 2>/dev/null | cut -d' ' -f1 | sort -u | head -40

# hashed 形式（现代默认，无法直接读出主机名）——只显示哈希
head -3 /mnt/df/root/.ssh/known_hosts
# |1|xxxxxxxxxxxxxx= ssh-ed25519 AAAA...    ← hashed，域名不可直接读

# config：私钥路径 / 跳板 / 连接复用
cat /mnt/df/root/.ssh/config /mnt/df/home/*/.ssh/config 2>/dev/null
```

| `config` 字段 | 取证意义 |
|---|---|
| `HostName` / `User` | 该别名实际连向哪台机器、用哪个账户 |
| `IdentityFile` | **使用的私钥路径**（→ 定位私钥文件） |
| `ProxyJump` | **跳板链**（→ 内网横向移动的路径图） |
| `ControlMaster` / `ControlPath` / `ControlPersist` | 连接复用设置（见 2.6） |
| `StrictHostKeyChecking no` | 禁主机密钥校验（自动化脚本常见） |

<a id="section-14"></a>

### 3.4 第 4 步：登录记账三库离线读取

```bash
# wtmp：成功登录历史
last -f /mnt/df/var/log/wtmp | head -30
# 关注：登录源 IP、终端（pts/N）、时长、以及 "still logged in"（会话异常中断）

# btmp：失败登录历史
lastb -f /mnt/df/var/log/btmp | head -30
# 关注：同一源 IP 反复失败 + 伴随"随后成功" = 爆破得逞

# lastlog：每用户最近登录
lastlog -f /mnt/df/var/log/lastlog 2>/dev/null | head

# utmp：仅在原机器运行时有效；离线镜像的 utmp 通常为空（重启已清）
# 若镜像是运行中抓取的（在线），才可读：
# last -f /mnt/df/var/run/utmp
```

**`last` 输出的关键字段解读**：

```
deploy   pts/0        203.0.113.77   Sat Mar 17 22:43   still logged in
│        │            │              │                 └─ 会话未正常结束（崩溃/断电/未更新）
│        │            │              └─ 开始时间
│        │            └─ 源 IP（可能为 :0 或空 = 本地 tty 登录）
│        └─ 伪终端（pts/N；tty1/2 = 物理终端/图形登录）
└─ 用户名
```

| 观察 | 取证含义 |
|---|---|
| 大量 `still logged in` | 会话记录未正常收尾，通常是**未正常关机/断电**——与机器状态吻合 |
| `lastb` 中同一 IP 密集失败后出现同 IP 成功 | **爆破成功序列** |
| `wtmp` 中无某次 `Accepted` 记录的会话 | 记账被 `utmp`/`wtmp` 截断或为 root 直接 su 的会话（su 不走 sshd） |

<a id="section-15"></a>

### 3.5 第 5 步：私钥材料识别与固定

```bash
# 1. 列出所有疑似私钥文件
find /mnt/df -xdev -type f \( -name 'id_*' -o -name '*.pem' -o -name '*.key' \) \
  -not -name '*.pub' -printf '%m %u:%g %TY-%Tm-%Td  %p\
' 2>/dev/null | sort

# 2. 判定私钥格式（看首行）
for f in $(find /mnt/df/root/.ssh /mnt/df/home/*/.ssh -type f -not -name '*.pub' 2>/dev/null); do
  echo -n "$f → "; head -1 "$f" 2>/dev/null
done
# -----BEGIN OPENSSH PRIVATE KEY-----   → OpenSSH 新格式容器（7.8+ 默认生成）
# -----BEGIN RSA PRIVATE KEY-----       → 旧 PKCS#1 PEM
# 注意：两种格式都可能带/不带口令，格式头不决定加密与否

# 3. 实测是否加密（不修改原文件）
ssh-keygen -y -P "" -f /evidence/extracted_key 2>&1 | head -1
# 若输出公钥 → 无口令保护；若报 "incorrect passphrase" → 有口令保护

# 4. 记录哈希（固定证据，不改动原文件）
sha256sum /evidence/extracted_key | tee -a /evidence/hashes.txt
```

> ⚠️ 不要对原始镜像里的私钥直接用 `ssh-keygen` 试口令——它可能修改文件（`-y` 一般不改，但仍应**先复制到证据目录**再操作）。

<a id="section-16"></a>

### 3.6 验证环节

| 验证对象 | 方法 | 通过标准 |
|---|---|---|
| SSH 配置生效值 | 读 `Include` 链 + 全部 drop-in | 目标项有唯一明确取值；矛盾处说明原因 |
| 公钥指纹核对 | `ssh-keygen -lf` 结果 vs auth.log 指纹 | 二者一致 = 强关联；不一致 = 区分"未用/未生效" |
| `authorized_keys` 权限 | `stat` 的 `%a` | 600；非 600 需在报告说明"该文件可能未生效" |
| 登录历史 | `last`/`lastb` vs auth.log | 登录时间、源 IP 互相对应 |
| 私钥格式 | 首行 + 内部 cipher 字段 | 与"OpenSSH 新旧"判定一致 |

---
<a id="section-17"></a>

## 四、常见陷阱

本章按**公钥指纹核对 → 登录记账 → 结论表述**归组，每条给出：现象、为什么会误判、误判代价、正确做法。
★ 标记表示该操作会导致原始检材永久灭失或不可逆改变，执行前必须停下来确认。

<a id="section-18"></a>

### 4.1 公钥指纹核对

<a id="section-19"></a>

#### 陷阱 1：只读 `sshd_config` 主文件就下结论

**现象**：`grep` 主配置得到 `PasswordAuthentication yes`，报告写「该主机允许密码登录」；而实际的 `60-cloudimg-settings.conf` 里有一条 `PasswordAuthentication no`（云镜像模板自带），并因"首次出现即生效"规则而优先。

**原因**：现代 OpenSSH 支持 `Include` 指令，`sshd_config` 本身可能不是最终生效配置。 Ubuntu/Debian 默认在文件开头就有 `Include /etc/ssh/sshd_config.d/*.conf`，真正的端口、认证设置常在这些 drop-in 里。更隐蔽的是取值优先级：OpenSSH 对多数列表型指令采用 first obtained value wins（首次出现即生效），所以同一项在主配置和 drop-in 里各出现一次时，哪一条生效取决于 `Include` 的位置，而不是文件名的字母序。

**影响**：这条错误会连锁放大。案例第 1 步的 `AllowUsers ubuntu deploy`（白名单）是缩小嫌疑范围的关键依据——如果这个值实际被 drop-in 里的另一条覆盖了，那么"只有这两个用户能登录"的前提就不成立，"Invalid user 记录都是被白名单拒绝的"这层解释也随之崩塌。

**核查**：先确认 `Include` 链，再把所有参与的文件按**实际解析顺序**一起读：

```bash
grep -nE '^\s*Include' /mnt/df/etc/ssh/sshd_config
for f in /mnt/df/etc/ssh/sshd_config /mnt/df/etc/ssh/sshd_config.d/*.conf; do
  [ -f "$f" ] || continue
  echo "== $f =="
  grep -nE '^\s*(Port|ListenAddress|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AllowUsers|AllowGroups|DenyUsers|PermitEmptyPasswords|MaxAuthTries|LogLevel|AuthorizedKeysFile)\b' "$f"
done
```

同一配置项在多处出现且取值冲突时，这就是分析要点本身——必须写明最终生效值及其决定因素（Include 位置 + first-wins）。

<a id="section-20"></a>

#### 陷阱 2：把 `authorized_keys` 存在当作"后门可用"

**现象**：在 `/root/.ssh/authorized_keys` 里发现一把公钥，报告直接写「攻击者已植入 root 后门，可随时登录」。

**原因**：**文件存在与文件生效之间隔着至少三道门**：① **权限**——`authorized_keys` 必须 600、`.ssh` 目录必须 700，过宽时 sshd 会忽略该文件、拒绝所有公钥登录；② **路径**——`AuthorizedKeysFile` 若被改成别的路径，`.ssh/authorized_keys` 里的内容根本没被读；③ **使用**——该公钥对应的指纹在 auth.log 里是否出现过 `Accepted publickey`。案例里 `/home/svc-backup/.ssh/authorized_keys` 正是权限 644 的例子，其指纹在 auth.log 里确实出现过，这构成了一个必须解释的矛盾：登录必发生在被 `chmod` 之前。

**影响**：把"文件在"当成"后门可用"，会让委托方把清理优先级排错。

真正可用的是那个权限正确且与日志指纹匹配的文件，而权限错误的那个文件可能从未生效过。

**核查**：三道门逐一过，并把交叉比对表（3.2 节）整张放进报告，每行给出结论：

| 情况 | 结论表述 |
|---|---|
| 权限 600 + 指纹在 auth.log 出现 | 该公钥**被实际使用过**（指纹 + 日志双源印证） |
| 权限 600 + 指纹从未出现 | 文件存在，**未见使用痕迹**（未使用/已轮换/痕迹已清，三种可能不可区分） |
| 权限非 600 + 指纹出现过 | 规则与日志**矛盾**：须比对 `mtime` 与首次使用时间，推断后续是否被 `chmod` |
| 权限非 600 + 指纹未出现 | 该文件**很可能从未生效**（sshd 忽略） |

<a id="section-21"></a>

#### 陷阱 3：把 auth.log 里没匹配到指纹就直接说"无 SSH 后门"

**现象**：提取全部 `Accepted publickey` 的指纹，与所有 `authorized_keys` 逐一比对，没有未匹配的项，于是结论写「未发现 SSH 公钥后门」。

**原因**：**"日志里没有"有多种成因，而它们不等价**：① 后门从未被使用（植入后未再登录，文件还在但无记录）；② 记录已被清理（auth.log 被截断/轮转掉了对应时段）；③ 后门使用的是密码而非公钥；④ 日志本身缺失（journal 只在内存、rsyslog 被改到 `/dev/null`）；⑤ 登录发生在 `LogLevel` 较低的配置下、`Accepted publickey` 行根本没记全（`LogLevel` 不是 `VERBOSE`/`DEBUG` 时，公钥指纹可能不完整）。**第⑤条尤其容易被忽略**——案例里 `Accepted publickey ... ssh2: ED25519 SHA256:9kPq...` 有指纹，是因为该机日志级别足够。

**影响**：这是代价最高的阴性结论。它会直接导致"主机不存在未授权访问"这一全局结论，而该结论是后续所有排除推理的地基。

**核查**：阴性结论要分层。写成：「在现有日志覆盖范围内，未发现 `Accepted publickey` 指纹与 `authorized_keys` 条目的未匹配项。该结论受限于：① 检材断电，journal 可能仅存于内存；② auth.log 轮转仅保留 N 个周期，更早记录不可得；③ `LogLevel` 为 `INFO`，公钥指纹字段可能不完整。」同时必须单独做**文件侧的正向清点**——把全盘所有 `authorized_keys`（含 `authorized_keys2`、自定义 `AuthorizedKeysFile` 路径）列出来，逐个给结论，阴性发现的价值在于"清点完整"而不是"没找到东西"。

<a id="section-22"></a>

#### 陷阱 4：把 `authorized_keys` 的选项前缀当成普通公钥行忽略掉

**现象**：`/root/.ssh/authorized_keys` 里三行公钥，报告只提取了指纹做比对，完全没提第一行有 `command="..."` 前缀。

**原因**：`authorized_keys` 的每一行可以带选项前缀：`command="..."`（强制执行固定命令，忽略用户请求）、`from="..."`（限制来源地址）、`no-pty`、`no-agent-forwarding`、`no-port-forwarding`、末尾注释。这些前缀**不写进任何日志**——auth.log 只会记 `Accepted publickey for <user> from <ip>`，看起来与普通公钥登录完全一样。但语义上它可能是一个**只能执行单条固定命令的受限入口**，甚至是一个把每次连接都转成命令执行的后门。

**影响**：漏掉 `command=` 前缀意味着你把一个"每次登录自动执行某命令"的后门，读成了一把"等待被人使用的钥匙"。

两者的风险模型完全不同。

**核查**：读 `authorized_keys` **全文**，不只提取指纹。对每一行标注：有无选项前缀、具体是什么、从 `"` 字段的取值能推出什么行为。`from="..."` 还能反向指出**攻击者的来源网段**（`known_hosts` 说不出这个方向）。

<a id="section-23"></a>

### 4.2 登录记账

<a id="section-24"></a>

#### 陷阱 5：★ 在分析机上直接跑 `last`（不指定 `-f`）

**现象**：执行 `last` 想看"最近谁登录过"，输出的是分析机自己的登录记录；或执行 `lastb` 直接读本机 btmp。报告里引用了这批输出。

**原因**：`last` 默认读的是本机的 `/var/log/wtmp`，不是检材的。你看到的每一行都是取证分析机自己的运维登录，与检材毫无关系。这类错误特别隐蔽，因为输出格式完全正常、有用户有时间有来源 IP，看起来像一份有效证据。

**影响**：把分析机的登录记录写进检材的时间线，是最典型的"污染证据"——不是污染了检材本身，而是污染了结论。

对方一旦发现报告里的登录 IP 是取证单位的出口 IP，整份报告的可信度直接崩塌。

**核查**：离线分析**必须**用 `-f` 指定镜像内的文件：

```bash
last  -f /mnt/df/var/log/wtmp      # 成功登录历史
lastb -f /mnt/df/var/log/btmp     # 失败登录历史
lastlog -f /mnt/df/var/log/lastlog
```

`-f` 参数不出现就是错的。若工具不支持 `-f`，把文件复制到隔离目录后用 chroot/容器方式读取，**绝不在分析机环境里直接跑**。

<a id="section-25"></a>

#### 陷阱 6：把 `utmp` 当登录历史

**现象**：镜像里 `/var/run/utmp` 解析出来几乎为空，报告写「该主机无登录历史记录」。

**原因**：**`utmp` 只描述"当前在线会话"，不是历史。** 它位于 `/var/run/`（tmpfs），**重启或断电后内容全部消失**——案例里的机器正是强制断电状态，`utmp` 必然是空的，这是**设计如此**，不是证据缺失。三个库的分工在 2.5 写得很清楚：`utmp` 答"现在有谁在线"（且只在运行中有效）、`wtmp` 答"过去谁成功登录过"、`btmp` 答"过去有哪些失败尝试"。

**影响**：空 `utmp` 被读成"无登录历史"，会让整个登录调查失去基础。

而正确结论是"当前在线状态不可得（断电）"，这两句话指向完全不同的调查方向。

**核查**：登录历史**只能看 `wtmp`**（`last -f`），失败尝试看 `btmp`。`utmp` 在断电检材上只能记为"该文件为易失存储，检材状态下无有效内容"，作为一条明确的证据局限而不是一条发现。

<a id="section-26"></a>

#### 陷阱 7：把 `wtmp`/`btmp` 当文本用 grep 搜

**现象**：对 `/var/log/wtmp` 执行 `grep 203.0.113`，无输出，于是写「wtmp 中无该 IP 的记录」。

**原因**：utmp/wtmp/btmp/lastlog 全都是二进制定长记录格式，不是行式文本。IP 与用户名以定长字段（含 NUL 填充）存放，grep 依赖的换行符根本不存在，输出为空是必然的。分析者看到"grep 无结果"时，天然会理解成"里面没有"，而实际是"工具不适用"。

**影响**：工具静默失败 + "无输出即无内容"的直觉 = 假阴性。报告里"wtmp 中未见该源 IP"这句话在质证时会被对方用一条 `last -f` 输出推翻。

**核查**：用对应的读取工具离线读（`last`/`lastb`/`lastlog` 配 `-f`），或用专门的 utmp 解析库。任何"某二进制库里没有"的结论，都必须先确认解析器适用。`lastlog` 另有一点：它是**稀疏文件**，`icat` 导出时会补零成完整声明大小（可能几十 MB），不要把补零区当成解析失败。

<a id="section-27"></a>

#### 陷阱 8：把 `known_hosts` 里的 IP 当成攻击源

**现象**：`/root/.ssh/known_hosts` 里有 `10.20.30.40`，报告写「攻击者从 10.20.30.40 发起攻击」。

**原因**：`known_hosts` 的方向与攻击来源方向相反。 它记录的是"**本机作为客户端连出去过哪些远端主机**及其主机密钥"——是本机 → 目标的连线记录。把它当成入站来源，等于把"这台机器访问过内网某处"读成"内网某处攻击了它"。

**影响**：方向一错，整个内网横向移动的图就画反了。

你会认为攻击者从内网某台机器打进来，而实际上是这台被控机器主动扫出去——这两种情形的处置方案完全不同（前者要找出被利用的跳板，后者要找出受害的下游主机）。

**核查**：明确方向：`known_hosts` 里的主机是**本机连过的目的地**，构成横向移动的候选路径（配合 `config` 里的 `ProxyJump` 画出跳板链）。入站来源只能从 auth.log 的 `from <ip>`、`wtmp` 的源 IP 列取。`known_hosts` 现代默认是 hashed 形式（`|1|xxx=`），**域名/IP 不可直接读出**——需要 `ssh-keygen -F <ip>` 或 `known_hosts` 原始未哈希版本（如 `ssh-keygen -F` 配合旧文件）；报告里要写明该文件是否 hashed，hashed 情况下主机名不可得本身就是一条局限。

<a id="section-28"></a>

### 4.3 结论表述

<a id="section-29"></a>

#### 陷阱 9：把"未见使用记录"写成"后门未被使用"

**现象**：`/root/.ssh/authorized_keys` 里有一把指纹 `SHA256:3nQ8...` 的公钥，auth.log 中查无此指纹，报告写「该后门未被使用过」。

**原因**：**"日志里没有使用记录"至少有四种不可区分的成因**：① 确实从未使用；② 使用记录在 auth.log 轮转掉的范围之外；③ 使用记录被清理；④ 使用过但通过 `-o` 指定了不同身份文件等路径导致指纹没记全。案例里的表述是对的：「文件存在但**未见成功登录**（未使用 / 已轮转 / 痕迹已清）」——**它列出了三种可能而没有选一种**。

**影响**："未被使用"是一个事实性断言，攻击方可以用"日志被清理了"来反驳；一旦被反驳，报告里其他基于该断言的推演（"因此攻击者未取得 root 访问"）全部连带失效。
**核查**：把结论收敛到证据能支撑的最小命题：「该公钥对应的指纹在本检材可得的 auth.log 记录中未出现」。**然后逐条列出使其无法判定的原因**，并把这三种可能写进报告。判读时优先看 `mtime` 与已知攻击窗口的关系：若公钥文件的 `mtime` 就在入侵窗口内（案例是 22:50:12），那么"植入后从未使用"与"植入后立即使用但痕迹被清"都需要保留。

<a id="section-30"></a>

#### 陷阱 10：把 `ControlMaster` 复用连接的会话数低估

**现象**：auth.log 里只有 1 条 `Accepted publickey`（22:44 建立的复用通道），但攻击者实际在该主机上执行了数十个操作，报告据"1 条 Accepted"推断"攻击者只登录了一次"。

**原因**：`ControlMaster auto` + `ControlPath` 会让第一次建立的 TCP 连接被后续所有同目标连接复用，并且第一次认证成功后认证结果被缓存在 socket 里，后续连接不再重新认证。 因此 `Accepted` 行数与实际会话活动次数之间**没有固定比例关系**。更麻烦的是，复用连接的后续活动可能连 `session opened` 都不产生（取决于 sshd 版本与配置）——这意味着复用窗口内的活动在 auth.log 里是完全不可见的。

**影响**：用它做活动频次统计会严重低估攻击者的实际操作量。

用它做时间线会以为"22:44 登录后无事发生"，从而把 22:44–22:52 之间实际发生的大量操作（写持久化文件、改配置）归为空白。

**核查**：检查 `~/.ssh/config` 里的 `ControlMaster`/`ControlPath`/`ControlPersist` 设置（3.3 节）。若存在复用配置，则：① 明确声明 `Accepted` 计数不等于活动次数；② 活动证据改从文件系统侧取（`mtime`/`ctime` 序列、命令历史）；③ 检查 `~/.ssh/cm-<user>@<host>:<port>` 形式的 socket 文件是否残留——残留说明复用通道未正常结束（注意 socket 通常在退出后消失，断电检材上基本不留，这是本机制的固有局限）。`ControlPersist yes`（无限期）还意味着认证凭据被长期缓存在内存中，这条要写进风险评估。

<a id="section-31"></a>

### 4.4 工具行为与环境前提

这一组讲的是**工具在你的环境里正常工作，但它读的不是检材**，以及**结论依赖某个版本或某个配置项的默认行为**。两类失误都不会留下任何错误提示。

<a id="section-32"></a>

#### 陷阱 11：在分析机上执行 `sshd -T` 核对配置

**现象**：为了确认某个配置项的最终生效值，在分析机上执行 `sshd -T`（或 `sshd -t -T`），把输出当作检材的生效配置写进报告的验证章节。

**原因**：`sshd -T` 的输出是"当前运行环境的 OpenSSH 解析结果"，不是检材的。 它读的是分析机自己的 `/etc/ssh/sshd_config`、分析机支持的指令集、以及分析机安装的 OpenSSH 版本。三个变量都与检材无关：分析机的发行版模板不同（Debian 的 `Include` 行、RHEL 的注释块都不一样），版本可能不支持检材上用的新指令（于是该指令被判为未知或被忽略），而版本差异还会影响**指令的默认值**（例如较新版本对部分选项的默认取值与旧版不同）。

**影响**：这是一次"看起来最权威"的验证——`sshd -T` 输出的确是真实生效值，格式完全正确，还带 "port 22" 这样的完整结果。**读者完全无法从报告本身分辨它来自哪台机器**。更实际的问题是：它会与 3.1 节读镜像得到的值冲突，报告里出现两个互相矛盾的"生效配置"，而其中一个是伪造的。这类矛盾一旦被对方发现，涉及该配置项的全部结论都要重做。

**核查**：生效值只能由镜像内的配置文件推导，不能由任何 `sshd` 命令产出。 固定流程是三步：`Include` 链 → 全部参与文件按解析顺序排列 → 同一指令项多值时按 first-wins 定出最终值并写明决定因素。要做语法有效性检查时，把配置**复制到隔离目录后**在副本上跑：

```bash
# 分析机上：核对指令拼写与参数是否被本机版本接受（仅作拼写检查，不作生效值来源）
cp -rp /mnt/df/etc/ssh /evidence/ssh-conf-test/
sshd -t -f /evidence/ssh-conf-test/sshd_config 2>&1 | head
# 报错行只说明"拼写或参数不被本机 OpenSSH 接受"，不能推出检材上的行为
# 若分析机版本低于检材版本，旧版不认识的指令会误报，需以检材的 sshd 包版本为准
```

**报告里要写明校验环境**：「`sshd -t` 语法检查在 `<分析机 OpenSSH 版本>` 上执行，仅用于发现拼写错误；最终生效值依据镜像内 `/etc/ssh/sshd_config` 及 `/etc/ssh/sshd_config.d/*.conf` 按 `Include` 顺序与 first-wins 规则推导。」

<a id="section-33"></a>

#### 陷阱 12：把 `Invalid user` 记录数量当成爆破规模的度量

**现象**：`lastb` 或 auth.log 里 `Invalid user <name> from <ip>` 出现几千条，报告写「攻击者对 `<用户名>` 进行了数千次口令尝试」或「攻击者使用了字典文件枚举有效用户名」。

**原因**：`Invalid user` 记录的产生条件是在认证之前——sshd 收到用户名后发现该用户不存在，直接拒绝并记 `Invalid user`，**这个阶段根本还没有提交口令**。所以它的数量反映的是**用户名枚举**的尝试次数，与口令尝试次数完全是两个量。而且这个计数会被两个因素放大：① `MaxStartups` 未认证连接上限与 `LoginGraceTime` 会丢弃一部分连接，那些尝试**没有日志**；② 暴露在公网的 SSH 服务上，`Invalid user` 里相当大一部分是全网自动化扫描器，与本案行为人通常无关——具体比例须按本案 `Invalid user` 的源 IP 分布做来源分离后判定。

**影响**：把用户名枚举当成口令爆破，会得出「攻击者掌握了这台机器的用户名清单」这个具体结论，并据此推断账号体系被摸清、后续定向攻击可行。**实际上用户名枚举往往来自互联网背景噪声**，把它算进本案证据，等于把公共扫描流量当成定向攻击的证据。

**核查**：**三条计数必须分开，且必须先做来源分离**：

```bash
# ① 用户名枚举（认证前拒绝，未提交口令）
grep -c 'Invalid user' /evidence/auth-merged.txt
# ② 口令失败尝试（已提交口令但认证不通过）
grep -cE 'Failed password|authentication failure' /evidence/auth-merged.txt
# ③ 成功登录
grep -cE 'Accepted (password|publickey)' /evidence/auth-merged.txt
```

**来源分离判据**：把 `Invalid user` 里的源 IP 做频次排序，若前若干位 IP 的失败量占绝大多数且**在整段时间内均匀分布**，基本可判为背景扫描；**与本案相关的那部分**通常表现为**同一 IP 在短时间内密集失败、随后紧跟一次成功**——案例里 `lastb` 中同 IP 密集失败后出现同 IP 成功才是爆破得逞的判据。报告里要把背景扫描的流量单列并标注"不纳入本案认定"，这比隐去它更可信。

<a id="section-34"></a>

#### 陷阱 13：用 `ssh-keygen -lf` 提取指纹后忽略算法差异

**现象**：拿 `ssh-keygen -lf authorized_keys` 的输出与 auth.log 里的指纹比对，发现字符串不一致，于是把该公钥判为"从未被使用"。

**原因**：同一条密钥在不同上下文里的指纹前缀可能不同，而 `ssh-keygen -lf` 的输出还带算法与注释，比对时容易只比一部分。 auth.log 的 `Accepted publickey` 行里指纹出现在 `ssh2:` 之后，形如 `ssh2: ED25519 SHA256:9kPq...`；`ssh-keygen -lf` 的输出形如 `256 SHA256:9kPq... AAAAB3... root@host (ED25519)`。两者都要取到 `SHA256:...` 这一段再比，直接整行比对必然不等。此外还有两个常见干扰项：① **同一条密钥以不同算法签名的多个公钥并存**（一把 ED25519、一把 RSA 都对同一私钥），它们的指纹完全不同，auth.log 用哪一把取决于客户端协商结果；② **指纹格式本身有历史差异**（旧版是 MD5 冒号分隔的 `aa:bb:cc:...`，新版默认 SHA256），检材的 OpenSSH 版本决定它记哪种格式。**照着用新格式去比旧日志，比对必然失败。**

**影响**：指纹比对失败会被读成"该公钥从未被使用"，也就是陷阱 9 的那条阴性结论，但它披着"已做交叉验证"的外衣——比单纯没比对更具说服力，也更难被发现是方法错误。这个错误还可能连带影响多条：所有"未见使用痕迹"的公钥会被一并判成未使用。

**核查**：统一提取 `SHA256:` 段再比，并按检材的 OpenSSH 版本确认日志里的格式：

```bash
# 文件侧：统一取 SHA256 指纹（去掉位数/注释）
ssh-keygen -lf /mnt/df/root/.ssh/authorized_keys | awk '{print $2}'
# 日志侧：从 Accepted publickey 行取 SHA256 段
grep -oE 'Accepted publickey.*SHA256:[A-Za-z0-9+/=]+' /evidence/auth-merged.txt \
  | grep -oE 'SHA256:[A-Za-z0-9+/=]+' | sort | uniq -c

# 确认检材 OpenSSH 版本，判断日志用的是 SHA256 还是旧式 MD5 指纹
strings /mnt/df/usr/sbin/sshd | grep -oE 'OpenSSH_[0-9]+\.[0-9]+' | sort -u | head
# 若日志里出现的是 32 位十六进制冒号分隔形式（MD5 指纹），需改用 -E md5 提取
# ssh-keygen -l -E md5 -f /mnt/df/root/.ssh/authorized_keys
```

**同一私钥多算法并存的核对**：`authorized_keys` 里若同一行注释相同但算法不同、或存在多条由同一私钥派生的公钥，要**全部列入比对表**并在报告中说明"该私钥可能以 `<算法列表>` 中任一形式被使用，日志记录的是协商结果"。指纹比对必须在标准化之后进行，逐行字符串比对不可靠。

<a id="section-35"></a>

#### 陷阱 14：把 `known_hosts` 里的非 hashed 主机名当成"本机曾连出"的全集

**现象**：某台机器的 `/root/.ssh/known_hosts` 是明文形式，列出 40 个主机名，报告写「该主机曾向这 40 台主机发起过连接」，并据此画出横向移动路径图。

**原因**：`known_hosts` 只记录"完成过主机密钥校验的连接"，而它被写入的前提是 `StrictHostKeyChecking` 允许且目标主机密钥通过了校验——**失败的连接尝试不会写入**。这与陷阱 12 是同一类偏差：这里记录的是成功集合而非全部尝试集，把它当成全集会低估实际发生的连接。同时还有一个反向偏差：`known_hosts` 里的条目可能不是本机主动发起的——跳板场景下经 `ProxyJump` 中转的连接，其条目归属于发起端机器而非中转机；而自动化工具（`ansible`、`ssh-copy-id` 的批量执行）会在几分钟内写进大量条目，这些条目的时间戳全部相同，无法区分是人工逐台操作还是脚本批量执行。

**影响**：横向移动路径图会被画成"该主机主动访问了 40 台内网主机"，其中可能大部分是批量工具留下的记录，时间上完全无法区分先后。**用这张图去指认"攻击者的扩散顺序"是不成立的**——同一秒写入的条目没有先后。委托方若据此认为 40 台主机都需排查，范围会被无依据地放大。

**核查**：**先确认条目是否被哈希、条目时间的粒度，再谈路径**：

```bash
# 首字段形如 |1|base64|hash = hashed（主机名不可直接读出）
head -3 /mnt/df/root/.ssh/known_hosts | cut -d' ' -f1
# 明文时才会直接是主机名/IP
cut -d' ' -f1 /mnt/df/root/.ssh/known_hosts | grep -vE '^\|1\|' | sort -u | head -40
```

**时间粒度判据**：`known_hosts` **不含逐条时间戳**，只能靠文件 mtime 与条目顺序推断，精度很粗。若多条条目在同一秒写入（表现为文件 mtime 集中、条目顺序与主机名无相关性），**必须标注为"批量写入，条目间无时序"**。hashed 形式下主机名不可读，此时可用 `ssh-keygen -F <候选主机>` 逐个反查——反查命中证明"连过该主机"，未命中不证明"没连过"（因为可能连过但条目已被 `ssh-keygen -R` 删除），这个不对称性要写进报告。

<a id="section-36"></a>

#### 陷阱 15：把认证日志里的时间直接当成会话开始时间

**现象**：用 auth.log 里 `Accepted publickey for deploy from 203.0.113.77 ...` 的行时间（22:44:01）作为"攻击者开始活动的时刻"，并据此划定入侵窗口起点。

**原因**：`Accepted` 记的是"认证通过"的那一刻，不是会话开始，也不是第一条命令执行的时间。 两者之间存在可观的间隔：客户端在认证通过后要做密钥交换完成、打开通道、加载 shell 配置（会 source `~/.bashrc` 与 `profile.d`，**攻击者的持久化脚本就在这时执行**）、才等到第一个提示符。而这个间隔在 `ControlMaster` 复用场景下更复杂：第一次认证建立通道，后续命令可能完全不再产生新的 `Accepted` 行。另一个方向的问题是**时区与格式**：`$time_local` 类的本地时间字符串在解析时若不做时区换算，与文件时间戳、其他日志比对时会整体偏移若干小时。

**影响**：时间线起点前移或后移，会直接改变"痕迹是否落在入侵窗口内"的判断。该字段一旦整体错 1 小时，案例里 22:43 登录、22:44 提权、22:47 起建立持久化这一串对齐关系就会失真，22:47 的持久化文件会被判为"早于入侵、与之无关"，真阳性直接丢失。

**核查**：**明确每个时间字段的语义，并用两个独立来源互相校准**：

| 时间字段 | 语义 | 权威来源 |
|---|---|---|
| `Accepted ...` 行时间 | **认证通过**时刻 | auth.log |
| `session opened` | 会话通道建立 | auth.log |
| `session closed` | 通道关闭 | auth.log |
| `wtmp` 条目时间 | 会话**开始**记录（由 sshd 写入） | `last -f` |
| 文件 `mtime` | 内容最后写入 | `stat` |

**校准方法**：拿同一次登录的 `Accepted` 与 `wtmp` 条目时间对比，**差值应在数秒内**；若差出整小时，就是时区问题，须先统一时区再比对。另外**第一条命令的时间**只能从命令历史（`.bash_history` 需正常退出才落盘）或文件时间戳侧推，不能从 `Accepted` 直接得到。

<a id="section-37"></a>

#### 陷阱 16：把 `MaxAuthTries` 或 `LoginGraceTime` 当成爆破窗口的准确上限

**现象**：读到 `MaxAuthTries 6`，报告写「攻击者每次爆破最多只能试 6 次口令，从 auth.log 数出 47 次 `Failed password`，因此至少尝试了 8 次独立连接」。

**原因**：`MaxAuthTries` 是"每次连接内的认证尝试次数"上限，不是"每 IP 的连接次数"上限，而 auth.log 记的是"失败事件"而不是"连接"。 一条连接可以产生多条 `Failed password`（每次 `password` 认证请求记一行），但反过来，**多次连接也可能在日志里被合并或因超限丢弃**。更要命的是两个速率类限制：`LoginGraceTime`（默认 120 秒）是认证必须在该时间内完成，超时连接被断开并可能不留下完整的失败序列；`MaxStartups` 是未认证并发连接上限，超限的连接会被随机拒绝（且部分实现直接丢弃不记账）——这意味着**日志里的失败次数是真实尝试次数的下界**，不是上界。

**影响**：用 `Failed password` 计数反推连接数，会得到一个精确到个位的"攻击规模"数字，而这个数字在机制上不成立。委托方可能据此评估"攻击者能力很强、试了 8 次"或反过来用它证明"攻击很轻微"，两个方向都建立在不可靠的换算上。**这种算术级的精确错误在专业读者面前特别显眼。**

**核查**：区分「事件计数」与「尝试计数」，并把速率类限制写进局限：

```bash
# 按源 IP 分别统计失败事件数（注意：这是事件数，不是连接数）
grep -E 'Failed password' /evidence/auth-merged.txt \
  | grep -oE 'from [0-9a-f.:]+' | sort | uniq -c | sort -rn | head
# 是否存在同一 PID 下的连续多条失败（同一连接内的多次尝试）
grep -E 'Failed password' /evidence/auth-merged.txt | grep -oE 'sshd\[[0-9]+\]' | sort | uniq -c | sort -rn | head
```

**判读规则**：同一 PID 下的多条 `Failed password` 属于同一次连接的多次尝试；不同 PID 才可能是不同连接，但**同一连接的多个连接尝试也可能复用同一 PID**（视 sshd 版本与实现）。因此报告里只能写：「源 `<IP>` 在 `<时段>` 内产生 `<N>` 条认证失败记录，其中 `<M>` 条归属于同一 PID，该计数为事件数，实际认证尝试次数因 `LoginGraceTime`/`MaxStartups` 限制可能更高，无法精确还原。」

**同时把这三个配置项的实际值取出来**（`MaxAuthTries`、`LoginGraceTime`、`MaxStartups`）作为速率评估的依据，并在报告里注明——它们是判断"攻击者是否可能已突破限额"的唯一可用基准。
<a id="section-38"></a>

## 五、案例示例

<a id="section-39"></a>

### 5.1 公钥指纹核对与从未使用的 root 后门密钥

**场景**

Ubuntu Server 22.04 Web 服务器 `web01`（ext4）。委托方要求查明 2024-03-17 至 03-18 期间攻击者是否留有 SSH 后门。检材 `DigiForensics.dd`（raw），ext4 起始扇区 1181696，**强制断电**。已知攻击者 22:43 用 `deploy` 密码登录成功。

公钥指纹是 SSH 类证据里可用于交叉核对的标识——它同时存在于 `authorized_keys` 文件和 `auth.log` 的登录行里，两边匹配可建立关联。

**处置过程**

第 1 步，SSH 服务配置（含 drop-in 机制）：

```bash
grep -nE '^\s*Include' /mnt/df/etc/ssh/sshd_config
# Include /etc/ssh/sshd_config.d/*.conf      ← 有 drop-in，必须一并看

ls -la /mnt/df/etc/ssh/sshd_config.d/
# 50-cloud-init.conf   60-cloudimg-settings.conf   ← Ubuntu 云镜像自带，正常

grep -nE '^\s*(Port|PermitRootLogin|PasswordAuthentication|AllowUsers|PermitEmptyPasswords)\b' /mnt/df/etc/ssh/sshd_config
# Port 22
# PermitRootLogin prohibit-password       ← root 密码登录被禁（Ubuntu 默认）
# PasswordAuthentication yes                ← 允许密码登录
# AllowUsers ubuntu deploy                  ← 白名单：只有这两个用户可登录
```

`AllowUsers ubuntu deploy` 说明该主机做过白名单限制，**能登录的账户被压缩到两个**，这与日志里大量 `Invalid user` 相互印证——不是所有用户都在被尝试。
第 2 步，从日志提取全部公钥登录记录：

```bash
grep -E 'Accepted publickey' /evidence/auth-merged.txt
# Mar 17 06:15:33 web01 sshd[2210]: Accepted publickey for ubuntu from 198.51.100.23 port 51234 ssh2: ED25519 SHA256:9kPq...（运维）
# Mar 18 08:40:11 web01 sshd[9810]: Accepted publickey for svc-backup from 198.51.100.9 port 52002 ssh2: RSA SHA256:7Kx9mNp...（备份）
```

第 3 步，全盘找 `authorized_keys` 并逐个取指纹：

```bash
find /mnt/df -xdev -type f -name 'authorized_keys*' -printf '%m %u:%g %TY-%Tm-%Td %TH:%TM %p\
' 2>/dev/null | sort
# 600 ubuntu     2022-05-11 09:30  /home/ubuntu/.ssh/authorized_keys     ← 正常运维
# 600 deploy      2022-05-11 09:30  /home/deploy/.ssh/authorized_keys      ← 正常
# 600 root        2024-03-17 22:50  /root/.ssh/authorized_keys             ← ★ 入侵窗口内
# 644 svc-backup  2024-02-01 10:00  /home/svc-backup/.ssh/authorized_keys  ← ★ 权限过宽

for f in /mnt/df/root/.ssh/authorized_keys /mnt/df/home/svc-backup/.ssh/authorized_keys; do
  echo "== $f =="; stat -c '  mode=%a mtime=%y' "$f"; ssh-keygen -lf "$f"
done
# == /root/.ssh/authorized_keys ==
#   mode=600 mtime=2024-03-17 22:50:12
# 256 SHA256:3nQ8bWx1KpL... deploy@x (ED25519)      ← ★ 与 auth.log 里任何 Accepted 都对不上
# == /home/svc-backup/.ssh/authorized_keys ==
#   mode=644 mtime=2024-02-01 10:00:03
# 256 SHA256:7Kx9mNpVr... svc-backup@y (RSA)       ← 与 auth.log 的 SHA256:7Kx9mNp... 匹配 ✓
```

第 4 步，服务端口确认（纠正"port 是服务端口"的误读）：

```bash
grep -E '^\s*Port' /mnt/df/etc/ssh/sshd_config
# Port 22
# 日志里的 port 40210 是客户端临时源端口，不是服务端口
```

第 5 步，登录记账三库交叉：

```bash
last -f /mnt/df/var/log/wtmp deploy
# deploy   pts/0   203.0.113.77   Sat Mar 17 22:43   still logged in    ← 从未正常结束
# deploy   pts/0   203.0.113.77   Sun Mar 18 09:40 - 09:41
lastb -f /mnt/df/var/log/btmp | head -5
# 对应 22:41 左右的爆破失败（与 auth.log 的 Failed password 吻合）
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 2024-03-17 22:43 攻击者以 `deploy` 密码登录（源 `203.0.113.77`） | auth.log + wtmp + journal，**三源** | 强 |
| 22:50:12 在 `/root/.ssh/authorized_keys` 植入一把 root 后门公钥（ED25519，`SHA256:3nQ8bWx1...`） | 文件存在 + 权限 600 + mtime 在入侵窗口 + 不在任何包清单 | 强（植入行为） |
| **该 root 后门公钥从未被成功使用** | auth.log 全量 `Accepted publickey` 无该指纹 | 强（**阴性发现，须写入报告**） |
| `svc-backup` 的公钥登录正常、权限松散属运维不当 | 指纹与 auth.log 匹配（相互印证） | 强 |

**不能证明的**：`/root/.ssh/authorized_keys` 的公钥"从未被使用"这一结论，**其强度受限于 auth.log 的覆盖范围**。

本案 `/var/log/journal` 持久化且覆盖到 03-18，断电前时段可查，所以这个阴性结论才成立；若 auth.log 被清且 journal 仅存于 `/run`，则只能写成"**在可查日志范围内未发现该指纹的使用记录**"。

**误判对照**

本案最容易得出的错误结论是「`/root/.ssh/authorized_keys` 里有一把 2024-03-17 写入的公钥，攻击者留了 SSH 后门，且因为机器 22:43 之后一直处于该公钥可用的状态，所以攻击者随时可以回来」。

前半句对，后半句的**"可用"**判断是错的。

**正确判据有三个字段，都在本案里可查**：

1. `PermitRootLogin prohibit-password`。这个值允许公钥、禁止密码，所以**该公钥在策略上是可用的**——这部分推断成立。
2. 指纹 `SHA256:3nQ8bWx1...` 在 auth.log 全部 `Accepted publickey` 行中不存在。既然登录成功必然留下 `Accepted publickey ... SHA256:<指纹>` 行，**指纹缺席即未使用过**。这是可判定的闭环，不是猜测。
3. 该文件的 mtime 22:50:12 与 `deploy` 提权时段吻合，说明植入动作属于同一攻击序列。

这三条合起来的正确结论是"植入已成立、使用未发生"，而不是"后门随时可用"。

差别在于：前者是既成事实（植入行为本身就是可定案的证据），后者是风险预测（需要额外的"下一次会不会来"假设）。

**按错误判据走的代价**：把"植入"和"可用"混为一谈，会让委托方启动一次完整的凭据轮换与应急响应（改密码、禁用账户、封 IP），而这些动作针对的是一个**从未被使用过、且该主机在 03-18 已停止活动**的入口。

更实际的风险是**这类过度反应会挤占真正的处置资源**——本案真正紧迫的是 `/tmp/.kworkerd` 那个 SUID 提权入口和仍在生效的 cron 载荷。如果把资源花在轮换一个未使用的公钥上，反而延误了对活跃威胁的处理。

第二个易错点：把 `/home/svc-backup/.ssh/authorized_keys` 的 644 权限当成"登录失败的原因"，从而否定日志里 02-01 之前确有 `Accepted publickey ... SHA256:7Kx9mNp...`。

正确判据是**时间顺序**：`sshd` 在 `StrictModes yes` 下确实会拒绝 644 的文件，但该文件的 mtime 是 2024-02-01 10:00:03，而日志里该指纹的成功登录发生在**更早**。

也就是说，**权限是在它正常服役之后才被放宽的**。指纹核对支持"这把钥匙以前能用、现在不能用了"，顺序不能反。

按错误判据走，会得出"日志不可信/指纹匹配是巧合"，从而丢掉一条已经相互印证的证据。

---

<a id="section-40"></a>

### 5.2 多密钥文件的行级归属：authorized_keys 内的时间证据

**场景**

同系列主机 `db05`（Debian 12），委托方在 `/root/.ssh/authorized_keys` 中发现 4 行公钥，要求查明"哪一把是本次入侵留下的、其余三把属于谁"。检材 `DigiForensics.dd`。

**单凭文件级 mtime 无法回答行级归属**，而"这个文件里既有攻击者的也有运维的"是授权密钥文件常见且容易判错的状态。

**处置过程**

第 1 步，取文件级时间戳与行级结构：

```bash
stat -c '%n crtime=%w mtime=%y ctime=%z size=%s' /mnt/df/root/.ssh/authorized_keys
# crtime=2022-05-11 09:30:00  mtime=2024-03-17 22:50:12  ctime=2024-03-17 22:50:12  size=1420

wc -l /mnt/df/root/.ssh/authorized_keys        # 6 行（4 条密钥 + 2 行空行/注释）
grep -vcE '^\s*(#|$)' /mnt/df/root/.ssh/authorized_keys   # 4 条有效密钥
```

crtime 是 2022-05-11、mtime 是 2024-03-17——文件在系统初始化时就存在，2024 年被改过。这是"追加"而非"新建"的第一个提示。

第 2 步，逐行取指纹（**这是行级归属的唯一可靠手段**）：

```bash
awk 'NF>=2 && $1 !~ /^#/ {print NR"\	"$1"\	"$2" "$3}' /mnt/df/root/.ssh/authorized_keys \
  | while IFS=$'\	' read n t rest; do
      printf '%s' "$rest" > /tmp/k.pub
      printf 'line %s  %-14s  %s\
' "$n" "$t" "$(ssh-keygen -lf /tmp/k.pub | awk '{print $2, $NF}')"
    done
# line 1  ssh-ed25519   SHA256:9kPqWv... ubuntu@ops-vault        ← 与 03-17 06:15 的 Accepted 匹配 ✓
# line 3  ssh-ed25519   SHA256:3nQ8bWx1... deploy@x              ← ★ 与任何 Accepted 都不匹配
# line 4  ssh-rsa       SHA256:Bm41... former-admin@corp          ← 2023-11 已不在 passwd
# line 6  ssh-ed25519   SHA256:3nQ8bWx1... deploy@x              ← ★ 与第 3 行指纹完全相同
```

第 3 行与第 6 行指纹完全相同 `SHA256:3nQ8bWx1...`——同一把公钥被写入了两次。
第 3 步，验证重复写入的判别依据（**不能只看指纹相同就断言**）：

```bash
# 逐行内容比对：确认是完全相同还是不同注释
sed -n '3p' /mnt/df/root/.ssh/authorized_keys | awk '{print $1, $2}'
# ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...
sed -n '6p' /mnt/df/root/.ssh/authorized_keys | awk '{print $1, $2}'
# ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...
# → 密钥体逐字节相同，注释也相同 → 同一行被追加了两次（或写入时重复了）

# 是否有公钥被注释掉
grep -nE '^\s*#.*ssh-(rsa|ed25519)' /mnt/df/root/.ssh/authorized_keys
# 5:#ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... deploy@disabled   ← ★ 另有一把被注释的
```

第 4 步，交叉日志确认每把指纹的使用情况：

```bash
for fp in 9kPqWv 3nQ8bWx1 Bm41; do
  printf '%s: ' "$fp"
  grep -c "SHA256:$fp" /evidence/auth-merged.txt
done
# 9kPqWv:    14    ← 运维密钥，14 次成功登录
# 3nQ8bWx1:   0    ← 攻击者密钥，零次
# Bm41:       3    ← 前管理员密钥，3 次，全部在 2023-11 之前
```

第 5 步，确认被注释密钥的指纹：

```bash
sed -n '5p' /mnt/df/root/.ssh/authorized_keys | sed 's/^#\s*//' > /tmp/d.pub
ssh-keygen -lf /tmp/d.pub
# 256 SHA256:3nQ8bWx1KpL... deploy@disabled (ED25519)
# → 与第 3/6 行同一把密钥，注释字段不同
```

**结论**

- `SHA256:3nQ8bWx1...` 这把 ED25519 密钥在本案中被写入了三次（第 3 行有效、第 6 行有效、第 5 行以注释形式存在），三次写入的密钥体与注释完全一致。**这是同一次操作中的重复写入，不是三次独立植入**——重复本身是自动化工具的典型特征。
- **这把密钥在可查日志范围内零次使用**（`grep -c` 得 0），而同一文件里 `9kPqWv` 有 14 次、`Bm41` 有 3 次。**零次是有意义的阴性结果，不是查不到。**
- 其余两把可归属：`9kPqWv` 属于 `ubuntu`（运维金库），对应 03-17 06:15 的 `Accepted publickey`；`Bm41` 注释为 `former-admin@corp`，对应 3 次历史登录且**全部发生在 2023-11-20 之前**，而该账户已不在 `/etc/passwd` 中。
- 因此委托方问题的答复：「本次入侵留下的是 `SHA256:3nQ8bWx1...`（重复写入 3 次、零次使用）；另两把为历史运维密钥，非本案引入。其中 `Bm41` 对应的账户已离职但密钥仍可用，这是一个独立于本案的发现——它意味着任何持有该私钥的人至今仍可登录 root。」

**误判对照**

本案最容易得出的错误结论有两个，都会直接导致错误的处置动作。

误判 A：「第 3 行和第 6 行指纹相同，说明是两次独立的植入尝试，第一次失败后又重试了一次，所以攻击者至少来了两轮。」

正确判据是**密钥体与注释的逐字节相同**。

`sed -n '3p'` 与 `sed -n '6p'` 输出的 `ssh-ed25519 AAAA...` 完全一致，注释 `deploy@x` 也相同。两次独立攻击者不会用**完全相同的私钥**做两次植入——私钥是本地生成的随机值，重复出现只有一种解释：**同一把私钥被同一段代码重复写入**。

而 `deploy@disabled`（第 5 行）这个注释字段说明作者当时就在做"写入-注释-再写入"的多重配置操作，**重复是设计的一部分，不是一次失败的重试**。

误判 B：「`Bm41` 这把密钥属于已离职的前管理员，所以在本次入侵中攻击者可能用了这把密钥来登录——毕竟它还没被删除。」

正确判据是**登录时间与账户状态的先后关系**：这把指纹的 3 次成功登录**全部发生在 2023-11-20 之前**，而 `Bm41` 对应的账户在该时间点之后才从 `/etc/passwd` 移除。

本次入侵发生在 2024-03-17，**相隔 4 个月，期间这把指纹零次出现**。若攻击者真的用过它，auth.log 里必然有 `Accepted publickey ... SHA256:Bm41`。

**按误判 A 走的代价**：虚构出"至少两轮攻击"，会把调查范围从"一次会话内的连续操作"扩大到"两个不同的攻击者或两个不同时间窗"，进而需要追查并不存在的第二台源主机或第二段时间线。

**按误判 B 走的代价**：这是**风险归属的错误**，危害更大。

报告会把"前管理员遗留密钥"写成"本次入侵使用的凭据"，导致委托方去追查已离职人员；反过来，真正的植入密钥 `3nQ8bWx1` 反而被当成"未使用的次要项"。

而正确的处置优先级恰好相反：**本次入侵的植入必须处置**（虽然未使用，但随时可被激活），**遗留密钥是一个需要独立立项的运维风险**（与本次入侵无关，但危害同样真实）。

**判据小结**：行级归属只能靠指纹逐行比对，文件级 mtime 只能给出一个"最后一次修改"的粗时间。

"某把密钥属于谁"靠指纹对日志，"某把密钥何时进入文件"通常无法从文件本身得到答案——本案能确定 22:50:12 那次写入，纯粹是因为它与攻击时间窗吻合，而不是因为文件里有行级时间戳。

---

<a id="section-41"></a>

### 5.3 反例：known_hosts 与 SSH 连接记账的时间归属

**场景**

同系列主机 `app09`，委托方询问"2024-03-17 那天这台机器主动 SSH 登录出去过哪些主机"。检材 `DigiForensics.dd`。

`known_hosts` 是"出向连接"少有的记账源，而它极易被误读成"入向登录"。

**处置过程**

第 1 步，取各用户的 `known_hosts`：

```bash
for u in root deploy app; do
  f=/mnt/df/home/$u/.ssh/known_hosts
  [ -f "$f" ] && { echo "== $f =="; stat -c '  mtime=%y size=%s' "$f"; wc -l < "$f"; }
done
# == /mnt/df/home/deploy/.ssh/known_hosts ==
#   mtime=2024-03-17 23:02:41  size=812
#   18 行
# == /mnt/df/home/root/.ssh/known_hosts ==
#   mtime=2022-05-11 09:30  size=340
#   7 行
```

第 2 步，看 `deploy` 的 known_hosts 里有谁（**注意是它主动连出去的**）：

```bash
ssh-keygen -lf /mnt/df/home/deploy/.ssh/known_hosts 2>/dev/null | head -20
# 256 SHA256:kQ81... 10.20.4.11 (ED25519)
# 256 SHA256:pL22... 10.20.4.12 (ED25519)
# 256 SHA256:Rx73... 10.20.8.5  (RSA)
# 256 SHA256:Vn91... 10.31.0.7  (ED25519)
```

第 3 步，与 22:50 植入的 root 公钥做指纹交叉：

```bash
ssh-keygen -lf /mnt/df/root/.ssh/known_hosts 2>/dev/null
# 256 SHA256:kQ81... 10.20.4.11 (ED25519)     ← 与 deploy 的第 1 行相同
# → deploy 主动连过 10.20.4.11，该主机的指纹被 root 也信任
```

第 4 步，看出向连接是否在 auth.log 留痕：

```bash
# auth.log 只记 sshd（本机作为服务端），出向连接由 ssh 客户端产生
grep -c 'sshd\[' /evidence/auth-merged.txt      # 本机入向会话数
# journal 里客户端侧记录（若启用了 SSH_LOG）
journalctl --directory /mnt/df/var/log/journal _COMM=ssh -o short-iso --no-pager 2>/dev/null | tail -5
# 2024-03-17T23:02:38+08:00 app09 ssh[8841]: connecting to 10.20.8.5 port 22
```

第 5 步，确认 known_hosts 的写入机制边界：

```bash
stat -c '%n ctime=%z' /mnt/df/home/deploy/.ssh/known_hosts
# ctime=2024-03-17 23:02:41   ← 与 mtime 相同，无后续元数据改动
grep -c 'StrictHostKeyChecking\|UserKnownHostsFile' /mnt/df/etc/ssh/ssh_config
# 0   ← 未禁用严格主机密钥检查
```

**结论**

- `/home/deploy/.ssh/known_hosts` 的 mtime 是 2024-03-17 23:02:41，含 18 条主机密钥，其中 `10.20.4.11` 的指纹 `SHA256:kQ81...` 同时出现在 `root` 的 `known_hosts` 里。
- 因此可确认：`deploy` 在入侵当日 23:02 前后主动 SSH 出向连接到过内网的 10.20.4.11、10.20.4.12、10.20.8.5、10.31.0.7 等主机（内网段 `10.x`，非 RFC1918 文档地址，均为内网）。**这是横向移动的记账源**。
- `root` 的 `known_hosts` mtime 停在 2022-05-11，`10.20.4.11` 的指纹与 `deploy` 相同，说明**这台主机的密钥信任早已存在于 root 账户下**（例如共享的运维密钥分发），`deploy` 连接它时只需接受一次即写入自己的 known_hosts。
- **关键限制**：`known_hosts` 记录的是"**我信任过哪些主机的公钥**"，**它不记录连接时间，也不记录连接结果**。

唯一的间接时间线索是文件 mtime（"最后一次新增/修改信任的时间"）。本次能收敛到 23:02:41 靠的是 mtime，且该 mtime 只表示"最后一次写入"，可能覆盖了此前多天的连接。

**误判对照**

本案最容易得出的错误结论是「`known_hosts` 里有 `10.20.4.11`、`10.20.4.12` 等 4 台主机，说明 `deploy` 入侵期间登录了这些机器的账号」。

**这是把"出向"读成"入向"**，方向完全反了。

**正确判据是文件所在的账户与它的语义**：

1. **`known_hosts` 属于客户端行为**。它记录的是"**我（客户端）连出去时，服务器给我看的公钥**"；`authorized_keys` 才是"**哪些人可以连我（服务端）**"。本案的 `known_hosts` 在 `/home/deploy/.ssh/` 下，说明 **`deploy` 是发起方**。
2. **入向连接由 auth.log 记账，格式完全不同**。入向成功是 `Accepted publickey/password for <用户> from <ip> port <n>`，出向连接在本机不产生 `sshd` 记录。所以"登录了 4 台机器的账号"这种说法，在本案的证据里**根本找不到支撑行**。
3. **`10.31.0.7` 这个 IP 段的差异**。`10.20.x` 与 `10.31.x` 若分属不同 VPC/子网，则这次出向连接**跨越了网络边界**——这才是值得追查的方向，而"登录了 4 个账号"不是。

**按错误判据走的代价**：把出向连接误读成入向登录，会得出一个**完全虚假的结论**："攻击者在 4 台主机上都有账号"。

据此扩大排查到 4 台内网主机，而那 4 台机器很可能从未被触碰过——它们只是被 SSH 探测过并交换了公钥。

更糟的是，委托方可能据此认定"内网 4 台机器已失陷"，触发一场不必要的大范围应急。

第二个易错点：把 `known_hosts` 的 mtime（23:02:41）当成"这些连接的连接时间"。

正确判据是这个 mtime 只表示**最后一次新增信任项的时刻**。

若 `deploy` 在入侵前一个月就连过 `10.20.4.12`，那一条记录的写入时间是上个月，**不会因为本次 23:02 的新增而更新**。

因此准确表述是：「`known_hosts` 的最后修改时间为 2024-03-17 23:02:41，说明**至迟在该时刻**发生了新的信任写入；**具体是哪台主机的信任在该时刻新增，本案无法确定**，需比对 journal 侧的连接记录或其他来源。」

**判据小结**：`authorized_keys` = 谁可以进我；`known_hosts` = 我连过谁。

两者在指纹上可以互相印证（`10.20.4.11` 的 `kQ81` 同时出现在两处），但方向语义相反，不能混用。

---
<a id="section-42"></a>

## 六、扩展阅读方向

<a id="section-43"></a>

### 前置基础：读懂 SSH 痕迹的前提

- [系统日志深度分析](../computer-log/computer-log-system-log-analysis.md) —— `auth.log` / `secure` 的落点判定与轮转归档。**本篇的日志侧证据完全依赖它**，尤其「归档里可能留着更早记录」这一点直接决定本篇 3.2 的搜索范围。
- [取证工件地图](computer-persistence-persistence-artifact-map.md) —— `/etc/ssh/`、`/var/log/wtmp` 等落点与账户体系位置。**账户属主与 UID 的确认在这一篇。**
- [时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md) —— 认证日志行首无年份，需要用带年份的源补锚，否则时间线排序本身是错的。

<a id="section-44"></a>

### 同层深入：认证成功之后的事

- [时间线重建](../computer-log/computer-log-linux-timeline-reconstruction.md) —— 把本篇确认的登录时段并入统一时间线。本篇给的是「谁在何时进来了」，那一篇负责「进来之后何时发生了什么」。
- [Shell 痕迹与命令历史](../computer-shell/computer-shell-shell.md) —— 登录后执行的内容。**SSH 认证日志不记命令，命令只能从这里找**，而它默认可能没有时间戳。
- [计划任务与持久化痕迹](computer-persistence-scheduled-tasks-and-persistence.md) —— 同一账户的其他自动启动机制。**「植入了一把公钥」通常不会孤立出现**，两条线要一起查。

<a id="section-45"></a>

### 相邻议题：别的协议与别的系统的登录痕迹

- [远程勘验与在线取证](../../imaging/imaging-acquire/imaging-acquire-remote-evidence-collection.md) —— 活系统上用 `ss` 观察当前 SSH 连接，可以直接确认哪些会话在线，`authorized_keys` 的判读与之配合。
- [proc 虚拟文件系统取证](../computer-shell/computer-shell-proc.md) —— 从连接反查进程。**「哪个进程发起的」是归属分析的必答项**，离线镜像里只能靠日志。
- [事件日志深度分析](../computer-registry-log/computer-registry-log-windows-event-log-analysis.md) —— Windows 侧的登录痕迹。Security 4624 / 4625 与 `Accepted` / `Failed password` 是结构化与非结构化的对照，字段语义与保留策略都不同。
- [远程工具凭据解密](../../crypto/crypto-app/crypto-app-remote-tool-credential-preservation.md) —— 本篇固定的私钥与凭据材料如何进入后续分析。**只做离线分析，授权与脱敏要求见该篇。**

<a id="section-46"></a>

### 工具与规范：材料固定与脱敏

- [证据文件格式](../../fundamentals/fundamentals-chain/fundamentals-chain-dd-e01-aff4-evidence-formats.md) —— 私钥材料的归档容器选择。**证据文件格式决定了后续能否被独立复核。**
- [证据保管链与委托证明](../../fundamentals/fundamentals-chain/fundamentals-chain-chain-of-custody-and-authorization.md) —— 私钥属于高敏感材料，**固定与移交都需要留痕**。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md) —— 涉及口令恢复时的授权范围。

<a id="section-47"></a>

### 判据与反例：哪些「没有」值得追问

- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— `authorized_keys` 被追加公钥与整文件被替换，在时间戳上的表现不同，**这个差异本身就是判据**。
- [用户行为痕迹](../computer-registry-log/computer-registry-log-user-activity-artifacts.md) —— Windows 侧的对应物。UserAssist 与 `~/.ssh` 目录的逻辑是同一个问题——用「最近用过什么」反推行为，两边对照能看清各自的能力边界。
<a id="section-48"></a>

## 七、命令速查

```bash
# ===== 1. SSH 服务配置（含 drop-in！）=====
grep -nE '^\s*Include' /mnt/df/etc/ssh/sshd_config
ls -la /mnt/df/etc/ssh/sshd_config.d/ 2>/dev/null
for f in /mnt/df/etc/ssh/sshd_config /mnt/df/etc/ssh/sshd_config.d/*.conf; do
  [ -f "$f" ] && { echo "== $f =="; grep -nE '^\s*(Port|ListenAddress|PermitRootLogin|PasswordAuthentication|AllowUsers|DenyUsers|PermitEmptyPasswords|AuthorizedKeysFile|MaxAuthTries)\b' "$f"; }
done

# ===== 2. ★ authorized_keys 清点 + 指纹闭环 =====
find /mnt/df -xdev -type f -name 'authorized_keys*' -printf '%m %u:%g %TY-%Tm-%Td %TH:%TM %p\
' 2>/dev/null | sort
for f in $(find /mnt/df -xdev -type f -name 'authorized_keys' 2>/dev/null); do
  echo "== $f =="; stat -c '  mode=%a owner=%U mtime=%y' "$f"; ssh-keygen -lf "$f"; done
# 权限必须 600；.ssh 目录必须 700
find /mnt/df -xdev -type d -name '.ssh' -printf '%m %u:%g %p\
' 2>/dev/null
# 从 auth.log 提取所有 Accepted publickey 指纹
grep -oE 'Accepted publickey for .* SHA256:[A-Za-z0-9+/=]+' /evidence/auth-merged.txt | grep -oE 'SHA256:[A-Za-z0-9+/=]+' | sort | uniq -c

# ===== 3. known_hosts / config =====
cat /mnt/df/root/.ssh/known_hosts 2>/dev/null | cut -d' ' -f1 | sort -u | head   # 本机连过的远端
cat /mnt/df/root/.ssh/config /mnt/df/home/*/.ssh/config 2>/dev/null            # IdentityFile/ProxyJump/ControlMaster

# ===== 4. 登录记账三库（离线读，二进制，勿 grep）=====
last -f /mnt/df/var/log/wtmp | head -30          # 成功登录历史
lastb -f /mnt/df/var/log/btmp | head -30         # 失败登录历史
lastlog -f /mnt/df/var/log/lastlog 2>/dev/null | head   # 每用户最近登录
# utmp(=/var/run/utmp) 仅运行态有效，断电镜像通常为空

# ===== 5. 认证日志事件提取 =====
grep -E 'Accepted (password|publickey)' /evidence/auth-merged.txt       # 成功登录
grep -E 'Failed password|Invalid user' /evidence/auth-merged.txt          # 失败/扫描
grep -E 'Disconnected from authenticating|Connection closed by' /evidence/auth-merged.txt  # 探测
# 注意：port <n> 是客户端源端口，不是服务端口！

# ===== 6. 私钥识别（先复制再操作，勿动原文件）=====
find /mnt/df -xdev -type f \( -name 'id_*' -o -name '*.pem' -o -name '*.key' \) -not -name '*.pub' -printf '%m %u %p\
' 2>/dev/null
for f in /mnt/df/root/.ssh/id_*; do echo -n "$f → "; head -1 "$f" 2>/dev/null; done
# OPENSSH PRIVATE KEY = 新格式（OpenSSH 7.8+）；RSA/DSA/EC PRIVATE KEY = 旧 PEM
cp --preserve=all /mnt/df/root/.ssh/id_ed25519 /evidence/extracted_key
ssh-keygen -y -P "" -f /evidence/extracted_key >/dev/null 2>&1 && echo "无口令保护" || echo "有口令保护"
sha256sum /evidence/extracted_key
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — Linux 取证 — SSH 痕迹与密钥取证」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《SSH 痕迹与密钥取证》（CC BY-SA 4.0）`

文中 `DigiForensics.dd` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
