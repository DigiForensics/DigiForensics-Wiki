---
title: "远程控制工具痕迹"
slug: "server-panel-remote-control-artifacts"
canonical: "https://www.digiforensics.cn/wiki/server-panel-remote-control-artifacts"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:52+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "server"
space: "服务器与云取证"
node_path: ["面板与控制台"]
---

# 远程控制工具痕迹

<a id="section-1"></a>

## 一、概述

前面几篇的排查顺序都是从文件系统和日志入手。但有一类痕迹，**它的起点不在磁盘上，而在网络连接表里**。

攻击者拿下服务器后往往会再装一个远控工具来保住长期控制——WebShell 随时可能被清理：向日葵、ToDesk、AnyDesk、TeamViewer、RustDesk。

这些工具**合法、签名完整、主流杀软不拦截**，因为它们本来就是给企业远程运维用的。

于是发现 `anydesk` 进程时，无法仅凭这一点判断它是运维装的还是攻击者装的。

本篇要回答的是：它什么时候、通过什么方式被装上的？谁在用它、连过哪些 IP？用过它传输了什么？

**答案多数藏在「外联」里。**

WebShell 是**被动等待**（你来请求我，我执行）。远控工具是**主动外联**（我主动连到厂商调度服务器注册上线，等你来找我）。这条主动外联在连接表、`/var/log/` 里的陌生 IP、systemd 服务配置中留下大量痕迹。

**这就是本篇的骨架：先看外联、再反查软件。**

理由很直接——磁盘上可能有几十万个文件，靠文件名匹配工具名会淹没在噪声里；而连接表里「一个非业务进程正连向某陌生公网 IP」这样的记录通常只有个位数。从连接反查进程、从进程反查文件，命中率远高于全盘 grep。

**在取证流程中的位置**：本篇属于**分析环的归因层**，是前面几篇（站点、WebShell、面板）之后的自然延伸——当站点侧查不出足够证据、但服务器确实被控时，远控痕迹是常见的那条出路。它同时是一条**横向扩线通道**：Xshell / FinalShell 的会话配置里存着运维连接过的所有主机清单，WinSCP 与 Navicat 的配置里存着数据库连接信息，**这些本身就是被控主机群的资产清单。**

**涉及的证据形态**（**没有一条命令能覆盖全部，必须分工具查**）：

| 工具 | Linux 侧关键痕迹 | 高价值字段 |
|---|---|---|
| **AnyDesk** | `/root/.anydesk/`、`/etc/anydesk/`、systemd unit | `TrustedDevices`（免交互放行的设备）、证书与私钥、无人值守口令哈希与盐 |
| **TeamViewer** | `/etc/teamviewer/`、`~/.config/teamviewer/` | `Connections_incoming.txt`（成功接入记录：对方 ID、账号名、起止时间） |
| **向日葵** | `/usr/local/sunlogin/`、systemd 服务 | `fastcode`（识别码）、本机验证码加密值、历史连接记录 |
| **ToDesk** | `/usr/local/bin/todesk*`、`/etc/systemd/system/todesk*.service` | **`config.ini` 的临时授权码** |
| **RustDesk** | `~/.config/RustDesk/`、systemd 服务 | `relay-server` 指向自建实例 = 非官方部署 |
| **Xshell / FinalShell** | `~/.Xshell/Xshell/Sessions/*.xsh`、`~/.finalshell/conn/` | `HostName`/`UserName`/`Port` 明文；`password` 密文 |
| **Navicat** | —（Windows 为主） | 连接配置与加密口令 |
| **RDP/3389** | `auth.log` 的 `rdesktop`/`xfreerdp`、`.bash_history` | 会话时长、来源 IP |

> ⚠️ **必须逐条核对实际环境**：TeamViewer 的 QuickSupport 把日志写在 `%APPDATA%` 而非 `%ProgramFiles%`；向日葵安装版 / 绿色版 / 简约版对应不同注册表子键；RustDesk 配置目录名大小写在版本间不一致。**不确定时以「两处都查」为准。**

**外联痕迹的判读表与「直连 vs 中继」的强度差异见 2.1。**

**定性的门槛**：**远控痕迹的定性门槛远高于普通后门。**

发现工具 ≠ 认定攻击。判定为攻击者所留需要**时间、IP、配置三项交叉**，缺任何一项都只能写成「存在远控软件，用途待定」（三项的具体判据见陷阱 1）。

把运维的正常工具写成攻击者痕迹，会让委托方的调查方向整个跑偏。

本篇要回答的问题：某个远控工具什么时候被装上、连过哪些 IP、有没有成功的接入记录（对方 ID、账号、起止时间）、配置指向的是官方还是自建实例、运维曾经连接过哪些主机。

明确不在范围内的：远控会话里具体传输了什么文件（**工具本身不记录**，要看流量或终端侧的痕迹）；工具被卸载后的痕迹（需靠文件系统残留与内存侧）。**发现工具不等于认定攻击**；配置里的口令能否还原（**只做离线分析，报告中脱敏**）。

**内容边界（本篇的红线）**：本文用于**已获得合法授权**的取证场景，目标只有**发现痕迹、固定证据**两项，**不提供任何安装、隐藏或绕过检测的方法**。

读到无人值守口令哈希、可信设备列表、临时授权码等材料时：只做离线分析与风险评估，不做在线验证、不尝试连接。

**报告中一律脱敏，涉密材料按密级登记管理。**

**读者前提**：需要 Linux 的网络与进程排查基础（见 [Linux 系统日志深度分析](../../computer/computer-log/computer-log-system-log-analysis.md) 与 [proc 虚拟文件系统取证](../../computer/computer-shell/computer-shell-proc.md)）、[取证工件地图（Linux 侧）](../../computer/computer-persistence/computer-persistence-persistence-artifact-map.md) 的痕迹体系，以及基本的 systemd 与配置目录认知。建议先按 [3.1 第 1 步](#section-8) 做外联排查——本篇的顺序不可颠倒。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 从「外联」记录开始排查

```
被控端（服务器）                        主控端（攻击者）
  ① 启动：主动连厂商调度服务器注册上线 → 出站 TCP 长连接
  ② 会话：双向流量（画面、键鼠）；NAT 打洞失败则经厂商中继转发
  ③ 心跳：周期性报到 → 连接长期存在，不会只连一次
```

| 现象 | 为什么能取证 | 强度 |
|---|---|---|
| **出站连接目的地陌生** | 业务服务器不该持续连陌生公网 IP | 强（需排除更新/云备份/监控） |
| **连接长期存在（心跳）** | 无人操作时连接也在 | 强 |
| **打洞成功时目的地是攻击者真实 IP** | 打洞失败才走中继；**中继是遮蔽，直连是暴露** | ★ 极强 |
| **配置里的服务器地址可反查** | 自建或被改配置的实例指向非厂商地址 | 强 |

第 3 条最实用：**中继隐藏攻击者 IP，直连把它写进连接表。**遇到直连可直接锁定攻击者出口 IP——但该 IP 本身仍可能是代理或跳板（见 5.1 的「不能证明的」）。

但出站连接不能孤立看——正常服务器也连更新源与监控，**判据是「发起连接的进程是什么」**。`ss -tunap` 直接显示进程名与 PID，这是连接表最有价值的部分。

<a id="section-4"></a>

### 2.2 各工具的痕迹落点对照

**没有一条命令能覆盖全部**，必须分工具查：

| 工具 | Windows 侧关键痕迹 | Linux 侧关键痕迹 | 高价值字段 |
|---|---|---|---|
| **AnyDesk** | `%APPDATA%\AnyDesk\`（`service.conf`、`system.conf`、`ad.trace`、`connection_trace.txt`、`thumbnails\`）、`%ProgramData%\AnyDesk\` | `/root/.anydesk/`、`/etc/anydesk/`、systemd unit | `ad.anynet.pwd_hash`/`pwd_salt`（无人值守口令哈希与盐）、`ad.anynet.cert`/`pkey`（证书与私钥）、`TrustedDevices`（可信设备列表——免交互放行的设备） |
| **TeamViewer** | `%APPDATA%\TeamViewer\`（`Connections.txt`、`LogFiles\`（连接历史日志，含远端 IP 与操作时长）、`TrustedDevices`、凭据管理器中的 `Credentials` 加密 blob）、`%ProgramFiles%\TeamViewer\`（`Connections_incoming.txt`、`TeamViewer*_Logfile*.log`） | `/etc/teamviewer/`、`~/.config/teamviewer/` | `Connections_incoming.txt`（成功接入记录：对方 ID、账号名、起止时间、类型）、`Connections.txt`（连出记录）、`LogFiles\` 中逐条会话日志 |
| **向日葵** | **新版走注册表**：`HKCU`/`HKLM\Software\Oray\SunLogin\SunloginClient`（`SunloginInfo`/`SunloginGreenInfo`/`SunloginLiteInfo` 三个子键） | `/usr/local/sunlogin/`、systemd 服务 | `encry_pwd`（本机验证码加密值）、`fastcode`（识别码）、历史连接记录 |
| **ToDesk** | `%APPDATA%\ToDesk\`（以 `config.ini` 为主） | `/usr/local/bin/todesk*`、`/etc/systemd/system/todesk*.service` | `config.ini` 的 `tempAuthPassex`（临时授权码） |
| **RustDesk** | `%APPDATA%\RustDesk\`（`RustDesk.toml`/`RustDesk2.toml`） | `~/.config/RustDesk/`、systemd 服务 | `key`（中继密钥）、`custom-rendezvous-server`、`relay-server`——指向自建实例 |
| **NetSarang** | WinSCP：`HKCU\Software\Martin Prikryl\WinSCP 2\Sessions`（旧版 `Password` 字段为 Base64 编码，可还原；新版改用 AES 加密）；Xshell：`%APPDATA%\NetSarang\Xshell\Sessions\*.xsh` | `~/.Xshell/Xshell/Sessions/*.xsh` | `.xsh` 中 `HostName`/`UserName`/`Port` 明文；口令加密（WinSCP 新版为 AES） |
| **FinalShell** | `%LOCALAPPDATA%\finalshell\conn\*.json`、程序同级 `finalShell_data` | `~/.finalshell/conn/`、程序同级 `finalShell_data` | `host`/`userName`/`port` 明文；`password` 密文 |
| **Navicat** | `%APPDATA%\Navicat\MySQL\*.tncf`（**连接信息文件**）、较新版 `%APPDATA%\PremiumSoft\Navicat*\Profiles\*.ncx`、旧版 `HKCU\Software\PremiumSoft\Navicat*\Servers` | — | 连接配置与加密口令 |
| **MRemote** | `%APPDATA%\MRemote\` | — | 连接配置与可能的凭据 |
| **RDP/3389** | `TerminalServices-*.evtx` | `auth.log` 的 `rdesktop`/`xfreerdp`、`.bash_history` 的 `mstsc` | 会话时长、来源 IP、登录类型 |

> ⚠️ **必须逐条核对实际环境**：TeamViewer 的 QuickSupport 把日志写在 `%APPDATA%` 而非 `%ProgramFiles%`；向日葵安装版/绿色版/简约版对应不同注册表子键；RustDesk 配置目录名大小写在版本间不一致。**不确定时以「两处都查」为准。**

<a id="section-5"></a>

### 2.3 Linux 侧的四个落点

**① 安装**：`/usr/bin/`、`/usr/local/bin/`、`/opt/` 下的可执行文件与自解压残留（`*.AppImage`、`setup.sh`），证明装过，配合 `mtime` 定时点。
**② 持久化**：`/etc/systemd/system/*.service`、`/etc/rc.d/init.d/`，unit 内可含明文 `Password=`，价值最高。
**③ 配置凭据**：`~/.config/<工具>/`、`/etc/<工具>/` 下的 `service.conf`、`.toml`，含中继地址、本机 ID、口令哈希。
**④ 运行外联**：`/tmp`、`/var/tmp` 的自解压残留与 `ss` 中的常驻出站连接，给出时间线与攻击者 IP。

**第 ② 类是重点。**

不少远控在 Linux 上以 systemd 服务安装，服务定义文件里可能直接写有 `Password=`。其性质与 `/etc/shadow` 的哈希不同——可能明文，也可能弱加密，取决于工具与版本。

取证动作是：找到 unit → 确认 `ExecStart` 确属该工具 → 检查 `Password=` → 记录「存在性」与「长度指纹」（明文脱敏）→ 固定并哈希。

这是本篇合规要求最严格的一步：发现的凭据只用于证明「该机存在无人值守访问配置」，**绝对不可拿去尝试连接**。

配置里的中继地址、本机 ID 与口令哈希如何固定，以及判断「解不开」时该停在哪一步，见[第 06 篇](../../crypto/crypto-app/crypto-app-remote-tool-credential-preservation.md)。

<a id="section-6"></a>

### 2.4 为什么不重复 Linux 通用痕迹

账户、SUID、`crtime`、时间线重建见[《Linux 取证 — 取证工件地图》](../../computer/computer-persistence/computer-persistence-persistence-artifact-map.md)；服务器现场抢占式固定见[第 01 篇](server-panel-linux-server-artifact-map.md)；面板侧攻击路径见[第 02 篇](server-panel-bt-panel-forensics.md)。本篇只做一件事：**识别远控工具痕迹并评估影响面。**

---

<a id="section-7"></a>

## 三、操作步骤

<a id="section-8"></a>

### 3.1 第 1 步：外联排查（第一优先级）

**价值最高，因为它不依赖「你知道要找什么工具」。**`ss -tunap` 输出示例（列：Netid State Recv-Q Send-Q Local Peer Process）：

```
tcp  ESTAB 0 0 10.0.1.5:41234 203.0.113.77:32899 users:(("anydesk",pid=2871,fd=9))
#                                                  ↑ 陌生进程 + 陌生 IP，双重信号
```

判读规则：**进程持续连向陌生公网 IP 且非业务程序** → 远控外联（强）；**目的地是厂商中继域名/IP** → 合法远控工具（中，仍可能被攻击者滥用）；**监听端口对应陌生进程** → 远控在等待连接（强）；**出站目的地是内网其他主机高端口** → 横向移动或隧道（中）。

> **重要边界**：`ss` 只反映**采集时刻**。心跳可能只持续几秒，也可能恰好空闲。**「没查到」≠「不存在」**——这正是必须反查软件痕迹的理由。

**离线镜像侧的替代入口**（在线抢不到就用日志）：把 `/var/log/` 里的陌生 IP 汇总出来，再回连接与工具痕迹。

```bash
grep -rhoE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' /mnt/df/var/log/auth.log /mnt/df/var/log/secure \
  /mnt/df/var/log/wtmp 2>/dev/null | sort | uniq -c | sort -rn | head -30
awk '$9 !~ /^\./ {print $1, $3, $9, $11}' /mnt/df/var/log/auth.log 2>/dev/null | sort -u | head -30
journalctl --directory=/mnt/df/var/log/journal -u anydesk --no-pager 2>/dev/null | head -40
journalctl --directory=/mnt/df/var/log/journal -u todesk -n 50 --no-pager 2>/dev/null
```

<a id="section-9"></a>

### 3.2 第 2、3 步：进程、服务与软件痕迹

```bash
ps auxwwf | grep -viE 'grep|\[' | head -40
ps -eo pid,ppid,user,lstart,etime,cmd --sort=-etime | head -30   # 按启动时长排序
systemctl list-unit-files --state=enabled | grep -iE 'todesk|anydesk|sunlogin|rustdesk|teamviewer|xrdp'
systemctl list-units --type=service --state=running | grep -iE 'todesk|anydesk|sunlogin|rustdesk|teamviewer|xrdp'
ls -l /mnt/df/etc/systemd/system/*.service 2>/dev/null          # 离线镜像更可靠
find /mnt/df -xdev \( -iname '*todesk*' -o -iname '*anydesk*' -o -iname '*sunlogin*' \
  -o -iname '*rustdesk*' -o -iname '*teamviewer*' -o -iname '*finalshell*' \) 2>/dev/null
ls -l /mnt/df/usr/bin/*desk* /mnt/df/usr/local/bin/*desk* /mnt/df/opt/ 2>/dev/null   # 安装目录
ls -l /mnt/df/etc/rc.d/init.d/ /mnt/df/etc/init.d/ /mnt/df/etc/xdg/autostart/ 2>/dev/null
ls -l /mnt/df/root/.xsession /mnt/df/root/.xsessionrc /mnt/df/home/*/.xsession 2>/dev/null
find /mnt/df -xdev -name '*.desktop' -path '*autostart*' 2>/dev/null             # 桌面自启动
find /mnt/df/tmp /mnt/df/var/tmp -type f \( -name '*.ko' -o -name '*.bin' -o -name '*.AppImage' \) 2>/dev/null | head
ls -l /mnt/df/root/.anydesk/ /mnt/df/etc/anydesk/ 2>/dev/null   # 配置目录（RustDesk 大小写两处都查）
grep -iE 'todesk|anydesk|sunlogin|rustdesk|teamviewer|finalshell' \
  /mnt/df/root/.bash_history /mnt/df/home/*/.bash_history 2>/dev/null
```

<a id="section-10"></a>

### 3.3 第 4 步：读取配置、提取外联线索

**优先读三类字段**：服务器/中继地址、本机 ID、连接记录。首个命令是高价值项，务必执行；AnyDesk 各文件逐个读取的命令见速查第 5 组。

```bash
grep -rn -iE '^[[:space:]]*(Password|Passwd)[[:space:]]*=' \
  /mnt/df/etc/systemd/system/ /mnt/df/lib/systemd/system/ 2>/dev/null
cat /mnt/df/root/.config/RustDesk/RustDesk.toml 2>/dev/null
strings /mnt/df/opt/xxx/bin/xxx 2>/dev/null | grep -iE 'server|host|port|token|password|domain' | head -20
```

**必查字段**：`ad.anynet.pwd_hash` / `pwd_salt`（无人值守口令哈希与盐，AnyDesk `system.conf`）、`ad.anynet.cert` / `pkey`（本机证书与**私钥，等同设备身份，切勿外传**）、`client-id` / `id`（本机唯一 ID，即「门牌号」）、`key`（**自建 RustDesk 服务器共享密钥**）、`custom-rendezvous-server` / `relay-server`（非厂商地址 → **可能被改造或自建**）、`tempAuthPassex`（ToDesk 临时授权码）、`encry_pwd`（向日葵本机验证码加密值）、`HostName` / `UserName` / `Port`（Xshell `.xsh` 与 FinalShell `.json` 中的目标资产清单，**通常明文**）。

> ⚠️ **两条硬性规定**：① 凭据字段一律脱敏，报告只写「已发现该字段，值见密级附件」；② 发现后**立即登记移交**，不得私留、不得用于任何连接尝试。

<a id="section-11"></a>

### 3.4 第 5 步：批量扫描脚本

仅依赖 Python 3.6+ 标准库，只读取不执行被检文件。已实测：路径命中、键值抽取、明文口令检测、敏感字段脱敏、空目录与非法参数处理均正常。运行 `python3 rtscan.py /mnt/df > /evidence/rtscan-report.csv` 后，输出（列：`category` `artifact_path` `size` `mtime` `kind` `detail`）：

```
remote-admin-tool,etc/systemd/system/anydesk.service,141,2024-03-18 01:12:33,plaintext-cred,systemd/init 含明文口令字段（已脱敏）
remote-admin-tool,root/.anydesk/service.conf,121,2024-03-18 01:10:07,server-addr,命中IP=198.51.100.9; ... | client-id=123456789 | direct-access=198.51.100.9
remote-admin-tool,root/.config/RustDesk/RustDesk.toml,139,2024-03-18 01:11:55,server-addr,... | server=rs-ny.example.com | serial=2091837408 | key=Ab************Op
```

**已知局限（必须写进报告，否则 CSV 会被误读）**：只按关键字匹配路径名，**无特征文件名会漏**；只解析明文键值对，**不解析二进制加密凭据**；敏感字段已自动脱敏（保留首尾 2 字符与长度指纹）；`kind` 列为 `path-name`（仅路径命中）/`server-addr`（提取到服务器地址）/`plaintext-cred`（明文口令字段）。**CSV 是线索排序，不是判决。**

```python
#!/usr/bin/env python3
# rtscan.py —— 远程控制/远程运维工具痕迹批量扫描器（只读，不执行被检文件）
# 用法: python3 rtscan.py <镜像根目录或只读挂载点> > rtscan-report.csv
import csv, os, re, sys, time

DIRS = """etc/anydesk etc/todesk etc/sunlogin etc/rustdesk etc/teamviewer
etc/finalshell_data etc/systemd/system lib/systemd/system etc/rc.d/init.d
etc/init.d etc/xdg/autostart usr/local/bin opt tmp var/tmp
root/.anydesk root/.todesk root/.config/RustDesk root/.config/rustdesk
root/.config/sunlogin root/.config/teamviewer root/.Xshell root/.finalshell
root/finalShell_data {H}/.anydesk {H}/.todesk {H}/.config/RustDesk
{H}/.config/rustdesk {H}/.Xshell {H}/.finalshell {H}/finalShell_data""".split()
KEYWORDS = """todesk anydesk sunlogin oray rustdesk teamviewer finalshell
xshell winscp navicat mremote xrdp""".split()
WANT_KEYS = set("""host hostname server port id serial key token user username
version address url domain client-id direct-access relay rendezvous
custom-rendezvous-server relay-server relay-servers rendezvous-servers""".split())
UNITS = ("etc/systemd/system", "lib/systemd/system", "etc/rc.d/init.d", "etc/init.d")
SENSITIVE = re.compile(r"(pass|pwd|secret|credential|auth|hash|salt|^key$)", re.I)
ADDR = re.compile(r"(host|server|address|url|domain|relay|rendezvous|direct-access)", re.I)
KV = re.compile(r"^([A-Za-z_][\w.\-]*)\s*[:=]\s*(.+?)\s*$")
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

def mask(v):
    """凭据类字段只留长度指纹，不输出明文。"""
    v = v.strip().strip("'\"")
    return "*" * len(v) if len(v) <= 4 else v[:2] + "*" * (len(v) - 4) + v[-2:]

def walk(root, rel):
    base = os.path.join(root, rel)
    if not os.path.isdir(base):
        return
    for d, _s, fs in os.walk(base):
        for fn in fs:
            yield os.path.join(d, fn)
def read(path, limit=65536):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return ""

def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "/"
    if not os.path.isdir(root):
        sys.exit("用法: python3 rtscan.py <镜像根目录或挂载点>")
    home = os.path.join(root, "home")
    homes = [u for u in sorted(os.listdir(home))
             if os.path.isdir(os.path.join(home, u))] if os.path.isdir(home) else []
    w = csv.writer(sys.stdout)
    w.writerow(["category", "artifact_path", "size", "mtime", "kind", "detail"])

    def emit(path, kind, detail):
        try:
            st = os.stat(path)
        except OSError:
            return
        w.writerow(["remote-admin-tool", os.path.relpath(path, root), st.st_size,
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
                    kind, detail])

    # 第一轮：路径名命中关键字的文件，抽取其中的关键配置项
    for rel in [d.replace("{H}", u) for d in DIRS for u in (homes or [""])]:
        for path in walk(root, rel):
            if not any(k in path.lower() for k in KEYWORDS):
                continue
            kind, detail = "path-name", "文件名/目录名命中关键字"
            body = read(path) if os.path.getsize(path) < 262144 else ""
            for line in body.splitlines()[:4000]:
                line = line.strip()
                if not line or line[0] in "#;[":
                    continue
                m = KV.match(line)
                if not m or m.group(1).lower() not in WANT_KEYS:
                    continue
                k, v = m.group(1), m.group(2)
                if ADDR.search(k):
                    kind = "server-addr"
                detail += f" | {k}=" + (mask(v) if SENSITIVE.search(k) else v.strip("'\"")[:120])
            detail = detail[:400] + "..." if len(detail) > 400 else detail
            ip = IP_RE.search(detail)
            emit(path, kind, (f"命中IP={ip.group(0)}; " if ip else "") + detail)

    # 第二轮：含明文口令字段的 systemd unit / init 脚本（文件名可能无特征）
    for rel in UNITS:
        for path in walk(root, rel):
            body = read(path)
            if (re.search(r"(?im)^\s*(Password|Passwd)\s*=", body)
                    and re.search(r"(?i)anydesk|todesk|rustdesk|sunlogin|teamviewer", body)):
                emit(path, "plaintext-cred", "systemd/init 含明文口令字段（已脱敏）")

if __name__ == "__main__":
    main()
```

<a id="section-12"></a>

### 3.5 第 6、7 步：确认影响面与证据固定

时间关系判读：**配置 `mtime` 早于二进制** → 配置后被改过（口令/服务器，中）；**`ctime` 与 `mtime` 差距大** → 发生过元数据变更（中）；**trace 日志最早一条** → 工具**使用**的时间下界（强）；**连接 IP 首现时间 ≈ 安装时间** → 装完即连（强）；**unit `mtime` 早于二进制** → 先注册服务后放二进制，或 unit 被改（弱）。固定动作有两条铁律：只 `cp` 不 `mv`（移动会改写原目录 inode 与 `ctime`），固定后立即 `sha256sum` 并在收工前 `sha256sum -c` 回验，证明分析过程未污染证据。 完整的 `stat`、`connection_trace.txt` IP 频次、压缩包检索、复制与哈希命令见第七节第 7 组。

---
<a id="section-13"></a>

## 四、常见陷阱

远控工具取证的陷阱有一个共同根源：**这类工具天生「合法」**。

签名完整、主流通行，装在服务器上完全合规。这让「存在」与「入侵」之间隔着很远的距离，而分析员很容易把前者当后者。本章按「定性的门槛 → 痕迹定位 → 处置与合规」三段归组。

<a id="section-14"></a>

### 4.1 定性的门槛

<a id="section-15"></a>

#### 陷阱 1：把「装了远控」直接定性为入侵

**现象**：发现 `/usr/bin/anydesk` 与对应 systemd unit，报告写「该服务器被安装了远控工具，判定为入侵」。

**原因**：向日葵、ToDesk、AnyDesk、TeamViewer、RustDesk 全都是合法的企业远程运维工具。

运维主动安装它们来管理分散的服务器，是完全正常的做法，很多公司还有正式的采购与授权记录。

工具本身「签名完整、主流通行」不是它可疑的原因，**恰恰相反——这正是攻击者选它们的原因**（主流杀软不拦截）。

**影响**：把一个合规工具定性为入侵工具，结论可能整体不成立。

更实际的问题是：一旦定性为入侵，报告的重心会全部偏向「攻入过程」，而**运维自己装的可能性没有排除**。委托方收到这样的报告，第一反应是「我们的运维确实装过」，于是质疑报告的严谨性。

**核查**：**定性门槛是三项交叉，缺一不可。**

**时间关系**：安装时间（unit 的 `mtime`、二进制的 `mtime`）与其他入侵证据的先后。

**IP 关联**：连接记录里的对端 IP 是否与本案的攻击源一致。

**配置内容**：是否存在无人值守配置（`Password=`、临时授权码、可信设备列表），以及**是否指向非厂商的服务器地址**。

案例里三项全部成立：unit 的 `mtime`（`2024-03-18 01:12:33`）晚于 WebShell 落地（`2024-03-17 22:48:14`）2.5 小时、连接对端是本案攻击 IP、unit 内含明文 `Password=`——**所以能写「存在攻击者所留的远控工具痕迹」**。

三项不齐时，正确表述是「发现 XX 工具痕迹，安装时间 X，**无法判断安装者身份**，建议向委托方核实运维工具清单」。

<a id="section-16"></a>

#### 陷阱 2：★ `ss` 没查到就写「无远控」

**现象**：在线时按工具名过滤 `ss -tunap` 输出为空，报告写「未发现远控工具的外联连接」。

**原因**：**`ss` 只反映采集时刻这一瞬间。**

而远控的连接是**间歇性的**。心跳可能恰好在你采集时处于休眠，会话可能在你采集前几分钟就结束了。而且离线镜像上根本没有 `ss` 可用。

案例里第一步按工具名过滤**确实是空的**，但改看全部出站连接就发现了 `anydesk` 正在连 `203.0.113.77`。

**影响**：**这一处的代价最大。**

远控痕迹的定性高度依赖「连接记录」，而连接只存在于内存和 trace 日志里。一旦因为「没查到」就否定它，接下来磁盘上的配置文件、unit、二进制这些持久证据也不会被认真对待，整条线索就此断掉。

**核查**：**`ss` 的空结果永远不能作为否定性证据。**

过滤时不要只按工具名。案例里按名字过滤为空，是因为要看的字段是「陌生进程 + 陌生目的地」的组合，而不是进程名里有没有「desk」。

反过来用：`ss` 空 → 转去查磁盘痕迹（systemd unit、配置目录、二进制、`/tmp` 残留），并从 `/var/log/` 汇总陌生 IP 做时间线。

报告里的否定结论必须写明范围与依据：「在 `<采集时刻>` 的连接快照中未发现外联连接；`ss` 仅反映采集时刻，远控心跳为间歇性，未查到不构成排除依据。」

有内存镜像时，从内存里恢复已关闭连接与 SNI，这是补齐连接证据最有效的手段。

<a id="section-17"></a>

#### 陷阱 3：把「配置里指向厂商服务器」当成排除依据

**现象**：读到 `service.conf` 里的服务器地址是 AnyDesk 官方域名，报告写「该配置指向官方服务器，判定为正常安装」。

**原因**：**指向官方服务器恰恰是攻击者最省事的选择。**

官方服务器提供全部功能——注册上线、NAT 打洞、中继转发，无需攻击者自己搭服务器。指向官方**不排除**是攻击者装的。

而**非官方地址**（自建中继、修改过的 `custom-rendezvous-server`）才是需要解释的异常，因为它意味着额外的服务器运维投入。

**影响**：**把最强的判别信号用反了。**

「指向官方」和「指向自建」在证据力上完全不同。前者是常态，后者才需要解释。

**核查**：判别点是「地址是否符合工具的正常形态」，而不是「地址是不是官方的」。

记录 `custom-rendezvous-server` / `relay-server` / `direct-access` 的值，与该工具的官方默认值比对。**非默认值 = 强异常信号**，说明工具被改造或配置被改过。

`direct-access` 里若写着一个具体的公网 IP，**那是直连目标，极可能就是攻击者出口 IP**——直连意味着不经过中继，攻击者的真实 IP 被写进了本机配置。

RustDesk 的 `key`（中继服务器共享密钥）若存在，说明连的是自建或改造过的中继。

**反向也要注意**：地址是官方的不构成排除，定性仍需回到时间、IP、无人值守配置这三项上。

<a id="section-18"></a>

### 4.2 痕迹定位

<a id="section-19"></a>

#### 陷阱 4：只查默认路径，漏掉同一工具的其他落点

**现象**：查了 `/root/.anydesk/` 什么都没找到，报告写「未安装 AnyDesk」。

**原因**：同一工具的落点在不同版本、不同安装方式下差别很大。

AnyDesk 的配置可能在 `/root/.anydesk/`、`/etc/anydesk/`，Windows 侧还有 `%APPDATA%` 与 `%ProgramData%` 两处。TeamViewer 的 QuickSupport 把日志写在 `%APPDATA%` 而不是 `%ProgramFiles%`。

RustDesk 的配置目录名大小写在版本间不一致，`RustDesk` 与 `rustdesk` 都出现过。向日葵有安装版、绿色版、简约版，对应三个不同的注册表子键。

只查一处必然漏。

**影响**：**「没找到」被写成「未安装」**，而实际上工具就在另一个路径下运行着。

案例里 AnyDesk 的 unit 明确指向 `/usr/bin/anydesk`，配置在 `root/.anydesk/` 是靠 `connection_trace.txt` 里的连接记录才被确认的。

**核查**：**同一工具的多个候选路径全部查一遍，这是硬性动作。**

速查里 RustDesk 同时列了 `~/.config/RustDesk/` 与 `~/.config/rustdesk/`，就是这个原因。

**更重要的是不要把「路径命中」当成唯一手段。**`rtscan.py` 的第二轮就是专门为了「文件名无特征但内容有特征」的情况：它扫描所有 `systemd/system`、`init.d` 下的 unit，用内容匹配（`Password=` + 工具名）而不是路径匹配，专门抓那种落在无特征目录里的痕迹。

报告里写「未发现 X 工具痕迹」时必须列出已查的完整路径清单。

<a id="section-20"></a>

#### 陷阱 5：★ 忽略 `/tmp` 与 `/var/tmp` 残留

**现象**：固定完 unit 和配置目录就开始分析，没看 `/tmp`。

**原因**：自解压安装包常落在 `/tmp`、`/var/tmp`。

这些工具的安装程序在运行时会把自身解压到临时目录，安装完成后可能不清理，或者只清理一部分。而 `/tmp` 在很多服务器上是 tmpfs（内存盘），重启即消失。

案例里运维已经重启过一次 Nginx。如果整个服务器重启过，`/tmp` 里的自解压残留就没了——而这些残留里往往含有原始安装包、命令行参数、可能的临时凭据文件，它们的 mtime 常常是**安装那一刻**的精确时间戳。

**影响**：**丢失「安装动作」本身的证据。**

unit 的 `mtime` 只能告诉你「unit 文件被写过」。`/tmp` 里的残留才能告诉你「安装程序被执行过、以什么参数执行的、原始包是从哪下载的」。

**核查**：在线时把 `/tmp`、`/var/tmp` 当高优先级目标固定——它们与内存一样「会消失」。

`find /mnt/df/tmp /mnt/df/var/tmp -type f \( -name '*.ko' -o -name '*.bin' -o -name '*.AppImage' \)` 只是初筛，**还要看这些文件里有没有工具名残留**。`strings` 一下比看文件名可靠，因为自解压目录名往往是随机串。

若现场已重启且 `/tmp` 为空，报告里写「`/tmp` 为 tmpfs 且已于 `<时间>` 重启，安装残留不可得」——这是取证局限，不要写成「未安装」。

<a id="section-21"></a>

#### 陷阱 6：全盘 `find` 不加 `-xdev`，扫到超时

**现象**：为找工具痕迹直接 `find / -iname '*anydesk*'`，跑了几分钟没结果，或者卡在某个网络挂载点上。

**原因**：不加 `-xdev` 时 `find` 会跨越文件系统边界。

它会进入 `/proc`、`/sys`、`/dev`，以及容器挂载点和其他网络文件系统。这些目录有大量动态内容，`/proc` 下遍历可能直接卡死或极慢。在容器环境里还会钻进 overlay 的上层目录。

**影响**：**命令跑不完，于是这一项检查被跳过。**

最后报告里这一项是空的，而读者无法区分「查了没有」和「没查成」。

**核查**：`find` 一律加 `-xdev` 并限定已知目录（`/etc`、`/root`、`/home`、`/usr`、`/opt`、`/var`），这正是速查里 `find /mnt/df -xdev \( -iname ... \)` 的写法。

如果因为范围太大而无法穷尽，必须在报告里写清「检查范围为 `<列出目录>`，未覆盖其他路径」，而不是留白。

<a id="section-22"></a>

#### 陷阱 7：把 RustDesk 的 `key` 当成「会话密码」

**现象**：报告里写「已获取远控会话密码」。

**原因**：`key` 的语义是「中继服务器共享密钥」，不是会话口令。

它的作用是让客户端信任某个中继/调度服务器——只有客户端与服务端持有同一个 key 才会连上。**它不参与用户认证，不能用来登录设备。**

混淆这一点会让报告对证据能力的描述失真。

**影响**：**结论表述失真，且可能误导处置。**

委托方会以为「攻击者掌握了一个可登录的口令」，从而高估泄露范围。反过来也可能以为「这只是技术参数、不重要」而忽略自建中继这一重要架构异常。

**核查**：**准确表述字段语义。**

RustDesk 的 `key` = 中继服务器共享密钥；`custom-rendezvous-server` / `relay-server` = 服务器地址（非官方即为异常）；ToDesk 的 `tempAuthPassex` = 临时授权码；向日葵的 `encry_pwd` = 本机验证码加密值；

AnyDesk 的 `ad.anynet.pwd_hash`/`pwd_salt` = 无人值守口令的哈希与盐；`ad.anynet.cert`/`pkey` = 本机证书与私钥。

**字段准确了，报告才既不夸大也不缩小攻击面。**

<a id="section-23"></a>

#### 陷阱 8：只看到 unit 里有 `Password=`，就认为「凭据已知」

**现象**：在 `anydesk.service` 里发现 `Password=` 字段，报告写「已获取无人值守口令」。

**原因**：**发现字段 ≠ 知道值 ≠ 能用。**

三种情况要分开：字段里的值就是**明文**（案例中就是这种，`ExecStart` 的 unit 里直接写口令）；值是**哈希**；值本身已**被脱敏**或被工具改成了引用外部文件（从 `PasswordFile=` 之类的地方读）。

分析员可能在没看清值的情况下就下了结论。

**影响**：**「有口令字段」被写成「已知口令」**。

委托方会认为攻击者手上就有这个口令，从而可能要求立即轮换所有相关凭据——而实际可能只是个哈希，或者根本不是明文。

**核查**：只登记「字段的存在性 + 类型 + 长度指纹」，明文脱敏。

报告写法：「`/etc/systemd/system/anydesk.service` 第 9 行存在 `Password=` 字段，值为 18 字符明文（已脱敏，值固定于证据 `E-07`）」。

**明文取值在受控环境内用于验证即可，验证后即封存。**这一条同时是合规要求（见 4.3）。

<a id="section-24"></a>

### 4.3 处置与合规

<a id="section-25"></a>

#### 陷阱 9：★ 用发现的凭据去连一下「验证」

**现象**：发现无人值守口令或临时授权码后，想「试一下能不能连上」，以此确认凭据真实有效。

**原因**：这**不是取证操作，是一次入侵尝试。**

委托方授权的是「取证」——发现、固定、分析、报告，**不是「登录」**。而且这类工具的凭据很多是**长期有效**的（设备 ID + 无人值守口令组合就是完整的远程访问能力），一旦连上，你就成了一个真正实施了入侵的行为人。

**影响**：**法律风险，且不可辩解。**

成功登录他人远控账号可能构成非法侵入计算机信息系统罪。哪怕目标本就已被入侵、哪怕是在「验证」，都无法辩解——授权书上的范围是取证，不是登录。

这件事一旦发生，取证报告的可信度归零，取证人员自身面临追责。

**核查**：**凭据只用于证明痕迹与连接关系，绝不用于连接。**

允许的用法只有：证明「该设备存在该工具痕迹」、用配置中的 IP 佐证「与哪些 IP 有过连接」、记录字段存在性与长度指纹、立即登记移交。

要验证凭据是否「看起来合理」，看长度、字符集、是否为哈希形态就够了，不需要真的连。

处置建议是中立的。可以建议委托方在厂商后台吊销该设备授权与设备 ID，**但不得由取证方代为执行**。

<a id="section-26"></a>

#### 陷阱 10：把凭据明文写进报告正文或截图

**现象**：在报告里贴出 `Password=` 的完整值，或把配置文件原文截图放进 PPT。

**原因**：**这是一个「顺手」的动作**，不涉及技术判断，因此特别容易发生。

但这些字段的敏感性是极高的：`ad.anynet.pkey` 是**设备私钥，等同于设备身份**，拿到它就能冒充这台设备；`key` 是自建中继的共享密钥；无人值守口令是完整的远程访问凭据。

它们比数据库口令更危险——数据库口令只能访问数据，而这些能直接获得交互式控制权。

**影响**：**报告和截图是流转最广的载体。**

报告进诉讼材料、发给委托方法务、可能成为附件；截图进汇报 PPT、被转发。

这些凭据一旦扩散，攻击者或任何拿到它们的人都保留了对该设备的持续访问能力——即使设备已被清理。

**核查**：**一律脱敏，只写「已发现该字段，值见密级附件」。**

具体做法：① 报告正文零明文；② 截图前先检查是否有明文字段、必要时遮挡；③ 扫描脚本的输出**已内建脱敏**（`rtscan.py` 的 `mask()` 只保留首尾 2 字符并用 `*` 填充，同时输出长度指纹）——**依赖工具的脱敏不够，输出后仍要人工检查一遍**；④ 完整值只存在于固定的证据载体里，该载体**单独登记、单独移交、签收留痕**，不进报告、不进聊天工具、不进个人设备。

<a id="section-27"></a>

#### 陷阱 11：写「经中继无法溯源」就结束分析

**现象**：看到连接目的地是远控厂商的中继服务器，报告写「因流量经中继中转，无法确定攻击者 IP」。

**原因**：中继隐藏的是网络侧的观察者，不是被控端本机的记录。

被控端本地仍然留有四样东西：**连接记录**（`connection_trace.txt`、TeamViewer 的 `LogFiles/` 与 `Connections_incoming.txt`、向日葵的历史连接记录）——里面**直接写着对端 IP**；**本机 ID**（`client-id`、`fastcode`、TeamViewer ID）；**配置里的 `direct-access` 字段**；systemd unit 里的 `Password=`。

**影响**：**放弃了一条完整的归因链。**

案例里 `connection_trace.txt` 明确记录了 `203.0.113.77` 的两次直连会话（含起止时间与时长），**攻击者 IP 就写在被控端自己的文件里**。因为这句「无法溯源」而不去查，等于把最好的证据扔了。

**核查**：**归因从被控端本地痕迹入手，不依赖网络侧溯源。**

读连接记录文件，提取全部对端 IP 与会话时段；与本案已知的攻击源 IP 比对；看连接是**直连**还是经中继——直连（目的地非厂商中继段）意味着攻击者真实 IP 被直接暴露，这是本篇强度最高的证据；结合本机 ID 向厂商或委托方申请后台记录作为补强（需委托方授权）。

报告里要区分「网络侧无法独立溯源」与「本机侧已有明确 IP 记录」这两件不同的事。

<a id="section-28"></a>

#### 陷阱 12：把「未发现某工具」写成无边界的否定结论

**现象**：报告写「未发现 RustDesk 痕迹」「未发现 TeamViewer 痕迹」，不写范围。

**原因**：远控痕迹的阴性发现被多重因素限制。

**路径**：同一工具多个落点（陷阱 4），只查一处就否定的覆盖面极小。**工具**：`rtscan.py` 的 CSV 是**按关键字匹配路径名**的，**没有特征文件名会漏**。**加密凭据**：脚本**只解析明文键值对，不解析二进制加密凭据**。**`/tmp` 残留**可能已随重启消失。**已卸载**：装过、用完、卸载、清痕迹的工具在磁盘上不留任何东西。

**影响**：**阴性发现的强度被高估**，委托方据此排除「还留了其他后门」——而这恰恰是法务在案例里最想确认的问题（案例场景就是「除 WebShell 外是否还有后门」）。

**核查**：**阴性发现必须写清范围与工具自身局限。**

案例里那句写法可以直接借用：「未发现 RustDesk 痕迹——仅限本机 `/root` 与 `/home/*` 的配置目录及 systemd unit 范围内检索；**未覆盖**：`/tmp` 残留（tmpfs 且已重启）、已卸载工具、加密形态的凭据、内存中已退出的进程。」

**并且扫描脚本的已知局限必须写进报告**——它是「线索排序工具，不是判决」。输出的 `kind` 列（`path-name` / `server-addr` / `plaintext-cred`）本身就说明每条命中的来源深度不同，**不能把所有行同等对待**。
<a id="section-29"></a>

## 五、案例示例

<a id="section-30"></a>

### 5.1 AnyDesk 无人值守服务的三源印证

**场景**

查获一台 Ubuntu 20.04 云主机 `web01`（首页被篡改、WebShell 已定位）。法务追问：「除 WebShell 外，攻击者是否还留了其他后门？」

镜像 `DigiForensics.dd`（raw，100 GB），ext4 起始扇区 1181696，已只读挂载到 `/mnt/df`。此前已发现该主机被植入 WebShell，本案要回答的是「还有没有第二通道」。

**处置过程**

第一步，外联排查。按工具名过滤 `ss` 输出为空——但这不能作否定结论：

```bash
$ ss -tnap state established '( dport = :7070 or dport = :21115 )'
# 无输出

$ ss -tnap state established | grep -v '127.0.0.1\|::1'
```

全部陌生出站连接中，`anydesk` 进程正与 `203.0.113.77` 保持 ESTAB。**关键是目的地不是厂商中继段**——这符合直连模式特征，**使对端 IP 成为可用的 IOC**。这是本案突破口。

判据：中继模式下目的 IP 属厂商段，直连模式下目的 IP 就是对端。一旦确认是直连，IOC 的价值完全不同。

第二步，进程与服务化确认：

```bash
$ ps -eo pid,ppid,user,lstart,etime,cmd | grep -i anydesk
 2871     1 root 2024-03-18 01:12:31 4 days 12:31 /usr/bin/anydesk --service
```

三个字段各自说明一件事：

| 字段 | 值 | 含义 |
|---|---|---|
| `ppid` | 1 | **由 systemd 拉起**，不是终端临时执行 |
| `user` | root | 以最高权限运行 |
| `etime` | 4 days 12:31 | **持续运行**，非一次性动作 |

```bash
$ stat -c '%n mtime=%y' /etc/systemd/system/anydesk.service
/etc/systemd/system/anydesk.service mtime=2024-03-18 01:12:33
```

`ppid=1` + unit 文件存在 = 服务化安装。这与「攻击者上传二进制后手动运行一次」的临时驻留有本质区别：前者能开机自启、能长期保持。

第三步，明文口令字段检测——**本步是本案的合规边界所在**：

```bash
$ grep -nE 'Password|pwd_hash|pwd_salt|ad.anynet|key=' /etc/systemd/system/anydesk.service
9:Password=<已脱敏，值见证据附件>
```

**unit 内含 `Password=` 字段**——即无人值守访问口令。这解释了攻击者为何**无需交互确认即可直接进入**。

**本步只做记录，不做任何验证。**不尝试登录、不验证口令是否有效、不连接厂商调度服务器。

第四步，读取配置与连接记录（同样只读不验）：

```text
root/.anydesk/connection_trace.txt
* 2024-03-18 01:15:22  203.0.113.77  连接请求（直连）已接受
* 2024-03-18 01:15:40  会话结束  时长 18 秒
* 2024-03-18 02:41:07  203.0.113.77  连接请求（直连）已接受
* 2024-03-18 03:58:51  会话结束  时长 1 小时 17 分

root/.anydesk/service.conf（敏感字段已脱敏）
[client]  client-id=123456789   direct-access=203.0.113.77
[authentication]  ad.anynet.pwd_hash=<64位哈希>  ad.anynet.pwd_salt=<32位盐>
```

**只记录字段名、类型与长度指纹，不记录值本身**：`pwd_hash` 64 位、`pwd_salt` 32 位。

这两个数字足以向委托方证明「存在一套口令派生材料」，而不需要知道口令是什么。

第五步，时间链交叉验证：

| 时间 | 事件 | 来源 |
|---|---|---|
| 2024-03-17 22:48:14 | WebShell 落地 | WebShell 目录时间戳 |
| **2024-03-18 01:12:33** | **AnyDesk unit 写入** | `stat` mtime |
| 2024-03-18 01:15:22 | 首次连接请求（直连） | `connection_trace.txt` |
| 2024-03-18 03:58:51 | 会话结束，最长 1 小时 17 分 | `connection_trace.txt` |
| 2024-03-22 09:40:18 | trace 最后更新 | 文件 mtime |

远控在 WebShell 之后约 2.5 小时安装，控制链条是「先拿 WebShell，再装远控保住长期控制」——攻击者从一次性访问升级为长期控制。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 装有 AnyDesk 无人值守服务 | unit + 二进制 + 配置目录，三源 | 强 |
| 攻击者 IP 为 `203.0.113.77` | `connection_trace.txt` 与 `ss` 快照两源一致 | 强 |
| 通过直连而非中继进入 | 目的地非厂商中继段 | 强 |
| 远控在 WebShell 之后安装 | unit mtime 晚于 WebShell 2.5 小时 | 强 |
| 攻击者无需交互即可登录 | unit 内明文口令字段 | 强 |
| 至少两次会话、最长 1 小时 17 分 | `connection_trace.txt` | 中（trace 可能被截断） |

**能证明的**：该主机被安装了具备无人值守能力的远控工具、对端 IP、进入方式为直连、安装时点在 WebShell 之后。

**不能证明的**：
- **不能证明该远控当前仍可用。** 镜像为 2024-03-22 之后制作，此后状态未知
- 不能证明除 `203.0.113.77` 外无其他对端。 trace 可能被截断或清理
- 不能证明是 `203.0.113.77` 的持有者本人操作。 该 IP 可能是代理或跳板
- **不能证明该工具为攻击者所留而非设备原有配置。** 本案由「紧随 WebShell 安装」这一时序支持，但非直接证明

**未覆盖范围**：其他远控工具（RustDesk、向日葵、Todesk 等）的配置目录、`/home/*` 下各用户的远控配置、厂商侧后台的设备记录、2024-03-22 之后的任何活动。

**误判对照**

**其一，尝试登录远控账号以「验证口令是否有效」。**

unit 里那个 `Password=` 字段就在眼前，验证它是否可用只需一次登录。

判据是**取证授权的边界**：

| 允许 | 禁止 |
|---|---|
| 记录「该设备存在口令字段，位于某路径」 | **尝试连接该远控账号或设备** |
| 用配置中的 IP 佐证「与哪些 IP 有过连接」 | **用授权码或 key 登录厂商调度服务器** |
| 记录字段存在性、类型、长度指纹 | 在报告/聊天/邮件中传播明文 |
| 立即登记并按流程移交 | **私留作后续处置备用** |

**登录他人远控账号属实质性入侵行为**，可能构成非法侵入计算机信息系统罪。哪怕目标本就被入侵，委托方授权的是「取证」而非「登录」，一旦发生无法辩解。

按错误判据走的代价：分析方登录成功并在报告中写「口令有效」，这条证据在法律上不可采信，整个案件的材料都受牵连。而它换来的信息量仅仅是「口令能用」——而这个结论从字段存在性已经可以推断。

其二，把「按工具名过滤无输出」写成「未安装远控工具」。

`ss` 按端口过滤无输出，看起来是干净的。但本次最终恰恰查出了 AnyDesk。

判据是**网络连接的过滤维度**：

| 过滤维度 | 本案结果 | 可靠性 |
|---|---|---|
| 按工具默认端口 | 无输出 | **低**，端口可改 |
| 按进程名 | 有命中 | 中 |
| 按非厂商段的陌生出站 | 有命中 | **高** |

**远控工具的端口可配置，服务名可伪装。**因此判据是**先看全部陌生出站连接，再反查进程**，而不是先按工具特征筛。

按错误判据走的代价：分析方用端口过滤得出「未发现远控」，写进报告。委托方据此认为只有 WebShell 一种入侵途径，不去检查第二通道——而攻击者恰恰通过第二通道在 4 天内进行了多次远程会话。

其三，把中继 IP 当成攻击者 IP 写进 IOC。

如果本次是厂商中继模式，`ss` 中出现的会是厂商段 IP。把它当作攻击者 IP 提交给委托方，会造成错误溯源。

判据是**目的 IP 的归属判定**：

| 模式 | 目的 IP | IOC 价值 |
|---|---|---|
| 直连 | **对端真实 IP** | 直接可用 |
| 中继 | 厂商调度段 | **不可用**，需向厂商申请对端披露 |
| P2P 打洞 | 双方公网 IP | 需结合 NAT 类型判断 |

本案之所以能给出 `203.0.113.77`，正是因为确认了直连。这个确认必须写在 IOC 之前，不能省略。

按错误判据走的代价：委托方把厂商中继 IP 提交给网络运营商协查，查询无果，同时真正的对端 IP 未被追查，溯源线索中断。

**其四，把「存在明文口令字段」写成「口令已泄露」。**

`Password=` 字段在文件中，意味着任何拿到该文件的人都能看到。**但这与「口令已泄露给攻击者」是两件事。**

判据是**字段存在与凭据使用的区别**：

| 事实 | 能推出 |
|---|---|
| 文件中存在 `Password=` 字段 | 工具支持无人值守 |
| 该文件在事发时位于 `/etc/systemd/system/` | root 可读 |
| trace 显示该配置生效 | **攻击者已用该配置登录** |

**第三项才是「口令被使用」的证据。**本案 trace 中「连接请求（直连）已接受」直接给出了这个证据。前两项只说明配置存在，不说明被使用过。

按错误判据走的代价：委托方据此对外发布「服务器管理员在配置文件里明文存储口令」，把注意力引向内部管理问题，而真正的问题是**该配置被攻击者建立并使用**。

其五，把 trace 的最后一条时间当作使用终点。

`connection_trace.txt` 最后更新于 2024-03-22 09:40:18，镜像是之后制作的。

判据是**「文件最后修改」与「最后一次使用」的区别**：

| 时间点 | 含义 |
|---|---|
| trace 最后一条记录 | 最后一次**被记录**的会话 |
| trace 文件 mtime | 最后一次**写入** |
| 工具进程 etime | 最后一次**启动** |
| 镜像制作时间 | 观察的截止点 |

**四者中最小的那一个，才是证据能支撑的最晚时点。**正确表述是「至少使用至 2024-03-22 09:40」，不能写「此后未再使用」。

按错误判据走的代价：报告写「远控最后一次使用是 3-22，此后无活动」，委托方据此判断攻击者在 3-22 已放弃。而实际上 3-22 到镜像制作之间可能还有会话，只是 trace 未记录。

<a id="section-31"></a>

### 5.2 其他远控工具的阴性结论与范围限定

**场景**

承接 5.1。委托方在得知存在 AnyDesk 后追问：「**还有别的吗？**」这个追问需要一份严格限定的阴性结论——因为远控工具的痕迹分布在多个位置，漏查一处就可能给出错误的否定。

委托方的原话是：「那就说没有其他远控。」

**处置过程**

第一步，先把「远控工具痕迹可能出现在哪些位置」列全——**阴性结论的价值取决于覆盖清单的完整度**：

```text
检查位置清单：
1. systemd unit 目录        /etc/systemd/system/
2. 服务用户级 unit 目录     /usr/lib/systemd/system/、/lib/systemd/system/
3. 进程表                   ps -eo cmd
4. 监听端口                 ss -tulpn
5. 出站连接                 ss -tnap state established
6. 配置目录（root）         /root/.anydesk/、/root/.config/rustdesk/ 等
7. 配置目录（各用户）       /home/*/.anydesk/、/home/*/.config/rustdesk/
8. 安装包痕迹               /var/log/dpkg.log、/var/log/apt/history.log
9. 计划任务                 /etc/cron.d/、/var/spool/cron/
10. 启动项                  /etc/rc.local、~/.bashrc、~/.profile
11. 内核模块                lsmod
12. 桌面自启动（若有图形）   ~/.config/autostart/
```

第二步，按清单逐项检查：

```bash
$ grep -rilE 'anydesk|rustdesk|todesk|teamviewer|sunlogin|ammyy|vysor' \
    /etc/systemd/system/ /usr/lib/systemd/system/ /lib/systemd/system/ 2>/dev/null
/etc/systemd/system/anydesk.service        ← 唯一命中

$ ps -eo user,pid,lstart,cmd | grep -iE 'anydesk|rustdesk|todesk|teamviewer'
root 2871 2024-03-18 01:12:31 /usr/bin/anydesk --service     ← 唯一命中

$ ls -d /root/.*anydesk /root/.*rustdesk /root/.*todesk \
      /home/*/.*anydesk /home/*/.*rustdesk /home/*/.*todesk 2>/dev/null
/root/.anydesk                                               ← 唯一命中

$ grep -cE 'anydesk|rustdesk|todesk' /var/log/dpkg.log /var/log/apt/history.log
/var/log/dpkg.log:3
/var/log/apt/history.log:1
```

第三步，`dpkg` 记录的核对 —— **这一步能给出安装时间与来源**：

```bash
$ grep -E 'anydesk' /var/log/dpkg.log
2024-03-18 01:11:47 hostname dpkg: installed anydesk:amd64 (6.3.0.8)
2024-03-18 01:12:29 hostname dpkg: installed anydesk-common (6.3.0.8)

$ grep -A3 -E 'anydesk' /var/log/apt/history.log
Start-Date: 2024-03-18 01:10:52
Commandline: apt-get install -y anydesk
```

`dpkg.log` 给出精确到秒的安装时间 01:11:47，与 unit 的 `mtime` 01:12:33 相差 46 秒。

顺序自洽：先启动 apt（01:10:52），装包（01:11:47），写 unit（01:12:33），进程于 01:12:31 启动。

第四步，确认没有第二工具的痕迹后，把阴性结论的范围钉死：

```bash
$ for d in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system \
           /root /home; do
    printf '%-28s ' "$d"
    grep -rilE 'rustdesk|todesk|teamviewer|sunlogin' "$d" 2>/dev/null | wc -l
  done
/etc/systemd/system         0
/usr/lib/systemd/system     0
/lib/systemd/system         0
/root                       0
/home                       0
```

```text
未覆盖范围：
- /home/* 各用户家目录下的全部隐藏目录（部分权限受限，可能未读全）
- 已删除但仍被进程持有的可执行文件（需从内存或 /proc/*/exe 入手）
- 内核模块形式的历史驻留（本机 lsmod 仅检查已加载项，未查历史加载）
- 用户态之外：LD_PRELOAD、cron 一次性任务、systemd timer
- 其他主机：本案仅检查 web01，同集群其余节点未检查
- 厂商侧后台记录：可查该设备 ID 在厂商处的授权历史
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 检出 12 个检查位置，仅 AnyDesk 一种工具命中 | 逐位置检查输出 | 强 |
| AnyDesk 安装时间为 2024-03-18 01:11:47 | `dpkg.log` 精确到秒 | 强 |
| 安装时间与 unit 写入、进程启动三者顺序自洽 | 四源时间差在 101 秒内且顺序正确 | 强 |
| `apt/history.log` 记录 `apt-get install -y anydesk` | Commandline 字段 | 强 |
| 在列明的 12 个位置内未检出第二种远控工具 | 逐位置计数均为 0 | 中（限于这 12 个位置与这 6 种工具名） |

**阴性结论（严格限定）**：

> 在 `web01` 的 `/etc/systemd/system/`、`/usr/lib/systemd/system/`、`/lib/systemd/system/`、`/root`、`/home` 五个位置、针对 `anydesk`、`rustdesk`、`todesk`、`teamviewer`、`sunlogin`、`ammyy` 六种工具名的字符串检索范围内，除 AnyDesk 外**未检出**第二种远控工具的安装痕迹或配置目录。
>
> 该阴性结论**不覆盖**：权限受限未读全的家目录、已删除但仍被进程持有的可执行文件、内核模块形式的历史驻留、`LD_PRELOAD` 与 cron/systemd timer 形式的一次性任务、以及本集群其余节点。**「未检出」不等于「不存在」。**

**能证明的**：AnyDesk 的安装时间、安装命令与安装包版本、以及在列明范围内未见第二种工具。

**不能证明的**：
- **不能证明主机上只有一种远控工具。** 检查范围与工具名均为有限枚举
- **不能证明攻击者未使用非远控类的持久化手段。** 本次未查内核模块与一次性任务
- **不能证明同集群其他主机未被植入。** 本次仅查 `web01`

**未覆盖范围**：见上列六项。

**误判对照**

其一，把「未检出第二种工具」写成「主机上只有 AnyDesk」。

委托方要的是这句话，但这句话的覆盖面远超本次检查。

判据是**阴性结论必须同时携带三样东西**：

| 要素 | 本案内容 |
|---|---|
| 检查范围 | 5 个位置路径 |
| 检查方法 | 对 6 种工具名的字符串检索 |
| 未覆盖项 | 6 类（含权限受限与其他主机） |

**范围与方法越窄，结论的限定就越强。**一旦省略范围，「只有 AnyDesk」就变成了一句无法验证的断言。

按错误判据走的代价：委托方据此向领导汇报「服务器只有一种后门，已清除」，而实际上 `LD_PRELOAD` 注入与 cron 一次性任务都不在这 6 个工具名里，从未被检索。

**其二，用工具名字符串检索当作「未安装」的判据。**

`grep -ri anydesk` 这类检索，**只能发现留下明文配置痕迹的工具**。

判据是**远控落地形态的差异**：

| 落地形态 | 字符串检索能否发现 |
|---|---|
| 明文配置目录 | **能** |
| systemd unit 文件 | **能** |
| 内核模块 | **不能** |
| **静态链接且无配置文件** | **不能** |
| **改名后的二进制** | **不能** |

**任何二进制重命名都能绕过字符串检索。**因此判据是**阴性结论必须说明检查方法的能力上限**，而不是笼统地说「查过了」。

按错误判据走的代价：委托方在报告里写「已确认无其他后门」，实际所做的只是一轮字符串匹配。**方法能力被报告的措辞夸大了。**

其三，把 `dpkg.log` 的存在等同于「有安装记录」。

`dpkg` 日志存在只说明系统用过 apt，不说明查的目标工具在里面。

判据是**必须检索到具体包名**：

```bash
$ grep -cE 'anydesk|rustdesk|todesk' /var/log/dpkg.log
3
```

**返回 3 才是阳性，返回 0 才是阴性。**同样地，`/var/log/apt/history.log` 中查 `Commandline` 行才对应具体安装动作。

按错误判据走的代价：分析方只确认「日志文件在」就写「已检查安装记录」，委托方追问具体时间时答不上来，报告出现一处无法复核的表述。

**其四，把多源时间一致当作时间线绝对可靠。**

unit `mtime`、进程 `lstart`、`dpkg.log`、`apt/history.log` 四者落在 101 秒内，看起来互相印证。但四者的时间来源并不相同。

判据是**时间戳的生成方**：

| 来源 | 生成机制 | 可信度 |
|---|---|---|
| `dpkg.log` 与 `apt/history.log` | **包管理器写入时的系统时钟** | 高 |
| unit `mtime` | **文件系统写时间，可被 touch 改** | 中 |
| 进程 `lstart` | 进程创建时刻，取自 `btime` + jiffies | 中 |

`mtime` 可以用 `touch -d` 任意设置——这在入侵场景中恰恰是常见的反取证手法。

判据是：当 `dpkg.log` 与 `mtime` 不一致时，以 `dpkg.log` 为准；当包管理日志被清空时，`mtime` 只能作为参考，并须在报告中注明其可篡改性。

按错误判据走的代价：报告以 `mtime` 为时间锚点，若攻击者事后 `touch` 过该文件，整个安装时间线被前移或后移，而分析方毫不知情。

**其五，把「未覆盖项」当作免责声明而非行动项。**

报告末尾列了六条未覆盖路径，但委托方认为那是「标准格式」，没有据此推进。

判据是**未覆盖项应当转为带优先级的待办**：

```text
待办（按优先级）：
1. 【高】补查 /home/* 下权限受限目录 → 需 root 之外的用户配合或重新提权
2. 【高】从内存镜像查已删除但仍被持有的远控可执行文件
3. 【中】查同集群其余节点的 systemd unit 与进程表
4. 【中】查 LD_PRELOAD 与 cron/systemd timer 的一次性任务
5. 【低】向厂商后台调取该设备 ID 的授权历史
```

**阴性结论的价值在于指路，不在于结案。**未覆盖项写成清单而不写成待办，等于把球踢回给委托方却不给下一步。

按错误判据走的代价：委托方读完报告认为「远控问题已查清」，关闭了工单，而这六条待办中任意一条都可能发现第二通道。

<a id="section-32"></a>

### 5.3 远控凭据的现场登记与移交流程

**场景**

承接 5.1 与 5.2。分析过程中陆续发现多类远控凭据材料：AnyDesk 的 `Password=` 字段与 `ad.anynet.pwd_hash`、`ad.anynet.pwd_salt`、以及某工具目录下的临时授权码。

这些材料既是案件的关键证据，也是最容易在流转过程中扩散的东西。委托方要求：「**这些都写进报告里吧，写清楚点。**」

**这一步需要一套明确的登记与移交流程。**明文写进报告在多数情况下不是正确做法。

**处置过程**

第一步，发现即登记——**只记录存在性与结构，不记录值**：

```text
证据登记单 EV-2024-0318-007
─────────────────────────────────────────────
字段名   ad.anynet.pwd_hash        位置  /root/.anydesk/service.conf
类型     十六进制字符串
长度     64 字符
值       不转录（受控存储，见下方引用）
处置     仅登记，不验证

字段名   ad.anynet.pwd_salt        位置  /root/.anydesk/service.conf
类型     十六进制字符串
长度     32 字符
值       不转录
处置     仅登记，不验证

字段名   Password                  位置  /etc/systemd/system/anydesk.service 第 9 行
类型     明文字符串
值       不转录
处置     仅登记，不验证
─────────────────────────────────────────────
```

**「长度 64 字符」本身就是有价值的证据**——它告诉委托方这是一家特定厂商的派生方案，而不是简单的明文口令。

第二步，把值写入受控存储并与报告分离：

```bash
# 值单独入加密包，与报告分离
$ gpg --symmetric --cipher-algo AES256 \
    --output creds-EV-007.gpg credentials.txt
$ rm -f credentials.txt          # 明文不留在工作区
```

**报告里的写法**：

```markdown
已在 `/root/.anydesk/service.conf` 与 `/etc/systemd/system/anydesk.service`
中检出远程控制凭据材料 3 项：

- `ad.anynet.pwd_hash`：64 字符十六进制串（口令派生值）
- `ad.anynet.pwd_salt`：32 字符十六进制串（盐值）
- `Password`：明文字符串（无人值守访问口令）

三者的**存在性与长度指纹**已登记为证据 EV-2024-0318-007。
**值本身未转录、未验证**，存于受控加密包 `creds-EV-007.gpg`，
按流程移交。任何需查验值的环节须经委托方书面授权。
```

第三步，把处置建议的边界写清：

```text
可以给出（建议）：
- 在厂商后台吊销该设备的设备 ID 与授权
- 重置该远控工具的访问凭据
- 变更 root 口令并检查是否存在其他共享凭据
- 检查其他主机是否存在同一设备 ID 注册

不可以代为执行：
- 登录厂商后台操作（需委托方账号与授权）
- 使用该凭据连接任何设备
- 将凭据提供给第三方安全厂商做信誉查询
```

第四步，把「未做验证」这件事本身写进报告——**这是一个应当主动声明的负面事实**：

```markdown
【本次未执行的验证动作（声明）】

以下动作技术上可行，但因超出取证授权范围而未执行：

1. 未使用 `Password=` 值尝试登录该远控设备
2. 未使用 `ad.anynet.pwd_hash` 与 `pwd_salt` 做口令验证
3. 未登录厂商调度服务器查询该设备的会话记录
4. 未用该 client-id 向厂商申请对端 IP 披露

上述四项均涉及实质性访问第三方账户或设备，
需委托方另行出具书面授权后方可进行。
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 检出 3 项远控凭据材料 | 字段名、位置、类型、长度 | 强 |
| `pwd_hash` 为 64 字符十六进制串 | 长度指纹，不涉及值 | 强 |
| 存在明文 `Password` 字段 | 字段存在性与所在行号 | 强 |
| 凭据值未转录、未验证 | 处置记录 | 强（可自证） |
| 凭据值存于受控加密包并按流程移交 | 登记单 + 移交签收 | 强 |

**能证明的**：该主机上存在何种凭据材料、位于何处、类型与长度，以及分析方在授权范围内所采取的处置。

**不能证明的**：
- **不能证明该凭据当前是否仍然有效。** 未验证，按授权范围
- **不能证明该凭据的使用次数与对端。** 需厂商侧或委托方另行授权
- **不能把「凭据存在」写成「凭据被使用过」。** 使用证据来自 `connection_trace.txt`，不来自凭据本身

**未覆盖范围**：凭据有效性、厂商侧会话记录、对端 IP 的正式披露、以及其他主机上的同一设备 ID。

**误判对照**

**其一，把明文凭据直接写进报告正文。**

委托方说「写清楚点」。而报告是会被广泛传阅的文档，明文一旦进入，就脱离了控制。

判据是**证据材料的分级与流转**：

| 材料 | 可否进报告正文 |
|---|---|
| 字段名、类型、长度 | **可以** |
| 值的哈希（对该值再哈希） | 可以 |
| **值本身** | **不可以** |
| 值的部分片段 | **不可以**，前缀同样可能泄露 |

**长度指纹已经足够**——64 位与 32 位这两个数字能证明「存在一套完整的口令派生材料」。委托方要判断是否有理由怀疑被滥用，这个信息已经够了。

按错误判据走的代价：报告经多个部门转发，值出现在邮件与聊天记录中。**一旦扩散，唯一的补救是把该凭据作废**——而作废会销毁证据本身，使这条发现失去价值。**扩散与灭失，二选一，都不可逆。**

**其二，把「登记了凭据」写成「验证了凭据」。**

登记单上有值，就容易在报告里写成「已确认有效」。

判据是**三个动作必须分开表述**：

| 动作 | 本案状态 |
|---|---|
| 记录字段存在性 | **已完成** |
| 转录值到受控存储 | 已完成，进入加密包 |
| **验证值是否可用** | **未完成，超出授权** |

**「已登记」与「已验证」是两个层次的结论。**报告里若混用，会让委托方误以为凭据已被确认可用，从而基于一个未经验证的判断采取行动（比如对外声称「攻击者持有效凭据」）。

按错误判据走的代价：委托方在汇报中写「已确认攻击者持有有效访问凭据」，而分析方实际从未验证过。这个结论一旦被对方质疑，报告的可信度受牵连。

**其三，把处置建议写成操作指令。**

报告写「建议吊销该设备 ID」，委托方直接照做，或者更糟——分析方自己代为登录厂商后台操作。

判据是**建议与执行的边界**：

| 类别 | 内容 |
|---|---|
| **建议**（可写） | 吊销、重置、检查其他主机 |
| **执行**（不写、也不代做） | 登录厂商后台、变更他方设备状态 |

**取证方的角色是提供依据，不是承担运维动作。**代为执行的后果有两层：一是操作需要委托方账号，本身就是一次未授权的第三方系统访问；二是执行后的状态变化会改变证据环境。

按错误判据走的代价：分析方登录厂商后台操作，平台日志显示该设备 ID 被访问；这份日志若出现在案件之外（例如厂商的安全评估中），会成为分析方未授权访问第三方系统的记录。

**其四，不主动声明「未做什么」。**

报告只写做了什么，没人问就不提未做的部分。

判据是**未执行动作的声明义务**：

| 情形 | 是否需声明 |
|---|---|
| 因超授权未做 | **必须声明** |
| 因技术条件做不到 | 必须声明 |
| 因不在委托范围内 | 建议声明 |

主动声明「未执行」的价值在于：它把合规责任显式交回委托方，并给出一条可行的补做路径。不声明则默认读者会假设「全都做了」，一旦发现没做，性质就从「未做」变成「隐瞒」。

按错误判据走的代价：委托方在另一份法律文书中引用本报告，称「已对远控凭据进行验证」，而实际从未验证。这已不是技术问题，而是报告使用方被误导的法律风险。

---
<a id="section-33"></a>

## 六、扩展阅读方向

**先把「外联」这个判据放到通用体系里。** 本篇的入口动作是看连接表，但为什么一条陌生出站连接值得追，需要先建立连接证据的完整读法与可采性边界。

- [网络连接与流量痕迹](../../memory/memory-artifact/memory-artifact-memory-network-artifacts.md)：`ss`/`netstat` 之外补齐 `/proc/net/tcp` 原始六元组、socket inode 反查进程，以及已关闭连接的残留。
- [网络流量与 PCAP 取证](../../memory/memory-network/memory-network-pcap.md)：当服务器侧日志被轮转清空时，从流量侧重建会话与 SNI，交叉验证连接表里的目的地。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md)：连接表这类易失证据的采集时机，以及为什么「先截图后分析」的顺序不能反。

**再补 Linux 主机侧的痕迹体系。**远控工具的落点虽在工具自带目录，但「谁装的、什么时候装的、怎么启动的」必须回到通用持久化痕迹里找答案。

- [计划任务与持久化痕迹](../../computer/computer-persistence/computer-persistence-scheduled-tasks-and-persistence.md)：systemd unit 之外，cron、at、rc.local、profile 脚本同样是开机自启的落点。
- [SSH 痕迹与密钥取证](../../computer/computer-persistence/computer-persistence-ssh.md)：用 `auth.log`、`wtmp`、`last` 区分合法运维登录与横向移动，并确认是否存在免密通道。
- [Shell 痕迹与命令历史](../../computer/computer-shell/computer-shell-shell.md)：从 `.bash_history`、`HISTTIMEFORMAT` 与时间戳缺失情况判断命令行是否被清理。
- [时间线重建](../../computer/computer-log/computer-log-linux-timeline-reconstruction.md)：把 systemd 首次启用时间、文件 mtime、日志首行时间统一到一条时间轴上，支撑本篇反复强调的「时间交叉」。

**邻近的入口侧议题。**远控往往不是第一现场，站点与面板才是。

- [Nginx 与 Apache 配置取证](../server-web/server-web-nginx-apache.md)：站点目录、access log 与 upload 路径，确认外联工具的安装包是否经由 Web 上传。
- [WebShell 工具流量特征](../server-web/server-web-webshell-traffic-patterns.md)：远控与 WebShell 并存时的先后关系判定——先有 shell 还是先有远控，决定了入口与定性的不同。
- [CDN 识别与源站挖掘](../server-web/server-web-cdn.md)：当可疑 IP 是 CDN 出口时，如何回溯真实源站与真实客户端。
- [Web 攻击痕迹还原](../server-log/server-log-web-attack-trace-reconstruction.md)：漏洞利用与后落地的时序对齐，解释远控工具是「下载安装」还是「提权后安装」。

**最后是判据与反例，以及合规边界。**这一组决定结论能不能站得住。

- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md)：攻击者最常清理的就是 `.bash_history` 与日志行，理解手法的**识别特征**才能判断阴性发现的真实范围。
- [注册表与用户行为痕迹](../../computer/computer-registry-log/computer-registry-log-user-activity-artifacts.md)：若被控主机是 Windows，`%APPDATA%` 下的 QuickSupport 日志、Prefetch 与 AmCache 是等价线索。
- [内存中的凭据与密钥](../../memory/memory-artifact/memory-artifact-memory-credentials-and-keys.md)：已卸载工具的内存驻留与注入型远控，解释「磁盘已清干净但连接仍在」的现象。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md)：读到无人值守口令、临时授权码、可信设备列表时，**离线分析、脱敏呈现、密级登记**的具体做法与红线。
<a id="section-34"></a>

## 七、命令速查

```bash
# ===== 1. 外联排查（第一优先级）=====
ss -tunap | grep -v '127.0.0.1'          # 出站连接（含进程名）
netstat -tunap 2>/dev/null | grep -v '127.0.0.1'   # 老系统无 ss 时的等价写法
ss -tulnp                              # 监听端口
iptables -L -n | head -50
iptables -L -n -v | grep -E 'ACCEPT|REJECT' | head -30
nft list ruleset 2>/dev/null | head -60 # nftables 环境

# ===== 2. 进程与服务 =====
ps auxwwf | grep -viE 'grep|\[' | head -40
ps -eo pid,ppid,user,lstart,etime,cmd --sort=-etime | head -30
systemctl list-unit-files --state=enabled | grep -iE 'todesk|anydesk|sunlogin|rustdesk|teamviewer|xrdp'
ls -l /mnt/df/etc/systemd/system/*.service 2>/dev/null

# ===== 3. 反查软件痕迹 =====
find /mnt/df -xdev \( -iname '*todesk*' -o -iname '*anydesk*' -o -iname '*sunlogin*' \
  -o -iname '*rustdesk*' -o -iname '*teamviewer*' -o -iname '*finalshell*' \) 2>/dev/null
ls -l /mnt/df/etc/rc.d/init.d/ /mnt/df/etc/init.d/ /mnt/df/etc/xdg/autostart/ 2>/dev/null
find /mnt/df/tmp /mnt/df/var/tmp -type f \( -name '*.ko' -o -name '*.bin' -o -name '*.AppImage' \) 2>/dev/null | head
ls -l /mnt/df/root/.anydesk/ /mnt/df/etc/anydesk/ 2>/dev/null
ls -l /mnt/df/root/.config/RustDesk/ /mnt/df/root/.config/rustdesk/ /mnt/df/etc/rustdesk/ 2>/dev/null
ls -l /mnt/df/root/.Xshell/Xshell/Sessions/ 2>/dev/null
grep -iE 'todesk|anydesk|sunlogin|rustdesk|teamviewer|finalshell' \
  /mnt/df/root/.bash_history /mnt/df/home/*/.bash_history 2>/dev/null

# ===== 4. 明文口令检测（高价值，务必执行）=====
grep -rn -iE '^[[:space:]]*(Password|Passwd)[[:space:]]*=' \
  /mnt/df/etc/systemd/system/ /mnt/df/lib/systemd/system/ 2>/dev/null

# ===== 5. 读取配置与提取外联线索 =====
for f in service.conf system.conf ad.trace connection_trace.txt; do
  echo "== $f"; head -40 "/mnt/df/root/.anydesk/$f" 2>/dev/null
done
cat /mnt/df/root/.config/RustDesk/RustDesk.toml 2>/dev/null
strings /mnt/df/opt/xxx/bin/xxx 2>/dev/null | grep -iE 'server|host|port|token|password|domain' | head -20

# ===== 6. 批量扫描（脚本全文见 3.4 节）=====
python3 rtscan.py /mnt/df > /evidence/rtscan-report.csv
column -s, -t /evidence/rtscan-report.csv | less -S

# ===== 7. 确认影响面与固定（只 cp 不 mv）=====
stat -c '%n  size=%s  mtime=%y  ctime=%z' \
  /mnt/df/root/.anydesk/service.conf /mnt/df/etc/systemd/system/anydesk.service
grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' \
  /mnt/df/root/.anydesk/connection_trace.txt 2>/dev/null | sort | uniq -c | sort -rn
find /mnt/df/root /mnt/df/home -type f \
  \( -name '*.zip' -o -name '*.rar' -o -name '*.7z' \) -newermt '2024-01-01' 2>/dev/null | head -20
grep -iE 'rdesktop|xfreerdp' /mnt/df/var/log/auth.log /mnt/df/var/log/secure 2>/dev/null | head
grep -iE 'mstsc|rdesktop|xfreerdp' /mnt/df/root/.bash_history 2>/dev/null
mkdir -p /evidence/remote-tool
cp --preserve=all /mnt/df/etc/systemd/system/anydesk.service /evidence/remote-tool/
cp -rp /mnt/df/root/.anydesk /evidence/remote-tool/dot-anydesk 2>/dev/null
cp -rp /mnt/df/root/.config/RustDesk /evidence/remote-tool/dot-rustdesk 2>/dev/null
find /evidence/remote-tool -type f -exec sha256sum {} + | tee /evidence/remote-tool/hashes.txt
umount /mnt/df && sha256sum -c /evidence/evidence.sha256

# ===== 合规提醒 =====
# 发现的凭据：只登记"字段存在性 + 路径 + 证据编号"，不写明文、不尝试连接、立即移交
```

> **本篇延伸**：攻击链上游的面板、WebShell、CDN 隐藏的源站分别见[第 02 篇](server-panel-bt-panel-forensics.md)、[第 06 篇](../server-web/server-web-webshell-detection.md)、[第 08 篇](../server-web/server-web-cdn.md)；服务器现场的时间压力与抢占式固定见[第 01 篇](server-panel-linux-server-artifact-map.md)。

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 服务器与 Web 取证 — 远程控制工具痕迹」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《远程控制工具痕迹》（CC BY-SA 4.0）`

文中 `DigiForensics.dd` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
