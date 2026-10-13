---
title: "远程工具凭据的离线固定"
slug: "crypto-app-remote-tool-credential-preservation"
canonical: "https://www.digiforensics.cn/wiki/crypto-app-remote-tool-credential-preservation"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:52+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "crypto"
space: "加密与密码取证"
node_path: ["应用与数据库加密"]
---

# 远程工具凭据的离线固定

<a id="section-1"></a>

## 一、概述

如果你接过一台被控嫌疑的 Windows 机器，需要回答委托方最常问的那个问题——**"这台机器什么时候被谁控制了、控到了哪些主机"**——你并不需要解出任何密码。设备 ID、对方识别码、连接时间线这三样在多数远控工具里是**明文**存的，它们躺在几个配置文件和日志文件里，等着你用关键字去捞。

所以本篇要解决的第一个问题是：远控取证的瓶颈通常不在解密，而在定位与时间相关性。

分析员真正的困难不在密码学。你不知道工具把配置放在了哪，不知道哪个目录才是这台机器实际在用的那一份，也不知道"装过"和"被控过"之间那道沟要用什么证据才跨得过去。

本篇把"关键词全盘扫描 → 判定归属与时间 → 读明文字段 → 按格式分级处置"这条主链一次走通。明文能解决的，绝不多走一步。

第二个问题是**边界划在哪里**。本篇涉及的工具里有一半（Navicat、Xshell、FinalShell、WinSCP）根本不是远控软件，是业务客户端。

但它们保存的数据库与 SSH 凭据，在案件里的价值往往比远控痕迹更高。

哪些该固定、哪些能还原、哪些**必须停在"存在"这一层**，本章要交给你的就是这个判断。尤其是单向哈希字段——把它当成"解不开的加密"反复换工具，既浪费时间，又容易滑向越界。

第三个问题是**合规**。

本领域最容易犯的错不是技术错误，是性质错误：用检材里还原出来的凭据去连一下目标主机，看看是不是真的有效。

这个动作会把你的工作从"取证"变成"入侵"，同时在远控服务端留下你的登录时间与来源 IP，污染证据。

这条红线的完整论证见 2.5，**没有例外条款**。

**本篇处理的证据形态**（这些文件名与字段名是判断"是什么工具、什么代次"的第一手依据）：

| 工具 | 关键文件或位置 | 决定性的字段 |
|---|---|---|
| AnyDesk | `service.conf`（`%ProgramData%` 或 `%APPDATA%`） | `ad.anynet.id`、`ad.anynet.pwd_hash` + `pwd_salt` + `token_salt` |
| 向日葵 | 注册表 `HKU\.DEFAULT\Software\Oray\SunLogin\SunloginClient\SunloginInfo`；旧版 `config.ini` | `fastcode`、`encry_pwd` |
| TeamViewer | `Connections_incoming.txt`（入向成功）、`connections.txt`（出向）、`TeamViewer15_Logfile.log` | 对方 ID、UTC 起止时间、认证事件行 |
| ToDesk | `%APPDATA%\ToDesk`、`C:\ProgramData\ToDesk\` | `access_pin_hash`（PBKDF2 加盐，单向） |
| Navicat | `*.tncf` 连接配置 | 主机名/端口/用户名为明文，密码为 AES |
| WinSCP | 注册表 `HKCU\Software\Martin Prikryl\WinSCP 2\Sessions` | `Password` 值（代次决定是可逆变换还是 AES-256-CBC） |
| FinalShell | `conn.json` | `password` 字段（AES，密钥与本机绑定） |
| RustDesk | `RustDesk.toml` | 配置项版本差异大，先看文件本身 |

**记住这张表是起点，不是事实表。**

同一款工具的配置位置会在版本间迁移，向日葵从 `config.ini` 移到注册表就是典型。所以任何时候只在一个位置拿到空值，正确动作是**换位置再找一次**，而不是下"不存在"的结论。

表里的路径最终要靠两件事确认：**目录或键是否存在**、**文件或值的修改时间是否与本案时间窗吻合**。

版本一变，这张表就过期。所以本篇的操作步骤刻意从"全盘关键字扫描"开始，而不是从查表开始。

**本篇的处置主链**是四步，每一步都有明确的产出与停手条件：

| 步骤 | 动作 | 产出 | 什么时候就该停 |
|---|---|---|---|
| 1 | 全盘关键字扫描 | 命中路径清单 + 大小 + 最后修改时间 | 零命中时先核对关键字覆盖面，再下结论 |
| 2 | 判定归属与时间相关性 | 系统级 or 哪个用户、是否落在时间窗内 | 时间不吻合就到此为止，不写"被控" |
| 3 | 读明文字段 | 设备 ID、IP、主机名、连接记录 | **多数案件到这一步就结束了** |
| 4 | 判断并还原密码字段 | 字段按明文 / 编码 / 加密 / 单向哈希四类定级 | 判定为单向哈希时**到此为止，不换工具** |

委托方的问题往往是"这台机器被谁控过、什么时候"，而这三个答案都是明文。解出口令在技术上更有趣，对交付却毫无增量，却把处置风险从"取证"整体推向了"入侵"。本篇第四章的合规红线不是形式主义，它就是这条判断的具体保障。

**在取证流程中的位置**：本篇属于**分析**环节的前段，紧跟在镜像制作之后。

**上游依赖**是[镜像制作](../../imaging/imaging-acquire/imaging-acquire-disk-imaging-and-evidence-preservation.md)与[只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md)。你需要一个只读挂载点，以及一份已经固定哈希的镜像。[注册表取证](../../computer/computer-registry-log/computer-registry-log-registry-forensics.md)里的 hive 离线提取手法，是本篇读取日葵、TeamViewer、WinSCP 三个工具的共同前置。

**下游支撑**的是时间线重建。定位与时间判定做完后，产出直接喂给[时间线重建](../../computer/computer-log/computer-log-linux-timeline-reconstruction.md)与其他痕迹源做交叉印证，跨文件的时序比较必须先统一到同一时间基准。同一批远控软件在 Linux 侧的行为侧形态见[远程控制工具痕迹](../../server/server-panel/server-panel-remote-control-artifacts.md)。

**本篇的产出形态**是一张结构化记录表：工具与版本、配置完整路径、归属主体、最后修改时间（UTC）、字段按 2.2 四类分级、关键明文值（脱敏）、关联日志路径与时间范围、处置记录（是否尝试还原、是否连接——后者恒为"否"）。

这张表可以直接进报告，也可以作为时间线重建的输入。

工具是否安装、属于哪个用户、最后活动时间、是否存在成功入向连接、对方标识与 IP 是什么、连接时间窗落在哪里、访问口令是否被设置过、是否存在哈希或密文凭据材料及其类型。

以下三类信息需要其他证据补充。

单向哈希字段（`pwd_hash`、`access_pin_hash`）的明文——那不是能力不足，是单向函数的定义，换工具不会改变结果。设了主密码的 WinSCP 与绑定用户环境的 Navicat 的密码内容。还有**连接是否真的发生过**——配置存在只能证明装过，成功连接必须靠 `Connections_incoming.txt` 或详细日志里的认证事件行。

至于**对方主机上发生了什么**，那超出委托授权范围，本篇明确不涉及。

**读者前提**：你需要先掌握注册表 hive 的离线提取与查询（[注册表取证](../../computer/computer-registry-log/computer-registry-log-registry-forensics.md)）、能读懂 ini/toml/json/注册表值这几种配置载体、以及时间戳换算的基本纪律（[时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md)）。

如果你的检材是刚做完镜像、还没固定过哈希，本篇的一切结论都不具备可辩护性，先回去补[证据保管链与委托证明](../../fundamentals/fundamentals-chain/fundamentals-chain-chain-of-custody-and-authorization.md)。口令哈希的处置方法论不在本篇，见[通用密码恢复](crypto-app-passware-and-password-recovery.md)的授权与最小化要求。


这句话里每一个限定词都有对应章节——"全盘范围"对应第四章陷阱 1，"时间窗"对应陷阱 8，"成功入向"对应陷阱 9，"未使用凭据连接"对应陷阱 7。如果你写不出带这些限定词的句子，说明本篇的哪一节没读进去。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 配置定位：先分"每用户"还是"每机器"

同一款工具往往有两套配置目录，**选错会得出"该机未安装"的错误结论**：

| 安装形态 | 目录 | 取证含义 |
|---|---|---|
| **免安装/绿色版** | `%APPDATA%\<工具>`、`%USERPROFILE%\<工具>` | 属于**某个具体用户**，时间戳能反映该用户的操作时间 |
| **正式安装版** | `%ProgramData%\<工具>`、`%ProgramFiles%\<工具>` | 属于**系统**，全用户可见，可能是 IT 统一部署 |

**判断原则**：两处都要查。

只查 `%APPDATA%` 会漏掉 IT 部署的；只查 `%ProgramData%` 会漏掉员工自己偷偷装的——**后者往往才是案情核心**。

<a id="section-4"></a>

### 2.2 密码字段的四种格式

拿到配置后，密码字段只有四种可能。先判断格式，再决定要不要动手。

| 格式特征 | 实际是什么 | 典型场景 |
|---|---|---|
| **纯 ASCII 且直接可读** | **明文** | 多数国产远控的旧版本、Xshell 旧版、部分工具的 PIN |
| 可被 `base64 -d` 还原为可读 ASCII | **base64 编码**，不是加密 | WinSCP 旧格式、Docker `auth` |
| 固定长度 hex/base64，且伴随 salt/iv 字段 | **真正的加密**（AES/RC4/自定义） | WinSCP 新版（主密码保护）、Navicat 12+、FinalShell |
| **形如 `$2y$`/`$6$`/32 位 hex** | **单向哈希** | AnyDesk `ad.anynet.pwd_hash`、ToDesk `access_pin_hash` |

> **最后一类无法还原成明文，也不应该还原。** 口令哈希的正确用法是**作为"该设备设了口令"的证据固定下来**，再结合弱口令规则做离线验证（方法论见 [04](crypto-app-passware-and-password-recovery.md)）。**不要因为解不出明文就换工具去撞库式尝试**——那已经越过取证与攻击的界线。

<a id="section-5"></a>

### 2.3 WinSCP：可逆混淆，不是加密

WinSCP 的 `Password` 注册表值在旧版本里是**一种可逆的单向字节变换**，不是密码学加密：

```
存储值 = (0xFF - 明文字节) XOR 0xA3
```

这个变换**是对称的**。把同样的两步再做一次，就还原了。这是 WinSCP 早期实现的固有弱点。

**取证要点**：新旧版本差异是这一节最容易翻车的地方——

| 版本 | 存储形式 | 处理方式 |
|---|---|---|
| 旧版（未设主密码） | `Password` 值 = 上面的可逆变换 | 按同一公式还原，**明文可得** |
| 新版（设了主密码） | 密文为 **AES-256-CBC**，密钥由主密码派生 | **必须先拿到主密码**，否则不可解 |
| 部分企业部署 | 改存 `WinSCP.ini` 配置文件 | 读文件而非注册表 |

**第一条判断指令永远是"先确认有没有主密码"。** 有主密码时，正确结论是"凭据受用户自定义主密码保护，**本阶段不可解**"，而不是继续尝试变换公式——公式对上了也解不开加密格式。

<a id="section-6"></a>

### 2.4 版本差异是这个领域最常见的失分点

同一个工具的路径与格式在版本间反复变化，这是本节的实用核心：

- **向日葵**：老版本 `config.ini`（`C:\Program Files\Oray\SunLogin\SunloginClient\` 或 `C:\ProgramData\Oray\SunloginClient\`），**新版本主要在注册表** `HKU\.DEFAULT\Software\Oray\SunLogin\SunloginClient\SunloginInfo`，关键值 `encry_pwd`（本机验证码）与 `fastcode`（识别码）。**只看 config.ini 会得出错误结论。**
- **AnyDesk**：目录随安装方式在 `%APPDATA%\AnyDesk`（免安装）和 `%ProgramData%\AnyDesk`（已安装）之间切换；密码是 `ad.anynet.pwd_hash` + `pwd_salt` + `token_salt` **三个字段一组**，缺一个都算不出。
- **TeamViewer**：`HKLM\SOFTWARE\WOW6432Node\TeamViewer`（机器级）/`HKCU\Software\TeamViewer`（用户级），`PermanentPassword` 是二进制值；连接记录在安装目录的 `Connections_incoming.txt`（**只记成功连接**）与 `%APPDATA%\TeamViewer\connections.txt`（出向）。
- **Navicat**：12 起用 AES，密钥**与当前操作系统用户环境绑定**；新版进一步依赖平台安全存储（Windows DPAPI / macOS Keychain），**跨机器/跨用户不可解**。
- **ToDesk**：`%APPDATA%\ToDesk` 与 `C:\ProgramData\ToDesk\`，PIN 以 `access_pin_hash` 形式保存（PBKDF2-SHA256 加盐），**单向，不可还原**。

> **通用做法：不要信任任何单一路径，包括我这张表。** 版本一变这张表就会过期，确认口径见第一章「记住这张表是起点，不是事实表」与陷阱 2。

<a id="section-7"></a>

### 2.5 ⚠️ 为什么"绝不连接"是硬红线

这是全文最重要的一段，请完整读完。

登录他人的远控账号、在他人设备上建立远程会话，在法律性质上属于"入侵行为"。后果与读取配置文件完全是两回事：

| 行为 | 法律与合规性质 |
|---|---|
| 读取检材中的配置文件、还原字段 | 取证行为（在授权范围内） |
| **用检材中的凭据连接目标主机** | **未经授权的入侵**，即使"只是看看"也构成实质入侵 |
| 在目标主机上执行命令、查看数据 | 加重情节 |

具体风险有三条。

**一、污染证据。** 远控服务在你的连接时会写日志——登录时间、来源 IP、会话记录。委托方之后再看这台机器，会发现"取证人员连接过"。**这会直接动摇证据的可靠性**，甚至让整个检材在质证中被质疑。

**二、越权取证。** 委托方授权你检验的是"这台机器"，**不是**"被控的那台机器"。对后者发起连接超出了授权范围。

**三、行为本身构成犯罪。** 即便目的是"确认凭据是否有效"，这个确认过程本身就是未经许可的访问行为。

> ### 🚫 硬性禁止
>
> 本文及本板块所有操作，一律不得使用检材中还原出的任何凭据发起真实连接。
>
> 取证阶段的正确做法是：
>
> 1. **只做离线解密**，把还原结果作为**凭据固定（credential fixing）**记录在案。
> 2. 需要验证凭据有效性时，由委托方在受控环境中自行验证，或由具备相应资质的机构在其授权范围内验证。
> 3. **发现的凭据立即通过正式渠道上报委托方**，不私存、不转作他用、不在非授权环境测试。
> 4. **报告中凭据必须脱敏**——完整口令不进报告正文，只记录存在性、类型、所属主体、发现路径。

> **报告中的正确表述**："在 `DigiForensics.dd` 的 `%ProgramData%\AnyDesk\service.conf` 中发现被控方 AnyDesk 账号的登录口令材料（`ad.anynet.pwd_hash`，SHA-256 形式，**单向不可逆**），可用于验证该设备是否设置了访问口令。**本次分析未使用该材料对任何目标设备发起连接。**"

---
<a id="section-8"></a>

## 三、操作步骤

<a id="section-9"></a>

### 步骤 1：全盘定位工具痕迹（不预设路径）

不要从路径表开始猜，**先做一次全盘关键词扫描**，让工具自己暴露位置：

```powershell
# 关键词扫描：一次覆盖主流远控 + 数据库/SSH 客户端
$KW = 'AnyDesk','Sunlogin','Oray','ToDesk','TeamViewer','RustDesk','Navicat',
      'Xshell','FinalShell','WinSCP','MRemote','FileZilla','ToDesk_Service'
$Out = 'D:\evidence\remote_tools_hits.csv'
'Hit,Path,Size,LastWrite' | Set-Content $Out
foreach ($k in $KW) {
  Get-ChildItem C:\ -Recurse -Force -Filter "*$k*" -ErrorAction SilentlyContinue |
    Select-Object -First 50 | ForEach-Object {
      '{0},{1},{2},{3}' -f $k, $_.FullName, $_.Length, $_.LastWriteTimeUtc
    } | Add-Content $Out
}
Get-Content $Out | Select-Object -First 40
```

> **只读要求**：本命令只做枚举与导出，**不打开、不修改、不启动任何被检程序**。

**永远不要在检材上双击运行远控客户端**——启动它本身就会写日志、改配置、可能拉起服务。

<a id="section-10"></a>

### 步骤 2：判定配置归属与时间相关性

对每个命中目录，回答三个问题。

1. **属于系统还是某个用户？** 路径在 `%ProgramData%`/`%ProgramFiles%` = 系统；在 `%APPDATA%`/`%Users\xxx` = 该用户。
2. **最后修改时间是否落在本案时间窗内？** 这一条比"是否存在"更重要。**存在但半年没动过**的配置，说明的不是"近期被控"。
3. **有多个用户目录吗？** 多个 `%APPDATA%\<工具>` 意味着**多台主机/多个操作人**，每个都要单独固定。

<a id="section-11"></a>

### 步骤 3：读出明文字段——这一步通常就够了

```bash
# 向日葵：注册表（新版本）——识别码与验证码字段
reg query "HKU\.DEFAULT\Software\Oray\SunLogin\SunloginClient\SunloginInfo"

# 向日葵：配置文件（旧版本）
cat "/mnt/image/Program Files/Oray/SunLogin/SunloginClient/config.ini"

# AnyDesk：服务级配置（%ProgramData%），只看键名不要贴全文
grep -oE '^ad\.[a-z_.]+=' "/mnt/image/ProgramData/AnyDesk/service.conf" | sort -u
# 关注：ad.anynet.id / ad.anynet.pwd_hash / ad.anynet.pwd_salt / ad.anynet.token_salt

# TeamViewer：连接记录（入向只记成功）
cat "/mnt/image/Program Files (x86)/TeamViewer/Connections_incoming.txt"

# ToDesk：定位配置文件后再看字段
ls -la /mnt/image/ProgramData/ToDesk/ /mnt/image/Users/*/AppData/Roaming/ToDesk/ 2>/dev/null
```

> 向日葵 `encry_pwd` / `fastcode` 的定位意义：`fastcode` 就是本机识别码（去掉开头字母后使用），`encry_pwd` 是本机验证码。**识别码本身是明文的高价值证据**；验证码字段的解密需要工具支持且**只能在离线环境下对检材副本操作**。

<a id="section-12"></a>

### 步骤 4：判断并还原密码字段

按 2.2 的四种格式分流，**只做离线还原**：

```bash
# (a) 疑似 base64：先试解码，能出可读 ASCII 就是编码而非加密
echo "<字段值>" | base64 -d 2>/dev/null; echo

# (b) WinSCP 旧格式：可逆字节变换（对称，做两次即还原）
python3 -c "
v = bytes.fromhex('<Password值hex>')
print(bytes((255 - b) ^ 0xA3 for b in v).decode('utf-8', 'replace'))"

# (c) 形如 $2y$ / 32位hex：单向哈希，**到此为止，不还原**
#     → 记录"设置了访问口令"这一事实，转 04 篇做弱口令离线验证
```

> **(b) 的重要限制**：这个公式**只对未设主密码的旧版有效**。新版是 AES-256-CBC、密钥由主密码派生，公式对上了也解不开。**先确认有无主密码，再决定用不用公式。**

<a id="section-13"></a>

### 步骤 5：可运行的批量汇总脚本

**只用 Python 标准库**，输出一份可入卷的 CSV。

它**只读不写、不解密**。把"发现"和"还原"分成两步，是为了避开脚本自动尝试解密带来的合规风险。

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scan_remote_tools.py — 汇总远控/连接类工具的配置痕迹（只读）
用法：python3 scan_remote_tools.py /mnt/image > remote_tools.csv
注意：本脚本不尝试任何解密，只做痕迹固定。"""
import os, sys, csv, re

# (关键词, 相对/绝对路径候选, 需要关注的字段)
TARGETS = [
    ("AnyDesk",   [r"ProgramData/AnyDesk", r"Users/[^/]+/AppData/Roaming/AnyDesk"], "service.conf"),
    ("Sunlogin",  [r"Program Files/Oray/SunLogin/SunloginClient",
                   r"ProgramData/Oray/SunloginClient",
                   r"ProgramData/Oray/SunloginClientLite"], "config.ini"),
    ("ToDesk",    [r"ProgramData/ToDesk", r"Users/[^/]+/AppData/Roaming/ToDesk"], None),
    ("TeamViewer",[r"Program Files \(x86\)/TeamViewer",
                   r"Program Files/TeamViewer",
                   r"Users/[^/]+/AppData/Roaming/TeamViewer"], None),
    ("RustDesk",  [r"Users/[^/]+/AppData/Roaming/RustDesk",
                   r"Users/[^/]+/AppData/Local/RustDesk"], "RustDesk.toml"),
    ("Navicat",   [r"Users/[^/]+/AppData/Roaming/Navicat",
                   r"Users/[^/]+/Documents/Navicat"], None),
    ("Xshell",    [r"Users/[^/]+/Documents/NetSarang/[^/]+/\d+",
                   r"Program Files \(x86\)/NetSarang/[^/]+/\d+"], None),
    ("FinalShell",[r"Users/[^/]+/.finalshell"], "conn.json"),
    ("WinSCP",    [r"Users/[^/]+/Documents/WinSCP.ini"], "WinSCP.ini"),
    ("FileZilla", [r"Users/[^/]+/AppData/Roaming/FileZilla"], "recentservers.xml"),
]
# 只挑出这些键名写入 CSV，值一律不落盘
INTEREST = re.compile(r"(id|code|host|name|user|ip|mac|pwd|pass|secret|token|hash|salt|pin)", re.I)

def iter_files(root, pattern):
    rx = re.compile(pattern)
    for dirpath, _dirs, files in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        for fn in files:
            p = os.path.join(rel, fn)
            if rx.search(p.replace(os.sep, "/")):
                yield os.path.join(dirpath, fn)

def main(root):
    w = csv.writer(sys.stdout)
    w.writerow(["Tool", "Path", "Size", "LastWriteUTC", "Field", "ValueMasked"])
    for tool, pats, want in TARGETS:
        for pat in pats:
            for p in iter_files(root, pat):
                try:
                    st = os.stat(p)
                except OSError:
                    continue
                if want and os.path.basename(p) != want:
                    continue
                w.writerow([tool, p, st.st_size, int(st.st_mtime), "", ""])
                if os.path.isfile(p) and os.path.getsize(p) < 2_000_000 \
                   and os.path.splitext(p)[1] in (".conf", ".ini", ".toml", ".json", ".xml"):
                    for line in open(p, encoding="utf-8", errors="ignore"):
                        m = re.match(r"\s*([\w.\-]+)\s*[=:]\s*(.+)", line)
                        if m and INTEREST.search(m.group(1)):
                            v = m.group(2).strip().strip('"')
                            # 脱敏：只留前 6 位，避免把凭据写进可流转的中间文件
                            w.writerow([tool, p, "", "", m.group(1), v[:6] + "…"])

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    main(sys.argv[1])
```

```bash
sudo mount -o ro,loop DigiForensics.dd /mnt/image
python3 scan_remote_tools.py /mnt/image > remote_tools.csv
head -40 remote_tools.csv
```

> **脚本为什么只输出前 6 位**：中间产物 CSV 会被反复传阅，可能进入案卷。

凭据的完整值只应出现在受控的解密记录里，不应在批量扫描产物中留痕。 需要完整值时，单独对目标文件执行定向提取并单独归档。

<a id="section-14"></a>

### 步骤 6：固定与上报

把每条发现整理成结构化记录，**最少包含**：

| 字段 | 说明 |
|---|---|
| 工具与版本 | 路径里的版本目录、`Version` 值 |
| 配置路径 | 完整路径（注册表写完整键路径） |
| 归属主体 | 系统级 or 哪个用户 |
| 最后修改时间 | UTC，**这是时间线的核心** |
| 发现的字段类型 | 明文 / base64 / 加密 / 哈希（**按 2.2 分类**） |
| 明文关键值 | **脱敏**；识别码、IP、主机名可保留 |
| 关联日志 | 对应的 `LogFiles`/`Connections_*.txt` 路径与时间范围 |
| 处置记录 | 是否尝试解密、成功与否、**是否连接（恒为"否"）** |

---
<a id="section-15"></a>

## 四、常见陷阱

本章按「定位阶段 → 字段判读 → 离线还原 → 合规边界与结论表述」归组，每条给出：现象、为什么会误判、误判代价、正确做法。
★ 标记表示该操作会导致原始检材永久灭失或不可逆改变，执行前必须停下来确认。

<a id="section-16"></a>

### 4.1 定位阶段：只查一个目录就下"未安装"的结论

<a id="section-17"></a>

#### 陷阱 1：只查 `%APPDATA%` 或只查 `%ProgramData%` 就断言"未安装"

**现象**：在 `C:\Users\*\AppData\` 下没找到 ToDesk 的配置，报告写"该机未安装远程控制软件"。

**原因**：同一款工具有**每用户**与**每机器**两套配置目录（2.1），选哪一套取决于安装形态——免安装/绿色版落在 `%APPDATA%`/`%USERPROFILE%`，正式安装版落在 `%ProgramData%`/`%ProgramFiles%`。**两者都只覆盖一部分情形。**

而 `ProgramData` 那一套恰恰是 IT 统一部署的情形，`AppData` 那一套才是员工自己装的——**后者往往才是案情核心**。只查一处会系统性地漏掉其中一整类。

**影响**："未安装"是一个**否定性结论**，而否定性结论在报告里往往是最被依赖、也最容易被引用的一句话。

一旦是漏查，它不仅错了，还错得**有欺骗性**——报告读起来完整可信，委托方据此认为"该机无远控痕迹"而终止调查，真正的痕迹就在被漏掉的那个目录里。

**核查**：**两处都查，并且不预设路径**。

步骤 1 的关键词全盘扫描就是为这个目的设计的——它不依赖路径表，让工具自己暴露位置：

```powershell
# 覆盖全盘，只做枚举不打开不启动
foreach ($k in 'AnyDesk','Sunlogin','Oray','ToDesk','TeamViewer','RustDesk','Navicat') {
  Get-ChildItem C:\ -Recurse -Force -Filter "*$k*" -ErrorAction SilentlyContinue |
    Select-Object -First 50 | ForEach-Object {
      '{0},{1},{2},{3}' -f $k,$_.FullName,$_.Length,$_.LastWriteTimeUtc }
}
```

**报告写法**：全盘扫描未命中时写"在 `C:\` 全盘范围按 13 个工具名与已知文件名模式扫描，未发现相关安装痕迹"，并列出**已扫描的关键字与范围**。只查一个目录得到的结论不能写进报告。

<a id="section-18"></a>

#### 陷阱 2：路径表当成事实，版本一变就漏掉关键信息

**现象**：向日葵按旧版经验只查 `C:\Program Files\Oray\SunLogin\SunloginClient\config.ini`，文件存在但关键字段为空，于是报告"未获取到设备识别码"。

**原因**：**同一款工具的配置位置在版本间会迁移**（2.4）。

向日葵的高版本主要信息已经移到注册表 `HKU\.DEFAULT\Software\Oray\SunLogin\SunloginClient\SunloginInfo`，而不是 `config.ini`。

你在旧路径找到的那个文件是真实存在的，它只是不再承载那些字段——"文件存在但字段为空"因此极易被读成"信息不存在"。

**影响**：漏掉的是**设备识别码**这类高价值明文证据。

案例里 `Connections_incoming.txt` 的入向连接记录与 `fastcode` 共同构成了"被控"这一结论的骨架，缺了它们，时间线就只剩孤立的日志行。

**更麻烦的是这类错误有正反馈**——分析员看到空值就以为这条路走不通，转向更昂贵的方法。

**核查**：**把路径表当起点而不是终点**，每个候选位置都要独立确认两件事：目录/键是否存在、字段是否有值：

```powershell
# 旧版路径
reg query "HKLM\SOFTWARE\Oray\SunLoginClient" /s 2>$null
# 新版路径：主要信息在这里
reg query "HKU\.DEFAULT\Software\Oray\SunLogin\SunloginClient\SunloginInfo"
```

**通用判据**：任何时候只在一个位置得到空值，正确动作是**换位置再找一次**，而不是下"不存在"的结论。版本一变，2.4 的整张表都会过期。

<a id="section-19"></a>

### 4.2 字段判读：把格式判断当成解密

<a id="section-20"></a>

#### 陷阱 3：把单向哈希当加密，反复换工具尝试还原

**现象**：`ToDesk` 的 `access_pin_hash`、AnyDesk 的 `ad.anynet.pwd_hash` 用各类工具试不出明文，分析员判断"工具不对"，转而寻找流解密工具。

**原因**：**这些字段本来就不是加密，是单向哈希**（2.2 的第四种格式）。`access_pin_hash` 是 PBKDF2-SHA256 加盐的输出；AnyDesk 是 `pwd_hash` + `pwd_salt` + `token_salt` **三个一组**才能参与运算，缺一不可。单向函数没有逆运算——找错工具不是工具弱，是这个方向本就不存在。继续换工具的实质是不断重复一次注定失败的搜索。

**影响**：一是工时浪费。

二是**报告里会出现"无法解密"这种含糊表述**，而正确表述是"该字段为加盐单向哈希，本阶段不可还原；其存在本身即证明该设备设置了访问口令"。

三是一个真实风险——为寻找"能解的工具"而尝试在线撞库或向服务方提交，性质已经从取证变成攻击。

**核查**：按 2.2 的四种格式分流，单向哈希这一类**到此为止**，只固定三件事：字段名、所在文件路径、文件修改时间。

弱口令的离线验证走 [04 通用密码恢复](crypto-app-passware-and-password-recovery.md) 的方法论，**且必须先用自制样本自测工具**。案例第 4 步的处理方式就是标准答案：判为"哈希三件套（单向，不还原）"。

<a id="section-21"></a>

#### 陷阱 4：字段被截断或分隔符处理错，误判为"已损坏"

**现象**：从配置文件里用正则截取密码字段，得到半截值，解出来是乱码，于是判断"该字段已损坏/被覆盖"。

**原因**：配置文件的字段值经常带**定界符**（引号、逗号、分号、`=` 后跟空格）。截取时如果连着分隔符一起取走，还原结果自然是乱码。

而**"还原出乱码"与"字段被破坏"在现象上完全一样**——都表现为无法读出可读字符。**同一个现象有多种成因，且在离线状态下无法区分。**

**影响**：误判成"已损坏"会导向一个错误的结论方向——认为该主机可能遭到过覆写攻击、时间线可能有破坏。

这会把一个普通的解析问题，升级成一个可能推翻整份报告时间线的怀疑。

**核查**：区分"截取问题"与"数据问题"用一次对照——**取同一配置里的其他字段做同样的截取-还原**：

```bash
# 1) 先确认字段的完整原文（含定界符），不要凭正则猜
grep -n "pwd" "/mnt/image/ProgramData/AnyDesk/service.conf"
# 2) 对照：同一个文件里格式相同的其他字段能否正确还原
```

其他同格式字段能还原、只有这一个不能 → 是数据问题；都不能 → 是截取或格式假设问题。报告里只写"按 2.2 格式判定为第 N 类"，不要在未做对照的情况下写"已损坏"。

<a id="section-22"></a>

### 4.3 离线还原：公式对版本不对

<a id="section-23"></a>

#### 陷阱 5：先套 WinSCP 公式，事后才确认有没有主密码

**现象**：从注册表取到 `Password` 值的 hex，直接套 `(0xFF - b) XOR 0xA3` 还原，出来一串不可读的字节，报告写"WinSCP 凭据已损坏"。

**原因**：**WinSCP 存在两代完全不同的存储机制**（2.3）。

未设主密码的旧版存的是那个可逆字节变换；设了主密码的新版存的是 **AES-256-CBC**，密钥由主密码派生。**这两者用同一个公式处理，后者必然输出乱码**——而"公式不适用"和"数据被破坏"在输出上无法区分。

根因是**顺序错了：判据应该在动手之前，而不是在失败之后**。

**影响**：得出"凭据已损坏"是一个关于数据状态的断言，它可能被委托方解读为"该机经历过破坏性操作"，从而引出与本案无关的怀疑。

更实际的问题是**放弃了本可解出的凭据**——如果主密码恰好在别处可取，这一步就白白丢掉了线索。

**核查**：**第一条指令永远是"确认有没有主密码"**，而不是"试公式"：

```bash
# 1) 先判断代次：是否设置了主密码（新版会留下主密码相关配置项）
# 2) 旧版才走可逆变换，且该变换是对称的——同样的两步做两次即还原
python3 -c "
v = bytes.fromhex('<Password值hex>')
print(bytes((255 - b) ^ 0xA3 for b in v).decode('utf-8','replace'))"
```

**有主密码时的正确结论是**"该凭据受用户自定义主密码保护，本阶段不可解"——**这是一个完整、专业的结论，不需要继续尝试**。

它比"解开了所以专业"更有价值，因为它划清了能力边界。

<a id="section-24"></a>

#### 陷阱 6：AnyDesk 只取 `pwd_hash` 不取两个 salt

**现象**：脚本从 `service.conf` 里正则出 `ad.anynet.pwd_hash` 的值，尝试验证时全部失败，判为"哈希无法匹配"。

**原因**：**AnyDesk 的口令验证需要三个字段一组**——`pwd_hash`、`pwd_salt`、`token_salt`。

单独一个 `pwd_hash` 里的摘要，是在**特定 salt 下**算出来的。缺了 salt，就无法复现同一次运算。

这是**字段集合完整性**问题，不是算法问题。"验证失败"在这里有三种成因（salt 缺失、salt 取错位置、字段本身不是这个用途），现象上无法区分。

**影响**：误判成"无法验证"并写进报告，等于给出一条不成立的技术结论。

同类的还有 `token_salt`——它是配套的第三个字段，漏掉它会让原本能做的验证也失败。

**核查**：提取时**按字段组取，不按单字段取**，并记录每个字段的偏移：

```bash
# 只看键名不贴全文
grep -oE '^ad\.[a-z_.]+=' "/mnt/image/ProgramData/AnyDesk/service.conf" | sort -u
# 关注：ad.anynet.id / ad.anynet.pwd_hash / ad.anynet.pwd_salt / ad.anynet.token_salt
```

**报告写法**："该机存在 AnyDesk 访问口令配置（`pwd_hash` + `pwd_salt` + `token_salt` 三字段齐全，均为加盐单向哈希，不可还原）"——**三字段齐全这一事实本身就是有价值的证据**，它比任何解谜尝试都更能说明设备状态。

<a id="section-25"></a>

### 4.4 合规边界与结论表述

<a id="section-26"></a>

#### 陷阱 7：★ 用检材中还原出的凭据去连接目标主机

**现象**：从 `service.conf` 拿到 AnyDesk ID 和口令后，为了"确认凭据有效"，在受控环境外尝试登录远控账号或建立远程会话。

**原因**：这个动作在直觉上像是"验证证据"——如果能登录成功，就证明凭据真实有效。

**但它完全改变了行为的法律性质**（2.5）。读取检材中的配置文件是在授权范围内的取证行为；用这些凭据发起连接是未经授权的访问，"只是看看"也构成实质访问。

委托方授权你检验的是"这台机器"，**不是**"被它控制的那台机器"。

而且**验证凭据有效性这个目的本身不能正当化手段**——它不是辩护理由，是把取证推向了另一个法律范畴。

**影响**：三重后果，**每一重都足以单独毁掉一个案件**。

其一，**污染证据**：远控服务会在服务端留下你的登录时间、来源 IP、会话记录。委托方之后查看时会发现"取证人员连接过"，这直接动摇证据可靠性。

其二，**越权取证**：超出授权范围的操作可能被认定为非法访问。

其三，**行为本身构成犯罪**，在部分司法辖区下与企业内部调查的豁免并不自动适用。

**核查**：**这是硬红线，不设例外**。凭据固定后，正确动作是**记录而非使用**：

- 固定：字段名、所在文件路径、文件修改时间、涉及的工具版本；
- 在报告中写明"**未使用检材中任何凭据对被控主机发起连接**"；
- 如委托方确需验证凭据有效性，**建议由委托方在自行受控的环境中完成**。

案例第 7 步就是这个处理方式的标准表述。**这条不需要更多论证——它不是权衡项。**

<a id="section-27"></a>

#### 陷阱 8：把"配置存在"等同于"近期被控"

**现象**：`C:\ProgramData\AnyDesk\` 存在，`service.conf` 有完整的 ID 与口令哈希，报告写"该机曾被远程控制"。

**原因**：**安装痕迹只证明"装过"，不证明"被控过"**。

远控软件可能是 IT 统一部署的，可能是员工自己为了远程加班装的，也可能是多年前装完再没用过。

关键区分点是文件最后修改时间是否落在委托方给出的时间窗内（步骤 2 的三问之一）。**存在性是静态的，时间相关性才是动态的**，而只有后者能支撑"被控"这个指控性结论。

**影响**：这是**"以为自己找到了"**的典型形态。

指控性结论（"该机被 X 远程控制"）是需要承担举证责任的。一旦把安装痕迹写成被控事实，对方只需出示一份 IT 部署记录或一个半年前的使用记录就能推翻，而你建立的其他发现也会被一起怀疑。

**核查**：把结论拆成两级，**分别需要各自的证据**：

| 结论级别 | 需要的证据 | 表述 |
|---|---|---|
| **存在远控软件** | 目录/键存在 + 文件时间 | "该机安装有 X 工具，配置最后修改于 <时间>" |
| **在时间窗内被控** | 成功连接记录 + 与时间窗吻合 | "在 <起> 至 <止> 期间存在来自 <对方标识> 的成功入向连接" |

案例里 `Connections_incoming.txt` 的 3 条入向记录（UTC 时间落在 2024-06-02 至 06-14 窗口内）与详细日志的 `AuthenticationPasswordLogin_Passive ... success` 构成**两条独立证据**，这才把"被控"坐实。只有配置存在、没有连接记录时，最高只能写到第一级。

<a id="section-28"></a>

#### 陷阱 9：把 `Connections_incoming.txt` 当作完整连接历史

**现象**：TeamViewer 的 `Connections_incoming.txt` 只有 3 条记录，报告写"该机被远程连接 3 次"。

**原因**：**这个文件只记成功连接**（2.4）。

失败尝试、部分完成的会话、以及出向连接都不在里面——出向记录在另一个文件 `%APPDATA%\TeamViewer\connections.txt`。

把"成功连接清单"当成"全部连接尝试"，会系统性地低估攻击面，而攻击方反复尝试失败恰恰是最有分析价值的部分。

**影响**：低报连接次数，同时丢掉失败尝试这条线索。

在入侵分析里，失败尝试的数量和分布往往比成功次数更能说明对方的自动化程度和目的，报告里一句"共 3 次连接"会让读者以为攻击规模很小。

**核查**：**三类记录分开取、分开表述**：

```bash
# 入向：仅成功（UTC 时间）
cat "/mnt/image/Program Files (x86)/TeamViewer/Connections_incoming.txt"
# 出向：本机主动发起的连接
cat "/mnt/image/Users/zhang/AppData/Roaming/TeamViewer/connections.txt"
# 失败尝试与详细事件：在日志文件里，需按时间窗过滤
grep -n "LogonAttempt\|AuthenticationPasswordLogin" \
  "/mnt/image/Program Files (x86)/TeamViewer/TeamViewer15_Logfile.log"
```

**报告写法**："`Connections_incoming.txt` 记录 3 条**成功**入向连接（<时间>）；详细日志中另有 N 条认证失败记录（<时间范围>）。两类记录的时间均以 UTC 计。"

<a id="section-29"></a>

#### 陷阱 10：忽略时区，把 UTC 与本地时间混排成错误时间线

**现象**：把 `Connections_incoming.txt` 的时间与详细日志的时间放进同一张表排序，发现"连接发生在认证成功之前 8 小时"，于是得出"日志被伪造"的结论。

**原因**：**两个来源用不同时区**。TeamViewer 的 `Connections_incoming.txt` 用 **UTC**，详细日志用**本地时间**。

两者的差值恰好等于时区偏移（本案机器若为中国标准时间就是 8 小时），**这个 8 小时是一个可预测的常数，而不是篡改痕迹**。

一旦不换算，任何跨文件的时序比较都会产出荒谬的"因果倒置"。

**影响**：**"日志被伪造"是一个极重的结论**，指控日志完整性被破坏，在质证环节需要极强的旁证才能支撑。

建立在时区换算错误上的这种结论，一旦被对方发现，**整份时间线都会作废**——而那张时间线往往正是本案的核心交付物。

**核查**：**时间线统一到一个基准，并在报告里写明基准**：

```bash
# 全量转 UTC 后再排序
TZ=UTC date -d "2024-06-05 14:32:11" "+%Y-%m-%dT%H:%M:%SZ"
# 检查机器本地时区
cat "/mnt/image/Windows/System32/config/SYSTEM" >/dev/null && \
  reged -x DigiForensics.dd "/Windows/System32/config/SYSTEM" /tmp/SYS && \
  grep -a -oE 'TimeZoneInformation' /tmp/SYS >/dev/null
```

**交付前自查**：时间线表里每一行都应标明原始时区与换算后值；"某事件先于某事件"这类因果性表述，只能在换算后的同一基准下做出。方法论细节见 [时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md)。

<a id="section-30"></a>

#### 陷阱 11：在报告里贴完整凭据，或把批量扫描产物当归档材料

**现象**：报告附件贴出完整连接串与口令；批量扫描脚本输出的 CSV（含全量明文凭据）与其他证据材料一起归档。

**原因**：两种做法都源于同一个直觉——"证据要完整、要便于复核"。

但**报告的传播范围远大于分析环境**：它会交给委托方、可能进卷宗、可能在质证中公开。

凭据是二次泄露的源头，而报告恰恰是最容易被广泛传阅的那份文件。 批量 CSV 则是"分析过程产物"与"证据材料"混在一起——它既没有经过脱敏，也没有记录生成条件。

**影响**：泄露后**责任在报告作者而不在原始泄露者**，通常还构成一宗需要立即启动凭据轮换的新安全事件。

归档侧的麻烦更慢：全量明文凭据混在证据包里，一旦调阅权限管理失效，泄露面等于所有敏感数据的总和。

**核查**：

- **报告正文只写存在性、类型、归属、时间、路径**，明文不进报告；
- **批量扫描产物只留脱敏值**（账号、权限范围、字段名、时间），完整凭据单独归档、单独授权调阅，并在归档记录里写明脱敏规则；
- 需要复核时用"字段 + 掩码前后若干位 + 校验方式"替代完整值。

**同一原则适用于范围外发现**：不属于委托范围的凭据材料（如其他用户的配置、其他主机的凭据）**必须上报而不是丢弃**，只是上报格式受最小化约束。
<a id="section-31"></a>

## 五、案例示例

<a id="section-32"></a>

### 5.1 明文时间线已足以定案：远程工具的三源交叉印证

**场景**

查获一台 Windows 11 笔记本（`DigiForensics.dd`）。委托方怀疑「该机在 2024-06 前后被他人远程控制并转移资料」。委托方授权范围仅限这台笔记本本身，不包括任何被控主机。

这条路径值得先走，是因为远程工具的设备 ID、连接时间、对端 IP 几乎全部以明文落在日志与配置里。

先把这些明文用足，才能判断哪些密码字段确实需要解密——**很多案件到这里就结束了。**

**处置过程**

第 1 步，关键词扫描定位安装痕迹：

```bash
# 在镜像上做只读路径枚举，不启动任何客户端
fls -o 2048 -r /evidence/DigiForensics.dd | grep -iE 'ProgramData/AnyDesk|Program Files \(x86\)/TeamViewer|Navicat'
# C:\ProgramData\AnyDesk\
# C:\Program Files (x86)\TeamViewer\
# C:\Users\zhang\AppData\Roaming\Navicat\
```

第 2 步，**归属与时间判定——安装位置本身就区分了权限语义**：

```bash
icat -o 2048 /evidence/DigiForensics.dd <inode> > /evidence/service.conf
istat -o 2048 /evidence/DigiForensics.dd <inode>
# service.conf 最后修改 2024-06-11
# ProgramData 属系统级 → 全机用户可见，影响面更大
```

第 3 步，**读明文字段（此步已可回答大部分问题）**：

```bash
# AnyDesk：本机 ID 是明文
grep -aE '^ad\.anynet\.(id|pwd_hash|pwd_salt|token_salt)' /evidence/service.conf
# ad.anynet.id = 123456789                    ← 本机 ID，明文

# TeamViewer：入向连接记录是明文，含对方 ID 与起止时间（UTC）
grep -a 'Connections_incoming' /evidence/TeamViewer15_Logfile.log
# 2024-06-05 08:12:03 UTC  对方 ID 9xxxxxxx  →  2024-06-05 08:47:55 UTC
# 2024-06-09 22:03:17 UTC  对方 ID 8xxxxxxx  →  2024-06-09 22:41:02 UTC
# 2024-06-11 14:55:30 UTC  对方 ID 7xxxxxxx  →  2024-06-11 15:20:44 UTC

# Navicat 连接配置：主机名、端口、用户名为明文
icat -o 2048 /evidence/DigiForensics.dd <inode> > /evidence/conn1.tncf
head -c 64 /evidence/conn1.tncf | xxd
# 5 bytes 前导 + 明文 Host / Port / UserName
```

第 4 步，密码字段定级——分清「可解」「不可解」「本阶段不做」三类：

```bash
# AnyDesk 是哈希三件套：单向，不还原
grep -aE '^ad\.anynet\.(pwd_hash|pwd_salt|token_salt)' /evidence/service.conf
# pwd_hash=... pwd_salt=... token_salt=...   → 单向哈希，本阶段不可解

# Navicat 新版 .tncf 为 AES 格式，与当前用户环境绑定
python3 navicat.py --file /evidence/conn1.tncf --user zhang --dpapi /evidence/DPAPI
# ERROR: DPAPI master key mismatch → 跨机不可解
```

第 5 步，**日志交叉印证（两条独立证据）**：

```bash
grep -aE 'AuthenticationPasswordLogin_(Passive|Interactive).*success' /evidence/TeamViewer15_Logfile.log
# 2024-06-05 08:12:09 UTC  ... success
# 与 Connections_incoming.txt 的 08:12:03 吻合
```

第 6 步，固定证据并统一时区：

```bash
printf 'anydesk_config_offset=0x%x\
tv_log_offset=0x%x\
tncf_offsets=%s\
' \
  <偏移1> <偏移2> '0x...,0x...' > /evidence/remote-offsets.txt
# 所有时间戳在报告中统一换算为 UTC，避免时区歧义
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 本机安装并运行过 AnyDesk / TeamViewer | 程序目录 + 配置存在 | 强（仅说明「装过」） |
| 2024-06-02 至 06-14 期间存在 3 次成功入向连接 | `Connections_incoming.txt` 3 条记录 | 强 |
| 入向连接经口令认证成功 | 详细日志 `..._Passive ... success` | 强（双源一致） |
| 本机保存过指向外部主机的数据库连接配置 | `.tncf` 中明文 Host/UserName | 强 |

**不能证明的**，先说最容易被跨过去的一条：**「存在入向连接记录」不等于「对方实施了控制」**——入向连接也可能是管理员运维或厂商支持。

「保存了连接配置」也不等于「用这些配置登录过目标主机」——配置可以被创建、被复制、被导入。

本次**未确认对方身份，也未确认资料确实被转移**。后者需要目标主机的服务端日志或网络流量证据。

**误判对照**

本案最容易犯的错误是因为没能解出 AnyDesk 的口令，就在报告里写「远程工具凭据已破解，可以登录被控主机核实」。

**为什么这个结论不成立**：`pwd_hash` + `pwd_salt` + `token_salt` 是**单向哈希三件套**，本来就不存在「解出口令」这回事——分析员无法通过任何手段还原出明文口令。

**「解不开」在这个字段上是正确结果，不是分析失败。**

**正确判据有三条**：

1. **先按字段形态定级再动手**。哈希类字段（`pwd_hash` 等）直接定性为「不可还原」；密文类字段（`.tncf`）先测 DPAPI 是否匹配；明文字段（ID、IP、时间戳）直接用。**顺序错了会在不可解字段上浪费全部时间。**
2. **区分「解不开」与「不适用」**。`.tncf` 报 `DPAPI master key mismatch` 说明**它绑定了原机原用户上下文**。这不是「难度不够」，是**在本案检材上根本不可能解开**。正确表述是「本阶段不可解，原因：与当前用户环境绑定」。
3. **委托方的核心诉求必须先拆解**。本案要证明的是「是否被远程控制」，**答案完全由明文时间线给出**——设备 ID、对方 ID、IP、时间戳全是明文。

解密口令既无必要，也把处置风险从「取证」推到了「入侵」。

**按错误判据走的代价**：一旦报告写下「凭据已破解」，就会有人按此去登录被控主机。

这在法律性质上是**未授权访问**，且会污染对方服务端的登录日志，反过来损害委托方自己的主张。

而实际结论只是「三个哈希字段不可还原」——**一句话之差，一个是高价值证据，一个是犯罪行为。**

<a id="section-33"></a>

### 5.2 伪造配置与真实配置的离线区分

**场景**

同一批检材中，还存在一个向日葵（Sunlogin）客户端目录。委托方把「该机能远程访问内网」列为独立疑点。关键问题是：这些配置是真实使用过的，还是可以被随意伪造的？

**处置过程**

本节**只做离线识别**，全部判据来自文件本身的结构与时间关系：

```bash
# 第 1 步：注意版本差异——新版本把配置移到了注册表，只按旧路径查会直接漏掉
icat -o 2048 /evidence/DigiForensics.dd <inode> > /evidence/sunlogin.ini
grep -aE '^(sunlogin|ver|host|port|guid)' /evidence/sunlogin.ini

# 注册表侧的同一份配置（新版本位置）
reged -x /evidence/SYSTEM 'HKEY_LOCAL_MACHINE\SOFTWARE\Oray\SunLogin' /evidence/sunlogin.reg
```

```bash
# 第 2 步：真实配置必须与服务端有往返痕迹，纯本地伪造不会产生这些
istat -o 2048 /evidence/DigiForensics.dd <日志inode>
# 日志中出现 2024-06-05 22:14:07 上行心跳，2024-06-05 22:31:52 下行远程指令分发
```

第 3 步，用日志与配置的交叉关系判断「配置是否被真正启用过」：

```bash
grep -acE 'online|heartbeat|accept|device_online' /evidence/sunlogin.log
# 若为 0 → 该配置从未被服务端确认过，不能作为「设备在线过」的证据
```

第 4 步，识别**明显的演示/测试配置**（这几类是伪造痕迹的高发点）：

```bash
# GUID 形态异常：全 0、全 F、或短于标准 32 位十六进制长度
grep -aoE 'guid[ =]*[0-9a-fA-F-]{8,}' /evidence/sunlogin.ini | awk 'length($0)<36'
# host 值等于 127.0.0.1 / 0.0.0.0 / RFC1918 保留段 → 本地测试配置
```

**结论**

- 本案检材中的向日葵配置**与服务端存在双向时间对应的通信记录**（心跳与指令分发时间戳连续且落在疑点窗口内），因此可认定为**真实使用过的配置**。
- **未覆盖范围**：本次**未做服务端侧比对**（需向日葵厂商与委托方账号侧配合），因此仅能确认「客户端侧存在双向通信痕迹」，不能确认「远程操作确实由真实用户发起」——会话可被转交或被冒用。
- **未做也不应做的动作**：本节全程未连接任何被控主机，未使用检材中任何设备 ID 发起远控会话验证。 此类验证应由委托方在受控环境中自行完成。

**误判对照**

两种错误方向都可能发生。一种是把「配置存在」直接当成「被远控过」，另一种相反——**看到配置可疑就当成伪造而排除掉**。

**为什么两种都危险**：前者在报告中写成「该机曾被远程控制」，但配置是纯本地文件，可以被任何进程写入，包括入侵者自己。

后者则可能把真正的痕迹当成噪音删掉。

两者都跳过了同一个关键问题：这个配置有没有跟服务端产生过真实的往返。

**正确判据有三条**：

1. **配置存在 ≠ 配置被使用**。**必须看日志里有没有对应的上下行时间戳**，且要与配置文件的修改时间形成先后顺序（配置先于或同于通信）。
2. **看通信方向与内容**。真实使用会出现周期性心跳与指令分发；纯伪造配置通常只有本地文件，没有时间连续的往返记录。`online|heartbeat|accept` 计数为 0 时，不得据此陈述「设备曾在线」。
3. **形态异常可直接判伪**。`guid` 长度不足或为全 0/全 F、`host` 为 `127.0.0.1` / `0.0.0.0` / 私有保留段——**这类配置有明确的测试特征**，可据此排除，且应在报告中记录排除依据。

**按错误判据走的代价**：若把纯本地配置定性为「远控证据」，委托方可能据此认定存在第三方入侵，**并对内网做全面排查与凭据轮换**——而真实原因只是该设备装了一个测试版客户端。

反之，若把真实配置误当伪造排除，**真正的远控痕迹就此消失，后续调查再无线索可追**。

<a id="section-34"></a>

### 5.3 反例：范围外发现的处置边界

**场景**

扫描过程中，还在同一个 `zhang` 用户目录下发现了**另一个域账号的 RDP 凭据条目**（`Windows\Credentials` 下），以及一台**已移交他案处置的旧笔记本**的 TeamViewer 残留目录。前者不属于本案委托范围，后者不在本次检材内。

**处置过程**

按「范围外发现」的统一约束处理：

```bash
# 1. 记录存在性与归属，不还原、不使用
icat -o 2048 /evidence/DigiForensics.dd <inode> > /evidence/rdp-cred.bin
python3 -c "print('target=%s persist=%s' % ('DOMAIN\\\\otheruser','LMEMORY'))"
# target=DOMAIN\otheruser  persist=LMEMORY

# 2. 区分「本机范围外」与「检材范围外」两类
# 本机范围外：属于本机的其他账户凭据 → 上报，受最小化约束
# 检材范围外：那台旧笔记本 → 不在镜像内，只能记录「另案处置」，不在本报告展开
```

**结论**

- 范围外发现**必须上报而不是丢弃**。丢弃会让委托方误判风险面——例如误以为该机只有单一账号活动。
- 上报格式受最小化约束：写「在 `Windows\Credentials` 下发现归属 `DOMAIN\otheruser` 的 RDP 凭据条目（类型 `LMEMORY`，未还原）」，不含解密值。
- **处置动作交由委托方**：是否通知域管理员、是否改密，由委托方决定，取证方不主动联系第三方。
- **不能证明的**：**未还原、未验证、未使用任何该凭据**。「存在凭据条目」不构成「该账号被登录过」的证据——凭据可被创建后弃用。

**误判对照**

最常见的错误是**顺手把范围外凭据解出来一起写进报告**，理由往往是「多给一点信息总没坏处」。

**为什么这是错的**：本案授权范围**仅限这台笔记本本身**。

把范围外的凭据还原并写入报告，**在程序上就已经超出了授权范围**——不管报告最终给了谁。

更实际的问题是，凭据一旦脱离最小授权范围流通，其后续使用**无法归因、无法追责**：一旦该账号出现异常登录，没有任何记录能说明是谁在什么授权下导出了它。

**正确判据有三条**：

1. **范围外 ≠ 不上报，范围外 ≠ 要还原**。上报的是「存在 + 类型 + 归属 + 位置」，不是值。委托方需要的决策信息在于「有没有超出预期的账号活动」，不需要具体口令。
2. **必须区分「本机范围外」与「检材范围外」**。前者在本报告里作为附带发现登记；后者属于另案处置范围，**记录一句「另案处置，本报告不展开」即可**，不应展开分析——那会牵涉到未授权的检材。
3. **必须写明未还原、未使用**。这一句是责任边界的书面固定。**写入报告的成本为零，省掉它的代价是无法预估的。**

**按错误判据走的代价**：把范围外凭据还原并写入报告，等于**用一次取证行为制造了一个新的凭据泄露事件**。

委托方的法务在流转中发现后，需要追溯报告的每一个接收方；而那个账号如果真的出问题，**账号所属单位的追责最终会落回这份报告**。

这类错误的代价不在取证环节，而在取证结束很久之后。


<a id="section-35"></a>

## 六、扩展阅读方向

下面五组方向不是链接清单，按"你在本篇之后会遇到什么"组织。


**第一组：同层深入——同一类目标的其他形态**

远控工具每家的存储格式都不一样，靠一篇覆盖全部不现实。下面这两篇补的是横向的方法面：一个在 Windows 端，一个在 Linux 端。

- [浏览器密码库与 Token 解密](crypto-app-browser-passwords-and-tokens.md) —— 单设备上凭据密度最高的目标。本篇的"字段分四种格式"在那篇里同样成立且更复杂：`Local Storage` 里的 token 常常是**明文**，拿到即用；而 Chrome 127 引入的 App-Bound Encryption 又让"读 `Local State` 就能解"的老路径在部分数据上失效。两篇合起来才构成 Windows 端凭据的完整地图。
- [远程控制工具痕迹](../../server/server-panel/server-panel-remote-control-artifacts.md) —— 本篇处理配置文件里的**静态痕迹**，那篇处理**外联行为**：进程、连接、自启动项。可以从行为侧独立印证"这台机器确实运行过它"，而不只是"配置存在"。

**第二组：相邻议题——痕迹的"另一只脚"是时间**

本篇判据大量依赖"最后修改时间是否落在时间窗内"。要把这个字段做实，离不开主机侧的其它时间源。

- [时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md) —— 本篇陷阱 10 的方法论底座。TeamViewer 的连接记录用 UTC、详细日志用本地时间，两者差值恰好等于时区偏移。不做统一基准的时序比较会产出"认证成功早于连接开始"这种荒谬的因果倒置，而"日志被伪造"是个极重的结论。
- [LNK 与 JumpList](../../computer/computer-execution/computer-execution-lnk-jumplist.md) —— 远控客户端被启动过这件事，程序侧痕迹往往比配置更细：MRU 里的完整路径、带时间戳的访问记录。**配置能被删，程序侧痕迹常常还在**，两者可以互为备份。
- [时间线重建](../../computer/computer-log/computer-log-linux-timeline-reconstruction.md) —— 本篇产出的记录表最终要汇入全局时间线。多来源合并时的基准统一、冲突处理与置信度标注在那篇里有完整方法。

**第三组：工具与规范——合规边界与凭据卫生**

本领域代价最高的错误往往不是技术错误，而是把取证做成了入侵。

这组讲"能做什么"与"不能做什么"的分界。

- [通用密码恢复](crypto-app-passware-and-password-recovery.md) —— 当字段判定为加盐单向哈希时（AnyDesk 三件套、ToDesk `access_pin_hash`），本篇的处置是"固定存在性、转离线验证"。那篇给出**授权范围界定、最小化与脱敏**的完整要求，以及"为什么暴力破解必须是最后手段"的优先级表。它的三条合规红线对本篇的每一条哈希字段都直接适用。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md) —— "验证凭据"与"使用凭据"的法律分界，本篇 2.5 给的是结论层面的论证，这篇是制度层面的依据。委托书里哪些字句覆盖哪些操作，值得在开工前逐句确认。
- [数据库与配置文件加密](crypto-app-database-configuration-decryption.md) —— 远控配置定位只是第一步。同一批用户目录下往往还躺着 SQLite 数据库与自定义二进制格式的配置文件，它们的编码识别与解密思路和本篇的四类字段判读是同一套方法论。

**第四组：判据与反例——结论的脆弱性**

这一组最容易被忽略，但它直接决定本领域产出负面结论时能不能站住。

- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— 本篇的判据几乎全部建立在"文件时间可信"这个前提上。而当对方有技术能力、有动机在检材上动手脚时，**这个前提本身就需要被检验**：同一事实能否从另一类痕迹侧独立得到印证。读它是为了知道自己的结论有多脆弱，不是为了学怎么改。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 本篇方法论（先定位后解密、先非爆破后爆破、时间相关性优先于存在性）的上游来源。新接手这类案件时先对齐这里的流程框架，能省掉大量返工。

**第五组：报告化——从记录表到可采信的结论**

最后一步是把发现整理成能被复核的句子。这组决定你的结论在质证时经不经得起追问。

- [反取证与时间线的冲突排查](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) 与本篇陷阱 10 是一枚硬币的两面：当时间线出现"不可能的顺序"时，先排除时区与时钟漂移这两种良性成因，再考虑篡改。这个排除顺序错了，会把一个技术问题升级成对证据完整性的指控。
- [内存证据的可采性与报告](../../memory/memory-artifact/memory-artifact-memory-evidence-and-reporting.md) —— 如果你把内存侧的发现写进了报告，那份报告的结论强度、限定语写法与复核方式都有额外要求。这篇处理的是"内存结论为什么天然弱于磁盘结论，以及该怎么表述才不被推翻"。
- [取证技能树](../../fundamentals/fundamentals-process/fundamentals-process-forensics-learning-path.md) —— 本篇要求的前置能力（注册表、配置解析、时间基准）在这张技能树上的位置，以及缺哪一块该先补哪一块。
<a id="section-36"></a>

## 七、命令速查

```bash
# ===== 1. 全盘定位（Windows PowerShell，命令见步骤 1）=====
# 注意：只枚举不启动；永远不要在检材上运行被检远控程序

# ===== 2. 向日葵 =====
reg query "HKU\.DEFAULT\Software\Oray\SunLogin\SunloginClient\SunloginInfo"  /v encry_pwd
reg query "HKU\.DEFAULT\Software\Oray\SunLogin\SunloginClient\SunloginInfo"  /v fastcode
cat "/mnt/image/Program Files/Oray/SunLogin/SunloginClient/config.ini"   # 旧版

# ===== 3. AnyDesk =====
ls -la /mnt/image/ProgramData/AnyDesk/ /mnt/image/Users/*/AppData/Roaming/AnyDesk/
grep -oE '^ad\.[a-z_.]+=' "/mnt/image/ProgramData/AnyDesk/service.conf" | sort -u
# ad.anynet.id / ad.anynet.pwd_hash / ad.anynet.pwd_salt / ad.anynet.token_salt（哈希三件套，单向）

# ===== 4. TeamViewer =====
cat "/mnt/image/Program Files (x86)/TeamViewer/Connections_incoming.txt"   # 入向，仅成功，UTC
cat "/mnt/image/Users/zhang/AppData/Roaming/TeamViewer/connections.txt"   # 出向
grep -c 'AuthenticationPasswordLogin_Passive' "/mnt/image/Program Files (x86)/TeamViewer/TeamViewer15_Logfile.log"

# ===== 5. ToDesk / RustDesk =====
ls -la /mnt/image/ProgramData/ToDesk/ /mnt/image/Users/*/AppData/Roaming/ToDesk/ 2>/dev/null
cat /mnt/image/Users/zhang/AppData/Roaming/RustDesk/RustDesk.toml

# ===== 6. WinSCP 旧格式（可逆混淆，非加密）=====
reg query "HKCU\Software\Martin Prikryl\WinSCP 2\Sessions" 2>/dev/null
python3 -c "
v = bytes.fromhex('<Password值hex>')
print(bytes((255 - b) ^ 0xA3 for b in v).decode('utf-8','replace'))"
# 新版设了主密码 = AES-256-CBC，须先拿到主密码，否则不可解

# ===== 7. base64 判定（编码 ≠ 加密）=====
echo "<字段值>" | base64 -d 2>/dev/null; echo

# ===== 8. 批量汇总脚本 =====
python3 scan_remote_tools.py /mnt/image > remote_tools.csv     # 只固定痕迹，不解密

# 🚫 全流程硬性禁止：用以上任何结果发起真实连接
# ✅ 正确做法：离线还原 → 脱敏记录 → 上报委托方 → 由委托方在受控环境自行验证
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 加密取证 — 远程工具凭据的离线固定」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《远程工具凭据的离线固定》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-mem.raw` 均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
