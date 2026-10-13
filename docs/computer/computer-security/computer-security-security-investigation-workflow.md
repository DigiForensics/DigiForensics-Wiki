---
title: "取证实战流程"
slug: "computer-security-security-investigation-workflow"
canonical: "https://www.digiforensics.cn/wiki/computer-security-security-investigation-workflow"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:51+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "computer"
space: "计算机取证"
node_path: ["安全与权限"]
---

# 取证实战流程

<a id="section-1"></a>

## 一、概述

前七篇讲"macOS 上有什么、怎么看"。

这一篇讲的是另一件事：**从接手一台 Mac 到出报告，按什么顺序做**。

三个现场特征直接决定流程怎么排：

| 特征 | 直接后果 |
|---|---|
| FileVault 2 在 Monterey 之后默认开启 | 关机后卷处于锁定态，不先解决密钥就读不到数据卷明文 |
| **APFS 多卷共享块池** | 单独镜像某个卷会**丢失容器级元数据**，完整性无法证明 |
| **Apple Silicon 只能启动签名映像** | 无法用传统外接启动盘现场启动取证环境，通常回到物理或逻辑镜像路径 |

核心原则只有一条：先在不改写证据的前提下尽可能多取易失数据，再做物理镜像。

顺序错了，要么丢数据，要么破坏证据同一性。

另有三个现实必须显式处理：

| 现实 | 处理方式 |
|---|---|
| 统一日志、Spotlight 索引、内存态工件随关机消失 | 现场用 `log show` / `mdfind` 导出 |
| macOS 上的恶意软件常主动检测取证环境 | 现场处置记录必须详尽 |
| 破坏 Apple 封条在法律上有明确后果 | 见 2.7 |

**在取证流程中的位置**：本篇是 macOS 板块的**流程编排篇**，横跨采集与报告两端，既不是"只读挂载怎么做"那种单点技术，也不是"某个工件怎么解析"。它的输入是"一台处于某种状态的机器"，输出是一份完整处置链路：现场状态记录 → 零密钥结构确认 → 镜像制作 → 只读挂载与验证 → 按序提取 → 工具链与报告。**顺序在这里是内容的一部分，不是格式**——同一个动作放错位置，性质就从"取证"变成"改写证据"。所以它是这个板块的实际起点：前几篇是它的参考手册，最后几篇是它的深水区。

**本篇处理的证据形态**，按易失程度分四类，处置顺序由此决定：

| 优先级 | 证据 | 现场手段 | 丢失后果 |
|---|---|---|---|
| **P0** | 进程列表、网络连接、登录会话、打开的文件 | `ps auxww`、`netstat -an`、`who`/`w`/`lsof -nP`，**每份输出前置 `date -u`** | 关机后无法再取 |
| **P1** | 统一日志、Spotlight 索引与 `kMDItemWhereFroms` | `/usr/bin/log show --last 30d --info --style json`、`mdfind`、`mdutil -s` | 关机后只剩部分持久化部分 |
| **P2** | 硬件与系统标识、加密状态 | `system_profiler SPHardwareDataType`（型号、Chip、序列号、Hardware UUID）、`sw_vers`、`uptime`、**`fdesetup status`** | `uptime` 直接决定值不值得保持通电 |
| **P3** | 镜像与卷结构 | **整个 APFS 容器**（不是单个卷）、`diskutil apfs list`、容器超级块 | 缺失则完整性声明站不住 |

**每份现场输出都必须带采集时刻，且必须录像**——屏幕内容、登录用户、连接状态都要入镜。零密钥阶段还有一层：`FileVault` 没解开时不碰数据，也能靠 `diskutil apfs list` 的容器与卷清单、`ntfs`/`apfs` 结构的可见部分确认这台机器上"应该有什么"，这个结论本身就是有价值的产出。

这台设备的型号、芯片、序列号与硬件 UUID、加密状态、卷与快照布局、通电时长、处置顺序为什么这么排，以及每个环节拿到了什么、每份输出的采集时刻。

**顺序对了不等于数据全**——关机状态下 Spotlight 索引与内存态工件已经没了，`log show` 导出的也只是持久化部分，报告里要写明"哪些易失项因设备关机未能获取"。FileVault 密钥不在这台机器上时，**镜像做得再规范也只能做零密钥结构分析**，此时能出的结论限于结构性判断（例如存在多少个用户卷、有没有加密的交换卷），内容层面一概不能碰，所以阴性表述的门槛在零密钥现场要高得多。`uptime` 短不代表没发生过什么，它只说明现场状态与事发状态可能已经隔开了，**时间线断层必须写明**。另外本篇给不出结论，结论要靠证据链与交叉验证得出（见 [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md)）；**它也无法判断机器上运行的恶意软件具体做了什么**——那要回到 plist、统一日志、`LaunchAgents` 与 Quarantine 的具体分析。

**读者前提**：需要先读完本板块前两篇，知道工件在哪些路径下；需要理解 FileVault 2 的加密范围与 APFS 容器／卷／共享块池的关系，这两件事直接决定"能不能取"和"怎么证明没被破坏"；需要知道 Apple Silicon 的启动安全性机制意味着无法现场外接启动盘，这不是工具缺失而是平台限制，通常只能回到物理镜像这条路径；还要接受一条纪律：**封条、录像、采集记录本身就是交付物的一部分**，现场处置记录越详细，复核时能还原的空间越大；最后需要具备现场判断能力——`uptime` 与封条状态这种信息只出现一次，判断错了没有第二次机会。

---
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 现场处置决策树

```
收到一台 Mac
    │
    ├─ 已关机？──→ FileVault 状态？
    │              ├─ 已解锁 → 直接镜像
    │              └─ 已锁定 → ★ 必须先取得密钥
    │
    └─ 通电 ──→ ★ 关键决策点
          ├─ 近期有使用且易失数据有价值 → 先导出易失数据 → 关机 → 镜像
          ├─ 长期闲置、易失数据无价值     → 直接关机 → 镜像
          └─ 疑似作案进行中              → ★ 保持现状，立即记录全部现场状态
```

**"是否关机"没有标准答案，只有权衡记录。**

复核人看的不是结论对不对，而是**当时的信息支撑下这个决策是否合理**。

**决策理由、决策人、时间必须写进现场记录。**

<a id="section-4"></a>

### 2.2 FileVault 密钥的四条合法路径

| 路径 | 适用 | 说明 |
|---|---|---|
| 委托人当面解锁 | 最常见 | 在委托方或司法人员在场时输入口令，当场镜像 |
| 个人恢复密钥 | 委托人记得 | Apple ID 账户可查 |
| 组织统一管理的恢复密钥 | 企业环境 | IT 部门集中保管，需书面授权 |
| 依法向 Apple 调取 | 常规路径均不可行 | 需司法程序，周期长 |

```bash
fdesetup status
# FileVault is Off.                        ← 未启用
# FileVault is On.                         ← 已启用且已解锁（通电状态）
# FileVault is Enabled, but not unlocked.  ← ★ 已启用且已锁定（关机状态，最常见）
```

> **三条红线**：报告只写"已使用合法取得的密钥解密"，**绝不记录密钥字符串**；不得尝试暴力破解或绕过密钥派生；**"已锁定"绝不等于"数据已销毁"**——这个措辞是事实性错误。

<a id="section-5"></a>

### 2.3 APFS 容器整体镜像的必要性

这是 macOS 取证中最容易造成不可逆后果的一类操作。

```
APFS 容器（disk0s2，494.4 GB）
├── 容器超级块（NXSB）        ← 块大小、总块数、块池分配表
├── 各卷的 B-tree 元数据      ← 文件名与 inode 映射
└── 共享块池
    ├── Macintosh HD（系统卷，只读签名）    ├── Macintosh HD - Data（用户数据）
    ├── Preboot（预启动）                   ├── Recovery（恢复）
    └── VM（交换）
```

**单独 `dd` 某个卷会丢掉什么**：

| 丢失的元数据 | 后果 |
|---|---|
| **容器超级块** | 无 `NXSB` 头，APFS 解析器**可能直接拒绝打开** |
| **块池分配表** | 无法确定哪些块属于哪个卷，**卷边界不可信** |
| **其他卷的元数据** | 缺 Preboot 会影响系统卷引导校验；缺 VM 丢失交换数据 |
| **快照索引** | 本地快照全部不可见，**丢失"删除前内容"** |

```bash
sudo dd if=/dev/rdisk0   of=/Volumes/Evidence/DigiForensics.dd bs=4m status=progress  # ✓ 整盘
sudo dd if=/dev/rdisk0s2 of=/Volumes/Evidence/DigiForensics.dd bs=4m status=progress  # ✓ 整容器
sudo dd if=/dev/rdisk3s5 of=/Volumes/Evidence/DigiForensics.dd bs=4m                  # ✗ 只镜像数据卷
```

> **"容量够就行"是错误的**。

数据卷显示的 447.8 GB **既不是该卷实际占用块数**（共享块池中属于它的块是离散的），也不是完整证据范围。

**正确做法是镜像整个容器或整盘。**

<a id="section-6"></a>

### 2.4 只读挂载的三种路径

| 方式 | 命令 | 限制 |
|---|---|---|
| **Linux `apfs-fuse`**（主力） | `apfs-fuse -r <key> -o vol=2,ro /dev/loop0 /mnt/mac-data` | ★ **默认只暴露一个卷**；FileVault 需 `-r` |
| **macOS `mount_apfs`** | `sudo mount_apfs -o rdonly,nobrowse …` | 原生兼容性最好 |
| **镜像挂载** | `diskutil image attach -readonly DigiForensics.dd` | 快速查看卷布局 |

> `hdiutil attach` 在现代 macOS 已弃用，实测会输出 `'hdiutil attach ...' is deprecated. Please use 'diskutil image attach ...' instead.`。报告里写命令要用 `diskutil image attach`。

> **只读挂载后必须做的事**：记录挂载前的镜像 SHA-256，分析完成后卸载并**重新校验哈希**。这是"全程未改写证据"的可复核证明。**只写"只读挂载"而没有哈希对比，等于没有证明。**

<a id="section-7"></a>

### 2.5 易失数据的优先级

| 优先级 | 内容 | 采集命令 | 丢失后果 |
|---|---|---|---|
| **P0** | 进程与网络连接 | `ps auxww`、`netstat -an` | **完全丢失** |
| **P0** | 已登录用户与登录会话 | `who`、`w` | **完全丢失** |
| **P1** | 剪贴板 | `pbpaste` | 完全丢失 |
| **P1** | 统一日志（近 30 天） | `/usr/bin/log show --last 30d` | 部分丢失（`.tracev3` 解析难） |
| **P1** | Spotlight 索引查询结果 | `mdfind` / `mdls` | 关机后无法通过索引查询取得（`.Spotlight-V100` 目录仍在镜像中，解析需另行处理） |
| **P2** | 打开的文件与网络挂载 | `lsof`、`mount` | 丢失 |
| **P3** | FileVault 状态等 | `fdesetup status` | 关机后仍可从镜像取得 |

> **P0–P2 大多在关机后无法再采集**，这就是"能不能关机"这个决策的核心依据。

<a id="section-8"></a>

### 2.6 Apple Silicon 与启动安全性

| 能力 | Intel Mac | Apple Silicon |
|---|---|---|
| 外接启动盘启动系统 | 可（`Option` 键） | ★ **不可**（只能启动签名映像） |
| 降低启动安全性策略 | 可（需管理员密码） | 需另一台 Mac + 恢复固件更新（**法律上通常不允许**） |
| 扣押后被引导攻击的风险 | 较高 | ★ **较低** |

> **对取证的影响**：Apple Silicon 上**无法制作可启动的取证副本**，只能逐块物理镜像后在分析机上分析。这不是技术缺陷，是安全设计的副作用。

<a id="section-9"></a>

### 2.7 封条与证据完整性

| 情形 | 风险 |
|---|---|
| 要求"保持原样"却破坏封条 | 证据同一性受质疑，委托方可能主张排除 |
| 拆机换盘导致来源链断裂 | 需额外说明拆机过程与新盘来源 |
| 涂抹机器标识 | 可能被认定为**破坏证据** |

**核查**：**开箱与拆机全程录像**（覆盖封条原状、序列号、型号）；**记录封条编号与状态**；**拆机前取得书面授权**并写明授权人、时间、范围；**拆下部件单独封存编号**，并记录它与主机的对应关系。

---

<a id="section-10"></a>

## 三、操作步骤

<a id="section-11"></a>

### 3.1 第 1 步：现场状态记录（通电状态下立即执行）

```bash
system_profiler SPHardwareDataType      # 型号、Chip、序列号、Hardware UUID
sw_vers; uptime                          # ★ uptime 判断是否值得保持通电
fdesetup status                          # ★ FileVault 状态

# 易失数据 P0（关机即永久丢失）
{ date -u '+%FT%TZ'; ps auxww; }  > /evidence/live-ps.txt
{ date -u '+%FT%TZ'; netstat -an; } > /evidence/live-netstat.txt 2>&1
{ date -u '+%FT%TZ'; who; w; lsof -nP; } > /evidence/live-users.txt 2>&1

# 易失数据 P1：统一日志与 Spotlight
/usr/bin/log show --last 30d --info --style json > /evidence/live-log-30d.json 2>/dev/null
/usr/bin/log show --last 1h --info --style compact \
  --predicate 'subsystem == "com.apple.securityd" OR subsystem == "com.apple.network"' \
  > /evidence/live-log-security.txt 2>/dev/null
mdfind -onlyin /Users/liwei "kMDItemWhereFroms == '*'" > /evidence/live-wherefroms.txt 2>/dev/null
mdutil -s / > /evidence/live-mdutil.txt
mount > /evidence/live-mount.txt;  df -h > /evidence/live-df.txt
```

> **每份输出都要带采集时刻**（上面已前置 `date -u`）。同时**录像**：屏幕内容、登录用户、连接状态都要入镜。

<a id="section-12"></a>

### 3.2 第 2 步：零密钥结构确认

取得密钥之前也有活可干，而且这些结论必须最先写进报告：

```bash
mmls /work/DigiForensics.dd                          # 找 APFS 分区起始扇区
APFS_PART=775920
xxd -s $((APFS_PART*512 + 32)) -l 16 /work/DigiForensics.dd
# → 4e585342 ...   ← NXSB 魔数：确认是 APFS 容器、块大小
apfsutil -o $((APFS_PART*512)) /work/DigiForensics.dd   # 卷列表、oid、快照
```

**零密钥可得的结论**：文件系统类型、块大小、卷数量与名称、各卷 `oid`、快照存在与否与创建时间。

**这些不依赖任何密钥，成本最低，也最经得起复核。**

<a id="section-13"></a>

### 3.3 第 3 步：镜像制作

```bash
diskutil list                             # 区分 (internal, physical) 与 (synthesized)
diskutil apfs list | grep -E 'APFS Container Reference|Volume Name|Capacity'
df -h /Volumes/Evidence                   # 目标 ≥ 容器标称容量 × 1.03
diskutil unmountDisk /dev/disk3           # 减少写入风险

sudo dd if=/dev/rdisk0   of=/Volumes/Evidence/DigiForensics.dd bs=4m status=progress
sudo dd if=/dev/rdisk0s2 of=/Volumes/Evidence/DigiForensics.dd bs=4m status=progress
shasum -a 256 /Volumes/Evidence/DigiForensics.dd | tee /evidence/DigiForensics.dd.sha256
```

| 纪律 | 原因 |
|---|---|
| 必须用 `r` 前缀设备 | 非 `r` 走缓冲 I/O，慢一个数量级 |
| `bs=4m` 或更大 | 默认 512 字节块做 500 GB 镜像需数小时 |
| 完成后立即算 SHA-256 | 为后续每次只读挂载前后提供可复核的同一性基线 |
| 记录 dd 起止时间 | 与案件时间线对照 |
| 目标 ≥ 容器标称容量 × 1.03 | APFS 独立卷与元数据开销不在主卷显示容量里，具体余量按现场文件系统状况调整 |

<a id="section-14"></a>

### 3.4 第 4 步：只读挂载与验证

```bash
shasum -a 256 /work/DigiForensics.dd > /evidence/baseline.sha256     # ★ 挂载前算基线
apfs-fuse -r "<恢复密钥>" -o vol=2,ro /dev/loop0 /mnt/mac-data
# 或：diskutil image attach -readonly /work/DigiForensics.dd
mount | grep apfs                       # 确认含 ro

EV=/mnt/mac-data
ls -1 $EV/Users/
ls -1 $EV/Library/LaunchDaemons/ | wc -l
ls -1 $EV/Users/*/Library/LaunchAgents/ | wc -l
ls -1 $EV/var/db/diagnostics/Persist/ | wc -l
ls -1 $EV/Users/*/Library/Containers/ | wc -l              # 沙盒容器数（最易漏）
ls -l  $EV/Users/*/Library/Keychains/;  ls -la $EV/Users/*/.Trash/
ls -la $EV/Volumes/*/.Trashes/ 2>/dev/null                # 外接卷废纸篓

last -f $EV/private/var/log/wtmp | head -10               # ★ 检材时间锚点

fusermount -u /mnt/mac-data
shasum -a 256 -c /evidence/baseline.sha256               # 卸载后复核
```

<a id="section-15"></a>

### 3.5 第 5 步：提取顺序

| 顺序 | 目标 | 入口 | 篇 |
|---|---|---|---|
| **1** | 容器/卷结构、快照 | `apfsutil`、`diskutil apfs listSnapshots` | 01/06 |
| **2** | 用户目录与 `~/Library` 全貌 | `ls` 清点 + 哈希 | 01 |
| **3** | 启动项与持久化 | `launchctl list`、`plutil` 清点 | 02 |
| **4** | 统一日志 | `log show` / 解析器 | 02 |
| **5** | 偏好与 ByHost UUID | `plutil`、UUID 比对 | 03 |
| **6** | **Quarantine 全量导出与解码** | `xattr -p` + 十六进制解码 | 05 |
| **7** | Keychain 元数据 | `security find-*`（工作副本） | 07 |
| **8** | 浏览器（Safari/Chrome/Firefox） | `sqlite3`、`plutil` | 07 |
| **9** | 废纸篓与 FSEvents | `ls`、FSEvents 解析器 | 06 |
| **10** | 邮件、IM、Messages | 数据库导出 | — |
| **11** | Time Machine（需单独扣押备份盘） | `tmutil listbackups` | 06 |

> **第 6 项放在第 7、8 项之前**：Quarantine 能一次给出文件经过下载通道的时刻与应用名，**且能指引后续浏览器分析方向**（先知道哪些文件是下载的，再去浏览器里查对应站点）；它证明的是下载通道，不证明文件内容可信。

<a id="section-16"></a>

### 3.6 第 6 步：工具链

| 类别 | 工具 | 用途 | 备注 |
|---|---|---|---|
| 事实采集 | `mac_facts`（Miro 等） | 一次性导出大量系统事实 | 需 root；**纯文本输出便于入报告** |
| APFS 解析 | `apfs-fuse`、`apfsutil` | 挂载与结构解析 | 主力组合 |
| plist | `plutil`、`plistutil` | 批量转换与统计 | `plistutil` 适合批量出 JSON |
| 痕迹关联 | `mac_apt` 类工具 | 持久化与应用清单关联 | 第三方，需实测 |

**时间线合并的三条纪律**：**每行必须有来源列**（否则无法复核）；**统一时区后再跨源比较**；**保留原始值**（解码前的十六进制、转换前的微秒值另存一列）。

```bash
printf '%s\	%s\	%s\	%s\
' "2024-09-05 14:22:25" "quarantine:xattr"    "客户名单.xlsx" "portal.rival-exim.example"
printf '%s\	%s\	%s\	%s\
' "2024-09-05 14:22:25" "safari:Downloads"   "客户名单.xlsx" "portal.rival-exim.example"
printf '%s\	%s\	%s\	%s\
' "2024-09-05 14:22:25" "chrome:urls"         "客户名单.xlsx" "portal.rival-exim.example"
```

---
<a id="section-17"></a>

## 四、常见陷阱

<a id="section-18"></a>

### 4.1 现场决策与处置顺序

<a id="section-19"></a>

#### 陷阱 1：★ 只镜像某一个 APFS 卷

**现象**

在 macOS 上用 `diskutil apfs list` 看到 `Macintosh HD`（系统卷，只读签名，约 20 GB）和 `Macintosh HD - Data`（数据卷，约 460 GB），于是只对数据卷执行 `dd if=/dev/rdisk0s2`。事后报告里写「已完整获取该机用户数据卷镜像」。

**原因**

APFS 的组织单位是**容器**，不是卷。

多个卷共享一个块池，容器的元数据结构如下：

```
APFS 容器（disk0s2）
├── 容器超级块（NXSB 魔数 4e585342）   ← 块大小、总块数、块池分配表
├── 各卷独立的 B-tree 映射             ← 文件名 ↔ inode ↔ 物理块
└── 共享块池
    ├── Macintosh HD（系统卷，SSV 签名，只读）
    ├── Macintosh HD - Data（用户数据）
    ├── Preboot（预启动）  ├── Recovery（恢复）  └── VM（交换）
```

单卷 `dd` 丢掉的不是"别的卷的内容"，而是**让这个卷可被正确解释的全部前提**：

| 丢失的元数据 | 后果 |
|---|---|
| **容器超级块** | 无 `NXSB` 头，APFS 解析器可能直接拒绝打开 |
| **块池分配表** | 无法确定哪些块归属哪个卷，**卷边界不可信** |
| **快照索引** | 本地快照全部不可见，**"删除前内容"整体丢失** |
| **Preboot 卷** | 系统卷签名校验依赖它，缺失影响可引导性 |
| **VM 卷** | 交换数据丢失，本就难以恢复的内存残留随之消失 |

**影响**

这是 macOS 取证中**事后无法补救**的错误。

镜像一旦做成，无法通过后期手段补回容器元数据与快照：

- 「删除前内容」往往直接依赖本地快照，而快照索引只存在于容器层
- 卷边界不可信意味着连"这个文件属于数据卷还是系统卷"都无法确定，后续所有归属判断都失去基础
- 报告写「完整获取」，实际是残缺镜像；一旦对方质证完整性，整份分析的可信度都会塌陷

**核查**

镜像整个容器（`disk0`），或至少 `disk0s2` 容器分区：

```bash
diskutil apfs list | grep -E 'APFS Container Reference|Volume Name|Capacity|Capacity Ceiling'
# 确认目标：容器 Capacity Ceiling 才是 dd 的对象，不是某个 Volume 的 Capacity

sudo dd if=/dev/rdisk0 of=/Volumes/Evidence/DigiForensics.dd bs=4m status=progress
# 目标介质容量 ≥ 容器标称容量 × 1.03
```

**注意不要用数据卷的显示容量来估算目标大小。**

共享块池中某个卷的 `Capacity` 与它实际占用的物理块没有固定关系，真正需要的是容器的 `Capacity Ceiling`。

<a id="section-20"></a>

#### 陷阱 2：★ 发现设备通电就直接关机，丢掉全部内存态证据

**现象**

扣押到一台正在通电运行的 Mac，第一反应是拔电关机保护数据，然后做镜像。报告里写「为保护证据，已立即关机」。

**原因**

关机这个动作**本身在销毁证据**，而且销毁的是最难替代的一类。

macOS 上 P0–P2 优先级的多数易失数据在关机后无法再采集：

| 优先级 | 内容 | 丢失后能否从镜像取回 |
|---|---|---|
| **P0** | 进程列表、网络连接、已登录会话 | **完全不能** |
| **P1** | 剪贴板内容、Spotlight 索引查询能力 | **完全不能**（`mdfind` 查询能力随系统停止，索引库本身需另行解析） |
| **P1** | 统一日志（近 30 天，含 `--info` 级别） | 部分丢失（`.tracev3` 离线解析困难） |
| **P2** | 打开的文件句柄、网络挂载点 | **完全不能** |
| **P3** | `fdesetup status` 等 | 可从镜像取得 |

其中 Spotlight 索引尤其关键：`mdfind -onlyin /Users/<name> "kMDItemWhereFroms == '*'"` 一次性列出全部带来源记录的文件，关机后**这条命令无法再执行**。

**影响**

- "立即关机保护证据"的表述本身就是**事实性错误**，关机恰恰是改写证据状态的动作
- 「下载文件列表」这一类直接指向外发行为的证据，可能只存在于内存态索引中
- 复核人看的是"当时的信息支撑下这个决策是否合理"。没有记录 `uptime`、登录状态、易失数据价值就直接关机，**决策缺少依据，无法自证合理性**

**核查**

关机/取易失数据是一个需要记录依据的权衡决策，不是默认动作：

```bash
# 决策前必须先采集的判断依据
system_profiler SPHardwareDataType
sw_vers; uptime                # ★ uptime 判断是否值得保持通电
fdesetup status
who; w                         # 是否有人在线使用
```

| 现场状态 | 处置 | 记录要求 |
|---|---|---|
| 近期有使用且易失数据有价值 | **先导出易失数据 → 关机 → 镜像** | 写明采集清单、采集时刻、决策人 |
| 长期闲置、易失数据无价值 | 直接关机 → 镜像 | 写明"因 `uptime` 显示长期无活动，易失数据无采集价值" |
| 疑似作案进行中 | **保持现状，立即记录全部现场状态** | 录像、拍照、记录连接状态，不做任何操作 |

即使决定不取易失数据，也必须在现场记录里写清"评估过、判断价值为低、理由是 XXX"，而不是省略这一步。

省略与"没想过"在复核时无法区分。

<a id="section-21"></a>

#### 陷阱 3：发现恶意软件就顺手"清理"

**现象**

在系统上发现可疑的 LaunchDaemon、异常 rootkit 特征或正在运行的可疑进程，现场处置人员直接删除文件、结束进程、卸载应用，认为"清除威胁后再取证更安全"。

**原因**

清理动作改变的是**证据状态**，而取证的目标恰恰是记录这个状态：

- 结束进程 → 内存态证据、进程与网络连接全部消失
- 删除文件 → 目录项、inode、以及 FSEvents 中已记录的变更线索一并消失
- 卸载应用 → `~/Library` 下的偏好、容器、Keychain 条目、LaunchAgent 全部可能被连带清除
- 恶意软件**本身就可能带有反取证行为**（检测分析环境、Hook 系统调用），清理过程会额外触发它，留下与案件无关的干扰记录

**影响**

- **在法律性质上，擅自改变设备状态可能构成破坏证据**，尤其是委托方设备或涉及刑事案件时
- 清理后无法判断该组件是何时、由什么方式植入的——这些时间线信息只存在于被删除的对象里
- 无法证明"清理前后的差异"，也就无法证明清理行为本身对案情的干扰程度

**核查**

**隔离而不清理，记录而不动作**：

```bash
# 观察与记录，不终止
ps auxww | grep -iE 'suspicious|miner|proxy' 
lsof -nP -p <pid> 2>/dev/null      # 记录该进程打开的所有文件与网络连接

# 保持网络可用性判断（是否需要断网由委托方与办案机关决定，不自行处置）
netstat -an | grep -E 'ESTABLISHED|SYN_SENT'
```

现场处置原则：**先记录、后隔离；只读、不改写。**

确需断网时，由办案机关或委托方书面决定，并记录决策时间与理由。

<a id="section-22"></a>

### 4.2 完整性与只读接入

<a id="section-23"></a>

#### 陷阱 4：先分析、后算基线哈希，导致"未改写证据"无法证明

**现象**

把镜像挂载上去开始分析（跑脚本、跑 `plutil`、跑解析器），等到想起来要证明镜像没被改过时，才对镜像算一个 SHA-256，报告里写「镜像哈希已记录，完整性可验证」。

**原因**

一个**事后**算出的哈希，只能证明"当前磁盘上的文件是这个哈希"，**不能证明它等于 `dd` 那一刻的状态**。

中间发生了多少读写，这个哈希一概不体现。

更有迷惑性的是：只读挂载确实降低了风险，但"只读"是一个**配置声明**，不是**验证结果**。

挂载参数写错了、工具在挂载点内建了临时文件、文件系统层的写操作发生在卸载时的缓存回写——这些都不会在事后哈希上体现。

**影响**

- 「全程未改写证据」这个结论**缺少可复核的依据**，成为报告里最容易被质疑的一句
- 一旦后续需要证明镜像的原始性，缺少基线就只能依赖其他间接证据，说服力大幅下降
- 争议案件中，委托方可能据此主张整份分析结果不可采

**核查**

**基线哈希必须在挂载之前算，并做前后对比**：

```bash
# 第一步：挂载前算基线
shasum -a 256 /work/DigiForensics.dd > /evidence/baseline.sha256
cat /evidence/baseline.sha256

# 第二步：只读挂载
apfs-fuse -r "<恢复密钥>" -o vol=2,ro /dev/loop0 /mnt/mac-data
mount | grep apfs                     # ★ 确认输出中含 ro

# 第三步：分析完成后卸载
fusermount -u /mnt/mac-data

# 第四步：重新校验，输出必须为 OK
shasum -a 256 -c /evidence/baseline.sha256
```

只有第四步输出 `DigiForensics.dd: OK`，才能在报告里写「分析前后哈希一致，可证明分析过程未改写镜像」。

**挂载点内不得运行任何写入操作**：不要在挂载点里建临时目录，不要在里面跑会产生缓存的数据库工具，也不要在挂载点里解压文件。

需要写操作时，一律先复制到分析侧工作副本。

<a id="section-24"></a>

#### 陷阱 5：`apfs-fuse` 默认只暴露一个卷，报告却写"已挂载全部卷"

**现象**

执行 `apfs-fuse -r "<key>" -o vol=2,ro /dev/loop0 /mnt/mac-data` 挂载成功，看到能读 `Users/` 目录，就在报告里写「该机文件系统已完整挂载」。后续分析在 `/mnt/mac-data` 下找不到 `System/Library/LaunchDaemons`、也找不到 `Volumes/`，于是记为「该机无此类内容」。

**原因**

`apfs-fuse` 默认只暴露 `vol=` 指定的那一个卷，并且它不提供卷选择菜单 —— 挂载"成功"只意味着那一个卷可读。

- `vol=2` 通常是数据卷，用户目录在它下面，所以看起来"一切正常"
- 系统卷（`Macintosh HD`）在另一个卷上，`/System/Library/` 下的启动项、预启动配置都拿不到
- `Preboot` 卷不可见 → 系统卷引导校验相关数据缺失
- `Recovery` 与 `VM` 卷不可见 → 交换数据丢失
- **APFS 本地快照全部不可见** —— 快照索引在容器层，未挂载容器等于放弃"删除前内容"

**影响**

把"没挂上"写成"不存在"，会在报告里制造一批**虚假阴性结论**：

- 「未发现恶意 LaunchDaemon」——实际是没看系统卷
- 「未发现外接卷废纸篓」——`/Volumes/*` 根本不在这个卷上
- 「未发现本地快照」——快照索引不在数据卷里

**核查**

**先列出全部卷，再逐个挂载**：

```bash
# 列出容器内所有卷及其 oid
apfsutil -o $((APFS_PART*512)) /work/DigiForensics.dd
# 或
diskutil apfs listSnapshots /dev/disk3

# 逐卷挂载到不同挂载点
apfs-fuse -r "<key>" -o vol=1,ro /dev/loop0 /mnt/mac-sys
apfs-fuse -r "<key>" -o vol=2,ro /dev/loop0 /mnt/mac-data

# 在 macOS 分析机上用原生挂载，兼容性最好，可一次看到全部卷
sudo mount_apfs -o rdonly,nobrowse /dev/disk3s1 /Volumes/vol1
sudo mount_apfs -o rdonly,nobrowse /dev/disk3s2 /Volumes/vol2
```

**报告里必须列出实际挂载的卷与未挂载的卷**，并明确"未挂载卷中的路径不可达"这一限制。

阴性结论只能限定在已挂载卷的范围内。

<a id="section-25"></a>

#### 陷阱 6：把「FileVault 已锁定」写成「数据已被销毁」

**现象**

设备已关机，`fdesetup status` 显示 `FileVault is Enabled, but not unlocked.`，报告里写「该设备已加密，数据处于不可恢复状态」或「数据已销毁」。

**原因**

FileVault 锁定是访问控制状态，不是数据状态。 盘上的每一个字节都还在，只是没有密钥就无法解密出可读内容。

三条合法路径中通常至少有一条可行：委托人当面解锁、个人恢复密钥（Apple ID 账户可查）、组织 IT 集中保管的企业恢复密钥。

`Enabled, but not unlocked` 只说明**本机当前没有密钥**，不说明**不存在密钥**。

"已锁定"与"已销毁"在技术上也完全不是一回事——即使 FileVault 关闭，APFS 加密（`Volume UUID` 密钥）仍可能单独生效。

**影响**

- 「数据已销毁」是**事实性错误**，会直接影响委托方对证据可用性的判断，可能导致他们放弃设备、销毁其他关联证据
- 措辞不当还可能被对方引用，主张取证方明知存在未穷尽的取证途径而提前终止

**核查**

「已锁定」「不可读」「无法访问」与「已销毁」必须严格区分：

```bash
fdesetup status
# FileVault is Off.                        未启用
# FileVault is On.                         已启用且已解锁（通电状态）
# FileVault is Enabled, but not unlocked.  已启用且已锁定
```

报告的标准表述：

> 设备处于关机状态，`fdesetup status` 显示 FileVault 已启用但未解锁。盘上数据经 FileVault 加密，**内容不可读，但未被销毁**。本次通过【委托人当面解锁 / 个人恢复密钥 / 组织统一恢复密钥】合法取得密钥，密钥字符串不在本报告中记录。镜像为完整物理镜像，解密后可见全部卷。

**三条红线同时适用**：报告不记录密钥字符串；不尝试暴力破解或绕过密钥派生；绝不使用「已销毁」「不可恢复」这类描述。

<a id="section-26"></a>

#### 陷阱 7：在分析机上跑 `last`、`who` 得出用户活动结论

**现象**

想确认这台 Mac 上最近有哪些用户登录过，直接在分析机上执行 `last reboot`、`last | head`，把输出写进报告作为「该机登录记录」。

**原因**

`last` / `who` / `w` 读的都是**本机**的记账文件：

- `last` → `/var/log/wtmp`（有的系统是 `/private/var/log/wtmp`）
- `who` / `w` → utmp 活动数据库
- `last reboot` → 重启记录

在分析机上跑，读到的是**分析机的**登录与重启历史，与检材毫无关系。

而分析机往往被多人共用，日志里全是别人的账号。

**影响**

- 报告里会出现**完全无关的第三方账号名**，这既是结论错误，也是信息泄露
- 复核人一眼就能看出问题，会连带质疑其他未经复核的数据
- 检材的真实登录记录仍然缺失，登录时间线这个关键维度直接断掉

**核查**

**从镜像路径读取，并用 `-f` 显式指定**：

```bash
EV=/mnt/mac-data
last -f "$EV/private/var/log/wtmp" | head -10      # ★ 完整登录/登出历史
last -f "$EV/private/var/log/wtmp" reboot | head   # ★ 重启记录
last -f "$EV/private/var/log/btmp" | head          # ★ 失败登录（需 root 读取）
```

`wtmp` 里的时间戳本身就是**检材的时间锚点**——它给出了"最后一次正常关机"和"最后一次登录"的确切时刻，是把磁盘态工件与时间线对齐的基准。

任何来自 `w`/`who` 的现场记录也必须标明采集时刻，否则无法与 `wtmp` 交叉。

<a id="section-27"></a>

#### 陷阱 8：无差别全盘提取，触碰无关人员隐私

**现象**

为"不漏掉任何东西"，对整个数据卷做全量文件提取，包括 `~/Documents` 里的私人聊天记录、家属的邮件、其他员工目录下的文件。委托方事后才发现提取范围远超授权。

**原因**

macOS 上一个用户目录往往混着**三类完全不同性质的数据**：

| 类别 | 举例 | 授权状态 |
|---|---|---|
| 与案件相关 | 下载目录、Quarantine 标记文件、浏览器痕迹 | 已授权 |
| 与案件无关的隐私 | 私人邮件、家人照片、医疗文档 | **未授权** |
| 涉及第三方 | 其他用户目录、系统账号文件 | **需单独授权** |

"不漏证据"的正当性与"全盘抓取"之间没有必然联系——定向提取同样可以做到不遗漏，而且证据价值高、可解释性强的正是那三类与案件相关的数据。

**影响**

- **超出授权范围提取在很多司法辖区都可能构成违法**，不只是职业规范问题
- 无关人员的隐私数据一旦进入证据链，后续需做额外的处置与封存，成本极高
- 委托方与设备其他所有人的权益都受影响，可能引发投诉乃至诉讼

**核查**

**按用户、按数据类别逐一确认授权，并记录范围**：

| 提取范围 | 授权依据 | 记录方式 |
|---|---|---|
| `/Users/liwei/Downloads/` | 委托方书面授权 | 授权文号、范围、期限 |
| `/Users/liwei/Library/` 痕迹类路径 | 同上 | 逐路径列出 |
| `/private/var/log/` | 案件需要 | 记入范围说明 |
| `/Users/<他人>/` | **单独授权** | 未授权则不动 |
| 私人文档内容 | **不提取** | 仅记录文件存在性与元数据 |

对未授权但可能有价值的内容，正确做法是**记录其存在性、路径与元数据**（大小、mtime、btime），把是否提取交由委托方决定，而不是自行打开。

<a id="section-28"></a>

### 4.3 报告结论表述

<a id="section-29"></a>

#### 陷阱 9：把时间线合并结果写成"该时刻用户正在做某事"

**现象**

三条时间一致的证据（Quarantine 解码时间、Safari 下载条目、Chrome 访问记录）都指向 `2024-09-05 14:22:25`，报告里写「14:22:25 用户下载并访问了 `portal.rival-exim.example`」。

**原因**

三类工件记录的是**三种不同的动作**，时间相同不等于动作相同：

| 工件 | 记录的实际内容 | 该时刻能证明的动作 |
|---|---|---|
| `com.apple.quarantine` xattr | 应用写入属性时的时间 | **文件被下载应用写入属性** |
| `Downloads.plist` | 下载条目 | **下载动作被 Safari 记录** |
| `History.db` / `urls` 表 | URL 访问 | **浏览器与该 URL 建立了访问记录** |

同一秒出现三条记录，最强的推论是「**这些动作发生在同一时间窗口内**」，不是「三个动作是同一个连续行为」。

文件被下载后可能被解压、被改名、被复制到别处、被邮件客户端读取——这些都不在这三条记录里。

也要警惕反向的过度推论：时间点接近也可能来自**同一次批量操作**（例如从列表页下载多个文件），而不是针对特定目标。

**影响**

- 把"文件来源"直接推成"文件被使用并外发"，中间缺了执行痕迹、传输痕迹等整条链
- 报告里的行为描述成为对方质证的重点：「你怎么证明用户打开了这个文件？」
- 一旦缺失环节被发现，整条时间线的可信度都会受影响

**核查**

时间线按来源列合并，且明确每行的证明边界：

```bash
# 每行必须有来源列，否则无法复核
printf '%s\	%s\	%s\	%s\
' "2024-09-05 14:22:25" "quarantine:xattr"  "客户名单-2024Q3.csv" "portal.rival-exim.example"
printf '%s\	%s\	%s\	%s\
' "2024-09-05 14:22:25" "safari:Downloads" "客户名单-2024Q3.csv" "portal.rival-exim.example"
printf '%s\	%s\	%s\	%s\
' "2024-09-05 14:22:25" "chrome:urls"       "客户名单-2024Q3.csv" "portal.rival-exim.example"
```

三条时间线合并的三条纪律：

1. **每行必须有来源列**，否则无法复核
2. **统一时区后再跨源比较**，并保留原始值（解码前的十六进制、转换前的微秒值另存一列）
3. **结论分层表述**：

> 三类工件在 `2024-09-05 14:22:25`（+0800）指向同一文件 `客户名单-2024Q3.csv` 与同一来源 `portal.rival-exim.example`：Quarantine 属性记录该文件由下载应用写入、下载记录存在该条目、浏览器存在对该 URL 的访问记录。以上可证明该文件在此时段经浏览器从该站点获取；三者由同一次下载流程连带写入，不作为三份互相独立的印证。文件是否被打开、是否被进一步处理或外发，未在本次证据中确认。

<a id="section-30"></a>

#### 陷阱 10：把"未在已挂载范围内发现"写成"该机无此行为"

**现象**

在报告的"未发现项"部分写「未发现恶意持久化项」「未发现数据外发痕迹」「未发现本地快照」，而不交代这些结论是在什么范围、什么条件下得出的。

**原因**

macOS 取证里，"未发现"至少有六种成因，每一种对应完全不同的结论强度：

| 成因 | 正确表述 |
|---|---|
| 工具不适用（该工件无法离线解析） | 「该工件无通用离线解析手段，未能验证」 |
| 读取失败（权限、加密、格式） | 「因 X 原因未能读取，该项未验证」 |
| 机制未启用 | 「该机制在本机未启用，无此类记录属预期」 |
| 证据易失（已关机丢失） | 「相关证据在关机时已灭失，本次无法取得」 |
| 数据被清理 | 「未见该工件，**存在清理可能，无法区分未使用与已清理**」 |
| **确实不存在** | 「在 X 范围内确认无 Y 行为」 |

现场取证的环境条件还会引入额外的范围限制：仅挂载了部分卷、易失数据未采集、FileVault 使某些内容不可读、外接介质未扣押。

任何一条都会直接削弱阴性结论。

**影响**

- 「未发现外发痕迹」被委托方读成「没有外发」，据此做出错误的商业或法律决策
- 一旦后续通过其他途径（如 Time Machine 备份、外接盘、云端记录）发现相关行为，本次阴性结论直接失效
- 报告里"未发现项"的分量往往比阳性发现更重，因为它常被当作免责依据

**核查**

**每个阴性结论都必须带三重限定：范围、条件、覆盖度**：

```text
未发现项清单（2024-09-05 采集）

| 项 | 结论 | 范围 | 限制条件 |
|---|---|---|---|
| 恶意 LaunchDaemon | 未发现 | 已挂载的系统卷与数据卷 LaunchDaemons/LaunchAgents 目录 | 未分析 Preboot 与 Recovery 卷 |
| 数据外发 | 未能验证 | — | 易失网络连接未采集；Time Machine 备份盘未扣押 |
| 本地快照 | 未发现 | 容器快照索引（`apfsutil` 输出） | 不含已过期并清除的快照 |
| Safari 访问历史 | 未能验证 | — | `History.db` 经 SQLCipher 加密，未取得密钥 |
| 剪贴板内容 | 未能取得 | — | 采集时设备已关机 |
```

「未能验证」与「未发现」在报告里**不得混用**：前者要写明原因，后者要写明范围。

<a id="section-31"></a>

## 五、案例示例

<a id="section-32"></a>

### 5.1 通电待机现场的易失数据优先决策

**场景**

查获 MacBook Pro 14（Apple Silicon M3，macOS 15，**设备通电待机**，屏幕未亮但系统未睡眠）。委托方为跨境电商公司，要求查明「2024-09-05 员工是否从竞争对手门户下载客户名单并外发」。封条完整、序列号清晰、委托方提供个人恢复密钥。现场处置全程录像。

**处置过程**

第一步，先固定时间基准与设备身份，再决定关机与否：

```bash
date -u; date                                       # 输出前置，固定取证时间基准
system_profiler SPHardwareDataType | grep -E 'Model|Serial|Hardware UUID'
sw_vers                                            # → 15.1.1
uptime                                             # → 3 days, 4:22   ★ 连续运行 3 天
fdesetup status                                    # → FileVault is On.（通电未锁定）
who                                                # → liwei  console  Sep 29 09:12
```

第二步，趁通电采集仅存在于内存或运行态的工件：

```bash
EV=/evidence/live
mkdir -p "$EV"
ps auxww        > "$EV/live-ps.txt"
netstat -an     > "$EV/live-netstat.txt" 2>&1
who             > "$EV/live-who.txt"
lsof -nP        > "$EV/live-lsof.txt" 2>&1
/usr/bin/log show --last 30d --info --style json > "$EV/live-log-30d.json" 2>/dev/null
mdfind -onlyin /Users/liwei "kMDItemWhereFroms == '*'" > "$EV/live-wherefroms.txt"
wc -l < "$EV/live-wherefroms.txt"                   # → 47
```

第三步，筛出与竞争对手相关的来源记录：

```bash
grep -c 'rival-exim.example' "$EV/live-wherefroms.txt"
# → 6
grep 'rival-exim.example' "$EV/live-wherefroms.txt"
```

```text
/Users/liwei/Downloads/客户名单-2024Q3.xlsx
/Users/liwei/Downloads/客户名单-2024Q3.zip
/Users/liwei/Downloads/rival-pricing-2024Q3.pdf
…
```

第四步，记录运行态网络连接并留存原始报文位图：

```bash
grep ESTABLISHED "$EV/live-netstat.txt" | grep -v '127.0.0.1' | head
netstat -an > "$EV/live-netstat.txt"    # ★ 关机前最后一次刷新
```

第五步，把「不关机」的推理链写成书面决策并让委托方签字：

```bash
# 现场记录（纸质/电子）：见 01-现场状态记录.md
# 决策：不关机，先取易失数据
# 依据：uptime=3 days, 4:22（连续运行 3 天）+ fdesetup status=On.（未锁定）
#       + who 显示 liwei console 会话仍在线 + 委托方称本周仍在使用
# 决策人：委托方法务 ______  取证人 ______  时间：现场时间基准 ______
```

**结论**

`uptime` 为 3 天 4 小时、`who` 显示 `liwei` 的 console 会话仍在、`fdesetup status` 为 On.（已启用未锁定），三项共同支撑「易失数据有采集价值」的判定，据此决定不关机、先采易失数据。运行态共采集 6 类工件，其中 `mdfind` 命中 47 条带 `kMDItemWhereFroms` 来源记录的文件、其中 6 条来源为 `rival-exim.example`——**这 47 条索引态元数据在关机后大部分无法再取**，是本次现场处置不可替代的收获。存在 3 条指向外部 IP 的 ESTABLISHED 连接，运行态网络快照与后续磁盘态时间线可互相印证；连接表本身只反映采集时刻的状态，不说明这些连接当时在传输什么。现场决策的依据、决策人与时间基准均已录像并书面留痕。

**误判对照**

最容易得出的错误结论是「现场设备通电就关机，取磁盘镜像即可，浏览器和网络证据都在磁盘上」。

正确判据是 Spotlight 索引查询、`lsof` 打开文件表、运行态进程环境变量与 ESTABLISHED 连接表都依赖系统运行，关机后无法再采集。

本案 `mdfind` 命中的 47 条来源记录在关机后能取到的只是部分文件的残留属性，上下文（父目录结构、是否仍在下载目录）会大量丢失。

按错误判据处置，报告里会写「发现 6 条来自竞争对手的文件」，却拿不出这 6 条在被发现时是否仍处于下载目录、是否刚下载完成等运行态上下文，证据从「行为链」降级为「文件存在」。

第二处易错点是把 `fdesetup status` 的 `FileVault is On.` 理解为「已解锁」，从而直接跳过易失数据采集去追求镜像。

正确判据是该命令的完整输出有三种形态：`FileVault is On.` 表示启用且当前已解锁；`FileVault is Off.` 表示未启用；`FileVault is Enabled, but not unlocked.` 表示启用但处于锁定态。

只有第一种才说明磁盘当前可读。

本案正是 `On.` 才得以在不关机的前提下完成后续只读挂载。若输出是 `Enabled, but not unlocked.`，则必须先关机再用委托方提供的恢复密钥解锁，整个现场处置顺序要重排。

第三处易错点是关机前不刷新易失数据就执行 `shutdown -h now`。

正确判据是易失采集必须在最后一次关机动作之前完成并落盘校验——本案在关机前又执行了一次 `netstat -an > live-netstat.txt` 覆盖刷新。

若不刷新，文件中保留的是十分钟前的连接表，而关机瞬间可能正在传输的数据不会出现在任何快照里。

顺序颠倒的代价是：报告写「未发现外发连接」时，无法区分「确实未外发」与「快照取得过早」。

<a id="section-33"></a>

### 5.2 关机后镜像与未正常关机造成的时间线断层

**场景**

完成易失采集后进入关机与镜像阶段。委托方要求就「事发时段的系统状态」给出结论，而本次交付物是关机后取得的离线镜像。

**处置过程**

第一步，正常关机并等待完全落盘：

```bash
sync; sudo shutdown -h now
# 委托方在场，重启并输入恢复密钥解锁
```

第二步，制作物理镜像并同步校验：

```bash
sudo dd if=/dev/rdisk0s2 of=/Volumes/Evidence/DigiForensics.dd bs=4m status=progress
shasum -a 256 /Volumes/Evidence/DigiForensics.dd | tee /evidence/DigiForensics.dd.sha256
# → a3f1…9c2e  DigiForensics.dd
```

第三步，APFS 容器映射并只读挂载：

```bash
apfs-fuse -r "<恢复密钥>" -o vol=2,ro /dev/loop0 /mnt/mac-data
# APFS 容器分区 → Data 卷（vol=2）
```

第四步，检查本机钥匙串 Hardware UUID 目录以确认挂载到的是正确用户卷：

```bash
ls /mnt/mac-data/Users/liwei/Library/Keychains/ | grep -Ei '^[0-9A-F]{8}-[0-9A-F]{4}'
```

第五步，用 `wtmp` / `last` 确定关机与登录边界：

```bash
last -f /mnt/mac-data/private/var/log/wtmp | head -5
```

```text
shutdown system  boot   Fri Nov 15 08:47:10 2024
liwei        console         Fri Nov 15 09:12:33 2024 - still logged in
```

第六步，把运行态 uptime 与 `wtmp` 交叉，判断是否存在非正常断电：

```bash
python3 - <<'PY'
# uptime=3 days 04:22 于 2024-11-18 现场取得 → 开机点 ≈ 2024-11-15 09:12
# wtmp 记录 2024-11-15 08:47:10 shutdown，随后 09:12:33 登录且 "still logged in"
print("开机点与 wtmp 登录点吻合:", "09:12" )
print("该会话此后无正常关机记录 → 属非正常结束")
PY
```

**结论**

关机前 `sync` 保证写入落盘，镜像后立即生成 SHA-256 校验文件，APFS 容器经 `vol=2` 映射到 Data 卷并以只读方式挂载，全程未对原始检材写入。

`wtmp` 显示 2024-11-15 08:47:10 一次正常关机，随后 09:12:33 登录且会话标记 `still logged in`（未正常结束）。

结合现场 `uptime` 3 天 4 小时反推的开机点与该登录时间吻合，可判定该会话自 2024-11-15 登录后没有对应的正常注销或关机记录。

这直接产生一条必须写入报告的局限：2024-09-05 事发时段对应的内存态工件（进程、网络连接、`lsof` 表）不存在于本次交付的离线镜像中，任何基于「事发时有无进程/连接」的判断只能依赖 `wtmp`、文件系统时间和日志三方间接推断，且必须明示置信度。

**误判对照**

最容易得出的错误结论是「`still logged in` 说明用户此刻正在使用电脑，因此设备是人为保持通电的，存在销毁证据行为」。

正确判据是 `wtmp` 中的 `still logged in` 仅表示该登录会话**没有对应的正常注销或关机记录**，成因至少有四种：正常关机未写入 `wtmp`（断电、强制断电、内核崩溃、`launchctl reboot` 绕过登录会话清理）、会话被脚本批量关闭、磁盘时间被回拨导致记录落在错误位置、以及用户确实未注销。

本案结合现场 `uptime` 反推出的开机点与 09:12:33 吻合，只能支持「开机后未再正常关机」，不能支持「人为规避关机取证」。

按错误判据写「存在规避取证的主观故意」，是把一个常见的技术性现象上升为主观意图指控，在质证环节极易被推翻并损害报告整体可信度。

第二处易错点是用 `last` 的登录时间直接当作镜像的取证时间基准。

正确判据是：镜像的取证时间基准来自现场第一次执行的 `date -u` 输出，以及镜像文件的创建时间与哈希生成时间；`wtmp` 的登录时间反映的是用户会话历史，与取证动作发生的时间不在同一时间轴上。

若把 2024-11-15 09:12:33 写成「取证时间」，会让委托方误认为镜像是在登录后立即制作，而现场处置实际发生在 2024-11-18，两者相差三天，卷标与哈希记录都会对不上。

第三处易错点是 `uptime` 反推开机点时忽略它只是近似值。

正确判据是 `uptime` 的输出精度为 1 分钟，且不排除时钟被调整（NTP 跳变、`date -s` 手动改时间）导致偏差；本案将其与 `wtmp` 吻合作为**互相印证**而非精确等值来表述。

反之，若把反推值当作精确开机时间写入时间线，后续与日志、文件时间做秒级比对时会产生看似矛盾实则来源不同的结论，浪费复核精力。

<a id="section-34"></a>

### 5.3 Quarantine 优先提取与外发阴性结论的边界

**场景**

委托方要求就「是否下载了客户名单并外发」给出结论。数据卷已只读挂载，但部分文件已被删除，且邮件、云盘、应用目录的排查结果全为阴性。

**处置过程**

第一步，在数据卷全域提取 Quarantine 扩展属性（`xattr -p` 只能读，不能改属性）：

```bash
find /mnt/mac-data/Users/liwei -type f -print0 | while IFS= read -r -d '' f; do
  v=$(xattr -p com.apple.quarantine "$f" 2>/dev/null) || continue
  [ -n "$v" ] && printf '%s\	%s\
' "$f" "$v"
done > /evidence/quarantine-all.tsv
wc -l < /evidence/quarantine-all.tsv
```

第二步，提取结果中出现已被删除目标的相关条目：

```bash
grep -E '客户名单' /evidence/quarantine-all.tsv
```

```text
/Users/liwei/Downloads/客户名单-2024Q3.csv  0083;66D94E21;Safari;B2C3D4E5-…
/Users/liwei/Downloads/客户名单-2024Q3.zip  0083;66D94E21;Safari;C3D4E5F6-…
```

第三步，解码 Quarantine 时间。属性值结构是 `flags;hex(epoch);agent;uuid`，第二段本身就是 Unix 秒，只是写成十六进制，**不需要跟 Apple 纪元做任何加减**：

```bash
python3 - <<'PY'
import datetime
h = "66d94e21"                    # 第二段原文，十六进制
val = int(h, 16)                  # → 1725517345，这已经是 Unix 秒
u  = datetime.timezone.utc
c  = datetime.timezone(datetime.timedelta(hours=8))
t  = datetime.datetime.fromtimestamp(val, u)
print(t.strftime("%Y-%m-%d %H:%M:%S UTC"), "=", t.astimezone(c).strftime("%Y-%m-%d %H:%M:%S +0800"))
PY
```

```text
2024-09-05 06:22:25 UTC = 2024-09-05 14:22:25 +0800
```

第四步，Safari 侧取无需解密的 `Downloads.plist`：

```bash
SAF=/mnt/mac-data/Users/liwei/Library/Containers/com.apple.Safari/Data/Library/Safari
plutil -p "$SAF/Downloads.plist" | grep -E 'DownloadEntry(URL|Date)'
```

```text
"DownloadEntryURL" => "https://portal.rival-exim.example/api/export?type=customer"
"DownloadEntryDate" => 2024-09-05 14:22:25 +0800
```

第五步，Chrome 侧取访问历史：

```bash
sqlite3 "/mnt/mac-data/Users/liwei/Library/Application Support/Google/Chrome/Default/History" \
 "SELECT datetime((visit_time/1000000)-11644473600,'unixepoch','localtime'), url
  FROM visits JOIN urls ON visits.url=urls.id WHERE url LIKE '%rival-exim%' LIMIT 5;"
```

```text
2024-09-05 14:20:58  https://portal.rival-exim.example/login
2024-09-05 14:22:25  https://portal.rival-exim.example/api/export?type=customer
```

第六步，外发方向的三重排查：

```bash
find /mnt/mac-data/Users/liwei/Library/Mail -name '*.emlx' -newermt '2024-09-05' 2>/dev/null | head
ls -la /mnt/mac-data/Users/liwei/Library/"CloudStorage"/ 2>/dev/null
grep -rl '客户名单-2024Q3' /mnt/mac-data/Users/liwei/Library/"Application Support"/ 2>/dev/null | head -3
```

```text
（Mail 无匹配；CloudStorage 为空；Application Support 无匹配）
```

**结论**

Quarantine 属性在文件被删除后仍保存在目录项中，本次提取到 `客户名单-2024Q3.csv` 与 `客户名单-2024Q3.zip` 两条记录，应用名均为 `Safari`，时间十六进制 `66D94E21` 解码为 2024-09-05 14:22:25 +0800。

该时间与 Safari `Downloads.plist` 的 `DownloadEntryDate` 及 Chrome `visits` 中 `api/export?type=customer` 的访问时间秒级一致、URL 相同，可判定 2024-09-05 14:22:25 该机从竞争对手门户导出并下载了客户名单。三者虽时间一致，但仍来自同一次下载流程的连带写入，不按三份独立印证计算。

`.csv` 与 `.zip` 出现时间相同、UUID 不同，支持「同一时段内完成导出与本地压缩」，但压缩属于本地归档行为，不指向任何传输通道（强度中）。外发方向的 Mail、`CloudStorage`、Application Support 三重排查均为阴性，报告结论只能写到「本次分析未发现文件被外发的证据」，并明确列出已排查的三个位置与排查方式，不能写成「未发生外发」。

**误判对照**

本案例最关键的误判是把阴性排查结果写成「未发生外发」。

正确判据是：阴性结论的强度完全取决于排查覆盖的范围与工件类型——本案只覆盖了本地 Mail 目录、`~/Library/CloudStorage` 和 Application Support，而邮件外发可能走的是 Webmail（凭据在 Keychain 或浏览器中，不产生本地 `.emlx`）、IMAP 客户端的服务器端副本、AirDrop（无本地工件）、`scp`/`rsync` 到外部主机（不留本地痕迹）或未挂载的移动介质。

按错误判据写成「未发生外发」，等于用三个目录的阴性结果替全部外发通道背书；一旦委托方后续从网关日志或防火墙侧发现外传，整份报告的结论会被整体推翻。

反过来，「本次分析未发现外发证据，已排查 Mail、CloudStorage、Application Support 三处」把结论的适用范围显式收窄，反而更有说服力。

第二处易错点是把 Quarantine 的时间基准当成 Cocoa 纪元。

正确判据是：第二段已经是 Unix 秒，只是用十六进制书写，直接 `int(h, 16)` 就能用，不做任何纪元加减。本案 `0x66D94E21 = 1725517345`，即 2024-09-05 06:22:25 UTC。

取证里 Apple 相关字段常带 978307200 这个 Cocoa 纪元偏移（iOS 的 `sms.db`、`CallHistory` 之类），看到 `macOS`、`Apple`、`Safari` 就顺手减一次是很自然的想法。但 978307200 是 31 年（约 11323 天）：`1725517345 - 978307200 = 747210145`，对应 1993-09-05 06:22:25 UTC——**凭空早了 31 年**。

31 年的偏移比几小时的偏移更隐蔽：它落在「这台机器还没出生」的年代，第一眼常被当成解析失败而回头重查，反而不易被识别为基准用错。真正让证据崩掉的是跨工件对照——本案的秒级一致性正建立在 `66D94E21` 与 Safari `DownloadEntryDate`、Chrome `visits` 三者相等上，一旦少减一次，这个对应关系彻底不存在。

判断基准用哪一套，看字段本身而不是看平台：Quarantine 第二段是 Unix 秒，plist 里的 `<date>` 经 `plutil` 转换后已是带时区的 ISO 串，而 `sms.db` 的 `message.date` 才是 Cocoa 纪元。同一个 macOS 案子里三种基准都可能出现。

第三处易错点是从 `.csv` 与 `.zip` 同秒出现就直接写「准备外发」。

正确判据是：压缩属于本地归档行为，不指向任何传输通道；支持外发意图的旁证必须来自传输侧工件——`unified log` 中的 `sharingd`/`AirDrop` 记录、`/var/log` 的网络连接、`.zip` 的 `btime` 与下载时间之间的间隔是否伴随移动介质挂载记录。

按错误判据写「已具备外发条件」，在只有归档行为的场景里会给出超出证据的指控；更稳妥的表述是「下载后立即压缩为 zip（时间相同、UUID 不同），压缩行为本身不指向具体传输通道」。

---

<a id="section-35"></a>

## 六、扩展阅读方向

**前置与基础。** 流程的第一步是盘外结构。容器与卷的两层关系、checkpoint 链表、
快照在删除前的抢救窗口，都决定了「还能不能拿到那天的系统状态」，
细节见 [《APFS容器与快照》](../../filesystem/filesystem-apple-fs/filesystem-apple-fs-apfs.md)。
同一层的还有加密边界：FileVault 的密钥层级、Secure Enclave 的职责划分，
T2 与 M 系列在硬件加密行为上的差异——先判断是硬件还是软件路径，
再谈能不能恢复明文。

**同层深入。** `VM` 卷的交换文件解析，以及内存镜像里的凭据与网络连接状态，
是流程中段的高价值动作。恶意软件的反取证检测也要在这里落位：
对 SIP、时钟回拨、终端环境的探测各有各的触发条件，
识别到检测行为本身也是一条时间线证据。

**相邻议题。** 工具链的建设决定了流程能不能复现：
事实采集工具的选择、`plistutil` 的批处理封装、
自建时间线库时的表结构设计，都不是一次性的事。
法律与合规则是流程的硬约束——封条破坏的后果、解密行为的授权边界、
跨境数据取证的合规要求，任何一步越界都会让前面的工作全部作废。

**工具与判据。** 流程里每一步的工件位置都可以回到
[《macOS取证工件地图》](computer-security-security-artifact-map.md) 核对，
卷级时间轴的具体解析见 [《FSEvents与时间机器》](../computer-log-persistence/computer-log-persistence-fsevents.md)。
整个流程遵循的通用原则——保全、验证、记录——在
[《取证流程与原则》](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md)
里有更完整的表述。

**判据与反例。** 「快照里没有这个进程」在不同系统版本上可能是三种完全不同的
事实：快照没覆盖那个时段、进程早已退出、或者快照本身被删除前就未创建。
三者对结论强度的削弱程度不一样，报告里不能混写成一句「未发现」。
同理，加密卷读不出明文时，正确的表述是「未解密」而非「无数据」。

---

<a id="section-36"></a>

## 七、命令速查

```bash
# ===== 1. 现场状态（★ 通电下立即执行，输出前置 date -u）=====
system_profiler SPHardwareDataType        # 型号 / Chip / 序列号 / Hardware UUID
sw_vers; uptime                           # ★ uptime 判断是否值得保通电
fdesetup status                           # On. / Enabled, but not unlocked.
ps auxww > /evidence/live-ps.txt;  netstat -an > /evidence/live-netstat.txt 2>&1
who > /evidence/live-who.txt;  lsof -nP > /evidence/live-lsof.txt 2>&1
/usr/bin/log show --last 30d --info --style json > /evidence/live-log-30d.json 2>/dev/null
mdfind -onlyin /Users/<u> "kMDItemWhereFroms == '*'" > /evidence/live-wherefroms.txt

# ===== 2. 零密钥结构确认（★ 不需要 FileVault 密钥）=====
mmls /work/DigiForensics.dd
APFS_PART=775920
xxd -s $((APFS_PART*512 + 32)) -l 16 /work/DigiForensics.dd   # 期望 4e585342 = "NXSB"
apfsutil -o $((APFS_PART*512)) /work/DigiForensics.dd

# ===== 3. 镜像（★ 整盘或整容器，绝不单卷）=====
diskutil list                             # 区分 (internal, physical) / (synthesized)
diskutil apfs list | grep -E 'APFS Container Reference|Volume Name|Capacity'
df -h /Volumes/Evidence                   # 目标 ≥ 容器标称容量 × 1.03
diskutil unmountDisk /dev/disk3
sudo dd if=/dev/rdisk0   of=/Volumes/Evidence/DigiForensics.dd bs=4m status=progress
sudo dd if=/dev/rdisk0s2 of=/Volumes/Evidence/DigiForensics.dd bs=4m status=progress
shasum -a 256 /Volumes/Evidence/DigiForensics.dd | tee /evidence/DigiForensics.dd.sha256

# ===== 4. 只读挂载 =====
shasum -a 256 /work/DigiForensics.dd > /evidence/baseline.sha256   # ★ 挂载前算基线
apfs-fuse -r "<恢复密钥>" -o vol=2,ro /dev/loop0 /mnt/mac-data
diskutil image attach -readonly /work/DigiForensics.dd   # macOS 侧（hdiutil attach 已弃用）
mount | grep apfs;  fusermount -u /mnt/mac-data
shasum -a 256 -c /evidence/baseline.sha256

# ===== 5. 检材时间锚点（★ 必须 -f 指向镜像内文件）=====
last -f /mnt/mac-data/private/var/log/wtmp | head -10

# ===== 6. 提取顺序 =====
# 1 容器/卷/快照 → 2 用户目录与 ~/Library → 3 LaunchAgents/Daemons → 4 统一日志
# 5 偏好与 ByHost → 6 ★Quarantine → 7 Keychain → 8 浏览器 → 9 废纸篓与 FSEvents
# 10 邮件/IM → 11 Time Machine（需单独扣押备份盘）

# ===== 7. 绝对禁止 =====
# security -g 在检材原件上        ← 修改钥匙串 ACL
# xattr -w / -d / -c 在检材上     ← 篡改扩展属性
# tmutil restore                  ← 写入目标
# mdutil -a -i / mdimport          ← 触发索引重建
# defaults write / delete         ← 修改系统配置
# "发现恶意软件就清理"            ← 改变证据状态，可能构成破坏
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — macOS 取证 — 取证实战流程」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《macOS 取证实战流程》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-mem.raw` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
