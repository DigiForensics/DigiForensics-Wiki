---
title: "取证工件地图"
slug: "computer-security-security-artifact-map"
canonical: "https://www.digiforensics.cn/wiki/computer-security-security-artifact-map"
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

# 取证工件地图

<a id="section-1"></a>

## 一、概述

拿到 Mac 镜像后的第一个障碍不是技术，是心智模型。

常见资料大多讲的是 Windows，思路固定："配置进注册表、行为进事件日志、用户痕迹进 AppData"。这套思路搬到 Mac 上会连续踩空——macOS 没有注册表、没有传统事件查看器、没有 `AppData`。

macOS 的组织方式是另一套：

| 维度 | Windows | macOS |
|---|---|---|
| 用户数据主位置 | `C:\Users\<u>\AppData`（Roaming/Local/LocalLow 三分） | **`~/Library/`**（一个根目录，子目录按用途分类） |
| 系统配置 | 注册表 hive | **`.plist` 文件**（一个文件一项） |
| 系统日志 | 多个 `.evtx` 文件 | **统一日志**，单一后端 |
| 启动项 | 5 个 Run 键 + 计划任务 + 服务 | **`launchd` 统一管理** |
| 全卷加密 | BitLocker（可选） | **FileVault 2**（Monterey 后默认开启） |

最需要先立起来的一条认识：macOS 的用户痕迹几乎全在 `~/Library/` 下。

Apple 把"系统的东西"放 `/System`、`/Library`，把"你的东西"全放 `~/Library`。这条线直接对应取证上"用户级证据"的边界。

三类代价很高的处置错误：

- 只镜像了某个卷而没镜像整个 APFS 容器。macOS 10.15 之后，系统盘是一个容器里挤着系统卷、数据卷、预启动卷、恢复卷、交换卷。单独 `dd` 数据卷会丢掉容器超级块和块池分配表，块号无法解析，证据完整性在法律层面就站不住（详见第八篇）。
- 发现设备开着就直接拔电。Spotlight 索引、内存交换、运行时统一日志一并丢失，还改变了设备状态。
- 把 `~/Library` 当普通目录扫过去。它有几百个子目录，其中 `Containers/`、`Group Containers/` 是 10.14 Mojave 之后的沙盒迷宫，漏掉等于漏掉整个应用生态的用户数据。

**在取证流程中的位置**：本篇是 **macOS 板块的入口篇**，位置在接手检材之后、任何具体分析之前。它的输出是一份**提取清单**，而不是分析结论——读它是为了知道"该往哪些路径去取"，取完才轮到 plist 解析、日志检索、钥匙串解密这些具体动作。所以它同时依赖上游的镜像规范（[只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md)）并把清单交给下游各篇：[plist 与偏好设置](../computer-plist-spotlight/computer-plist-spotlight-plist.md)、[Quarantine 与 Gatekeeper](computer-security-quarantine-gatekeeper.md)、[Keychain 与 Safari 痕迹](computer-security-keychain-safari.md)、[取证实战流程](computer-security-security-investigation-workflow.md)。具体动作的先后顺序由最后一篇决定。

**本篇处理的证据形态**，是三层目录加两个存储后端：

| 层次 | 路径 | 内容与判读要点 |
|---|---|---|
| 系统层 | `/System` | Big Sur 起是独立的签名系统卷（SSV），**基本无个性化证据**，但 `/System/Library/LaunchDaemons/` 可作启动项基线（见陷阱 10） |
| 全局可写层 | `/Library` | 所有用户共享：`LaunchDaemons/`（★ 系统级启动项，开机即跑 root）、`Preferences/`、`Application Support/`、`Keychains/System.keychain` |
| 用户层 | **`~/Library/`** | 几乎所有个人痕迹：`Preferences/`（+ `ByHost/`）、`Application Support/`、`Containers/` 与 `Group Containers/`（10.14+ 沙盒数据）、`Safari/`、`Keychains/`、`Messages/`、`Mail/`、`LaunchAgents/`、`Mobile Documents/`、`Autosave Information/`（**被删文档的历史版本**）、`~/.Trash`（**在 `~` 根下，不在 Library 内**） |
| 统一日志 | `/var/db/diagnostics/` | **持久化存储，现役系统日志的后端**；导出用 `log show`，现场就要做 |
| 其他系统级 | `/private/var/log/install.log`、`wtmp`、`appfirewall.log`、`/etc/hosts`、`/etc/sudoers`、`/private/var/db/dslocal/nodes/Default/users/`（**本地用户目录服务数据库**） | 安装日志、**关机时间锚点**、sudo 授权 |

`/var/log` 与 `/private/var/log` 的关系见 2.3 脚注，报告里统一写 `/private/var/log`。

某个用户在系统上做过什么（`~/Library/` 的覆盖）、装过哪些应用（`Containers/` 下的 bundle id 目录）、系统级持久化有哪些（`LaunchDaemons/`）、设备什么时候开过关机（`wtmp`）、哪些软件被安装过（`install.log`）、以及**该去哪些路径取哪些工件**。

**目录存在不代表内容被读取过**——`Caches/`、`HTTPStorages/`、`Autosave Information/` 里都可能残留早已不用的数据，判断使用行为要靠访问时间戳与应用侧记录，不是靠"文件在不在"。**路径清单也不覆盖加密内容**：`Messages/` 的数据库是加密的、`Keychains/` 解不开就只有一堆密文，而这两处恰好是聊天证据与凭据证据的主力。具体解读都要交给下游各篇，本篇只给地图。阴性结果的边界在这里最明显：没在 `~/Library/` 下找到东西，等于说它在用户目录里没有，不能推广到 `/var/db/`、FSEvents 日志、交换卷、APFS 快照（快照里可能有已删除目录的旧版本，容易与当前状态混淆）。另外版本差异是硬约束：10.14 之后 Safari 多已迁到 `Containers/`，按老路径去 `~/Library/Safari/` 找会得到一个空目录——**"没找到"有时候只是路径过时**。

**读者前提**：需要先有 [APFS 容器与快照](../../filesystem/filesystem-apple-fs/filesystem-apple-fs-apfs.md) 的概念基础，理解容器与卷的关系——不理解这一点，就没法理解为什么单独 `dd` 数据卷会破坏完整性声明；需要知道 `launchd` 是 macOS 的统一启动管理机制，`LaunchAgents` 与 `LaunchDaemons` 的区别是用户级与系统级；需要理解 `~/Library` 是 Apple 刻意划出的用户数据边界，这正是"用户级证据"这个概念在 macOS 上的落点；还要接受一件事：这台机器的具体版本与架构（Intel 还是 Apple Silicon、大版本号）决定了一部分路径是否存在，动手前先定版本，否则清单会有一半是废弃路径。

---
<a id="section-2"></a>

## 二、核心原理

APFS 容器与卷结构原理见[文件系统分析板块](../../filesystem/filesystem-apple-fs/filesystem-apple-fs-apfs.md)，本篇不重复 B-tree 与 checkpoint 机制。

<a id="section-3"></a>

### 2.1 三层目录结构：系统 / 全局 / 用户

```
/System      只读系统卷（Big Sur 起独立为 SSV 签名卷）→ 基本无个性化证据
/Library     全局可写层：所有用户共享的第三方内容
             ├── LaunchDaemons/   ★ 系统级启动项（开机即跑，root）
             ├── Preferences/  Application Support/  Keychains/System.keychain
~/Library    ★★★ 用户级：几乎所有个人痕迹都在这里
             ├── Preferences/ (+ByHost/)          偏好设置 plist
             ├── Application Support/             应用数据库、浏览器、IM 数据
             ├── Containers/ (+Group Containers/) 沙盒数据（10.14+）
             ├── Safari/  Keychains/  Messages/  Mail/
             ├── LaunchAgents/                    ★ 用户级启动项
             └── Mobile Documents/  Caches/  HTTPStorages/  Metadata/
```

`/Library`（全机持久化）与 `~/Library`（个体行为）都要提取。

时间有限时 `~/Library` 优先级高于 `/Library`——这是提取优先级，不是"可以只查一处"（陷阱 5）。

<a id="section-4"></a>

### 2.2 关键目录速查：`~/Library/` 各子目录用途

这张表列出 `~/Library/` 下各子目录的用途与通常用途的证据形态。`★` 表示该目录通常含有较多个人痕迹，标注的是取证潜力而非数据可得性（见陷阱 9）。

| 子目录 | 用途 | 价值 | 备注 |
|---|---|---|---|
| `Preferences/` | 偏好设置 `.plist` | ★★★★★ | 见[03](../computer-plist-spotlight/computer-plist-spotlight-plist.md)，注意 `cfprefsd` 缓存 |
| `Preferences/ByHost/` | **按主机区分**的偏好 | ★★★★ | 文件名含主机 UUID，可确认拷机痕迹 |
| `Application Support/` | 应用数据库与配置 | ★★★★★ | Chrome/Firefox/IM/邮件核心数据 |
| `Containers/` | **沙盒应用数据** | ★★★★★ | 10.14+；路径形如 `com.vendor.app/Data/…` |
| `Group Containers/` | 沙盒应用组共享 | ★★★★ | 扩展插件、共享数据库 |
| `Safari/` | Safari 历史/书签/会话 | ★★★★★ | **10.14+ 多已迁至 Containers**，见[07](computer-security-keychain-safari.md) |
| `Messages/` | 信息/iMessage 附件 | ★★★★★ | 聊天证据主力；数据库加密 |
| `Keychains/` | 登录钥匙串 | ★★★★★ | 解密需用户密码，见[07](computer-security-keychain-safari.md) |
| `LaunchAgents/` | **用户级启动项** | ★★★★★ | 恶意持久化高发，见[02](../computer-log-persistence/computer-log-persistence-macos-unified-logs-and-launch-agents.md) |
| `Application Support/MobileSync/Backup/` | **iOS 设备备份** | ★★★★★ | 见[06](../computer-log-persistence/computer-log-persistence-fsevents.md) |
| `Mobile Documents/` | **iCloud 同步目录** | ★★★★ | 含 `~apple` 云盘痕迹，见[03](../computer-plist-spotlight/computer-plist-spotlight-plist.md) |
| `Mail/` | 邮件账户与缓存 | ★★★★ | 新版多在 `Containers/com.apple.mail` |
| `HTTPStorages/` | 各站点 Cookie/会话 | ★★★ | 部分为数据库格式 |
| `Logs/` | 用户级应用日志 | ★★★ | 很多是纯文本，可直接读 |
| `Autosave Information/` | iCloud 自动保存版本 | ★★★ | **被删文档的历史版本** |
| `CloudStorage/` | 第三方云盘挂载 | ★★★ | 反映装过哪些网盘 |
| `Metadata/` | 捆绑与标签元数据 | ★★★ | macOS 特有的"标签"体系 |
| `Caches/` | 各类缓存 | ★★ | 价值低但含 WebKit 缓存/临时凭据 |
| `~/.Trash` | 用户废纸篓 | ★★★★ | 在 `~` 根下，不在 Library 内 |

`Containers/` 最容易漏（陷阱 4）。

`ls -1 ~/Library/Containers/ | grep -iE 'safari|chrome|wechat'` 能快速判断装过哪些应用。

<a id="section-5"></a>

### 2.3 系统级关键位置

| 路径 | 内容 | 价值 |
|---|---|---|
| `/Library/LaunchDaemons/` | **系统级启动项 plist** | ★★★★★ |
| `/Library/LaunchAgents/` | 系统级登录项（较少） | ★★★★ |
| `/System/Library/LaunchDaemons/` | Apple 自带守护进程 | ★★ 基线比对用 |
| `/var/db/diagnostics/` | **统一日志持久化存储** | ★★★★★ |
| `/private/var/log/install.log` | **软件安装日志**（现为纯文本） | ★★★★ |
| `/private/var/log/wtmp` | **登录会话历史**（关机时间锚点） | ★★★★ |
| `/private/var/log/asl/` | 旧版 Apple System Log | ★★★ 10.12 前 |
| `/private/var/log/appfirewall.log` | 防火墙记录 | ★★★ |
| `/Library/Preferences/SystemConfiguration/` | 网络配置 | ★★★★ |
| `/etc/hosts`、`/etc/sudoers` | 主机名映射、sudo 授权 | ★★★★ |
| `/private/var/db/dslocal/nodes/Default/users/` | **本地用户目录服务数据库** | ★★★★★ |

> `/var/log` 与 `/private/var/log` 是同一个目录（`/var` 是 `/private/var` 的符号链接，两者 inode 相同）。工具里可互换，报告里**统一写 `/private/var/log`**，避免复核人困惑。

<a id="section-6"></a>

### 2.4 版本与架构差异

差异直接决定工件是否存在、路径在哪。

| 差异点 | 10.14 Mojave 及以前 | 10.15 Catalina 起 | 11 Big Sur 起 | 12 Monterey 起 |
|---|---|---|---|---|
| **系统盘结构** | 单 HFS+/APFS 卷 | 单 APFS 卷 | **系统卷 + 数据卷分离（SSV）** | 同 |
| **FileVault** | 可选 | 可选 | 可选 | **默认开启** |
| **Safari 数据** | `~/Library/Safari/` | `~/Library/Safari/` | 迁至 `Containers/com.apple.Safari/` | 同 |
| **iCloud 目录名** | `~/Mobile Documents/` | `~/Library/Mobile Documents/` | 同 | 同 |
| **旧 ASL 日志** | `/private/var/log/asl/*.asl` 存在 | 逐步停用 | 基本停用 | 无 |
| **Apple Silicon** | — | — | **M1 首发** | 主流 |

三条架构事实。

（1）Apple Silicon 与 Intel 的启动安全模型不同。

Intel Mac 可按住 `Option` 选外接启动盘或进恢复环境；Apple Silicon 机型只能启动签名的系统映像，恢复环境受启动安全性策略（Boot Security Policy）约束。

这意味着在 Apple Silicon Mac 上不能用传统方式从外接介质启动做取证副本，只能逐块物理镜像。副作用是降低了扣押后被远程启动攻击的风险。

（2）T2 芯片机型有 Secure Enclave（安全隔区）。

密钥材料与生物识别数据由这块独立处理器保护。T2 的加密是硬件辅助的，部分 APFS 解析库不支持硬件加密内层——解不开时先确认是不是这一类，而不是反复试密码。

（3）Big Sur 之后用户数据在 `Data` 卷，`System` 卷只读且带签名。

跨卷解析能力差的工具在 Big Sur+ 上会漏数据。

APFS 容器必须整体镜像的原因也在这里：各卷共享同一块池。

<a id="section-7"></a>

### 2.5 取证准备：卷布局与镜像

现场第一件事：**搞清楚盘上有几个卷、哪个是容器**。

```
/dev/disk0 (internal, physical):
   0:  GUID_partition_scheme              *500.3 GB   disk0
   1:  Apple_APFS_ISC Container disk1       524.3 MB  disk0s1
   2:  Apple_APFS Container disk3          494.4 GB   disk0s2   ← ★ 主容器

/dev/disk3 (synthesized):
   0:  APFS Container Scheme              +494.4 GB   disk3
   1:  APFS Volume Macintosh HD            14.1 GB   disk3s1   ← 只读系统卷
   2:  APFS Volume Preboot                  21.7 GB   disk3s2
   3:  APFS Volume Recovery                  3.1 GB   disk3s3
   4:  APFS Volume Macintosh HD - Data     447.8 GB   disk3s5   ← ★ 用户数据在这
   5:  APFS Volume VM                        5.4 GB   disk3s6   ← 交换
```

`disk3` 是 `synthesized`（合成）设备——不是真实硬件，而是系统对 `disk0s2` 容器的软件抽象。

镜像的物理来源是 `disk0` 或 `disk0s2`，不是 `disk3`。按 `disk3` 容量做镜像，会因卷容量加和与容器实际占用不符而出错。

| 镜像硬性要求 | 原因 |
|---|---|
| 镜像整个 APFS 容器（`disk0s2`）或整盘（`disk0`） | 卷共享块池与容器超级块，见第八篇 |
| **目标介质 ≥ 源容器标称容量 × 1.03** | `Preboot`/`VM` 等独立卷与容器元数据不计入主卷显示容量 |
| 先 `diskutil unmountDisk` 再 dd | 挂载中的卷可能被 GC / 快照机制写入 |

---

<a id="section-8"></a>

## 三、操作步骤

<a id="section-9"></a>

### 3.1 第 1 步：确定架构、系统版本与加密状态

这一步决定后续所有工具与路径选择。

```bash
system_profiler SPHardwareDataType     # 关注 Chip（Apple M 系列）/ Processor Name / Hardware UUID
sw_vers; uptime
fdesetup status                      # FileVault is Off. / On. / Enabled, but not unlocked.（已关机）
```

> **FileVault 密钥的三条合法获取路径**（详见第八篇）：委托人当面解锁并当场镜像；委托人提供**个人恢复密钥**（Apple ID 账户可查）；依法向 Apple 或云服务商调取。报告只写"已使用合法取得的密钥解密"，绝不记录密钥字符串。

<a id="section-10"></a>

### 3.2 第 2 步：卷布局确认与容器识别

```bash
diskutil list                           # 区分 (internal, physical) 与 (synthesized)
diskutil apfs list | grep -E 'APFS Container Reference|Volume Name|Capacity'
diskutil info / | grep -E 'Volume Name|File System Personality'
# 同时存在 "Macintosh HD - Data" → Big Sur+ 分离结构
```

**离线镜像的确认方法**（不需要密钥）：

```bash
mmls /work/DigiForensics.dd             # 找 Apple_APFS 分区起始扇区
APFS_PART=775920                        # ← 换成 mmls 实际输出
xxd -s $((APFS_PART*512 + 32)) -l 16 /work/DigiForensics.dd
# 000f7fa0: 4e58 5342 0000 0001 0000 0010 3bf1 3f00   NXSB............><
#           ↑NXSB 确认    ↑块大小 4096
```

> 这一步的结论不依赖 FileVault 密钥，因此在零密钥条件下即可成立（案例第 1 步与陷阱 3 均按此处理）。

<a id="section-11"></a>

### 3.3 第 3 步：镜像制作

```bash
df -h /Volumes/Evidence                    # 目标空间须 ≥ 容器标称容量 × 1.03
sudo dd if=/dev/rdisk0   of=/Volumes/Evidence/DigiForensics.dd bs=4m status=progress
sudo dd if=/dev/rdisk0s2 of=/Volumes/Evidence/DigiForensics.dd bs=4m status=progress
#                          ↑省空间，但必须覆盖容器内全部卷
shasum -a 256 /Volumes/Evidence/DigiForensics.dd | tee /evidence/DigiForensics.dd.sha256
```

三条纪律：

用 `r` 前缀设备（不用 `r` 走缓冲 I/O，慢一个数量级）；`bs=4m` 或更大（默认 512 字节块做 500GB 镜像要数小时）；制作后立即校验哈希——这是后续所有结论可复核的基线。

<a id="section-12"></a>

### 3.4 第 4 步：只读挂载与工件清点

```bash
shasum -a 256 /work/DigiForensics.dd > /evidence/baseline.sha256   # 挂载前基线
apfs-fuse -r "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX" -o vol=2,ro /dev/loop0 /mnt/mac-data
# 或：hdiutil attach -readonly /work/DigiForensics.dd
mount | grep -E 'apfs|loop'              # 确认含 rdonly
```

```bash
EV=/mnt/mac-data
ls -1 $EV/Users/                                              # 用户目录
ls -1 $EV/Library/LaunchDaemons/ | wc -l                      # 系统启动项数
ls -1 $EV/Users/*/Library/LaunchAgents/ | wc -l                # 用户启动项数
ls -1 $EV/var/db/diagnostics/Persist/ | wc -l                  # 统一日志文件数
ls -1d $EV/Users/*/Library/Containers/com.apple.Safari 2>/dev/null
ls -1 $EV/Users/*/Library/"Application Support"/MobileSync/Backup/ 2>/dev/null
ls -l  $EV/Users/*/Library/Keychains/;  ls -la $EV/Users/*/.Trash/
```

| 验证对象 | 方法 | 通过标准 |
|---|---|---|
| 容器识别正确 | `xxd` 读 `NXSB` | 输出 `4e585342` |
| 挂载未改写镜像 | 挂载前后 `shasum -a 256` 比对 | 完全一致 |
| 块大小实测 | `apfsutil` 的 `Block size` | 通常 4096，**不要假设** |
| 卷标识记录 | `apfsutil` 各卷 `oid` | 报告引用文件必须带卷标识 |

---
<a id="section-13"></a>

## 四、常见陷阱

★ 标记表示该操作会导致原始检材永久灭失或不可逆改变，执行前必须停下来确认。

<a id="section-14"></a>

### 4.1 镜像获取

<a id="section-15"></a>

#### 陷阱 1：★ 只 dd 了单个卷，丢掉容器元数据与其它卷

**现象**：镜像做完发现用户目录能读到，但 `/System/Volumes/VM`（交换卷）缺失、`Preboot` 卷不存在、卷名与卷号对不上，分析被迫返工。

**原因**：**APFS 的所有卷共享同一个块池与容器超级块。**

2.5 末的硬性要求写得很明确：必须镜像整个 APFS 容器（`disk0s2`）或整盘（`disk0`），而不是某个单独卷。

原因是：块分配信息（卷 → 块的映射）在容器超级块里。`Preboot`/`VM` 等独立卷虽然不计入主卷显示容量，但**它们参与块分配**。只镜像主卷会导致块号无法解析或内容错位。

**影响**：返工不可逆，现场时间也可能无法挽回。

更麻烦的是"部分可读"的假象——某些文件能正常解出来，另一些损坏或缺失。不复核就交付，报告里的数据完整性无从保证。

**核查**：

```bash
# 1. 先卸载，让 APFS 机制不写入（挂载中的卷可能被 GC / 快照机制写入）
diskutil unmountDisk /dev/disk2

# 2. 镜像整个容器（不是单个卷）
dd if=/dev/rdisk2 of=/work/DigiForensics.dd bs=4m status=progress
# 或整盘
dd if=/dev/rdisk0 of=/work/DigiForensics.dd bs=4m status=progress

# 3. 容量预检
df -h /dev/rdisk2     # 目标介质 ≥ 源容器标称容量 × 1.03
```

`1.03` 这个系数是为容量预检留的余量，具体取值按现场实际占用调整。

`Preboot`/`VM` 等独立卷与容器元数据不计入主卷显示容量，源卷显示的容量小于容器实际占用。容量不足会在 dd 进行到一半时失败，那时拿到的镜像是不完整的。

<a id="section-16"></a>

#### 陷阱 2：挂载中的卷直接 dd，不 unmount

**现象**：现场直接把 `/dev/rdisk2` dd 到外接盘，没有先 `diskutil unmountDisk`，镜像完成，交付。

**原因**：挂载中的卷会被 APFS 自己的 GC 与快照机制写入。

这些写入与你的 dd 读操作并发，导致两种后果：① 块在读取过程中被回收或改写，镜像内部出现前后不一致；② 卷内的 APFS 快照可能在 dd 过程中被自动清理或创建，使镜像内的快照集合与现场状态不符。

**影响**：得到一个**内部不一致但看起来完整**的镜像。

它能正常挂载、大部分文件可读，但少数区域的数据与现场不符——**你无法知道哪些区域有问题**。

这类问题在质证时难以抗辩：对方只需指出"镜像获取时卷处于挂载状态"，基于该镜像的结论都需要重新评估。

**核查**：**先卸载再 dd，且把卸载输出记录进证据处理记录**：

```bash
diskutil unmountDisk /dev/disk2                      # 记录完整输出
diskutil list                                        # 记录设备标识与卷结构
dd if=/dev/rdisk2 of=/work/DigiForensics.dd bs=4m conv=noerror,sync status=progress
sync && shasum -a 256 /work/DigiForensics.dd          # 镜像后立即计算哈希并记录
```

**若因业务需要无法卸载**（例如现场正在运行的业务系统），必须在报告的证据处理记录里写明"卷在挂载状态下获取镜像，存在 GC/快照机制并发写入风险"，并把这作为一条证据局限明示；报告中对受影响的结论应标注该前提。

<a id="section-17"></a>

#### 陷阱 3：FileVault 已锁定时硬解，把"解不开"写成"无数据"

**现象**：镜像拷回实验室，FileVault 已开启且处于锁定状态，尝试解密失败，报告写「该机数据已加密，无法获取任何内容」。

**原因**：**FileVault 锁定 ≠ 数据不可取。** 案例第 1 步的做法是正确的：**在无密钥的情况下先做结构性判断**——读 APFS 容器超级块的魔数（偏移 32 处应为 `NXSB`），用 `apfsutil` 列出卷结构，这些都**不依赖密钥**：

```bash
xxd -s $((775920*512 + 32)) -l 32 /work/DigiForensics.dd
# 000f7fa0: 4e585342 0000 0001 0000 0010 3bf1 3f00   NXSB...
apfsutil -o $((775920*512)) /work/DigiForensics.dd
# NXSB Block Count: 131072000
# Volume 1 (oid=2, name='Macintosh HD', ...)          只读系统卷
# Volume 2 (oid=3, name='Macintosh HD - Data', ...)   ★ 用户数据卷
# Volume 8 (oid=12, name='VM', ...)                   交换卷
```

**影响**：把"暂时解不开"写成"无数据"，会让你在还没尝试其它途径前就放弃。

而 FileVault 的密钥来源有多条：用户的登录密码、恢复密钥、另一台同组设备、用户的 Apple ID。其中恢复密钥往往由委托方直接提供。

放弃得越早，越可能失去一批只能在解密后取得的证据（Keychain、Messages 数据库、Safari 加密数据）。

**核查**：结构性结论先行，不依赖密钥。案例第 1 步写的「确认为 APFS 容器，物理块大小 4096，用户数据位于 `Macintosh HD - Data` 卷（oid=3）。本机为 Big Sur+ 分离结构，用户数据不在系统卷上」——这段结论在没有密钥时就已成立并可写入报告。然后再取得密钥：

```bash
apfs-fuse -r "<恢复密钥>" -o vol=2,ro /dev/loop0 /mnt/mac-data
```

`-o vol=2` 挂载用户数据卷（不是系统卷），`ro` 只读——这与其它板块的只读原则一致。

报告里把"结构性结论"与"需密钥才能取得的结论"分开写：前者是在无密钥条件下已成立的判断，后者须写为证据局限。

<a id="section-18"></a>

### 4.2 路径定位

<a id="section-19"></a>

#### 陷阱 4：沿用旧版 macOS 的路径，找不到 Safari 数据就写"无浏览记录"

**现象**：在 macOS 14 的镜像上找 `~/Library/Safari/History.db` 不存在，报告写「该用户无 Safari 浏览记录」。

**原因**：2.2 的表格明确写了：Safari 在 10.14+ 多已迁至 `Containers/`。

macOS 10.14 引入沙盒后，Safari 的数据被移到 `~/Library/Containers/com.apple.Safari/Data/Library/Safari/`。沿用旧路径会系统性地错过整个 Safari 数据集。

**影响**：这是"同名概念在不同版本指不同位置"的典型。

在委托方明确要求"查明是否访问过客户网站"的场景下，报告结论"无浏览记录"与事实可能完全相反。这类错误很难自查——因为你确实查了，只是查错了地方。

**核查**：先确定系统版本，再按版本确定路径：

```bash
sw_vers                                        # 版本决定路径布局
ls -1 ~/Library/Containers/ | grep -iE 'safari|chrome|wechat|firefox'   # ★ 先看装过什么
ls -l ~/Library/Safari/ 2>/dev/null
ls -l ~/Library/Containers/com.apple.Safari/Data/Library/Safari/ 2>/dev/null
```

`Containers/` 最容易漏（见 2.2）。

先 `ls -1 ~/Library/Containers/` 快速判断装过哪些应用，再决定去哪个容器里找数据。沙盒数据路径形如 `com.vendor.app/Data/…`。

同时别忘了 `~/Library/Group Containers/`（扩展插件、共享数据库）和 `~/Library/Application Support/`（非沙盒应用的数据）——三者都要覆盖。

<a id="section-20"></a>

#### 陷阱 5：把 `~/Library` 与 `/Library` 只查一边

**现象**：把全部精力放在 `~/Library`（用户目录），报告写「已全面排查该机痕迹」；`/Library/LaunchDaemons/` 下的系统级启动项完全没看。

**原因**：2.1 讲了三层结构：`/Library`（全局可写层，所有用户共享的第三方内容）与 `~/Library`（个体行为）都要提取。

两者的证据性质不同：`~/Library` 主要是**个体行为**痕迹，`/Library` 主要是**全机持久化**痕迹。

尤其是 `/Library/LaunchDaemons/`，**开机即跑、无需任何用户登录**，因此不受用户会话痕迹的覆盖范围约束。

**影响**："已全面排查"这个表述被证伪。

更实际的损失是漏掉系统级持久化——`LaunchDaemons` 里的载荷不依赖任何用户会话，仅删除用户账户并不能清除它。

**核查**：两层并列清点，数量都要报：

```bash
ls -1 /Library/LaunchDaemons/*.plist 2>/dev/null | wc -l
ls -1 /Library/LaunchAgents/*.plist 2>/dev/null | wc -l
ls -1 /Library/Preferences/ /Library/Application\ Support/ 2>/dev/null
ls -1 ~/Library/Preferences/*.plist 2>/dev/null | wc -l
ls -1 ~/Library/Containers/ 2>/dev/null | wc -l
```

2.1 给的优先级是提取顺序上的建议，不是覆盖面上的取舍。

报告里要分别给出两层的清点结果与筛查结论。

<a id="section-21"></a>

#### 陷阱 6：★ 在分析机上直接跑 `last reboot` 取关机时间

**现象**：想确定检材的最后关机时间，在分析机上执行 `last reboot`，得到一个时间，直接写进报告作为现场的最后活动时间。

**原因**：`last` 默认读的是本机的 `/var/log/wtmp`，不是检材的。 你看到的每一行都是取证分析机自己的启动记录。案例第 2 步专门标注了这一点：「★ 必须用 `-f` 指向检材的 wtmp；在分析机上直接跑 `last reboot` 拿到的是分析机的时间」。

**影响**：这是"污染证据"的一种——不是污染检材，而是污染结论。

关机时间是评估证据局限的基础（案例第 2 步明确说"关机之后产生的磁盘态工件不会有对应的内存态痕迹，这是评估证据局限的基础"）。

拿分析机的关机时间去划定检材的时间边界，后续所有"某事件发生在关机前/后"的判断全部作废。

**核查**：离线读检材的登录会话必须用 `-f` 指定镜像内文件：

```bash
last -f /mnt/mac-data/private/var/log/wtmp | head -4
# liwei   ttys000   Fri Nov 15 09:12:33 2024   still logged in
# shutdown system  boot   Fri Nov 15 08:47:10 2024
```

`still logged in` 是一个需要解释的信号：会话记录未正常收尾，可能对应未正常关机、断电，也可能只是登出记录未落盘；区分方法见 5.2。

关机时间（`shutdown ... boot` 那行）是划定时间边界的锚点，必须来自检材，而不是分析机。

<a id="section-22"></a>

### 4.3 工件判读与结论表述

<a id="section-23"></a>

#### 陷阱 7：把"路径不存在"当成"没有该行为"

**现象**：某工件目录为空或路径不存在，报告直接写"无该行为"。

**原因**：每个工件路径的不存在都有多种成因，且它们的结论强度完全不同。

至少要区分四类：① **机制未启用/版本不适用**（如 10.12 前的 `asl/` 目录在现代系统上本就没有；`/private/var/log/install.log` 位置在不同版本有差异）；② **数据易失**（`Caches/` 会被定期清理；`HTTPStorages/` 里的会话数据会过期）；③ **沙盒迁移**（旧路径不存在但新路径有数据，见陷阱 4）；④ **被清理**（有清理痕迹：目录存在但内容为空、时间戳异常）。

**"路径不存在"这一观察本身无法区分它们。**

**影响**：不可辩护的阴性结论。

而且"路径不存在"在 macOS 上尤其容易出错——因为版本差异和沙盒迁移造成的路径变化太多，一个基于旧版本知识得出的"不存在"很可能只是找错地方。

**核查**：阴性发现按成因分档标注强度，并在报告里写明排查了哪些替代路径：

| 情形 | 阴性强度 | 表述 |
|---|---|---|
| 路径不存在 + 该版本本就不该有 + 替代路径已查且为空 | 中 | 「该机制在此系统版本中未启用，替代路径（列出）亦无数据」 |
| 路径不存在 + 替代路径未查 | 弱 | 「该路径不存在，**替代路径未排查**，结论不完整」 |
| 目录存在但内容为空 | 视情况 | 「目录存在但无内容；需结合目录 `mtime` 判断是'从未使用'还是'已被清空'」 |
| 机制本身易失 | 弱 | 「该工件为易失数据，检材状态下可能已过期，**不反映历史使用情况**」 |

**目录的 `mtime` 是个简单但有效的判别工具**：目录 `mtime` 反映最后一次增删。

若目录 `mtime` 远早于案发窗口，说明这段时间内没有文件增删；若 `mtime` 就在案发窗口内，说明"清空"是那一段时间发生的。这仍只是一个时间相关性判断，删除主体需另证。

<a id="section-24"></a>

#### 陷阱 8：把"用户目录只有一个账户"当成"只有一个人用过这台机器"

**现象**：挂载后 `ls /mnt/mac-data/Users/` 只有一个用户 `liwei`，报告写「该机仅由 `liwei` 一人使用」。

**原因**：用户目录反映的是"当前存在的账户"，不是"历史上使用过这台机器的所有人"。

至少五类痕迹会让已删除的账户"复活"：① `/Users/` 下已删除但未清除的目录（`rm -rf` 不完全、磁盘未回收）；② `MobileSync/Backup/` 下的 iOS 备份记录（可能有多台设备、多个人）；③ Keychain 里的证书与凭据（含已删除账户的残留）；④ 系统日志（`install.log`、`wtmp`、统一日志）里的其它用户名；⑤ 应用数据里的 `accountName` 字段。

**影响**：把"当前账户"当成"全部使用者"，会在涉及多人的场景（比如离职员工 + 交接同事）里漏掉关键的人。

案例的场景是"怀疑离职员工"。如果还有交接人用过这台机器，操作归属的判断就完全不同。

**核查**：用户清单要从多个来源交叉建立，而不是只 `ls /Users/`：

```bash
ls -1 /mnt/mac-data/Users/
# 系统日志里的其它用户名
grep -oE '[^ ]+\b' /mnt/mac-data/private/var/log/install.log 2>/dev/null | sort -u | head
last -f /mnt/mac-data/private/var/log/wtmp                    # 历史登录账户
# iOS 备份记录
ls -1 /mnt/mac-data/Users/*/Library/Application\ Support/MobileSync/Backup/ 2>/dev/null
# Keychain 目录（实测与 Hardware UUID 同名）
ls -1 /mnt/mac-data/Users/*/Library/Keychains/ 2>/dev/null
```

**报告写法**：「`/Users/` 下当前存在单一账户 `liwei`。**该目录反映的是当前存在的账户，不等于历史使用者。**`wtmp` 登录记录中另见账户 X（最近登录 YYYY-MM-DD），`install.log` 中提及账户 Z。上述账户痕迹说明**本机历史上至少由 N 个账户使用**。」

<a id="section-25"></a>

#### 陷阱 9：把"高取证价值"星级当成"必然有数据"

**现象**：按 2.2 的表格逐项清点，`Messages/`、`Keychains/`、`Application Support/MobileSync/Backup/` 这些五星项都存在，于是认为"高价值证据齐备"，报告基调乐观。

**原因**：**"★"标注的是取证潜力，不是数据可得性。** 这些目录普遍存在，但里面的关键数据可能是不可读的：`Messages/` 目录存在但**数据库加密**（无用户密码解不开）；`Keychains/` 目录存在但**解密需用户密码**（见 Keychain 篇）；`Application Support/` 里不同应用的数据格式各异，**LevelDB/SQLite/自定义格式**都需要各自的解析器，工具不支持就只能得到字节碎片。

**目录在 ≠ 数据可读。**

**影响**：报告基调与实际证据量不匹配。

委托方按"证据齐备"的预期投入资源，最后发现关键数据库全是加密或格式未解，信任度受损；更实际的问题是**你会在报告里承诺一份你拿不到的数据**。

**核查**：清点时对每一项记录"可得性状态"，而不只是"是否存在"。这是案例第 1 步"无密钥下的结构性判断"思路的延伸——把结论分成"结构性可得"与"需条件才可得"两层：

| 工件 | 存在性 | 可读性 | 缺失原因/条件 |
|---|---|---|---|
| `Messages/chat.db` | 是 | **否** | 数据库加密，需用户密码或证书 |
| `Keychains/login.keychain-db` | 是 | **否** | 需用户密码解锁 |
| `Application Support/<app>/` | 是 | 部分 | 需按应用格式选解析器 |
| `MobileSync/Backup/` | 视情况 | 视情况 | iOS 备份亦可能设密码 |

报告里要有一节"证据可得性清单"，逐项写明状态。

这样委托方清楚知道哪些结论有支撑、哪些受限于解密条件——这比"高价值工件都在"的乐观基调有用得多。

<a id="section-26"></a>

#### 陷阱 10：把"Big Sur+ 分离结构"下的系统卷当成"无个人痕迹"就跳过

**现象**：确认 `~/Library` 优先后，只提取了 `Macintosh HD - Data` 卷，`Macintosh HD`（只读系统卷）完全没读，报告写「系统卷为签名只读卷，无个人证据」。

**原因**：Big Sur+ 的分离结构下，系统卷（SSV）确实签名只读、个人痕迹极少，这个判断本身是对的。

但"个人痕迹极少"不等于"没有取证价值"——系统卷上仍有可用的**基线数据**：Apple 自带启动项清单（用于比对异常启动项）、系统配置、`/System/Library/LaunchDaemons/` 的原始状态（案例第 3 步验证沙盒路径时就是在做这类基线比对）。

而判定"第三方目录 + 系统风格 Label 是伪造信号"（LaunchAgents 篇的规则 1）需要系统侧基线。

**影响**：主要是基线缺失的损失——没有基线，"这个 Label 是伪造的"这个判断就少了一半依据。

案例第 3 步做的正是这类基线比对，跳过系统卷就没有这项验证。

**核查**：系统卷以"基线比对"为目的选择性提取，不求全：

```bash
apfs-fuse -o vol=1,ro /dev/loop0 /mnt/mac-sys      # vol=1 = 只读系统卷
ls -1 /mnt/mac-sys/System/Library/LaunchDaemons/ | sort > /evidence/baseline-sys-daemons.txt
ls -1 /mnt/mac-sys/System/Library/LaunchAgents/  | sort >> /evidence/baseline-sys-agents.txt
```

然后与 `/Library/LaunchDaemons/`、`~/Library/LaunchAgents/` 的清单做差集——**差集里出现的项就是需要解释的**。

报告里写：「已提取系统卷启动项基线（N 项）用于与用户/全局目录做差集比对」——这行字让"异常"这一判断有可复核的依据。

<a id="section-27"></a>

## 五、案例示例

<a id="section-28"></a>

### 5.1 无密钥下的结构性判断与沙盒路径陷阱

**场景**

MacBook Air（M4，Apple Silicon，macOS 27，FileVault 已开启且已锁定）。委托方为一家外贸公司，要求查明"2024-11-15 前后该机是否通过浏览器访问过客户网站、是否下载文件并外发"。检材 `DigiForensics.dd`（raw，500 GB），APFS 容器分区起始扇区 775920，委托人提供个人恢复密钥。

拿到密钥之前就能得出若干结构性结论。

把"能立刻确定的"与"必须等密钥的"分开，既缩短交付时间，也避免过早下结论。

**处置过程**

第 1 步，**无密钥下的结构性判断**：

```bash
xxd -s $((775920*512 + 32)) -l 32 /work/DigiForensics.dd
# 000f7fa0: 4e585342 0000 0001 0000 0010 3bf1 3f00   NXSB........

apfsutil -o $((775920*512)) /work/DigiForensics.dd
# NXSB Block Count: 131072000
# Volume 1 (oid=2, name='Macintosh HD', block_addr=40)         ← 只读系统卷
# Volume 2 (oid=3, name='Macintosh HD - Data', block_addr=80)  ← ★ 用户数据
# Volume 8 (oid=12, name='VM', ...)                            ← 交换卷
```

`NXSB` 魔数 + 卷列表，这两项**不依赖密钥**。

结构性结论此刻即可写入报告：确认为 APFS 容器，用户数据位于 `Macintosh HD - Data` 卷（oid=3），本机为 **Big Sur+ 分离结构**。

第 2 步，取得密钥后确认时间锚点：

```bash
apfs-fuse -r "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX" -o vol=2,ro /dev/loop0 /mnt/mac-data
ls -1 /mnt/mac-data/Users/                        # → 单一用户 'liwei'

# ★ 必须用 -f 指向检材的 wtmp；在分析机上直接跑 last reboot 拿到的是分析机的时间
last -f /mnt/mac-data/private/var/log/wtmp | head -4
# liwei   ttys000   Fri Nov 15 09:12:33 2024   still logged in
# shutdown system  boot   Fri Nov 15 08:47:10 2024
```

最后一次正常关机为 **2024-11-15 08:47:10**，09:12:33 起有登录会话且未正常结束。**关机之后产生的磁盘态工件不会有对应的内存态痕迹**（本案该时段的处理见 5.2）。

第 3 步，**沙盒路径验证（本篇结论的直接实战检验）**：

```bash
EV=/mnt/mac-data/Users/liwei
ls -1 "$EV/Library/Containers" | wc -l                                      # → 243 个沙盒容器
ls -1 "$EV/Library/Safari" 2>/dev/null | wc -l                               # → 0
ls -1 "$EV/Library/Containers/com.apple.Safari/Data/Library/Safari" | wc -l  # → 187
```

`~/Library/Safari/` 为空（0 项），实际数据在容器路径。

第 4 步，把"结构性结论"与"内容结论"分层：

```bash
# 第①层：无需密钥即成立
echo "APFS 容器 / 用户数据在 Data 卷(oid=3) / Big Sur+ 分离结构"

# 第②层：需密钥但无需解析内容即成立
ls -1 /mnt/mac-data/Users/ | wc -l                    # → 1（单一用户 liwei）
last -f /mnt/mac-data/private/var/log/wtmp | wc -l     # → 288 条登录记录

# 第③层：需解析具体工件
ls -1 "$EV/Library/Containers/com.apple.Safari/Data/Library/Safari" | head -3
# History.db  Downloads.plist  Bookmarks.plist
```

第 5 步，卸载与完整性校验：

```bash
fusermount -u /mnt/mac-data
shasum -a 256 -c /evidence/baseline.sha256
# /work/DigiForensics.dd: OK     ← 全程只读 ✓
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| Apple Silicon + Big Sur+ 分离结构，用户数据在 `Data` 卷 | `NXSB` 魔数 + `apfsutil` 卷列表 | 强（**不依赖密钥**） |
| 最后正常关机为 2024-11-15 08:47:10，其后有未结束登录会话 | 检材 `wtmp`（`last -f` 读取） | 强（会话是否结束见 5.2） |
| 单一用户 `liwei`，共 288 条登录记录 | `~/Users` 清点 + `wtmp` | 强（仅指当前账户，非历史使用者，见陷阱 8） |
| Safari 数据位于沙盒容器路径，旧路径为空 | 目录清点实测 | 强 |
| 事发时段内存态工件（会话、网络连接）未采集 | 现场处置记录 | 已明示为局限 |

**误判对照**

本案最容易得出的错误结论有两个，第二个更隐蔽。

误判 A：「`~/Library/Safari/` 目录是空的（0 个文件），说明 Safari 的浏览痕迹已被清空，存在反取证行为**」。

**正确判据是沙盒路径这一系统机制**，两步：

1. **路径位置本身就是判据**。macOS 10.14 引入沙盒后，Safari 的数据被移到 `~/Library/Containers/com.apple.Safari/Data/Library/Safari/`，旧路径不再被使用。目录存在但为空（0 项）是**系统设计的正常状态**，不是"被清空"的形态。
2. **实证检验最有力**。同一时间清点三个位置：容器目录 243 个、容器内 Safari 数据 187 项、旧路径 0 项。旧路径为 0 而容器内数据完整，这个对比本身就证明了数据是被系统放在容器里，不是被人删除。

**按误判 A 走的代价**：会得出"存在反取证清空行为"的定性，并把调查方向从"读 Safari 容器内的数据"引向"找是谁清的"。而委托方真正要的"是否访问过客户网站"这个答案就在容器路径里——若按误判 A 的路径走完，委托方要的答案一个都拿不到，反而多了一个错误的发现。

误判 B（更隐蔽）：「在分析机上直接跑 `last reboot` 得到的时间是检材的时间轴」——若分析机恰好也在运行且时间相近，分析者可能直接把分析机的时间当成检材的。正确判据是 **`last -f` 的 `-f` 参数**：`last` 默认读本机 `/var/log/wtmp`（即分析机自己的登录记录），必须用 `last -f /mnt/mac-data/private/var/log/wtmp` 显式指向检材。这条纪律对本案尤其重要，因为委托方的关注时段是 2024-11-15，而分析机的时间是 2026 年——若读错，得到的会是"最近有人登录过"这类完全无关的信息。

**按误判 B 走的代价**：整条时间线锚点错误，后续所有"关机后产生的磁盘工件"推论全部作废。而且这个错误不会报错——`last` 会正常输出一堆看起来合理的登录记录。凡是可能读系统默认路径的命令，都要确认它指向检材。

---

<a id="section-29"></a>

### 5.2 断电现场的证据局限与内存态缺失

**场景**

同系列 MacBook（Apple Silicon，macOS 26），委托方要求查明"2024-11-15 09:12 登录后到机器停止运行之间，该用户做了什么"。检材 `DigiForensics.dd`（APFS 容器镜像），现场未采集内存镜像、未做在线快照（macOS 无 `/proc`，对应手段为 `vmmap` 快照或统一日志实时导出）。

"能查到什么"与"查不到什么"必须在报告里逐项说清，而本案这类现场（会话未正常收尾）的证据缺口有一个固定的结构。

**处置过程**

第 1 步，先确定机器的停止状态（**这一步决定所有局限的表述**）：

```bash
last -f /mnt/mac-data/private/var/log/wtmp | head -5
# liwei       console  Fri Nov 15 09:12:33 2024   still logged in
# shutdown system  boot   Fri Nov 15 08:47:10 2024
# → 无 shutdown 记录 → 非正常关机（断电/强制重启/被拔电）

# 关机证据
ls -l /mnt/mac-data/var/db/ 2>/dev/null | grep -iE 'shutdown|boot'
# 无 shutdown_cause 文件 → 无正常关机记录

# 磁盘写入是否干净（APFS 挂载状态）
apfsutil -o $((APFS_PART*512)) /work/DigiForensics.dd | grep -iE 'clean|dirty|unmount'
# apfs.util: volume 'Macintosh HD - Data' is dirty (not cleanly unmounted)
# → ★ 未干净卸载
```

第 2 步，**逐项清点"内存态"证据的可用性**（这是本案例的核心）：

```bash
# ① 关机前最后时刻能否确定？
last -f /mnt/mac-data/private/var/log/wtmp | head -1
# liwei  console  Fri Nov 15 09:12:33 2024  still logged in
# → 只能确定"会话开始于 09:12:33 且未正常结束"

# ② 统一日志能覆盖到什么时候？
DIAG=/mnt/mac-data/var/db/diagnostics
ls -1t $DIAG/Persist/*.tracev3 | head -1 | xargs -I{} stat -f '%N  mtime=%Sm' -t '%Y-%m-%d %H:%M:%S' {}
# /var/db/diagnostics/Persist/0000000000001c47.tracev3  mtime=2024-11-15 09:41:03
# → 统一日志覆盖到 09:41:03

# ③ 用户态日志（谁在做什么）
/usr/bin/log show --directory $DIAG --start "2024-11-15 09:12" --end "2024-11-15 09:45" \
  --style compact --predicate 'process == "loginwindow" OR process == "Dock" OR process == "Safari"' \
  > /evidence/session-0941.txt
wc -l /evidence/session-0941.txt
# 3412 条
```

第 3 步，**确定"最后可确证的动作"并划出边界**：

```bash
# 最后一个事件是什么？
tail -5 /evidence/session-0941.txt
# 2024-11-15 09:40:58.771  Safari[2210]: (libnetwork) ... connection established
# 2024-11-15 09:41:01.220  Safari[2210]: request finished (bytes=284192)
# 2024-11-15 09:41:03.008  WindowServer[188]: session logout requested
# 2024-11-15 09:41:03.104  loginwindow[422]: user "liwei" logged out
# 2024-11-15 09:41:06.331  powerd[96]: Entering Sleep state due to 'Idle Sleep'
```

第 3 步导出到 09:41:45 为止时，`09:41:06 powerd Entering Sleep state` 是日志中**最后一个事件**，这一点本身需要验证：它是机器停止工作的时刻，还是查询窗口结束的时刻。第 4 步的扩展时间窗正是为此。

第 4 步，验证"睡眠"与"关机"的区别（这决定了后续能查多久）：

```bash
pmset -g log 2>/dev/null | tail -5   # 离线机不可用，仅示意
# 在镜像内查 sleep/wake 记录
/usr/bin/log show --directory $DIAG --start "2024-11-15 09:40" --end "2024-11-15 10:30" \
  --style compact --predicate 'process == "powerd"' | head -6
# 2024-11-15 09:41:06.331  Entering Sleep state due to 'Idle Sleep'
# 2024-11-15 09:41:06.902  Wake reason: DarkWake/Ethernet
# 2024-11-15 09:41:07.114  Entering Sleep state due to 'DarkWake'
# 2024-11-15 10:02:44.771  Wake reason: DarkWake/Ethernet
# 2024-11-15 10:02:45.118  Entering Sleep state due to 'DarkWake'
# → ★ 机器进入睡眠后被网络唤醒（DarkWake），持续到……
tail -3 <(同上命令)
# 2024-11-15 14:18:22.004  powerd[96]: Entering Sleep state due to 'DarkWake'
# 2024-11-15 14:18:22 之后无任何日志
# → 睡眠状态持续到 14:18，此后日志中断 → 该时刻是最后一次唤醒
```

第 5 步，查睡眠期间的 DarkWake 活动（这是常被忽略的窗口）：

```bash
/usr/bin/log show --directory $DIAG --start "2024-11-15 09:41" --end "2024-11-15 14:18" \
  --style compact --predicate 'process == "Safari" OR process == "mDNSResponder"' \
  | grep -vE 'DarkWake\[' | head -10
# 2024-11-15 11:22:04  mDNSResponder[881]: Answer portal.customer.example A 203.0.113.40
# 2024-11-15 11:22:19  Safari[2210]: (libnetwork) GET https://portal.customer.example/export
# → ★ 睡眠期间（DarkWake）仍有网络访问
```

**结论**

- 机器不是断电，而是在 2024-11-15 09:41:06 进入睡眠，并被网络以 DarkWake 方式周期性唤醒，最后一次唤醒在 14:18:22，此后日志中断。这比"断电"的假设多出 4.5 小时的证据窗口。
- **睡眠期间的 DarkWake 活动是真实且可查的**：11:22:04 有 DNS 解析（`portal.customer.example`），11:22:19 有 `Safari` 的 GET 请求。DarkWake 状态下 CPU 会被周期性完全唤醒以处理网络与维护任务，因此这段记录与会话期间的记录来自同一日志库，可查性相同；但日志本身不等于内容证据，GET 请求记录只能说明请求被发起。
- **可确证的最后动作**：09:41:01 Safari 完成一次请求（284192 字节）、09:41:03 用户 `liwei` 登出、09:41:06 进入睡眠。但注意 `09:41:03 user "liwei" logged out` 之后仍有 11:22 的 Safari 活动——登出后的活动必须单独说明，归属见下文第三条。
- **不可得的证据（须写入局限）**：
  1. 14:18:22 之后至机器被扣押之间的全部证据不可得（日志中断，无正常关机记录，APFS 卷状态为 dirty）。
  2. **无内存镜像**，因此无法确定当时的网络连接状态、进程内存内容、已打开但未落盘的文件。
  3. 睡眠期间的 DarkWake 只覆盖网络唤醒原因触发的活动；若用户在睡眠期间有本地键盘操作引发的 Full Wake，该部分活动**在本案无日志可查**。

**误判对照**

本案最容易得出的错误结论是「`wtmp` 里 09:12:33 的会话标注 `still logged in`，统一日志最后一条是 09:41:06，说明机器在 09:41 断电，之后的证据全部不可得」。

**正确判据是 `powerd` 的睡眠日志**，三条：

1. `Entering Sleep state` 不等于关机。macOS 的睡眠（Sleep）与 DarkWake 是**持续数小时的低功耗运行状态**，此时 CPU 会被周期性完全唤醒以处理网络、维护任务。本案 09:41:06 之后仍有 10:02、11:22、14:18 等多次 `Wake reason: DarkWake/Ethernet` 记录，**说明机器在"睡眠"状态下仍在活动**。
2. **判定机器停止工作需要的是"日志突然中断且无后续任何记录"**，而不是"看到某个时间点后没有日志"。本案日志在 14:18:22 之后才真正中断，**中间的 4.5 小时是有效证据窗口**。
3. `still logged in` 的会话标注同样不指向断电。它只表示"wtmp 里没有该会话的 logout 记录"——登出记录可能因睡眠/休眠而未落盘，也可能是用户直接合盖未登出。**把"会话未正常结束"读成"机器断电"是双重跳跃。**

**按错误判据走的代价**：会**主动放弃 4.5 小时的证据**，其中包含 11:22 那次对 `portal.customer.example` 的请求记录。丢失之后，报告只能写"11:22 之后无记录"，**把一段有证据的时段写成了证据缺口**。

第二个易错点：看到 `09:41:03 user "liwei" logged out`，就把 09:41:03 之后的一切活动排除在"该用户行为"之外。 正确判据是**登出与进程运行的分离**：

- 登出只终止了**该用户的登录会话**；
- 但 `Safari[2210]` 这个进程在 11:22 仍有活动——可能是登出前未关闭的浏览器窗口（macOS 登出不会强制杀掉所有应用）、可能是自动更新、也可能是登录窗口下的另一个用户。
- **判定归属需要的是"这个进程的属主是谁"**，而不是"用户是否已登出"。

准确写法：「09:41:03 记录 `liwei` 登出。但 11:22:19 仍有 `Safari[2210]` 的 GET 请求。该请求发生于 `liwei` 登出之后，其归属需通过该进程的 uid/属主进一步确认；本案 `pid` 属主信息随内存态不可得，故该请求的归属不可确定。」

第三个易错点（常见）：把 `apfs.util` 报的 `dirty (not cleanly unmounted)` 解读为"文件系统损坏，证据不可信"。正确判据是 APFS 的 dirty 标志表示"上次没有正常卸载"，是这类现场的常见状态，不代表数据损坏。APFS 采用写时复制 + 元数据校验，**已提交的数据是完整可用的**；把它写成"文件系统损坏"会导致整台机器的证据被无谓降级。准确写法是「APFS 卷状态为 dirty，表示检材为非正常关机现场，已提交数据完整可解析，未提交事务不可得」。

---

<a id="section-30"></a>

## 六、扩展阅读方向

**前置与基础。** 盘外结构要先立住：APFS 容器与卷的两层关系、快照如何挂在卷上、
删除的快照能不能在快照仍存活时捞回来。FileVault 的 KEK/VEK 层级决定了哪些路径
在拿到密钥前根本读不了，先把它和 BitLocker 的恢复路径放在一起对比着看
[《BitLocker 全卷加密取证》](../../crypto/crypto-volume/crypto-volume-bitlocker.md)。

**同层深入。** 这张地图给的是位置，分析要从具体工件往下走。系统级活动与持久化
分两条线：统一日志走 `log show` 的时间线重建，LaunchAgents 与登录项走配置文件的时间戳比对。
把分散的证据组织成能交付的调查过程，看[《统一日志与 LaunchAgents》](../computer-log-persistence/computer-log-persistence-macos-unified-logs-and-launch-agents.md)；
完整跑一遍现场处置，看[《macOS 取证实战流程》](computer-security-security-investigation-workflow.md)。

**相邻议题。** Apple Silicon 改变了启动链的安全假设：启动安全性策略、Secure Enclave、
Secure Boot 各自在哪一层拦截，会影响能不能拿到内存镜像。T2 上的硬件加密与
软件加密行为不同，先分清是哪种再谈恢复。iCloud 生态里 `Mobile Documents`
和 `MobileSync/Backup` 的痕迹分属不同数据源，时间线要合并看。

**工具与判据。** 偏好设置与 plist 的解析、Spotlight 索引作为旁证、时间机器快照
与 FSEvents 的配合，三者各自能证明什么、不能证明什么见
[《plist 与偏好设置》](../computer-plist-spotlight/computer-plist-spotlight-plist.md)、
[《FSEvents 与时间机器》](../computer-log-persistence/computer-log-persistence-fsevents.md)、
[《系统痕迹与 DFU 恢复》](../../mobile/mobile-ios/mobile-ios-dfu.md)。

**判据与反例。** 「`~/Library` 下没有对应目录」经常被当成阴性结论，但目录不存在本身
也是结论——可能从未配置、可能被清理、也可能路径被改写过，**三者的处置完全不同**。
同理，统一日志里没有相关条目，只说明该 log 已滚动或该时间窗内无记录，不等于行为未发生。
所有阴性表述都必须写出时间窗与 log 范围。

---

<a id="section-31"></a>

## 七、命令速查

```bash
# ===== 环境 =====
# macOS 侧命令在 macOS 分析机执行（本文验证于 macOS 27 / Apple M4）
# Ubuntu 侧镜像结构确认用 sleuthkit

# ===== 1. 架构、版本、加密状态 =====
system_profiler SPHardwareDataType      # Chip / Model Identifier / Hardware UUID
sw_vers; uptime
fdesetup status                         # FileVault 是否开启 / 解锁

# ===== 2. 卷布局与容器识别 =====
diskutil list                           # 区分 (internal, physical) 与 (synthesized)
diskutil apfs list                      # 容器与各卷详情
diskutil info / | grep -E 'Volume Name|File System Personality'

# 离线镜像（不需要 FileVault 密钥）
mmls /work/DigiForensics.dd
APFS_PART=775920                        # ← 换成 mmls 实际输出
xxd -s $((APFS_PART*512 + 32)) -l 16 /work/DigiForensics.dd   # 期望 4e585342 = "NXSB"
apfsutil -o $((APFS_PART*512)) /work/DigiForensics.dd        # 卷列表、oid、block_addr

# ===== 3. 镜像制作（目标 ≥ 容器标称容量 × 1.03）=====
df -h /Volumes/Evidence
sudo dd if=/dev/rdisk0   of=/Volumes/Evidence/DigiForensics.dd bs=4m status=progress
sudo dd if=/dev/rdisk0s2 of=/Volumes/Evidence/DigiForensics.dd bs=4m status=progress
shasum -a 256 /Volumes/Evidence/DigiForensics.dd | tee /evidence/DigiForensics.dd.sha256

# ===== 4. 只读挂载 =====
shasum -a 256 /work/DigiForensics.dd > /evidence/baseline.sha256
apfs-fuse -r "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX" -o vol=2,ro /dev/loop0 /mnt/mac-data
# 或：hdiutil attach -readonly /work/DigiForensics.dd
mount | grep -E 'apfs|loop'              # 确认 rdonly
fusermount -u /mnt/mac-data
shasum -a 256 -c /evidence/baseline.sha256

# ===== 5. 检材时间锚点（必须 -f 指向镜像内的文件）=====
last -f /mnt/mac-data/private/var/log/wtmp | head -10      # 登录 / 关机记录
last -f /mnt/mac-data/private/var/log/utmpx 2>/dev/null | head -5

# ===== 6. 工件清点（"缺失"本身是发现）=====
EV=/mnt/mac-data
ls -1 $EV/Users/
ls -1 $EV/Library/LaunchDaemons/ | wc -l
ls -1 $EV/Users/*/Library/LaunchAgents/ | wc -l
ls -1 $EV/var/db/diagnostics/Persist/ | wc -l
ls -1d $EV/Users/*/Library/Containers/com.apple.Safari 2>/dev/null
ls -1 $EV/Users/*/Library/"Application Support"/MobileSync/Backup/ 2>/dev/null
ls -l  $EV/Users/*/Library/Keychains/;  ls -la $EV/Users/*/.Trash/
ls -1 $EV/Users/*/Library/Containers/ | wc -l                # 沙盒容器数（最易漏）
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — macOS 取证 — 取证工件地图」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《取证工件地图》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-mem.raw` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
