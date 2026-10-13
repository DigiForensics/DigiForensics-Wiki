---
title: "iOS 备份与沙盒提取"
slug: "mobile-ios-ios-backup-and-sandbox-extraction"
canonical: "https://www.digiforensics.cn/wiki/mobile-ios-ios-backup-and-sandbox-extraction"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:51+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "mobile"
space: "移动取证"
node_path: ["iOS"]
---

# iOS 备份与沙盒提取

<a id="section-1"></a>

## 一、概述

iOS 取证与 Android 的主要区别在于：苹果把"可获取的数据"按层级严格区分，且每一层都需要不同的凭证。

| 层级 | 手段 | 需要什么 | 覆盖内容 |
|---|---|---|---|
| **备份层** | iTunes / Finder 备份 | 设备解锁 + 信任 | 短信、通讯录、日历、Safari、部分 App 数据 |
| **逻辑层（AFC）** | 媒体与部分文档 | 设备解锁 + 信任 | 仅媒体类 |
| **物理层** | 完整文件系统 | 越狱或开发者镜像 | 文件系统全量 |

三层之间不是包含关系而是能力递进：备份层拿到的是应用写入到沙盒并被纳入备份范围的数据，物理层拿到的是文件系统全量。两者覆盖范围不可直接换算成比例。

实战中相当一部分 iOS 案件停留在备份层。不需要越狱，不需要锁屏密码之外的额外条件，**对设备状态的改动也较小**。

这不是能力不足，是起点成本较低的一层。

一次备份就能拿到短信、通讯录、日历、Safari 历史，还有相当一部分应用数据。更重要的是**检材状态不变**——需要向委托方交代"我们做了什么"的时候，这一点值不少。

**没有这一层会发生什么**：直接切物理层，要么越狱（改了设备状态，还得额外授权），要么走 DFU 恢复（见 [iOS 系统痕迹与 DFU 恢复](mobile-ios-dfu.md)），风险更高。

而在备份层就能回答的问题上硬走物理层，付出的是检材完整性风险，新增收益有限。

**在取证流程中的位置**：采集环节的主路径，也是 iOS 侧在不需要越狱等额外前提时就能拿到较多数据的一层。

上游是设备状态固定——`ideviceinfo` 的输出本身要哈希固定，`DeviceName` 属于个人信息，需脱敏。

下游是**文件定位与解包**：`Manifest.db` 索引 → 按哈希取文件 → 还原目录树，再往下是数据库与沙盒内容分析。

它同时是 [Keychain 与 Safari 痕迹](../../computer/computer-security/computer-security-keychain-safari.md) 的数据来源之一。备份里含 Safari 历史数据库与部分 Keychain 条目。

**结构说明**：iOS 的 APFS 容器、卷、快照结构与桌面 macOS 高度一致，这部分见 [APFS 容器与快照](../../filesystem/filesystem-apple-fs/filesystem-apple-fs-apfs.md)，不重复。

本篇只讲**备份层与沙盒层**。

**本篇要讲清的三件事**：备份存了什么、加密备份的密钥怎么来、沙盒怎么提取。

**涉及的证据形态**（保留真实产品的强制文件名）：

| 形态 | 具体位置 | 结构特征 |
|---|---|---|
| 备份根目录 | `~/Library/Application Support/MobileSync/Backup/<设备 UDID>/` | 目录名即 UDID |
| 核心索引 | `Manifest.db` | **SQLite**，`Files` 表存 `fileID` / `domain` / `relativePath` / `flags` / `file` BLOB |
| 归档字段 | `Manifest.db` 的 `file` 列 | **NSKeyedArchiver 归档**（头 `1b 0b 00 00`），**不是普通 plist**，含 Size、时间、Hash、保护类与 per-file key |
| 备份配置 | `Manifest.plist` | 二进制 plist；**加密备份时含 `ManifestKey`**，另有 `ITER` 迭代次数 |
| 完整性判据 | `Status.plist` 的 `IsFullBackup` | 为 1 才是全量备份，差量备份的数据不完整 |
| 设备信息 | `Info.plist` | 文本 plist，含设备名、型号、版本、**已安装应用列表** |
| 实际数据 | `<2hex>/<38hex>` 与同名 `.plist` | 内容本体 + 该文件自己的 Info.plist（未加密备份为**明文 XML**） |
| 沙盒路径 | `AppDomain-<BundleID>-...` | 每个应用独立域，路径含随机化前缀 |

`Manifest.db` 为什么是整个备份里最关键的一个文件：备份中所有文件都被重命名为 SHA-1 哈希，原文件名一个都不留。`Manifest.db` 存的就是"哈希 ↔ 原始路径"这张映射表。

没有它，备份目录只是一堆无法解释的随机文件。后面所有操作都建立在它上面。

设备上装过哪些应用、短信与通讯录内容、备份发生在什么时间点、某个应用的数据存在哪些路径。某次数据变动是否发生在备份之后，对比哈希就能判定。

备份时点之后的事——**备份是时间切片，不是持续记录**。

未进入备份域的应用数据，各 App 覆盖率不同，得逐个查 `domain`。已删文件的残留，备份层没有 freelist 概念。Apple 账户云端数据走 iCloud，那是另一套法律程序。

**本文不做的事**：不越狱，不提供 DFU 绕过或激活锁绕过手段，不编写针对特定 iOS 版本的解密工具。

**加密备份口令走委托方提供路径**：委托方知道口令就用委托方给的，不知道就明确告知"需要委托方在设备上手动解锁后重新备份"。

这个动作必须由有权解锁的人完成，不是分析方能代替的技术步骤。

**读者前提**：SQLite 读取能力（本篇的核心索引就是 SQLite，见 [SQLite 基础与结构](../mobile-database/mobile-database-sqlite.md)）、Apple plist 与 NSKeyedArchiver 的概念、基本的目录与哈希操作。

**建议先把备份当作一棵哈希命名的树来看**。

理解"索引 + 内容"这两层之后，后面的定位与解包就都顺了。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 备份目录结构

```
~/Library/Application Support/MobileSync/Backup/     （macOS）
└── 00008020-001A2B3C4D5E6F70            ← 目录名 = 设备 UDID
    ├── Info.plist        ← 设备名/型号/版本/上次备份时间/应用列表
    ├── Status.plist      ← IsFullBackup、备份状态
    ├── Manifest.db       ← ★ 核心索引（SQLite）
    ├── Manifest.plist    ← 备份配置；加密备份时含 ManifestKey
    ├── 3d/ 3d0d7e5fb2ce288813306e4d4636395e047a3d28
    └── ...               ← 数万至数十万个哈希命名文件
```

| 文件 | 格式 | 取证价值 |
|---|---|---|
| `Info.plist` | 文本 plist | ★★★★ 设备识别 + 已安装应用列表 |
| `Status.plist` | 二进制 plist | ★★★ `IsFullBackup` 判断完整性 |
| `Manifest.db` | **SQLite** | **★★★★★ 备份里最关键的一个文件** |
| `Manifest.plist` | 二进制 plist | ★★★★★ 加密备份的 `ManifestKey` |
| `<2hex>/<38hex>` | 原始或密文 | ★★★★★ 实际数据 |

**`Manifest.db` 为什么是核心**：备份里所有文件都被重命名为 SHA-1 哈希，**文件名完全不保留原名**。它保存"哈希 ↔ 原始路径"的映射。

没有它，备份里就是一堆无法解释的随机文件。

<a id="section-4"></a>

### 2.2 `Manifest.db` 的表结构

```sql
CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT,
                    relativePath TEXT, flags INTEGER, file BLOB);
```

| 字段 | 含义 |
|---|---|
| `fileID` | 形如 `HomeDomain-Library/SMS/sms.db`，**其 SHA-1 就是磁盘文件名** |
| `relativePath` | 域内相对路径，**这是最有用的字段** |
| `flags` | `1`=文件，`2`=目录，`4`=符号链接 |
| `file` | **NSKeyedArchiver 归档**，含 Size、时间、Hash、**保护类与包裹的 per-file key** |

| domain | 内容 |
|---|---|
| `HomeDomain` | 短信、通讯录、日历、Safari、系统偏好 |
| `CameraRollDomain` | 相机胶卷照片与视频 |
| `AppDomain-<BundleID>` | 单个 App 的沙盒数据 |
| `MediaDomain` / `RootDomain` | 音乐播客 / 系统根目录配置 |

`file` 归档内含每个文件自己的元数据，其中 `Hash`（内容 SHA-1）、`ProtectionClass`、`EncryptionKey` 是加密备份解密链的必需材料。

```bash
sqlite3 Manifest.db "SELECT file FROM Files WHERE fileID='HomeDomain-Library/SMS/sms.db';" > file_meta.raw
xxd -l 16 file_meta.raw     # 1b 0b 00 00 04 0b 08 01 ...  ← 归档头，非 XML plist
# 键值在 $objects 数组中，需用归档解析器读取，不是普通 plist
```

<a id="section-5"></a>

### 2.3 未加密备份的 per-file `Info.plist`

未加密备份的每个文件在磁盘上都有两个伴生文件：`<2hex>/<38hex>` 是内容本体，`<2hex>/<38hex>.plist` 是**该文件自己的 Info.plist，明文 XML**。

这是更省事、也更适合做完整性验证的路径，优先走它。

```bash
HASH=3d0d7e5fb2ce288813306e4d4636395e047a3d28
plutil -p $BK/${HASH:0:2}/$HASH.plist
# {   "Birth" => 2023-04-11T02:19:33Z
#     "Hash" => "3d0d7e5fb2ce288813306e4d4636395e047a3d28"
#     "LastModified" => 2024-08-31T15:14:02Z
#     "RelativePath" => "Library/SMS/sms.db"
#     "Size" => 2457600 }
```

| 价值 | 说明 |
|---|---|
| **完整性验证** | `Hash` 是内容 SHA-1，**可与实际文件重算比对** |
| **时间线锚点** | `Birth` 与 `LastModified` 是**设备侧时间**（UTC） |
| **路径还原** | `RelativePath` 是设备上的原始路径 |

> `Last Backup Date` 与 `LastModified` 不是一回事：前者是备份动作的时间，后者是该文件最后被修改的时间，两者常相差数月，**不可混用**。

<a id="section-6"></a>

### 2.4 加密备份的密钥结构

```
备份口令（用户设置，与设备锁屏密码无关）
      │  PBKDF2-SHA256( salt, iterations )
      ▼
Backup Key（32 字节）
      │  解密 Manifest.plist 的 BackupKeyBag
      ▼
Class Key（按数据保护类：ThisDeviceOnly / AfterFirstUnlock / …）
      │  解密 Manifest.plist 的 ManifestKey
      ▼
ManifestKey（32 字节，保护 Manifest.db 与元数据）
      │  解密每个文件记录中的 per-file key
      ▼
Per-file Key（每文件一个 32 字节密钥）
      │  AES-256-CBC（每 4096 字节滚动 IV，每段 16 字节 HMAC-SHA1 tag）
      ▼
明文文件
```

| 环节 | 参数 | 取证意义 |
|---|---|---|
| 派生 | **PBKDF2-SHA256** | 迭代次数在 `Manifest.plist` 的 `BackupKeyBag` 中读取 |
| 迭代次数 | 早期约 10,000；**iOS 10.2 之后约 10,000,000** | **决定口令恢复的可行性与耗时** |
| 内容加密 | **AES-256-CBC** | 密钥 32 字节，IV 长度见 `IVLength`（常见 0x10） |

> **备份口令与设备锁屏密码完全无关。** 即使通过司法程序解锁了设备，备份仍可能是加密的。报告中必须把"设备已解锁"与"备份已解密"作为两件独立的事分别说明。

> **迭代次数的影响是决定性的**：10,000,000 次 PBKDF2-SHA256 使现代硬件上每个候选口令的验证也需要可观计算量。短口令（6 位数字、常见弱口令）仍有机会，长随机口令在合理时间内不可行。 遇到高迭代 + 强口令的备份，应当**如实说明不可行**并转向其他证据来源，而不是给出含糊结论。

<a id="section-7"></a>

### 2.5 iOS 沙盒结构

```
/private/var/mobile/Containers/Data/Application/<UUID>/
├── Documents/                          ← 用户可见文档
├── Library/
│   ├── Preferences/<BundleID>.plist    ← 应用配置
│   ├── Caches/
│   └── Application Support/            ← 数据库常在这里
└── tmp/
```

| 事实 | 取证意义 |
|---|---|
| **每个 App 独立沙盒** | 只能逐个分析 |
| **沙盒 UUID 每次重装会变** | **不能当稳定的 App 标识**，应通过 `BundleID` 关联 |
| 系统数据库在 `/private/var/mobile/Library/` | 短信、通话、通讯录、日历等 |

iOS 侧没有 Android 那套 userdata 分区与多用户机制，两条移动取证路径的门槛差异见[第 01 篇](../mobile-android/mobile-android-android-data-storage-overview.md)，便于在预算与时间受限时先做取舍。

---

<a id="section-8"></a>

## 三、操作步骤

<a id="section-9"></a>

### 第 1–2 步：环境准备与设备识别

```bash
sudo apt install libimobiledevice-utils usbmuxd ifuse libplist-utils
sudo usbmuxd &                        # ★ 不跑会报 no device found
idevice_id -l
ideviceinfo > device-info.txt          # ★ 提取前先固定设备信息
grep -E 'UniqueDeviceID|ProductType|ProductVersion|DeviceName' device-info.txt
# UniqueDeviceID: 00008020-001A2B3C4D5E6F70
# ProductType:    iPhone14,2
# ProductVersion: 16.6.1
# DeviceName:     某某的 iPhone      ← 用户自命名，可能是姓名线索
sha256sum device-info.txt
```

<a id="section-10"></a>

### 第 3 步：执行备份

```bash
mkdir -p /work/ios-backup
# 交互式：会提示备份口令，务必在终端内输入，不写在命令行
idevicebackup2 -i backup /work/ios-backup/ 2>&1 | tee backup.log
```

| 实务建议 | 理由 |
|---|---|
| **交互式输入口令** | 命令行会进 shell 历史，也会出现在 `ps` 输出里 |
| **若为空密码，明确记录"未设置"** | 空密码加密备份没有 KDF 开销，且是设备使用习惯证据 |

> ⚠️ **备份不会修改设备数据**，这是它相对物理提取的主要优势。但部分 App 可能因"备份触发"更新状态（如云同步标记），应在报告中作为已知限制说明。

<a id="section-11"></a>

### 第 4–5 步：分析备份结构并查询 `Manifest.db`

```bash
BK=/work/ios-backup/00008020-001A2B3C4D5E6F70
plutil -p $BK/Status.plist | grep IsFullBackup      # "IsFullBackup" => 1  ← 全量
if plutil -p $BK/Manifest.plist | grep -q ManifestKey; then
  echo "★ 加密备份"
  plutil -p $BK/Manifest.plist | grep -E 'ITER|WasPasscodeSet'
  # "ITER" => 10000000                   ← 10,000,000 次 PBKDF2
fi
sqlite3 $BK/Manifest.db "PRAGMA integrity_check;"
sqlite3 $BK/Manifest.db "
SELECT domain, COUNT(*) n FROM Files WHERE flags=1 GROUP BY domain ORDER BY n DESC LIMIT 5;"
sqlite3 -header $BK/Manifest.db "
SELECT fileID, relativePath FROM Files WHERE relativePath LIKE '%sms.db%';"
```

**关键判断**：迭代次数 **10,000,000** 说明是 iOS 10.2 之后创建的备份。委托方已提供口令，本步无恢复问题——但**该字段仍应记录在报告中**，它决定了"若口令错误是否还有恢复路径"。

<a id="section-12"></a>

### 第 6 步：按哈希定位并提取文件

```bash
# fileID 的 SHA-1 就是磁盘路径：前 2 字符为目录名
echo -n "HomeDomain-Library/SMS/sms.db" | sha1sum
# 3d0d7e5fb2ce288813306e4d4636395e047a3d28
cp $BK/3d/3d0d7e5fb2ce288813306e4d4636395e047a3d28 ./sms.db

HASH=3d0d7e5fb2ce288813306e4d4636395e047a3d28
plutil -extract Hash raw $BK/${HASH:0:2}/$HASH.plist
sha1sum sms.db                 # 两者必须一致 ✓
```

> **注意增量备份**：最新一次 `Manifest.db` 引用了全部文件，但**未被修改的旧文件可能物理上仍存放在历史备份目录中**。不能只在最新备份目录里找文件。

<a id="section-13"></a>

### 第 7 步：解包为可浏览目录树

```bash
cat > restore_backup.py <<'PYEOF'
#!/usr/bin/env python3
# 把 iTunes/Finder 备份按 Manifest.db 还原为目录树（仅未加密备份）
# 用法: python3 restore_backup.py <备份目录> <输出目录>    Python 3.8+，仅标准库
import hashlib, os, sqlite3, sys

src, dst = sys.argv[1:3]
conn = sqlite3.connect(f"file:{os.path.join(src, 'Manifest.db')}?mode=ro", uri=True)
n = ok = miss = 0
for domain, relpath in conn.execute(
        "SELECT domain, relativePath FROM Files WHERE flags=1"):
    n += 1
    # 磁盘文件名 = fileID 的 SHA-1，前 2 字符为子目录
    h = hashlib.sha1(f"{domain}-{relpath}".encode()).hexdigest()
    f = os.path.join(src, h[:2], h)
    if not os.path.exists(f):
        miss += 1          # 增量备份：文件可能在历史备份目录中
        continue
    out = os.path.join(dst, domain, relpath)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(f, "rb") as fi, open(out, "wb") as fo:
        fo.write(fi.read())
    ok += 1
print(f"共 {n} 个文件，还原 {ok} 个，缺失 {miss} 个（增量备份时属正常）")
PYEOF

python3 restore_backup.py $BK /work/restored/
find /work/restored -type f | wc -l
```

> ⚠️ **仅适用于未加密备份。** 加密备份的 `Manifest.db` 本身也是密文，顺序是"先解密 `Manifest.db`，再用它定位其他文件"。

<a id="section-14"></a>

### 第 8 步：沙盒与 AFC 提取

```bash
# AFC（App File Container）：通过 usbmuxd 访问的媒体/文档通道
ifuse --list-documents       # 列出 AFC 可见的文档目录
afcclient ls /DCIM/100APPLE | head
mkdir -p /mnt/ios-afc && ifuse /mnt/ios-afc && ls /mnt/ios-afc
fusermount -u /mnt/ios-afc    # ★ 用完务必显式卸载
```

| AFC 能取 | AFC 不能取 |
|---|---|
| `DCIM/`、`PhotoData/` | `/private/var/mobile/Library/` 下的系统数据库 |
| `Download/`、部分 `Documents/` | App 的 SQLite（除非应用把库放在 Documents） |
| 部分应用的媒体目录 | Keychain、沙盒内的配置与缓存 |

> **AFC 通道 ≠ App 沙盒提取。** AFC 在 iOS 侧是按目录白名单开放的，它不提供遍历 `/private/var/mobile/Containers/Data/Application/` 的能力。凡声称"用 AFC 就能拿到任意 App 沙盒"的结论都是错误的。

要取沙盒内的 SQLite 库，实际可行的路径有四条：

| 路径 | 前提 | 证据强度 |
|---|---|---|
| **① 加密备份** | 该 App 参与备份、且有备份口令 | **最强**（可逐文件校验） |
| **② 越狱设备 + 沙盒工具** | 设备已越狱，须委托方授权 | 强 |
| **③ 开发者镜像** | 设备支持、应用为**本方开发** | 中 |
| **④ 物理/内存镜像** | 有文件系统级检材 | 视解密情况 |

```bash
# 越狱设备上的沙盒提取（示例，能力与支持范围以实际环境为准）
frida-ios-dump -H <host> -U -F   # dump 指定 bundle id 的沙盒
```

> **`frida-ios-dump` 的两条硬前提**：① **越狱设备**，或已为该 App 挂载**开发者磁盘镜像**（仅对可配证书的自家 App 可行）；② **必须逐个指定 bundle id**，无法"一把梭"导出所有 App。
> 它的实现原理是**在 App 进程内枚举文件并复制**，因此**对正在运行且被系统保护的 App 可能失败**——失败就如实记为"未获取"，不可推断为"无数据"。

---
<a id="section-15"></a>

## 四、常见陷阱

<a id="section-16"></a>

### 4.1 备份凭证与整体判断

<a id="section-17"></a>

#### 陷阱 1：把备份口令当成设备锁屏密码

**现象**：委托方提供了锁屏密码，分析师直接用它作为备份口令尝试解密；失败后报告写"口令错误，备份无法解密"。

**原因**：备份口令与设备锁屏密码在 iOS 中是完全无关的两套凭证。

前者是用户在设置 iTunes/Finder 备份时自己设定的字符串，可以与锁屏密码毫无关系；后者由用户单独设置，与设备加密密钥体系也是两条链路。

误判的来源是"移动取证 = 拿到设备密码 = 拿到一切"这个直觉。这个直觉在 iOS 上是错的——**即使通过司法程序解锁了设备，备份仍可能是加密的**。

**影响**：**把一个可解的检材直接判定为不可解**，并终止了后续取证工作。

更实际的后果是，这个"口令错误"的结论会写进报告。委托方据此以为还能提供别的密码，而实际问题在于，他们提供的从来就不是需要的东西。

**核查**："设备已解锁"与"备份已解密"必须作为两件独立的事分别记录，并确认口令来源的合法性。

```bash
# 先判断备份是否加密、是否需要口令
BK=/work/ios-backup/00008020-001A2B3C4D5E6F70
if plutil -p $BK/Manifest.plist | grep -q ManifestKey; then
  echo "★ 加密备份，需备份口令"
  plutil -p $BK/Manifest.plist | grep -E 'ITER|WasPasscodeSet'
fi
```

报告中的状态表述应该分三句写，不要合并：

"设备已于 `<时间>` 由委托方解锁并信任分析机；备份口令由委托方于 `<时间>` 提供，来源与合法性已确认；备份加密状态：`<加密/未加密>`。"

合并成一句"设备已解锁，数据可提取"，后两个信息就都丢了。

<a id="section-18"></a>

#### 陷阱 2：★ 在命令行传入备份口令

**现象**：为了脚本化，把口令写进命令行执行备份，事后在 shell 历史或进程列表中发现了它的痕迹。

**原因**：**命令行参数在三个地方同时暴露**——shell 历史文件、同一用户下其他进程的 `ps` 输出、以及部分审计日志。

无人值守、便于放进流水线，这样的考虑本身是合理的。但**这条命令在执行那一刻就已经不可撤回地泄露了凭证**。

事后删除历史也没用：已产生的进程列表快照、日志与终端回滚缓冲仍可能留有痕迹。

**影响**：**备份口令的扩散是不可逆的**。

口令泄露后，攻击者可以离线解密整个备份的全部内容，而这些内容往往包含设备上所有应用的数据——**泄露的影响面远大于单个文件**。

这类问题往往在交付之后才被发现。

**核查**：**口令只经交互式输入，脚本中永不留存**。

```bash
# 交互式：工具会提示输入口令，不要加任何口令参数
idevicebackup2 -i backup /work/ios-backup/ 2>&1 | tee backup.log
```

配套纪律：备份目录本身按敏感检材管理（限制访问、加密归档、传输走加密通道）；分析日志与 `backup.log` 要检查是否混入了口令；若已发生泄露，应在报告中记录并建议委托方更换口令。

<a id="section-19"></a>

### 4.2 备份结构与文件定位

<a id="section-20"></a>

#### 陷阱 3：只在最新备份目录里找文件

**现象**：最新一次备份的 `Manifest.db` 中列出了 14,273 个文件，按哈希去磁盘上找，结果只找到 4,000 余个，报告写"备份不完整，大量文件缺失"。

**原因**：**增量备份只传输变化的部分**。

最新一次 `Manifest.db` 引用的是全部文件，但未被修改的文件可能物理上仍存放在上一次全量备份的目录里，或者存在于同一 UDID 目录下被系统轮转保留的其他备份中。

误判的来源是"备份目录 = 一个自包含的完整快照"这个假设。实际上**只有全量备份才接近自包含**。

**影响**：**把正常的增量机制报告为检材缺陷**，这份"缺失清单"还会成为后续所有"未发现"结论的错误前提。

委托方据此认为数据不可得，可能直接放弃这条取证路径。

**核查**：先读 `IsFullBackup`，再跨全部备份目录检索。

```bash
BK=/work/ios-backup/00008020-001A2B3C4D5E6F70
plutil -p $BK/Status.plist | grep IsFullBackup        # "IsFullBackup" => 1  ← 全量

# 跨全部备份目录查找同一 fileID 的哈希（同一 UDID 下可能有多个备份）
HASH=$(echo -n "HomeDomain-Library/SMS/sms.db" | sha1sum | cut -d' ' -f1)
find ~/Library/Application\ Support/MobileSync/Backup/ -name "$HASH" -o -name "$HASH.plist"
```

报告须写明三件事：`IsFullBackup` 的取值、**本次实际检索覆盖了几个备份目录**、每个文件的来源是哪一个备份。

确实找不到的记为"未获取"，**不可推断为"设备上不存在"**。

<a id="section-21"></a>

#### 陷阱 4：把磁盘文件名当作原始路径

**现象**：在备份目录里看到 `3d/3d0d7e5f...`，把它当作某个应用的数据库文件直接用 `sqlite3` 打开；或者按 `Library/SMS/sms.db` 这样的路径去备份目录里 `find`。

**原因**：备份里所有文件都被重命名为内容的 SHA-1，文件名完全不保留原名。

而且这个哈希是 `fileID`（`domain` + `-` + `relativePath`）的 SHA-1，不是文件内容的哈希。后者是 `.plist` 里记录的 `Hash` 字段，两个值不同，不能互换。

"文件名总是有点线索"，这个直觉在 iOS 备份上不成立——它就是刻意做成不可读的。

**影响**：**无法把任何文件与业务语义关联起来**。拿到的字节无法判断属于短信、日历还是某个 App，报告里也就无法陈述"提取到了什么"。

**核查**：永远通过 `Manifest.db` 查询映射关系。

```bash
# 路径 → fileID → SHA-1 → 磁盘路径，三步不可跳
echo -n "HomeDomain-Library/SMS/sms.db" | sha1sum
# 3d0d7e5fb2ce288813306e4d4636395e047a3d28
cp $BK/3d/3d0d7e5fb2ce288813306e4d4636395e047a3d28 ./sms.db

# 反向：给定磁盘文件，查它是什么
sqlite3 $BK/Manifest.db "SELECT domain, relativePath FROM Files WHERE fileID='HomeDomain-Library/SMS/sms.db';"
```

`domain` 与 `relativePath` 两列必须成对记录。

只有 `relativePath` 没有 `domain`，仍然无法还原完整路径——`AppDomain-com.whatsapp` 与其他 App 的同名相对路径会冲突。

<a id="section-22"></a>

#### 陷阱 5：把 `Files.file` 字段当普通 plist 解析

**现象**：从 `Manifest.db` 里 `SELECT file` 取出 BLOB，用 `plutil` 或文本编辑器打开，看到 `$archiver` / `$objects` 之类的结构就认为字段损坏。

或者把 `$top` 里的结构键误当成业务字段。

**原因**：`file` 字段是 NSKeyedArchiver 归档，不是普通 plist。

键值对被拆散放进 `$objects` 数组，靠 `$number`、`$string` 这类标记和 UID 引用重新关联。

直接读只能看到间接结构，看不到 Size、LastModified、Hash、EncryptionKey 这些真正需要的值。

归档头 `1b 0b 00 00 04 0b 08 01` 也不是 XML plist 的 `bplist` 或 `<?xml`。据此判断"不是 plist，字段无效"，是这里最常见的误判。

**影响**：**丢掉了加密备份解密链的必需材料**。`EncryptionKey`（包裹的 per-file key）就藏在这个归档里，跳过它意味着加密备份的每个文件都无法解密。

**核查**：**用归档解析器读取；未加密备份则优先走更省事的路径**。

```bash
# 未加密备份：直接读磁盘上的 per-file Info.plist（明文 XML）
HASH=3d0d7e5fb2ce288813306e4d4636395e047a3d28
plutil -p $BK/${HASH:0:2}/$HASH.plist
# { "Birth" => ..., "Hash" => ..., "LastModified" => ..., "RelativePath" => ..., "Size" => ... }
```

未加密备份的 per-file `.plist` 是明文 XML，含 `Hash`、`LastModified`、`Size`、`RelativePath`，是更省事也更适合做完整性验证的路径。加密备份没有这些明文伴生文件，必须回到归档解析。

两条路径的产出字段不同，**报告要写明用的是哪一条**。

<a id="section-23"></a>

#### 陷阱 6：把 `Last Backup Date` 当成文件修改时间

**现象**：报告用 `Info.plist` 里的 `Last Backup Date`（2024-09-01）作为"数据最后更新时间"写入时间线，并据此判断"9 月 1 日后无相关活动"。

**原因**：**这是两个完全不同的时间**。

`Last Backup Date` 是**备份动作发生的时间**，`LastModified` 是**该文件在设备上最后被修改的时间**，两者常相差数月。一个 9 月 1 日做的备份，完全可能包含着 8 月 22 日就再没动过的数据库。

**影响**：**产生方向完全相反的时间线结论**。

用它证明"9 月后无活动"，实际上只能证明"9 月 1 日之后没再备份过"。这期间设备上发生了什么，检材里根本没有。

**核查**：**两种时间分别使用，并在报告中标注来源**。

| 时间 | 来源 | 含义 | 可支撑的结论 |
|---|---|---|---|
| `Last Backup Date` | `Info.plist` | 备份动作时刻 | **数据提取的时间上界** |
| `LastModified` | per-file `.plist` / `Manifest.db` | 文件在设备上最后被改动的时刻 | **该文件内容的时间上界** |
| `Birth` | per-file `.plist` | 文件创建时刻 | 存在性证据 |

```bash
plutil -p $BK/Info.plist | grep 'Last Backup Date'
plutil -extract LastModified raw $BK/${HASH:0:2}/$HASH.plist
```

阴性结论的正确句式是："本检材为 `<Last Backup Date>` 执行的备份，此后设备活动不在本检材范围内"——而不是"此后无相关活动"。

<a id="section-24"></a>

### 4.3 数据库解读与时间换算

<a id="section-25"></a>

#### 陷阱 7：漏加 Cocoa 纪元偏移

**现象**：从 `sms.db` 的 `message` 表读出 `date = 731,658,667`，直接当 Unix 秒处理得到 1993 年，报告写"该短信发送于 1993-03-14"。

**原因**：iOS 系统库（`sms.db`、`CallHistory`、`Calendar` 等）普遍使用 Cocoa 纪元，即 2001-01-01 00:00:00 UTC。

该时刻的 Unix 秒数是 `978307200`，而表里存的是从这个纪元起的偏移量，不是 Unix 时间戳。

两者差一个常量。漏加就整体偏移 31 年，所有时间落回 1970 年附近。

**影响**：**跨库时间线彻底失效**。

这类错误很隐蔽——数字本身"看起来合理"。不与通话记录、WhatsApp 等其他来源比对，单独看不会发现。而一旦发现，全案的时间线都要重做。

**核查**：**先确认纪元来源，再统一换算，并用跨库一致性验证**。

```bash
# 978307200 = 2001-01-01 00:00:00 UTC 的 Unix 秒数
sqlite3 -header -column sms.db "
SELECT text, datetime(date/1000 + 978307200,'unixepoch','+8 hours') AS t
FROM message WHERE text LIKE '%关键词%' ORDER BY date;"

# WhatsApp 走 Core Data，同为 Cocoa 纪元
sqlite3 -header -column ChatStorage.sqlite "
SELECT ZTEXT, datetime(ZPUSHED + 978307200,'unixepoch','+8 hours') AS t
FROM ZMESSAGE WHERE ZTEXT LIKE '%关键词%' ORDER BY ZPUSHED;"
```

**验证方法**：换算后与第二个独立来源对齐。本案中短信 20:11、WhatsApp 20:14、通话 20:15，三者顺序与间隔合理，**这种跨库自洽才是纪元选择正确的证据**。

而"落在 1993 年"或"落在 1970 年"本身就是纪元选错的信号。

<a id="section-26"></a>

#### 陷阱 8：直接用 `sqlite3` 打开提取的库，把报错当作文件损坏

**现象**：对提取出的库执行 `sqlite3 file.db ".tables"`，报 `file is not a database`，报告写"该数据库已损坏，无法解析"。

**原因**：iOS 侧大量应用数据库默认启用加密（SQLCipher 或应用自研方案），密文库的首字节不是 `SQLite format 3\0`，任何 SQLite 工具都会报同样的错。

而"文件损坏"与"文件被加密"在错误信息层面无法区分——这一点容易造成误判。

**影响**：**把可解密的数据判为不可用**。

若应用用了可识别方案（密钥硬编码在应用二进制中，或密钥来自钥匙串、服务端），分析师本可继续推进。报告一旦写"已损坏"，委托方就失去了继续投入的依据。

**核查**：**先看首字节，再判断加密类型**。

```bash
head -c 16 sms.db | xxd
# 53 51 4c 69 74 65 20 66 6f 72 6d 61 74 20 33 00   → "SQLite format 3\0"  明文
# 其他                                          → 加密或非 SQLite 格式

sqlite3 sms.db ".tables" 2>&1 | head -1
```

若首字节不符，报告应写"该库为加密存储，密钥未获取，在现有授权下无法解密"，并列出已排查的密钥来源（应用二进制、钥匙串、备份中的 per-file key、服务端下发）。

**严禁写成"数据不存在"，也严禁推测内容。**

<a id="section-27"></a>

#### 陷阱 9：提取出的库未核对 `-wal` / `-shm` 配套文件

**现象**：从备份中提取出 `sms.db`，用 `sqlite3` 打开后按 `date` 查最近记录，最新一条停在 8 月 22 日，报告写"该号码 8 月 22 日后无短信往来"。

**原因**：SQLite 库在 WAL 模式下，最近的提交可能还在 `-wal` 里。

iOS 应用普遍使用 WAL，而备份层同样会把这三个文件一起备份。只取主库而不取同目录的 `-wal` / `-shm`，读到的就是**一个旧快照**。

iOS 侧还有一层额外风险：`AppDomain` 下同一目录可能存在多个相近命名的库，**只按 `*.db` 通配而不核对配套文件很容易漏**。

**影响**：**"未发现"直接变成错误的否定结论**。

这会把提取不完整伪装成事实不存在，也因此较难自查。

**核查**：提取后按哈希在 `Manifest.db` 中核对配套文件，并检查 `write_version`。

```bash
# 在 Manifest.db 中查该库所在目录下的全部条目
sqlite3 -header Manifest.db "
SELECT relativePath, flags FROM Files
WHERE fileID LIKE 'AppDomain-com.digiforensics.sample-%'
  AND relativePath LIKE '%ChatStorage%';"
# 注意 -wal / -shm 也是独立条目，需一并提取

# 打开时用 immutable=1，避免读取动作触发 checkpoint 改写文件
cp sms.db /work/DigiForensics-analysis.db
sqlite3 "file:/work/DigiForensics-analysis.db?immutable=1" "PRAGMA journal_mode; PRAGMA integrity_check; PRAGMA freelist_count;"
```

`PRAGMA journal_mode` 返回 `wal` 说明该库处于 WAL 模式，**此时必须确认 `-wal` 是否已一并提取**。

`integrity_check` 返回 `ok` 只说明结构一致，**不代表已获取全部提交数据**。

这两个结论必须分开陈述。

<a id="section-28"></a>

### 4.4 沙盒、AFC 与范围声明

<a id="section-29"></a>

#### 陷阱 10：把沙盒 UUID 当作稳定的 App 标识

**现象**：报告以 `/private/var/mobile/Containers/Data/Application/A1B2C3D4-.../Documents/` 作为标识来分析。

跨检材比对时发现同一 App 在另一份镜像里 UUID 不同，于是误判为"存在两个不同应用"或"数据被复制过"。

**原因**：**沙盒目录的 UUID 每次 App 重装都会变**——重装、升级后清理、容器迁移都可能产生新 UUID。

它**不是稳定的 App 标识**，甚至不保证同一 App 多次安装的 UUID 不同（系统可能复用）。

真正的稳定标识是 `BundleID`。它需要通过 `Info.plist`（沙盒路径在 `Library/Preferences/<BundleID>.plist` 中可反推）或备份中的 `AppDomain-<BundleID>` 来确定。

**影响**：**同一份数据被当成多份**。

按 UUID 统计"发现 N 个应用实例"，数字会虚增；反过来按 UUID 追踪"同一 App 的历史"，则会断裂。

**核查**：全程用 `BundleID` 关联，UUID 只作为本次检材内的定位符。

```bash
# 沙盒目录 → BundleID：通过应用内的 Preferences 文件名反推
ls /private/var/mobile/Containers/Data/Application/A1B2C3D4-.../Library/Preferences/
# com.digiforensics.sample.plist   ← BundleID

# 备份层：domain 本身就带 BundleID
sqlite3 Manifest.db "SELECT DISTINCT domain FROM Files WHERE domain LIKE 'AppDomain-%';"
```

报告中应写："沙盒目录 `<UUID>` 对应 `BundleID = com.digiforensics.sample`（由 `Library/Preferences/<BundleID>.plist` 确认）。"

UUID 为本次检材内的定位符，重装后会变化，不可作为跨检材关联依据。

<a id="section-30"></a>

#### 陷阱 11：期待用 AFC 通道取到应用沙盒数据

**现象**：通过 `ifuse` 挂载成功后，在挂载点下反复查找 `Library/Preferences` 与应用数据库，全部找不到，报告写"该应用未在设备上留下数据"。

**原因**：AFC 通道在 iOS 侧按目录白名单开放，不提供遍历 `/private/var/mobile/Containers/Data/Application/` 的能力。

它能看到的主要是 `DCIM/`、`PhotoData/`、`Download/`，以及部分被应用显式暴露的文档目录。

沙盒内的 SQLite、Preferences、Caches 都不在其中，除非该应用恰好把文件放在了 AFC 可见的目录下。

"能挂载一个目录 = 能访问文件系统"——这个类比在这里不成立。AFC 是一个受限的导出通道，不是文件系统视图。

**影响**：**把通道能力边界误当成数据不存在**，这类"未发现"完全无法支撑任何结论。

**核查**：先明确 AFC 的能力边界，再按四条路径评估可行性。

| 路径 | 前提 | 证据强度 |
|---|---|---|
| **① 加密备份** | 该 App 参与备份、且有备份口令 | **最强**（可逐文件校验） |
| **② 越狱设备 + 沙盒工具** | 设备已越狱，须委托方授权 | 强 |
| **③ 开发者镜像** | 设备支持、应用为**本方开发** | 中 |
| **④ 物理/内存镜像** | 有文件系统级检材 | 视解密情况 |

AFC 只在表中"仅媒体类"那一行有位置。任何"用 AFC 拿到任意 App 沙盒"的说法都是错误的。

用完挂载点必须显式卸载（`fusermount -u`），避免设备侧残留连接。

<a id="section-31"></a>

#### 陷阱 12：把沙盒提取失败记为"该应用无数据"

**现象**：对某 App 执行沙盒提取工具，输出"未找到容器"或直接失败，报告写"该应用在设备上无任何本地数据"。

**原因**：沙盒提取工具的实现原理是在 App 进程内枚举并复制文件，因此对正在运行且被系统保护的 App 可能失败。工具能力与支持范围也随版本与设备状态变化。

"工具失败"与"App 没有数据"是两个不同的事件，而失败信息往往只有一句错误输出，不具备可区分性。

把失败直接归为"无数据"，就是把工具的能力边界当成了事实。

**影响**：**产出一条无法支撑的否定结论**。

该 App 若是案件关键，报告却已写明"无数据"，委托方据此排除方向。

**核查**：失败与"无数据"必须严格区分，失败一律记为"未获取"。

```bash
# 记录工具版本、目标 bundle id、执行参数与完整输出
frida-ios-dump -H <host> -U -F -b com.digiforensics.sample 2>&1 | tee dump-sample.log
```

报告句式规范："沙盒提取对 `com.digiforensics.sample` **未能完成**（原因：`<工具返回信息>`）。因此**该应用沙盒内容在本次检材中未获取**，**不构成"该应用无本地数据"的结论**。补取路径：`<越狱设备/开发者镜像/云备份>`。"

<a id="section-32"></a>

### 4.5 结论表述

<a id="section-33"></a>

#### 陷阱 13：把"备份层可得"直接写成"数据已全部获取"

**现象**：报告结论写"短信、通讯录、通话记录、WhatsApp 聊天记录均已完整提取"，同时又在局限性里提到"未解析 `Z_*` 表关系、Keychain 未提取"。

**原因**：**"已提取"与"已完整解读"被合并成了一句话**。

"提取"只是把字节拿到手，"解读"才是把内容变成可用的事实。

本案的 WhatsApp 用 Core Data 格式，仅在 SQL 层查询而未解析 `Z_*` 表的关系模型，**联系人、附件路径都未关联**。此时声称"已完整提取聊天记录"是超出实际的。

更根本的是，**备份层本身就有明确的覆盖边界**：`knowledgeC.db`、CoreDuet、完整照片元数据等通常不在普通备份范围内。

**影响**：**在报告最显眼的位置给出超出证据能力的陈述**。

委托方与后续办案人员往往会以此为据。要更正一个已进入决策链条的结论，成本远高于一开始就写准。

**核查**：结论中的每条陈述必须标明层级与完整性状态，并给出明确的未覆盖清单。

| 结论项 | 层级 | 完整性状态 |
|---|---|---|
| 短信记录 | 备份层（`HomeDomain`） | 已提取、已解码、Cocoa 时间已换算并跨库验证 |
| 通讯录 | 备份层 | 已提取；`ABMultiValue` 多值字段未逐一展开 |
| WhatsApp 聊天 | 备份层（`AppDomain-`） | **字节已提取，SQL 层已查询；关系模型未解析** |
| Keychain | — | **未提取** |

配合两条硬性要求：

- **区分"完整备份"与"完整数据"**：`IsFullBackup=1` 说的是传输方式，**不代表备份范围内含所有数据**；
- **个人信息按需脱敏**：`DeviceName` 常含真实姓名、`Info.plist` 中有应用列表，报告对外版本应脱敏，内部材料保留为线索并注明。

**范围、方法、未覆盖范围、效力上限**——这四项是"未获取""未解析""未提取"类陈述的统一交付标准。

---
<a id="section-34"></a>

## 五、案例示例

<a id="section-35"></a>

### 5.1 三源印证的可疑会面约定与 Cocoa 时间对齐

**场景**

查获一台 iPhone（iOS 16.6.1，锁屏密码已知）。委托方要求提取短信记录、通讯录与 WhatsApp 聊天记录，并查明委托事项中"两名嫌疑人在事发前一日有过会面约定"这一说法。

检材已由委托方解锁并信任分析机，**加密备份口令由委托方提供**。

本案的关键不在能否拿到数据库，而在**三个来源的时间线能否对齐**。短信、即时通讯、通话记录各自用不同的纪元与时区，不对齐就无法把三个来源拼成一条线。

**处置过程**

第一步，设备识别与备份：

```bash
$ ideviceinfo > device-info.txt
$ grep -E 'UniqueDeviceID|ProductVersion' device-info.txt
UniqueDeviceID: 00008020-001A2B3C4D5E6F70
ProductVersion: 16.6.1
$ sha256sum device-info.txt

$ idevicebackup2 -i backup /work/ios-backup/ 2>&1 | tee backup.log
$ du -sh /work/ios-backup/00008020-001A2B3C4D5E6F70
18.2G
```

`DeviceName` 为真实姓名，**属个人信息，报告中按需脱敏**，内部材料保留为线索。

第二步，结构判定与解密：

```bash
$ BK=/work/ios-backup/00008020-001A2B3C4D5E6F70
$ plutil -p $BK/Status.plist | grep IsFullBackup
IsFullBackup => 1                     ← 全量备份

$ plutil -p $BK/Info.plist | grep -E 'Last Backup Date|Product Version'
Last Backup Date => 2024-09-01T02:14:33Z
Product Version => 16.6.1
```

第三步，**先建立"备份可得性"清单，再动手提取**。这一步能省下后续返工：

| 数据库 | 备份中是否可见 | 关键表 | 备注 |
|---|---|---|---|
| **短信** `sms.db` | **可见** | `message`、`handle`、`chat` | 日期为 **Cocoa 纪元**，需 `+978307200` |
| **通话记录** `CallHistory.storedata` | **通常可见** | `CallHistory`（`Z` 前缀） | 路径随版本变化，**以实测为准** |
| **通讯录** `AddressBook.sqlitedb` | **可见** | `ABPerson`、`ABMultiValue` | 含"最近联系人" |
| **日历** `Calendar.sqlitedb` | **可见** | `CalendarItem`（`Z` 前缀） | 旧版为 `Calendar.sqlite` |
| `knowledgeC.db`、CoreDuet、完整照片元数据 | **通常不可见** | — | 需越狱设备或物理镜像 |

**这张表决定了每条结论的层级归属。** 不先划边界，很容易在报告里把"备份里没有"写成"设备上没有"。

第四步，通过 `Manifest.db` 定位文件，而不是猜路径：

```bash
$ sqlite3 -header decrypted/Manifest.db "
SELECT fileID FROM Files
WHERE relativePath LIKE '%SMS/sms.db%'
   OR relativePath LIKE '%AddressBook%'
   OR (domain='AppDomain-com.whatsapp' AND relativePath LIKE '%ChatStorage%');"
HomeDomain-Library/SMS/sms.db
HomeDomain-Library/AddressBook/AddressBook.sqlitedb
AppDomain-com.whatsapp-.../Shared/AppGroup/.../ChatStorage.sqlite
```

第五步，恢复并对每个库做完整性验证：

```bash
$ python3 restore_backup.py decrypted /work/restored/
$ for f in sms.db AddressBook.sqlitedb ChatStorage.sqlite; do
    p=$(find /work/restored -name "$f" | head -1)
    [ -z "$p" ] && { echo "=== $f  备份中不存在（需越狱或物理镜像）"; continue; }
    echo "=== $f ($(stat -c %s "$p") bytes)  $(sqlite3 "$p" 'PRAGMA integrity_check;')"
  done
=== sms.db (2516582 bytes) ok
=== AddressBook.sqlitedb (5033164 bytes) ok
=== ChatStorage.sqlite (32715545 bytes) ok
```

`integrity_check` 返回 `ok` 是"文件未被截断、表结构可读"的最低门槛，不是"内容完整"的证明。 备份传输中断同样可能留下结构完整但内容缺失的库。

第六步，Cocoa 时间换算与跨库检索：

```bash
$ sqlite3 -header -column sms.db "
SELECT text, datetime(date/1000 + 978307200,'unixepoch','+8 hours') AS t
FROM message WHERE text LIKE '%明天下午%' OR text LIKE '%老地方%' ORDER BY date;"
```

```text
text                          t
明天下午三点老地方等我          2024-08-30 20:11:07
好的                            2024-08-30 20:12:33
```

```bash
$ sqlite3 -header -column ChatStorage.sqlite "
SELECT ZTEXT, datetime(ZPUSHED + 978307200,'unixepoch','+8 hours') AS t
FROM ZMESSAGE WHERE ZTEXT LIKE '%明天%' OR ZTEXT LIKE '%老地方%' ORDER BY ZPUSHED;"
```

```text
ZTEXT        t
好 明天见     2024-08-30 20:14:02
```

第七步，通话记录同样换算后对齐：

```bash
$ sqlite3 -header -column CallHistory.storedata "
SELECT ZADDRESS, ZDURATION, datetime(ZDATE + 978307200,'unixepoch','+8 hours') AS t
FROM ZCALLRECORDER WHERE ZDURATION > 0 ORDER BY ZDATE DESC LIMIT 5;"
```

```text
ZADDRESS        ZDURATION  t
+8613910000000  42         2024-08-30 20:15:20
```

第八步，固化：

```bash
$ sha256sum $BK/Manifest.db $BK/Info.plist $BK/Status.plist > backup-hashes.txt
$ find /work/restored -type f -exec sha256sum {} \; > restored-hashes.txt
$ wc -l restored-hashes.txt
14273
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 三个数据库均已提取且结构完整 | `integrity_check` 全部 `ok`，14,273 个文件恢复 | 强 |
| 存在会面约定 | 短信 20:11:07 与 WhatsApp 20:14:02 相互印证 | 强（双源） |
| 通话紧随约定之后 | 通话记录 20:15:20，42 秒 | 强（第三源） |
| 三条事件集中在 4 分 13 秒内 | 20:11:07 → 20:15:20 | 强 |
| 备份为全量且时间已知 | `IsFullBackup=1`，`Last Backup Date` 2024-09-01 02:14:33Z | 强 |

**能证明的**：约定内容、三源各自的时间点、以及二者在同一晚间窗口内发生。

**不能证明的**：
- 不能证明两条短信与两条 WhatsApp 消息属于同一组当事人。 号码与会话归属需从 `handle`/`ZWACHATSESSION` 关联，本案未完成该关联
- **不能证明通话的两端是这两名当事人。** `CallHistory` 只有主叫号码，被叫需运营商侧数据
- **不能证明该约定的后续是否履行。** 备份时点之后无数据
- **不能声称已建立完整聊天记录。** 本案仅做 SQL 层查询，未解析 `Z_*` 表完整关系

**未覆盖范围**：Keychain、`knowledgeC.db` 与 CoreDuet、完整照片元数据、`ZWACHATSESSION` 与 `ZWACONTACT` 的联系人关联、2024-09-01 02:14 之后的设备活动。

这一串要原样写进报告的局限性章节。

**误判对照**

其一，漏加 `978307200` 导致时间全部落到 1970 年。

`sms.db` 的 `message.date` 与 WhatsApp 的 `ZPUSHED` 都以 **Cocoa 纪元**（2001-01-01 UTC）计。直接 `datetime(date/1000,'unixepoch')` 会得到 2001 年前后的日期。

判据是**换算后的时间必须落在设备使用年代内**：

| 纪元 | 换算式 | 判据 |
|---|---|---|
| Unix | `date/1000` | 2001 年后的日期 |
| **Cocoa** | **`date/1000 + 978307200`** | 2015–2025 |
| Apple 参考秒 | `date` 直接作为秒 | 与 Cocoa 同 |

最快的自检是"换算后的日期是否落在设备的活跃年代"。若得到 2001 年或 1970 年，说明纪元搞错了。

按错误判据走的代价：三个来源的时间全部错误，但**报告里看不出任何异常**。

每条记录内部仍然是自洽的，只是整体平移了 23 年。委托方拿着错误的日期去核对运营商侧通话记录，全部落空。

其二，把 `datetime(...,'unixepoch','+8 hours')` 的时区参数当成可有可无。

加了 `+8 hours` 与不加，结果相差 8 小时。8 小时足以让"约定在前、通话在后"的顺序颠倒。

判据是**跨源顺序的自洽性检查**：

| 检查 | 本案（+8h） | 不加时区 |
|---|---|---|
| 短信约定 | 20:11:07 | 12:11:07 |
| WhatsApp 应答 | 20:14:02 | 12:14:02 |
| 通话 | 20:15:20 | 12:15:20 |
| 顺序是否自洽 | **是** | 是 |

**本案加不加时区都不影响顺序**，这正是危险之处 —— 顺序自洽无法证明时区正确。真正的判据是**与设备本地时间或第三方记录对齐**：

```bash
# 判据1：备份时间戳用 UTC，而短信库用本地时区，两者必须有明确换算
# 判据2：找一条与现实事件对应的记录验证（如短信提到的日程、运营商侧的通话记录）
# 判据3：与 CallHistory 的 ZDATE 对比，两者若同源则偏移应一致
```

**"顺序正确"不等于"时区正确"。** 三个来源同时用错 8 小时，顺序依然自洽。报告中的时间陈述必须注明时区基准。

按错误判据走的代价：报告给出 20:11 的会面时间，委托方据此调取该时段的相关监控或基站记录，全部为空；而真实的时段就在 8 小时前。

其三，把 `integrity_check` 返回 `ok` 理解为"数据完整"。

`PRAGMA integrity_check` 检查的是 SQLite 页结构与 B-tree 索引的自洽性，不检查业务层面是否丢数据。

判据是**三种"结构完整但内容缺失"的常见情形**：

| 情形 | `integrity_check` | 如何发现 |
|---|---|---|
| 备份传输截断 | 通常报错 | 页数与 `Manifest.db` 记录不符 |
| WAL 未合并 | `ok` | 主库行数与业务预期差距大 |
| 备份本身不含该表数据 | `ok` | 表存在但行数为 0 |

必须把恢复文件数与 `Manifest.db` 的记录数对账：

```bash
$ sqlite3 decrypted/Manifest.db "SELECT COUNT(*) FROM Files WHERE flags=1;"
14273
$ wc -l restored-hashes.txt
14273
$ sqlite3 sms.db "SELECT COUNT(*) FROM message;"
9812
```

三方对账才能确认"该备份里该有的都在"。单看 `integrity_check` 返回 `ok`，无法区分"数据完整"与"数据本来就是空的"。

按错误判据走的代价：报告称"短信库已完整提取"，而实际主库 9812 行、WAL 中还有未合并的记录，委托方以为证据齐全并据此下结论。

**其四，把三个来源的时间线当成三次独立印证。**

短信、WhatsApp、通话记录看起来是三个独立来源。但若它们**描述的是同一次交互的三个侧面**，那么"三源印证"实际只有一个事件源。

判据是**来源独立性要看写入方，而不是看文件**：

| 来源 | 写入方 | 是否独立 |
|---|---|---|
| `sms.db` | 系统 `Messages` 服务 | 独立于 WhatsApp |
| `ChatStorage.sqlite` | WhatsApp 应用自身 | **独立于** `sms.db` |
| `CallHistory.storedata` | 系统电话服务 | 独立于前两者 |
| `AddressBook.sqlitedb` 的"最近联系人" | **由上述交互派生** | **不独立** |

`ABMultiValue` 中的最近联系人列表是从通话与消息派生出来的，把它当第四个印证源会重复计数。

按错误判据走的代价：报告写"四个独立来源印证"，委托方据此认为证据链极强；而实际上只有三个来源，且三者可能都由同一个前置事件触发。

**其五，把"备份里没有"写成"设备上没有"。**

本案 `knowledgeC.db` 与 CoreDuet 在普通备份中不可见。这只说明**该层级取不到**，不代表数据不存在。

判据是**iOS 数据的三层来源**：

| 层级 | 获取方式 | 本案状态 |
|---|---|---|
| 逻辑层（加密备份） | `idevicebackup2` + 口令 | **已获取** |
| 文件系统层 | 越狱设备或物理镜像 | **未获取** |
| 硬件层 | 芯片级提取 | 未获取 |

**三层能回答的问题范围不同**：

| 数据类型 | 逻辑层可得 |
|---|---|
| 短信、通话、通讯录、日历 | 是 |
| 应用沙盒（部分） | 是 |
| 系统智能（`knowledgeC.db`） | **否** |
| 已删除文件残留 | **否** |
| Keychain | **仅部分** |

正确表述是"在加密备份范围内未检出该记录"；错误表述是"设备上不存在该记录"。后者一旦被委托方引用为否定性依据，方向性错误无法挽回。

按错误判据走的代价：委托方据此向对方主张"你设备上没有这条记录"，对方出示一张从其他渠道获得的截图，报告可信度整体崩塌，且已发出的主张难以收回。

<a id="section-36"></a>

### 5.2 ChatStorage Core Data 的关系映射与会话归属还原

**场景**

承接 5.1。委托方追问：在 WhatsApp 的 31 MB `ChatStorage.sqlite` 中，那条 20:14:02 的"好 明天见"属于**哪个会话**、与**哪个联系人**，以及在 8-30 之前有没有更早的同类约定。

5.1 中只做了关键词检索，没有做关系关联。

"有一条消息"和"这条消息属于谁"是两个层次的结论，而后者才能对接委托方提供的人员名单。

**处置过程**

第一步，先摸清 Core Data 的表结构，避免按普通 SQLite 的习惯去找外键：

```bash
$ sqlite3 ChatStorage.sqlite ".tables" | tr ' ' '\
' | grep -E '^Z' | head -12
Z_ENT
Z_METADATA
Z_PRIMARYKEY
ZWACHATSESSION
ZWACONTACT
ZWAMEDIAITEM
ZWAMESSAGE
ZWAChatmessage
ZWAChatsession
```

Core Data 会为同一实体生成大小写不同的多套表，并用 `Z_PRIMARYKEY`、`Z_METADATA` 等元数据表描述实体与主键映射。

关系靠列名约定表达，没有 `FOREIGN KEY` 约束。

第二步，确认实体映射与主键列：

```bash
$ sqlite3 -header -column ChatStorage.sqlite "SELECT Z_NAME, Z_SUPER FROM Z_ENT ORDER BY Z_NAME;"
Z_NAME         Z_SUPER
ZWACHATSESSION
ZWACONTACT
ZWAMESSAGE      ZWACHATSESSION

$ sqlite3 -header -column ChatStorage.sqlite "
SELECT Z_PK, Z_ENT, Z_NAME FROM Z_PRIMARYKEY ORDER BY Z_ENT;"
Z_PK  Z_ENT  Z_NAME
1     1      ZWACHATSESSION
2     2      ZWAMESSAGE
3     3      ZWACONTACT
```

`ZWAMESSAGE.Z_ENT = 2`，`ZWACHATSESSION.Z_ENT = 1`。

第三步，定位目标消息并取出其所属会话的指针：

```bash
$ sqlite3 -header -column ChatStorage.sqlite "
SELECT Z_PK, Z_ENT, Z_CHATSESSION, ZPUSHED, ZTEXT, ZSTATE
FROM ZWAMESSAGE
WHERE ZTEXT LIKE '%明天见%' ORDER BY ZPUSHED;"
```

```text
Z_PK    Z_ENT  Z_CHATSESSION  ZPUSHED      ZTEXT     ZSTATE
9044122  2      3318           736231142   好 明天见  0
```

`Z_CHATSESSION = 3318` 是一个指针，必须再跳一次表才能拿到会话实体。

第四步，跳到会话实体并取其标识字段：

```bash
$ sqlite3 -header -column ChatStorage.sqlite "
SELECT Z_PK, Z_IDENTIFIER, Z_DISPLAYNAME, ZPARTNERNUMBER, ZCHATMESSAGECOUNT
FROM ZWACHATSESSION WHERE Z_PK = 3318;"
```

```text
Z_PK  Z_IDENTIFIER                              Z_DISPLAYNAME  ZPARTNERNUMBER  ZCHATMESSAGECOUNT
3318  9f3a2b7c-4d51-4e88-a1c6-77b20e4f9d10     王某          +8613910000000   412
```

`Z_IDENTIFIER` 才是稳定标识，`Z_PK` 是本地自增值。

第五步，把时间与方向字段一次性取全并交叉核对：

```bash
$ sqlite3 -header -column ChatStorage.sqlite "
SELECT Z_PK,
       datetime(ZPUSHED + 978307200,'unixepoch','+8 hours')        AS pushed_cst,
       datetime(ZMESSAGE.receivedDate + 978307200,'unixepoch','+8 hours') AS recv_cst,
       ZMESSAGETYPE, ZFROMJID, ZTOJID, Z_ISFROMME
FROM ZWAMESSAGE
WHERE Z_PK = 9044122;"
```

```text
Z_PK    pushed_cst            recv_cst             ZMESSAGETYPE  ZFROMJID           ZTOJID             Z_ISFROMME
9044122 2024-08-30 20:14:02   2024-08-30 20:14:03  0             +8613910000000@c.us  8613910000000@c.us  0
```

各字段用途不同：

| 字段 | 含义 | 本案值 |
|---|---|---|
| `ZPUSHED` | 服务端推送时间 | 20:14:02 |
| `receivedDate` | 本机接收时间 | 20:14:03 |
| `ZMESSAGETYPE` | 0=文本，1=图片等 | 0 |
| `Z_ISFROMME` | 0=对方发出 | 0 |

`Z_ISFROMME = 0`、`ZFROMJID` 是对方号码、`ZTOJID` 是本机号码，三者互洽 —— 方向认定成立。

第六步，把该会话在 8-30 之前的消息全部列出，判断是否存在更早的同类约定：

```bash
$ sqlite3 -header -column ChatStorage.sqlite "
SELECT datetime(ZPUSHED + 978307200,'unixepoch','+8 hours') AS t, Z_ISFROMME, ZTEXT
FROM ZWAMESSAGE
WHERE Z_CHATSESSION = 3318
  AND ZPUSHED + 978307200 < strftime('%s','2024-08-30 00:00:00','-8 hours','utc')
ORDER BY ZPUSHED DESC LIMIT 5;"
```

```text
t                  Z_ISFROMME  ZTEXT
2024-08-30 20:14:02 0         好 明天见
2024-08-28 21:05:47 0         有 明天下午可以
2024-08-28 21:02:14 1         明天下午你有空吗
```

**8-28 已有一次同类确认**，说明这不是一次性约定。

第七步，与短信库做跨源对照，确认是同一约定而非两次独立约定：

```bash
$ sqlite3 -header -column sms.db "
SELECT datetime(date/1000 + 978307200,'unixepoch','+8 hours') AS t, address, text
FROM message WHERE text LIKE '%老地方%' ORDER BY date;"
```

```text
t                   address          text
2024-08-30 20:11:07  +8613910000000  明天下午三点老地方等我
```

号码 `+8613910000000` 与 `ZWACHATSESSION.ZPARTNERNUMBER` 及 `ZTOJID` 一致。

第八步，固化：

```bash
$ sha256sum ChatStorage.sqlite > chatstorage.sha256
$ sqlite3 ChatStorage.sqlite "SELECT COUNT(*) FROM ZWAMESSAGE;"
14862
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 目标消息属会话 `3318`，对方为 `+8613910000000` | `Z_CHATSESSION` → `ZWACHATSESSION` 两跳关联 | 强 |
| 该会话稳定标识为 `9f3a2b7c-...-77b20e4f9d10` | `Z_IDENTIFIER` | 强 |
| 消息方向为对方发出 | `Z_ISFROMME=0` + `ZFROMJID`/`ZTOJID` 互洽 | 强 |
| 推送与接收时间相差 1 秒 | `ZPUSHED` 与 `receivedDate` | 强 |
| 8-28 已存在同类约定 | 该会话内两条更早消息 | 强 |
| 8-30 的约定在短信与 WhatsApp 两处成立 | 号码一致 + 内容语义一致 | 中（两处表述不同，非逐字一致） |

**能证明的**：消息的会话归属、对话方、方向、以及更早的同类约定存在。

**不能证明的**：
- 不能证明 `Z_IDENTIFIER` 对应的是特定自然人。 该 UUID 是本地生成，号码可被回收或转移
- 不能证明 `Z_ISFROMME=0` 的消息确由该号码本人在当时发送。 号码可能不在本人手中
- **不能证明消息未被编辑或转发。** Core Data 不保留原始传输层信息
- **不能证明短信与 WhatsApp 是同一人所发。** 号码一致但短信可能来自另一终端

**未覆盖范围**：`ZWAMEDIAITEM` 的附件路径与原始文件、`ZWAChatmessage` 与 `ZWAMESSAGE` 两套表的差异、消息的已读回执、以及该会话早于 8-28 的历史。

**误判对照**

其一，按普通 SQLite 的外键习惯去找关联表。

Core Data 没有 `FOREIGN KEY` 约束。如果按 `PRAGMA foreign_key_list` 的思路去找关联，必然一无所获。

判据是**Core Data 的关系表达方式**：

| 普通 SQLite | Core Data |
|---|---|
| `FOREIGN KEY (a) REFERENCES t(b)` | 列名约定：`Z_CHATSESSION` → `ZWACHATSESSION.Z_PK` |
| 声明式约束 | **无约束，靠约定** |
| 关联列名自由 | **关系列名以 `Z` 开头并等于目标实体名** |

`ZWAMESSAGE.Z_CHATSESSION` → 目标实体是 `ZWACHATSESSION`，指向它的 `Z_PK`。**这层映射必须由分析方自己完成。**

按错误判据走的代价：报告写"该消息未关联到具体会话"，委托方无法确认对话方，整条证据链在归属环节断掉。

**其二，把 `Z_PK` 当成稳定的会话标识。**

`Z_PK` 是本地自增主键，删库重建、导入恢复、跨设备迁移都会改变它。

判据是**两个字段的稳定性对比**：

| 字段 | 生成方式 | 稳定性 |
|---|---|---|
| `Z_PK` | 本地自增 | **不稳定**，重建后变化 |
| `Z_IDENTIFIER` | UUID，恢复时保留 | 相对稳定 |

报告里对外引用会话，必须用 `Z_IDENTIFIER`。 若只有 `Z_PK`，则必须注明"该标识仅在本设备本次备份内有效"。本案 `3318` 与 `9f3a2b7c-...` 一一对应，但引用时应用后者。

按错误判据走的代价：委托方拿 `Z_PK=3318` 去比对另一份备份的同一会话，发现数值不同，误认为是两个不同会话，从而得出"存在两个联系人"的错误结论。

**其三，用 `ZPUSHED` 单独作为消息时间。**

Core Data 里有多个时间字段，语义各不相同。

判据是**三个时间字段的差别**：

| 字段 | 含义 | 可用性 |
|---|---|---|
| `ZPUSHED` | 服务端推送时刻 | **首选** |
| `receivedDate` | 本机接收时刻 | 辅助 |
| `ZCREATEDDATE` | 消息创建时刻（**发件端本地时间**） | 辅助 |

`ZCREATEDDATE` 记录的是发送方设备上的本地时间，跨时区时与 `ZPUSHED` 可差数小时。

本案 `ZPUSHED=20:14:02`、`receivedDate=20:14:03`，差 1 秒，属正常网络延迟。

**判据是三个时间的差值应与网络延迟同量级**。

若 `ZCREATEDDATE` 与 `ZPUSHED` 差 8 小时，说明发送方在另一个时区——这是**有价值的发现**，但不能把 `ZCREATEDDATE` 直接当事件时间。

按错误判据走的代价：报告用一个跨时区的时间戳作为事件时间，与运营商侧记录比对时出现整点级偏差，被误判为"时间不可信"。

其四，把 `Z_ISFROMME=0` 直接解读为"消息是对方发的"。

`Z_ISFROMME` 只表示**在本机视角下是否为发出方**。它不校验实际发送者。

判据是**方向认定的三个字段必须互洽**：

| 检查 | 含义 |
|---|---|
| `Z_ISFROMME` | 本机视角 |
| `ZFROMJID` | JID 形式的发送方 |
| `ZTOJID` | JID 形式的接收方 |

| `Z_ISFROMME` | 预期 `ZFROMJID` | 预期 `ZTOJID` |
|---|---|---|
| 0（对方发） | 对方号码@c.us | 本机号码@c.us |
| 1（本机发） | 本机号码@c.us | 对方号码@c.us |

本案三者互洽，方向结论成立。但这只证明"数据库记录的收发关系如此"，不证明实际操作者身份 —— 号码不在本人手中的情形无法从库内排除。

按错误判据走的代价：报告认定"王某在 8-30 20:14 发出该消息"，而实际号码可能已停用或被他人使用。身份类结论需要外部佐证。

其五，把 `Z_*` 表与 `ZW*` 表当成两组不同数据。

Core Data 在某些配置下会为同一实体保留多套列名不同的表，**内容可能重复也可能只更新其中一套**。

判据是**三处行数必须交叉核对**：

```bash
$ sqlite3 ChatStorage.sqlite "
SELECT (SELECT COUNT(*) FROM ZWAMESSAGE),
       (SELECT COUNT(*) FROM ZWAChatmessage),
       (SELECT COUNT(*) FROM ZWACHATSESSION),
       (SELECT COUNT(*) FROM ZWAChatsession);"
```

```text
14862  0  211  0
```

**注意后两组为 0**：说明本案配置下只有一套表生效。

**但这必须在每个库上实测，不能假定。** 若两套表行数都非零且不等，必须确认哪一套是当前生效的，再决定以哪套为准。

按错误判据走的代价：把两套表当作两个不同会话的数据，消息数量翻倍，同一条约定被统计成两次，报告的计数结论错误。

<a id="section-37"></a>

### 5.3 备份层级缺失的阴性结论限定与增量备份链核对

**场景**

另一起委托。委托方提供一份 iPad 的备份目录 `DigiForensics-tablet.vc`，要求查明 2024 年 7 月一批照片"是否曾经通过 AirDrop 分享给特定设备"。

同时要核实委托方的说法："备份里没有该记录，所以设备上没有。"

委托方已经自己翻过备份目录，没找到相关痕迹，因此认为结论可以写成"未发现分享记录"。

这一案的价值在于：一份阴性结论要成立，必须先说清"备份是哪一层、什么结构、覆盖到哪个时点"，否则它否定的东西比委托方以为的多得多。

**处置过程**

第一步，先判定备份类型 —— **全量与增量能回答的问题完全不同**：

```bash
$ BK=/work/case/DigiForensics-tablet.vc/00008110-000A4B5C6D7E8F90
$ plutil -p $BK/Status.plist | grep -E 'IsFullBackup|Version'
IsFullBackup => 0
Version => 3.3
$ plutil -p $BK/Info.plist | grep -E 'Last Backup Date|Product Version'
Last Backup Date => 2024-08-14T09:41:02Z
Product Version => 17.1
```

`IsFullBackup = 0` → 这是增量备份。 增量备份只包含自上个节点以来变更过的文件，**未变更的文件不在本次目录中，但在上次的目录里**。

第二步，核对备份链是否完整 —— **链断一环，全部文件的时序就不可信**：

```bash
$ python3 manifest_chain.py $BK
00008110-000A4B5C6D7E8F90  2024-08-14T09:41:02Z  IsFullBackup=0
  └─ 00008110-000A4B5C6D7E8F90  2024-08-02T07:15:33Z  IsFullBackup=0
      └─ 00008110-000A4B5C6D7E8F90  2024-07-19T22:03:11Z  IsFullBackup=0
          └─ 00008110-000A4B5C6D7E8F90  2024-07-06T18:30:55Z  IsFullBackup=1  ← 全量基线
```

**链是完整的**，四个节点，最底层是全量基线 2024-07-06。这意味着"2024-07-06 之后的所有变更"在理论上是可组合还原的。

第三步，**按委托问题的时间点定位应在哪个备份节点中查找**：

```bash
# 委托问题指向 2024 年 7 月中旬 → 对应节点 2024-07-19
$ python3 locate_file.py $BK 2024-07-19
AppDomain-com.apple.mobilesafari/.../ImageExportSession.sqlitedb
$ sqlite3 -header restored/ImageExportSession.sqlitedb "
SELECT datetime(ZDATE+978307200,'unixepoch','+8 hours') AS t, ZPATH
FROM ZASSETSESSION WHERE ZDATE > 0 ORDER BY ZDATE;"
```

```text
t                   ZPATH
2024-07-18 16:22:41  /var/mobile/Media/DCIM/100APPLE/IMG_4821.HEIC
2024-07-18 16:22:44  /var/mobile/Media/DCIM/100APPLE/IMG_4822.HEIC
```

**该备份节点确实包含 7 月中旬的照片记录。** 若委托方只翻了最新那个增量目录，就会看不到这些。

第四步，查 AirDrop 相关痕迹 —— 先明确"AirDrop 分享"会留下哪些痕迹，哪些不会：

| 痕迹位置 | 是否在备份内 | 说明 |
|---|---|---|
| `ImageExportSession.sqlitedb` | 是 | 系统分享会话记录 |
| `ZASSETSESSION.ZSHAREID` | 是 | 分享会话标识 |
| 蓝牙配对记录 | 通常是 | 系统配对数据库 |
| **AirDrop 传输的对端设备标识** | **可能不含明文** | 走 APFS 与蓝牙，不一定落盘 |
| 目标设备的接收记录 | **否** | **在对端设备上** |

第五步，列出该表内全部分享记录并核对文件哈希：

```bash
$ sqlite3 -header restored/ImageExportSession.sqlitedb "
SELECT datetime(ZDATE+978307200,'unixepoch','+8 hours') AS t, ZSHAREID, ZFILESIZE
FROM ZASSETSESSION WHERE ZSHAREID IS NOT NULL AND ZSHAREID <> '' ORDER BY ZDATE;"
```

```text
t                   ZSHAREID                              ZFILESIZE
2024-06-28 10:14:22  9C4E7A20-3B1F-4C88-9E05-71D2A6B3F814  2841934
2024-07-21 19:33:08  5D8F2C31-7A64-4B19-8C72-03E9D1F6A2B7  5120440
```

7 月中旬（7-18）无分享记录，7-21 有一条，6-28 有一条。

```bash
$ python3 hash_match.py IMG_4801.HEIC IMG_4802.HEIC sha256sums.txt
IMG_4801.HEIC  9c4e7a20…f814   2841934 bytes  ← 与 6-28 的分享记录对应
IMG_4802.HEIC  5d8f2c31…a2b7   5120440 bytes  ← 与 7-21 的分享记录对应
```

第六步，把阴性结论的范围钉死：

```bash
$ sqlite3 restored/ImageExportSession.sqlitedb \
  "SELECT COUNT(*) FROM ZASSETSESSION
   WHERE ZDATE+978307200 BETWEEN strftime('%s','2024-07-10','utc')
                             AND strftime('%s','2024-07-19','utc');"
0
```

```text
未覆盖：
- 2024-07-06 18:30:55（全量基线）之前的活动，备份链未覆盖
- AirDrop 对端设备标识：经蓝牙与 APFS 传输，部分中间件标识不落盘
- 目标设备侧的接收记录（不在本检材内）
- ZASSETSESSION 表以外的分享渠道（如"共享"菜单的其他路径）
- ZDATE 为 0 或负值的记录（本表存在此类数据，见误判对照）
- Manifest.db 记录数与实际恢复数的逐节点对账（见误判对照）
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 备份链完整，含 4 个节点 | `manifest_chain.py` 逐层解析 | 强 |
| 2024-07-06 为全量基线 | 最底层 `IsFullBackup=1` | 强 |
| 2024-07-10 至 07-19 窗口内无分享记录 | 该窗口 `ZASSETSESSION` 计数 0 | 强（限于该表） |
| 7 月中旬的照片记录存在于 7-19 节点 | `ZASSETSESSION` 有 7-18 两条 | 强 |
| 存在 6-28 与 7-21 两条分享记录，文件哈希对应 | `ZSHAREID` + 字节数一致 | 中（哈希前缀比对，非完整比对） |
| 委托方"备份里没有所以设备上没有"的推论不成立 | 备份仅覆盖 7-06 之后，且 AirDrop 部分标识不落盘 | 强（否证结论） |

**阴性结论（严格限定）**：

> 在**逻辑备份层**、`ImageExportSession.sqlitedb` 的 `ZASSETSESSION` 表内、2024-07-06 18:30:55 至 2024-08-14 09:41:02 的备份链覆盖范围中，未发现 2024-07-18 当日存在照片分享会话的记录。
>
> 该阴性结论**不支持"设备上从未发生该次分享"**：AirDrop 的对端设备标识与部分传输中间件信息不落盘至备份范围，目标设备侧的接收记录不在本检材内，且 `ZASSETSESSION` 之外的分享路径未检查。

**能证明的**：备份链的结构与时间覆盖、`ZASSETSESSION` 表内的分享记录分布、以及委托方前提推论的不成立。

**不能证明的**：
- **不能证明该次分享未发生。** 只能证明该表该时段无记录
- **不能证明 2024-07-06 之前的活动情况。** 备份链未覆盖
- **不能证明分享的对端设备身份。** `ZSHAREID` 是本地会话 UUID，不含对端设备标识
- **不能证明备份链本身未被篡改。** `BackupKey` 的完整性校验本次未做

**未覆盖范围**：备份基线之前的历史、目标设备侧数据、蓝牙与 APFS 层的传输痕迹、非 `ZASSETSESSION` 的分享渠道、`ZDATE<=0` 的记录、以及 `BackupKey` 完整性验证。

**误判对照**

其一，把"最新一个增量备份目录里没有"当成"整个备份里没有"。

委托方只翻了 8-14 那一个目录。增量备份的语义决定了它只含 7-02 到 8-14 之间的变更，7 月中旬的记录虽然不在这个目录里，却在 7-19 的节点里。

判据是**增量备份的组成**：

| 备份类型 | `IsFullBackup` | 目录内容 |
|---|---|---|
| 全量 | 1 | 设备上全部可备份文件 |
| 增量 | 0 | **仅自上个节点以来的变更文件** |

判据是必须先把备份链走完，再决定"查不到"意味着什么：

```bash
$ python3 manifest_chain.py $BK | tail -2
00008110-…  2024-07-19T22:03:11Z  IsFullBackup=0
00008110-…  2024-07-06T18:30:55Z  IsFullBackup=1   ← 组合边界
```

按错误判据走的代价：分析方与委托方同时认定"该记录不存在"，双方在后续沟通中都基于这个前提，方向性错误难以在中途纠正。

**其二，把"备份里没有"写成"设备上没有"。**

委托方的原话就是这句。这个推论有三处断裂。

判据是**从备份层到设备层的落差清单**：

| 断裂点 | 说明 |
|---|---|
| 时间落差 | 备份只反映备份时刻状态，之后的删除不可见 |
| 层级落差 | AirDrop 传输标识等不落盘至备份范围 |
| 方向落差 | 接收侧记录在**对端设备**上，不在本检材内 |

**特别要强调方向落差**：AirDrop 的"分享"是双向动作，本设备上可能只留发送痕迹或连发送痕迹都不留，而接收痕迹在对端。**只查发送侧就下"未分享"的结论，逻辑上不成立。**

按错误判据走的代价：报告写"未发现分享记录"，委托方据此向对方主张"你的设备没分享过这批照片"，对方出示接收方的接收截图，报告可信度崩塌。

**其三，把"备份链完整"理解为"所有文件都在"。**

链完整只保证**可以组合还原**，不保证**没有文件缺失**。

判据是**文件级对账**：

```bash
$ sqlite3 decrypted/Manifest.db "SELECT COUNT(*) FROM Files WHERE flags=1;"
28417
$ find restored -type f | wc -l
28390
$ python3 missing_files.py decrypted/Manifest.db restored
00008110-…/Library/SMS/sms.db          ← 缺失
00008110-…/Library/Keyboard/text.ttf   ← 缺失
```

**逐节点对账才有效**。本案存在缺失文件，其中包含 `sms.db` —— 这直接削弱了"短信类证据不存在"的阴性结论强度。

**链完整与文件齐备是两件事**：链完整说的是"节点间的时间与哈希关系没断"，文件齐备说的是"每个节点该有的文件都在"。两者必须分别验证。

按错误判据走的代价：以"备份链完整"为前提写出全部数据的阴性结论，而实际上 `sms.db` 在恢复中缺失，报告据此否定"短信记录不存在"的结论无效。

其四，把 `ZSHAREID` 当成对端设备标识。

`ZSHAREID` 形如 `9C4E7A20-3B1F-4C88-9E05-71D2A6B3F814`，看起来是设备标识，实际是**本地生成的分享会话 UUID**。

判据是**该表是否含设备标识类字段**：

```bash
$ sqlite3 restored/ImageExportSession.sqlitedb "PRAGMA table_info(ZASSETSESSION);" \
    | grep -iE 'device|remote|peer'
# 无命中
```

无命中即说明**表内不存在对端设备信息**。**判据是查字段列表，而不是看值像不像标识。**

按错误判据走的代价：报告把 UUID 当成"对方设备 ID"提交给委托方用于跨设备比对，比对无果，且该 UUID 在其他备份中并不相同。

**其五，忽略 `ZDATE = 0` 的记录。**

`ZASSETSESSION` 中存在 `ZDATE` 为 0 或负值的行。直接用 `datetime(ZDATE+978307200,'unixepoch')` 会得到 1970 年或负年份，这类记录在做时间窗口过滤时会被静默丢弃。

判据是**过滤前先统计异常值的数量**：

```bash
$ sqlite3 restored/ImageExportSession.sqlitedb "
SELECT SUM(ZDATE<=0) AS zero_or_neg, COUNT(*) AS total FROM ZASSETSESSION;"
zero_or_neg  total
37           2846
```

**37 条零值记录占总数的 1.3%**，不可忽略。需确认成因：

```bash
$ sqlite3 restored/ImageExportSession.sqlitedb "
SELECT Z_PK, ZDATE, ZSHAREID, ZPATH FROM ZASSETSESSION WHERE ZDATE<=0 LIMIT 3;"
```

零值通常表示**该分享会话尚未完成或已被清理**，其 `ZPATH` 仍可能指向有意义的文件。**这些记录不能因为时间无效就整体排除**，应单独列为"时间不可判定的分享记录"。

按错误判据走的代价：按时间窗口过滤时这 37 条被排除，报告写"该时段无分享记录"，而实际上其中可能正包含目标记录 —— **一条被过滤掉的阴性结论，等于没有查过。**

**其六，把阴性结论写成"未发现异常"。**

错误写法：

> 经分析，该设备未发现 2024 年 7 月的照片外发记录。

正确写法（限定范围 + 列出未覆盖）：

> 在逻辑备份层、`ImageExportSession.sqlitedb` 的 `ZASSETSESSION` 表内、2024-07-06 18:30:55 至 2024-08-14 09:41:02 的备份链覆盖范围内，未发现 2024-07-18 当日存在分享会话的记录。该结论不支持"设备上未发生该次分享"：AirDrop 对端标识与部分传输中间件信息不落盘至备份范围，接收侧记录不在本检材内。未覆盖路径：备份基线之前的活动、目标设备侧数据、蓝牙与 APFS 层传输痕迹、其他分享渠道、`ZDATE<=0` 的 37 条记录、逐节点文件对账、以及 `BackupKey` 完整性验证。

**判据是三要素缺一不可**：检查范围、检查方法、未覆盖项。"未发现外发记录"这个表述会让读者以为已排除外发行为，而实际上接收侧与传输层都未查。

按错误判据走的代价：委托方把"未发现外发记录"理解为"照片没有外流"，据此做出不利的公开处理决定，而实际上目标接收方手上的照片证据并未被排除。

---
<a id="section-38"></a>

## 六、扩展阅读方向

本篇讲的是"从备份层拿到数据"。往下走会遇到四类问题：数据在备份里但读不懂、口令拿不到、设备层还有别的东西、iOS 与 macOS 的证据互相重叠。下面几组文章分别对应这四类。

**读懂备份里拿到的文件**

- [SQLite 基础与结构](../mobile-database/mobile-database-sqlite.md) —— `Manifest.db` 本身就是 SQLite，而 `sms.db`、Safari 历史、WhatsApp 消息库也都是。先读这篇，再读本篇的第 4–5 步，效率完全不同。
- [SQLite WAL 取证](../mobile-database/mobile-database-sqlite-wal.md) —— 备份里的库是否带 `-wal`，以及带与不带对数据完整性的影响。
- [时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md) —— Apple 生态里 Cocoa 时间（基准 2001-01-01）非常常见，漏掉 `978307200` 这个换算会让整条时间线偏 31 年。本篇 4.3 与陷阱 4.3 讲的是这个问题在 iOS 上的具体形态。
- [Keychain 与 Safari 痕迹](../../computer/computer-security/computer-security-keychain-safari.md) —— Safari 历史数据库、书签、下载记录的解析思路，以及 Keybag 的解密路径。备份里能拿到部分 Safari 数据，完整的历史与 Keychain 要从设备层走。

**结构底层：备份之下的文件系统**

- [APFS 容器与快照](../../filesystem/filesystem-apple-fs/filesystem-apple-fs-apfs.md) —— **iOS 与 macOS 共用的底层结构**。快照机制意味着"某文件的旧版本"在磁盘上可能仍可恢复，而备份层完全看不到这一层。
- [iOS 系统痕迹与 DFU 恢复](mobile-ios-dfu.md) —— 备份层拿不到时的另一条路，以及它的风险与适用条件。
- [FSEvents 与时间机器](../../computer/computer-log-persistence/computer-log-persistence-fsevents.md) —— macOS 侧的文件变动记录。它与 iOS 备份时间戳交叉，能把"某文件在被备份前的变动史"补出来。

**跨端与云端：同一账号的其他落点**

- [plist 与偏好设置](../../computer/computer-plist-spotlight/computer-plist-spotlight-plist.md) —— 本篇 `Info.plist` / `Status.plist` / `Manifest.plist` 的通用知识。二进制 plist 与 NSKeyedArchiver 的解析方法都在这里展开。
- [Quarantine 与 Gatekeeper](../../computer/computer-security/computer-security-quarantine-gatekeeper.md) —— macOS 侧的下载来源记录。它能佐证 iOS 备份里看到的应用是从哪来的。
- [Spotlight 索引与元数据](../../computer/computer-plist-spotlight/computer-plist-spotlight-spotlight.md) —— 元数据索引本身就是高价值证据，与 iOS 的 `Manifest.db` 是同一类东西的两面。

**边界与规范**

- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md) —— iCloud 调取、备份口令获取的法律程序与授权要求。委托方不知道口令时的正确处理路径，这一篇给的是边界。
- [证据保管链与委托证明](../../fundamentals/fundamentals-chain/fundamentals-chain-chain-of-custody-and-authorization.md) —— 18 GB 备份的哈希固定与交接记录要求。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— "备份不改变设备状态"这个优势为什么必须在报告里写明。
<a id="section-39"></a>

## 七、命令速查

```bash
# ===== 环境 =====
sudo apt install libimobiledevice-utils usbmuxd ifuse libplist-utils
sudo usbmuxd &                        # ★ 不跑会报 no device found
idevice_id -l

# ===== 设备识别（提取前必做）=====
ideviceinfo > device-info.txt
grep -E 'UniqueDeviceID|ProductType|ProductVersion|DeviceName' device-info.txt
sha256sum device-info.txt

# ===== 备份（交互式输入口令，不写命令行）=====
mkdir -p /work/ios-backup
idevicebackup2 -i backup /work/ios-backup/ 2>&1 | tee backup.log
BK=/work/ios-backup/00008020-001A2B3C4D5E6F70

# ===== 结构分析 =====
plutil -p $BK/Info.plist       # 设备名/型号/版本/上次备份时间/应用列表
plutil -p $BK/Status.plist     # IsFullBackup
plutil -p $BK/Manifest.plist   # ManifestKey / ITER / WasPasscodeSet

# ===== 查询 Manifest.db（未加密或已解密后）=====
sqlite3 $BK/Manifest.db "PRAGMA integrity_check;"
sqlite3 $BK/Manifest.db "
SELECT domain, COUNT(*) n FROM Files WHERE flags=1 GROUP BY domain ORDER BY n DESC;"
sqlite3 -header $BK/Manifest.db "
SELECT fileID, relativePath FROM Files WHERE relativePath LIKE '%sms.db%';"

# ===== 取文件元数据（未加密备份：读磁盘上的 per-file Info.plist）=====
HASH=3d0d7e5fb2ce288813306e4d4636395e047a3d28
plutil -p $BK/${HASH:0:2}/$HASH.plist    # Hash / LastModified / Size / RelativePath
# 加密备份：file 是 NSKeyedArchiver 归档，需用归档解析器

# ===== 磁盘路径 = fileID 的 SHA-1（前 2 字符为子目录）=====
echo -n "HomeDomain-Library/SMS/sms.db" | sha1sum
cp $BK/3d/3d0d7e5fb2ce288813306e4d4636395e047a3d28 ./sms.db
sha1sum sms.db                 # 与 per-file Info.plist 的 Hash 一致 ✓

# ===== 解包为目录树（增量备份会有缺失，属正常）=====
python3 restore_backup.py $BK /work/restored/
find /work/restored -type f | wc -l

# ===== 数据库验证 =====
sqlite3 sms.db "PRAGMA integrity_check;" && sqlite3 sms.db ".tables"
# ★ 检查同目录是否有 -wal / -shm 配套文件

# ===== Cocoa 时间换算（iOS 数据库通用）=====
# 978307200 = 2001-01-01 00:00:00 UTC 的 Unix 秒
sqlite3 -header -column sms.db "
SELECT text, datetime(date/1000 + 978307200,'unixepoch','+8 hours') AS t
FROM message WHERE text LIKE '%关键词%' ORDER BY date;"

# ===== AFC（只能访问媒体与部分文档）=====
afcclient ls /DCIM/100APPLE
mkdir -p /mnt/ios-afc && ifuse /mnt/ios-afc && ls /mnt/ios-afc
fusermount -u /mnt/ios-afc        # ★ 用完显式卸载

# ===== 固化 =====
sha256sum $BK/Manifest.db $BK/Info.plist $BK/Status.plist
find /work/restored -type f -exec sha256sum {} \; > restored-hashes.txt
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 移动与数据库取证 — iOS 备份与沙盒提取」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《iOS 备份与沙盒提取》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.vc` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
