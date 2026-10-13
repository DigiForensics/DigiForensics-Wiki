---
title: "Android 数据存储总览"
slug: "mobile-android-android-data-storage-overview"
canonical: "https://www.digiforensics.cn/wiki/mobile-android-android-data-storage-overview"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:50+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "mobile"
space: "移动取证"
node_path: ["Android"]
---

# Android 数据存储总览

<a id="section-1"></a>

## 一、概述

Android 取证最难的不是"读不出来"。

是读出来的那一份数据，到底代表哪个时刻的设备状态。

手机几乎从不关机。`userdata` 是全盘加密的，没有密钥就是一整片随机字节。`/data/data/` 上还压着 SELinux，不是 root 就进不去。更麻烦的是，一台设备上可能同时跑着机主、工作资料、访客三套彼此隔离的数据。

真正把人带偏的失败模式，是**读到了一部分，然后以为读全了**。

设备锁着的时候，`adb shell ls /data/data/` 不报错，只是给回一份很短的包名列表。这份输出和"设备上只装过这几个应用"在终端上根本分不出来。案件于是沿着"该设备使用痕迹很少"走下去，真正的证据一次都没碰到。

所以本篇要解决的就一件事：**动手之前先把结论边界划出来**。

它在流程里的位置是采集环节的前置判定层。不产出证据材料，只决定后面能不能产出证据。

上游是镜像到底是块设备还是逻辑提取、`ro.crypto.*` 属性读不读得到；下游是应用数据提取（[第 4 步](#section-12)）、即时通讯数据定位（见 [即时通讯取证](mobile-android-instant-messaging-forensics.md)）和结论表述（见 [4.4 结论表述](#section-28)）。

**涉及的证据形态**（具体到路径与结构，不是"日志文件"这种大类）：

| 形态 | 具体位置 | 结构特征 |
|---|---|---|
| 设备状态快照 | `adb devices -l`、`getprop`、`pm list users`、`getenforce` | 几 KB 纯文本，是结论边界本身 |
| 包管理台账 | `/data/system/packages.xml` | **单行长 XML**，含 `firstInstallTime` / `installerPackageName`，含卸载保留条目 |
| 加密策略 | `ro.crypto.state` / `type` / `mountstate`、`/data/misc/vold/` | `block`=FDE / `file`=FBE，决定 CE 与 DE 分层 |
| CE 数据层 | `/data/user/<userId>/<包名>/` | 凭据解锁后才挂载，历史路径 `/data/data/` 是软链 |
| DE 数据层 | `/data/user_de/<userId>/` | **开机即可读**，与锁屏凭据无关 |
| 分区表 | `/dev/block/by-name/`、`/proc/partitions`、GPT | 注意 `super` 动态分区与 `_a`/`_b` 双槽 |
| 系统日志 | `adb bugreport` 打包的 `logcat` + `dumpsys` | 压缩包，含全量服务转储 |

这台设备处于什么加密状态；能拿到哪些用户档案、哪些数据层；哪些应用装过、什么时候装的、从哪装的；本次提取的覆盖上限在哪里。

具体应用里存了什么内容（那是 [应用私有数据](mobile-android-sharedpreferences.md) 与 SQLite 那几篇的事）；设备被锁定时的 CE 内容，拿不到就记为受限，别写成"没有"；设备上发生过什么行为，得先有时间线；服务器侧数据不在检材范围内。

**本文不做的事**：不讨论 bootloader 解锁，也不提供 FRP 绕过。设备已经锁定时的手段也不写——不是没写，是这类手段在取证里就是攻击。

设备处理不了的时候，正确动作是三步：停止操作、记录状态、回到委托方沟通。

**读者前提**：磁盘分区与 GPT 结构、Linux 目录树与权限模型、哈希与只读挂载的规范（见 [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md)）。文件级深度解析在 [NTFS 结构与 MFT 解析](../../filesystem/filesystem-ntfs/filesystem-ntfs-ntfs-master-file-table.md) 与 [ext4 结构与 inode](../../filesystem/filesystem-unix/filesystem-unix-ext4-inode.md) 里已经铺过。

`getprop` 都没跑过的话，先按 [三、操作步骤](#section-8) 的第 1 步做一遍。别直接跳到提取。

另外有个技术前提值得先看一眼：委托方交来的手机如果是锁屏且未授权解锁，[TWRP 恢复分区取证](mobile-android-twrp.md) 讲的物理镜像路线才是对的，本篇的逻辑提取路线不适用。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 分区结构：哪些分区有取证价值

现代 Android 使用 **GPT** 分区表，`/dev/block/by-name/` 下的软链接是标准访问方式。

| 分区 | 常见名 | 内容 | 取证价值 |
|---|---|---|---|
| 引导程序 | `bootloader` | 厂商引导链（高通 `sbl`/`abl`/`devcfg`/`tz`/`hyp`） | ★★ 设备识别 |
| 内核/启动 | `boot`、`init_boot` | 启动镜像。`init_boot` 为 Android 13 起新增，**具体划分随版本与设备而异，以实际分区表为准** | ★★★ 伪造启动、反取证可能留痕 |
| 恢复 / 系统 / 厂商 | `recovery` / `system` / `vendor` | 恢复镜像；AOSP 框架与系统应用（Android 10+ 只读，`priv-app` 可作分析对象）；OEM HAL 与内核模块 | ★★ ~ ★★★ |
| **用户数据** | **`userdata`** | **`/data` 全部内容，本篇主战场** | ★★★★★ |
| 逻辑容器 / 启动状态 | `super` / `misc` | 动态分区容器，容纳 `system`/`vendor`/`product`/`odm`；引导计数与恢复标记 | ★★ |

> **必须掌握的现代变化**：Android 10 引入 **A/B 无缝更新与 Virtual A/B**，系统分区变成 `super` 内的**逻辑分区**，同一物理分区上同时存在 `_a`、`_b` 两个槽位。只读一侧会漏掉另一槽的旧系统版本与已删除系统应用数据。

```bash
adb shell ls -l /dev/block/by-name/ ; adb shell cat /proc/partitions   # 设备侧真实布局（优先）
fdisk -l DigiForensics.dd                                            # 镜像侧先确认有无 super 动态分区
partx -s -o START,SECTORS,NAME DigiForensics.dd                       # util-linux 的 partx
```

<a id="section-4"></a>

### 2.2 `/data` 是取证主战场

```
/data
├── data/            ← 历史路径，Android 7+ 已是 /data/user/0/ 的兼容软链
│   └── <包名>/
├── user/            ← ★ 实际存放处
│   ├── 0/           ← 主用户
│   └── 10/          ← 工作资料 / 次要用户（userId 常见 10–15）
├── user_de/         ← ★ Device-Encrypted（DE）数据，锁屏前即可读
│   └── 0/
├── app/             ← 预装应用 APK
├── media/           ← 内部共享存储（DCIM、Download 等，FUSE 呈现）
├── misc/
│   ├── keystore/    ← 应用密钥材料（受 TEE 保护）
│   └── vold/        ← FBE 加密策略
└── system/          ← 注意：这不是 system 分区，而是用户数据
    ├── packages.xml ← ★★ 全部已安装应用与版本、uid、安装时间戳
    └── users/0/
```

**两条最关键的结构事实**：

（1）`/data/data/<包名>` 与 `/data/user/<userId>/<包名>` 是同一份数据。 Android 7.0 之后应用私有目录已经迁到 `/data/user/<userId>/`，`/data/data` 变成兼容软链。

两处都要看。不同工具、不同系统版本吐出来的路径不一样，只查一个容易漏。

```bash
adb shell su -c "ls -ld /data/data /data/user/0"   # 典型输出：/data/data -> /data/user/0
```

（2）`/data/user_de/0/` 是"解锁前可读"的那一半。 FBE 把凭据加密（CE）与设备加密（DE）分开，开机后、用户输入锁屏密码之前，系统只解密 DE 部分。

设备锁着的时候，`user_de` 下的东西照样读得到。这是一份常被忽略的免费证据源。

| 目录 | 全称 | 可读时机 | 典型内容 |
|---|---|---|---|
| `/data/user/0/` | Credential-Encrypted | **必须已解锁** | 聊天记录、账号 token、私密文件 |
| `/data/user_de/0/` | Device-Encrypted | **开机即可读** | 闹钟、后台数据、部分缓存 |

> `/data/system/packages.xml` 是**性价比最高的单个文件**：一次回答"这台设备装过什么、什么被卸载过"。

<a id="section-5"></a>

### 2.3 加密状态判断：三个属性的组合

这是第一个要做的判断，而且有确定依据：`StorageManager.isEncrypted()` / `isFileEncryptedNativeOnly()` / `isBlockEncrypted()` 读的就是下面这三个属性。

`ro.crypto.state` 取 `encrypted` / `unencrypted`；`ro.crypto.type` 取 `block`（**FDE**）/ `file`（**FBE**）/ `aes`（早期块加密遗留）/ `legacy`；`ro.crypto.mountstate` 取 `mounted` / `unmounted`，指示 DE 部分是否已挂载。

FBE 和 FDE 的取证差异：

| 维度 | FDE（`type=block`） | FBE（`type=file`） |
|---|---|---|
| 加密粒度 | 整个 `userdata` 扇区 | **每个文件 + 文件名**（文件名用 AES-CBC-CTS 加密） |
| 锁屏后 | `/data` 整体不可读 | `/data/user/0` 不可读，`/data/user_de/0` 可读 |
| 物理镜像价值 | **无密钥基本无用** | 密钥未解时连文件名都看不到 |
| 典型版本 | Android 5.0–9 | Android 7.0 起（**Android 10 起强制 FBE**） |
| 密钥保护 | 用户凭据经 Keymaster 保护 | 硬件密钥派生 512 位文件密钥，**用户凭据只保护硬件密钥** |

```bash
# ① 加密三件套（最重要的一条判断）+ ② 一次性固定所有加密相关属性 + ③ fscrypt 挂载点
adb shell getprop ro.crypto.state ; adb shell getprop ro.crypto.type ; adb shell getprop ro.crypto.mountstate
adb shell getprop | grep -iE 'crypto|encrypt|keystore|vold|selinux' | tee Android-crypto-props.txt
sha256sum Android-crypto-props.txt ; adb shell mount | grep -iE 'fscrypt|/data'
```

> **重要的现实**：FBE 的文件密钥在 TEE（可信执行环境）内由硬件密钥派生，**即使有 root 也拿不到明文文件密钥**。root 能读到的是"已解锁状态下被密钥解密的明文数据"，以及 `/data/misc/vold` 下的加密策略结构。**"有了 root 就等于能解 FBE"是错误认知**——root 的价值在于跨过 SELinux 权限墙，不是破开 TEE。

<a id="section-6"></a>

### 2.4 SELinux 与 root：两道墙不是一回事

**DAC**（传统权限位）下 `shell` 不属于任何应用 uid，可 `su` 提权到 root；**SELinux** 是强制访问控制标签，**root 也会被策略拒绝**，需 permissive 或策略绕过。

```bash
adb shell getenforce                    # Enforcing（正常）/ Permissive（只记录不拦）
adb shell su -c id                      # uid=0(root) → 已 root
adb shell su -c "id -Z"                 # u:r:magisk:s0 ← 验证 su 后的域
```

**取证价值常被低估的一点**：SuperSU / Magisk 这类 root 工具会**在设备上留下自己的数据库与日志**（哪个应用何时被授予 root、授权时是否录屏/录 touch）。在网络诈骗、赌博、刷单类案件中，"root 授权记录"可作为该设备存在自动化操作痕迹的旁证；它本身只证明某应用曾被授予 root 权限，不足以单独断定操作主体与操作性质。

<a id="section-7"></a>

### 2.5 多用户与工作资料

```bash
adb shell pm list users
# UserInfo{0:机主:13} running
# UserInfo{10:工作资料:30}          ← 工作资料常见 userId=10
```

userId `0` 是机主（主体数据，但不一定是嫌疑人使用的数据）；`10`–`14` 通常是工作资料，业务 App 数据与个人账号互不可见，必须单独提取；其余为访客、访客分身，常用于"临时"使用，是**反侦查行为的重要指标**。

> **工作资料为什么重要**：企业微信、钉钉在 work profile 下有独立沙盒，**聊天记录与个人账号互不可见**。只取 `/data/user/0` 会系统性漏掉全部工作场景证据。

iOS 侧没有这套分区与多用户机制，取证走的是 iTunes 备份与沙盒路径两条路，`Manifest.db` 怎么索引、备份怎么解密见[第 06 篇](../mobile-ios/mobile-ios-ios-backup-and-sandbox-extraction.md)。

---

<a id="section-8"></a>

## 三、操作步骤

<a id="section-9"></a>

### 第 1 步：建立连接并固定设备状态

```bash
adb devices -l | tee adb-devices.txt    # 授权状态本身是检材信息
{
  echo "=== date ===";  adb shell date;        echo "=== getprop ===";  adb shell getprop
  echo "=== id ===";    adb shell id;          echo "=== getenforce ==="; adb shell getenforce
  echo "=== users ==="; adb shell pm list users; echo "=== packages ==="; adb shell pm list packages -f -U
} > device-state.txt 2>&1
sha256sum device-state.txt
```

<a id="section-10"></a>

### 第 2 步：判断加密与访问级别

```bash
adb shell getprop ro.crypto.state ; adb shell getprop ro.crypto.type   # encrypted/unencrypted；block(FDE)/file(FBE)
adb shell getprop ro.crypto.mountstate ; adb shell mount | grep '/data/user/0'   # mounted → CE 已挂载
adb shell id ; adb shell su -c id ; adb shell su -c "ls /data/data/"  # 真能列出目录才算穿透成功
```

<a id="section-11"></a>

### 第 3 步：解锁与提权（仅在已授权检材上执行）

```bash
PKG=com.digiforensics.sample
adb shell mount | grep '/data/user/0'      # ① FBE 设备须先在设备端输入锁屏凭据完成解锁
adb shell su -c "ls -la /data/data/"       # ② 已 root 设备
adb shell pm path $PKG                      # ③ 未 root 的替代路径：定位 APK，无需 root
adb shell dumpsys package $PKG | head -60   #    权限、组件、签名
adb shell "run-as $PKG" ls -la             #    仅 debuggable=true 的应用
```

> ⚠️ `adb shell su -c` 会在检材上执行命令，写入系统日志与 shell 历史。 正式案件应：① 在检查笔录中记录操作依据；② 每次操作后重新哈希关键文件确认未被改写；③ **只读取不写入**——不要 `rm`、不要改权限、不要 `settings put`。

<a id="section-12"></a>

### 第 4 步：提取应用私有数据

```bash
PKG=com.digiforensics.sample
adb shell su -c "du -sh /data/data/$PKG"
adb shell su -c "find /data/data/$PKG -maxdepth 2 -type d" | tee app-dirs.txt

# ① 整目录 tar 流式导出（首选；tar 包可哈希为单一证据容器）
adb shell su -c "tar -cf - -C /data/data $PKG" > extracted-$PKG.tar
tar -tf extracted-$PKG.tar | head -50          # 先列不拆，确认包完整
mkdir -p extracted/$PKG && tar -xf extracted-$PKG.tar -C extracted/$PKG

# ② 按目录 pull（tar 不可用时）
adb pull /data/data/$PKG/databases  extracted/$PKG/

# ③ 立即哈希固定
find extracted/$PKG -type f -exec sha256sum {} \; > hashes-app.txt
```

> **`adb pull` 对权限与符号链接敏感。** 目录中有 socket、特殊设备文件或 SELinux 拒绝路径时 `pull` 会失败，此时用 `tar`（方式 ①）更稳。

<a id="section-13"></a>

### 第 5 步：提取系统级工件与 `adb backup` 的现状

```bash
adb pull /data/system/packages.xml   extracted/       # 最高性价比
adb pull /sdcard/Download/            extracted/
adb pull /sdcard/Android/media/      extracted/
adb bugreport device-bugreport.zip                    # 含 logcat + 全量 dumpsys
sha256sum device-bugreport.zip
```

> **`adb backup` 的现状**：Android ≤ 11 尚可运行但需设备端人工确认，且大量应用 `allowBackup="false"` 直接拒绝；Android 12/13 各版本与厂商 ROM 行为不一致。**能否使用不能靠记忆版本号，必须实测**（看是否弹出确认、是否返回 `Unable to backup`）。**覆盖面不可控，不应作为取证方案**——现代主流路径是 **root + 目录级提取**；`allowBackup` 检查方法见 [03](mobile-android-apk-manifest.md)。

<a id="section-14"></a>

### 第 6 步：验证

```bash
# ① 抽样比对设备侧与主机侧哈希（不一致 → 检查是否因 WAL 未同步或权限截断）
adb shell su -c "md5sum /data/data/com.digiforensics.sample/databases/app.db"
md5sum extracted/com.digiforensics.sample/databases/app.db
# ② 记录时间基准（设备时间用户可改 + 分析机时间 + 时差）
adb shell date; date
# ③ 确认关键文件可读
sqlite3 extracted/com.digiforensics.sample/databases/app.db ".tables"
# 报 "file is not a database" → 可能是加密库，见 [09](../mobile-database/mobile-database-sqlite-wal.md)
```

---
<a id="section-15"></a>

## 四、常见陷阱

Android 取证最贵的错误不是「没读到」，而是**读到了一部分却以为读全了**。

这一章把四类最容易出错的环节拆开：访问级别、路径覆盖、状态固定、结论表述。每一条都给机制、代价和可执行的替代动作。

<a id="section-16"></a>

### 4.1 加密、权限与解锁状态

<a id="section-17"></a>

#### 陷阱 1：设备处于锁屏状态就提取，把空目录当成「没有数据」

**现象**：一台 Android 10 以上的手机连上电脑，直接 `adb shell su -c "ls /data/data/"` 拿到一份极短的包名列表，于是报告写「该设备仅安装过这些应用，未发现其他应用数据」。

**原因**：Android 10 起强制 FBE，凭据加密区（CE）的挂载条件是「用户已完成一次凭据解锁」，而不是「开机了」。设备重启后、用户输入锁屏密码之前，`/data/user/0` 整个目录**没有被挂载**——`ls` 返回空是**挂载状态的事实**，不是内容的事实。操作者看到「命令成功执行、目录存在但为空」，在终端上与「目录里确实只有这几个包」**完全无法区分**。这一误判的隐蔽性在于：命令没有报错，权限也没有被拒绝，**没有任何异常信号提示你正处在错误的状态里**。

**影响**：整份报告的应用清单、聊天记录结论、数据规模判断，全部作废。

这种结论一旦被采纳，案件会沿着「该设备使用痕迹很少」走下去，而真正的证据一次都没被碰到。

**核查**：任何提取动作之前先判定挂载状态，把「能不能读」和「有没有」彻底分开：

```bash
adb shell getprop ro.crypto.state ; adb shell getprop ro.crypto.type
adb shell getprop ro.crypto.mountstate            # mounted → CE 已挂载
adb shell mount | grep -E '/data/user/0|/data/user_de' 
```

`ro.crypto.mountstate` 为 `unmounted` 时，`/data/user/0` 下的任何结论都不成立，此时应终止 CE 部分的提取并在笔录里记录终止原因。委托方若要求必须取到 CE 数据，只能在设备端由有权解锁人完成凭据解锁后重来——**解锁动作本身是检材状态变更，需要单独授权**。同时记住 `/data/user_de/0` 在这个状态下**仍然可读**，不要因为 CE 不可读就整台设备都判为「不可用」。

<a id="section-18"></a>

#### 陷阱 2：把「设备已 root」当成「什么都能读」

**现象**：设备上装有 Magisk、`su -c id` 返回 `uid=0(root)`，于是报告写「设备已 root，应用私有数据已全部提取」。

**原因**：root 和 SELinux 是两道独立的墙，不是一道。 DAC 权限位这一层 root 无往不利，但 SELinux 是强制访问控制标签，策略里显式拒绝的路径**即使是 root 也会被拒**——而且拒绝的表现是 `Permission denied`，与「文件不存在」在终端上极易混淆。`su` 提权后进入的域（用 `id -Z` 看，通常是 `u:r:magisk:s0` 或厂商自定义域）**未必拥有原生 init 域的全部权限**，部分厂商 ROM 的 SELinux 策略还额外加固。另外还有一个更根本的认知错误：FBE 的文件密钥在 TEE 内由硬件密钥派生，root 拿到的是「当前已解锁状态下被系统解开的明文」，永远不是密钥本身——「有了 root 就能解 FBE」在技术上是错的。

**影响**：报告把「部分路径读取失败」合并进「已全部提取」，**覆盖范围被系统性高估**。复核时只要有一条 `avc: denied` 日志或一个读不出的文件，整份报告的可信度就会连带受损；更实际的是分析人员会基于「数据已完整」的假设去解释矛盾现象——**明明是提取不全，却被当成数据异常写进分析结论**。

**核查**：穿透要用「实际读到一个已知明文文件」来证明，而不是用 `id` 的输出来证明。`id=0` 只能说明拿到了 root 身份，说明不了访问控制已通过：

```bash
PKG=com.digiforensics.sample
adb shell su -c "ls -lZ /data/data/$PKG"          # 看域标签与实际可见性
adb shell su -c "head -c 64 /data/system/packages.xml"   # 能读出 XML 才算穿透
adb shell su -c "sqlite3 /data/data/$PKG/databases/app.db '.tables'"  # 应用级验证
```

**验证不通过时，报告要逐条写明受限路径和受限原因。** 不要笼统写一句「部分数据未能获取」。

一份诚实的「`/data/user/0/com.xxx/shared_prefs` 因 SELinux 拒绝未取得」，比一句「已全部提取」在复核中安全得多。

<a id="section-19"></a>

#### 陷阱 3：把 `/data/system` 当成 `system` 分区

**现象**：报告里写「在 `system` 分区发现可疑应用」，附带的路径是 `/data/system/`，另一份报告写「在 `/data/system/packages.xml` 中发现……」，两者混用同一句结论。

**原因**：Android 存在两个都叫「system」的东西——**`system` 是只读系统分区**（Android 10+ 位于 `super` 动态分区容器内的逻辑分区），装的是 AOSP 框架与系统应用；`/data/system` 是用户数据分区下的一个普通目录，里面是 `packages.xml`、`users/0/`、各种系统设置与状态数据库。它们的挂载源、生命周期、可写性、内容性质完全不同，但在路径书写上只差一个前导斜杠。 取证脚本里把两者混作一个变量名是极常见的写法，产出的结论也跟着混。

**影响**：**证据来源标注错误，属于可被质疑的取证过程描述。** 报告引用一个实际并不存在的路径，会让整条证据链的可信度被质疑——「这个文件在哪找到的？」答不上来的情况下，后续所有基于它的结论都会被连带动摇。

**核查**：**书写时把分区名和路径严格区分**：分区写「`system` 分区（`super` 内的逻辑分区）」，路径写「`/data/system/`（`userdata` 分区内）」。在工具脚本里也用不同变量名承载，并在报告中明确标注每个工件所属的分区与挂载点。判断某文件属于哪一侧，看它出现在块设备分区表里还是 `/data` 目录树里——这是唯一可靠的方法。

<a id="section-20"></a>

### 4.2 路径覆盖与数据层级

<a id="section-21"></a>

#### 陷阱 4：漏掉 `/data/user_de/0`——把设备加密层当成没价值

**现象**：提取脚本只遍历 `/data/user/0/<包名>`，产出的目录树里每个应用都只有空壳目录，报告写「应用数据目录无有效内容」。

**原因**：FBE 把应用数据拆成两层，凭据加密区（CE，落在 `/data/user/<userId>/`）与设备加密区（DE，落在 `/data/user_de/<userId>/`）。DE 部分由「设备已解锁」这个条件保护，与用户锁屏凭据无关——开机后、任何人输入锁屏密码之前它就已经是明文可读的。很多应用会把闹钟、后台任务状态、部分缓存、下发的预配置、部分 SQLite 库写进 DE 层。提取者往往只认 CE 层这个「常识上的应用数据目录」，DE 层从头到尾没被看一眼。 而「目录存在但内容为空」这个现象在权限不足、路径拼错、DE/CE 混淆三种情况下长得一模一样。

**影响**：**免费证据被整体漏掉，却写成了「未发现」。**

设备没解锁的场景下，这几乎决定了整次提取的成败。CE 拿不到时，DE 是唯一还能出数据的地方。漏了它，等于本次委托交白卷。

**核查**：**DE 层是常规提取项，不是兜底项**，与 CE 层并列写进清单：

```bash
adb shell su -c "ls -d /data/user_de/*"                 # 先确认存在哪些 DE 用户目录
adb shell su -c "du -sh /data/user_de/0"                 # 评估体量
adb shell su -c "tar -cf - -C /data/user_de 0" > DigiForensics-user_de-0.tar   # 独立归档
```

报告中把 CE 与 DE 拆成两栏写明各自取得了什么。遇到「CE 因未解锁不可读」时，DE 层的完整度直接决定报告的可用价值，必须优先做、优先写。

<a id="section-22"></a>

#### 陷阱 5：只取主用户 0，漏掉工作资料与分身用户

**现象**：提取脚本里写死 `userId=0`，提取完成后报告列出「设备内共 6 个应用有数据」，未见异常。

**原因**：Android 10 起设备上可能同时存在多个用户档案：工作资料（work profile，常见 `userId=10`）、访客用户、以及厂商实现的应用分身（不同厂商的 userId 分配不同，常见 999、10–15）。每个用户有自己独立的 `/data/user/<userId>/` 与 `/data/user_de/<userId>/`，彼此完全隔离、互不可见。 企业微信、钉钉在 work profile 下有独立沙盒，工作账号与个人账号的聊天记录在文件层面是两份数据。**写死 0 的脚本不会报错**——它老老实实提取了主用户的数据，输出看起来完全正常。设备上只有工作资料没有个人数据（或反之）时，提取结果甚至可能只有几个 KB，看起来更像「这台设备很干净」。

**影响**：这是典型的系统性漏检，而漏掉的那部分往往是案件的核心事实。

职务侵占、团伙协作、上下级指挥关系这类案件，业务沟通几乎全部发生在 work profile 里。漏了它，报告里那句「未发现相关沟通记录」就是彻底错误的阴性结论，而它会直接把案件定性带偏。

**核查**：userId 必须从设备上动态枚举，不允许写死在脚本里：

```bash
adb shell pm list users                          # 权威来源：UserInfo{0:机主:13} / {10:工作资料:30}
adb shell su -c "ls -d /data/user/*"             # 与上一条交叉，避免 pm 输出不全
adb shell su -c "ls -d /data/user_de/*"
```

然后对枚举出的**每一个** userId 走完整的提取流程，归档目录按 `user-<id>` 分开。

报告里必须列出已覆盖的 userId 清单，并且明确写出「本机存在/不存在工作资料」。这个判断本身就是一项应当交付的事实，不是提取过程的副产品。

<a id="section-23"></a>

#### 陷阱 6：只看 `pm list packages`，丢掉已卸载应用与安装来源

**现象**：设备做过恢复出厂或手动清理，`pm list packages` 只返回现存应用，报告据此写「该设备从未安装赌博类应用」。

**原因**：**应用列表和安装历史是两份不同的数据。** `/data/system/packages.xml` 记录的是包管理器的完整状态，包含当前已安装应用**以及卸载后仍在保留期内的条目**；每个包条目带有 `firstInstallTime`、`lastUpdateTime`、`installerPackageName`、安装路径等字段。其中 `installerPackageName` 为 `null` 意味着**没有记录到安装来源**——应用商店安装会写入来源包名，而侧载（手动装 APK）通常为 `null`。`pm list packages` 是当前态查询，`packages.xml` 是状态台账，前者会随卸载而删除记录，后者保留历史。很多「这台设备没有装过」的结论，是只问了当前态而没查台账。

**影响**：「从未安装」和「当前未安装」是两个完全不同的定性。

前者指向设备使用历史与主观意图，是案件定性的核心事实。后者只是一个瞬时状态。写错之后，辩护方一查安装记录就能推翻。

**核查**：把 `packages.xml` 当第一优先提取项（体量只有几百 KB，性价比极高），与 `pm list packages` 交叉比对，差异项就是已卸载或有历史的应用：

```bash
adb pull /data/system/packages.xml extracted/        # ★ 最高性价比的单个文件
# packages.xml 通常是单行长 XML，用 grep -o 截取片段，不要用 -A/-C
grep -o 'package="com.digiforensics.lottery".\{0,160\}' extracted/packages.xml
```

比对时重点看三类差异：① `pm` 里有而 `packages.xml` 时间戳异常早的（可能是替换包）；② `packages.xml` 里有而 `pm` 里没有的（已卸载）；③ `installerPackageName` 为 `null` 的（侧载痕迹）。

<a id="section-24"></a>

### 4.3 提取工艺与状态固定

<a id="section-25"></a>

#### 陷阱 7：用 `adb shell ... > file` 流式导出而不做完整性校验

**现象**：用 `adb shell su -c "tar -cf - -C /data/data $PKG" > DigiForensics-extracted.tar` 导出应用数据 tar 包，命令正常返回，之后直接进入解压和分析，从未校验过这个包是否完整。

**原因**：这条管道没有任何完整性保证，也没有任何完整性检查。 USB 连接抖动、adb 服务重启、设备进入深度睡眠、`su` 弹窗被系统中断——其中任何一种发生，命令都可能只传输了部分字节就终止，而 shell 的退出状态在重定向场景下经常被后续管道掩盖。结果是一个**大小看起来合理、能列出内容、甚至能解出一部分目录**的 tar 包。它不是「明显损坏的文件」，而是「静默截断的文件」。 分析工具解析到缺失位置就停在那里，剩下的内容既不报错也不提示。

**影响**：**分析基于一份不完整的证据，得出的却是完整的结论。** 最典型的表现是「数据库里最近几天的记录不见了」，分析人员会把它解释为「用户近期未使用该应用」——**而真相只是传输在那个位置断了**。这个错误会把「时间上最近的行为」整段抹掉，恰好是案件最需要的那一段。

**核查**：流式传输必须配三件套：源侧哈希、接收侧哈希、结构验证。

```bash
# ① 设备侧先算哈希（源侧基准）
adb shell su -c "sha256sum /data/data/$PKG/databases/app.db"

# ② 传输（tar 流式导出）
adb shell su -c "tar -cf - -C /data/data $PKG" > DigiForensics-extracted-$PKG.tar

# ③ 接收侧比对同一文件 + 验证归档结构
tar -xf DigiForensics-extracted-$PKG.tar -C verify/ && tar -tf DigiForensics-extracted-$PKG.tar | wc -l
ls -l DigiForensics-extracted-$PKG.tar          # 与源侧 du -sh 得到的体积量级对照，差一个数量级即截断
```

**「归档能列出内容」不等于「内容完整」**——tar 格式允许末尾截断后仍能列出已完整的成员。真正可靠的判据是**源侧与接收侧对同一文件哈希一致**，以及提取出的文件数与源侧 `find | wc -l` 一致。不一致就重传，并在笔录里记下重传次数。

<a id="section-26"></a>

#### 陷阱 8：设备状态快照没固定就开始提取

**现象**：连上设备后第一件事是开始拉数据，`getprop`、`adb devices -l`、`pm list users` 的输出到最后才想起来补记，或者干脆没记。

**原因**：这些体积只有几 KB 的输出，是整份报告的结论边界。 `adb devices -l` 记录授权状态（已授权还是被拒绝）、`getprop` 记录系统版本与加密状态、`pm list users` 记录用户档案构成、`getenforce` 记录 SELinux 模式——它们回答的是「这份数据是在什么状态下、以什么访问级别拿到的」。补记做不到位，因为设备状态随时可能变：委托方可能在提取期间解锁了屏幕、插入了另一张卡、重启了设备。**事后补记填进去的已经不是提取当时的状态了**，而报告读者会把它当作提取时的事实。

**影响**：**报告缺少可复现性基础。** 一旦委托方或复核方质疑「你说 SELinux Enforcing 下未取得数据，那提取时到底是 Enforcing 还是 Permissive」，没有任何同期记录可以回溯回答。这类质疑无法事后补救——**证据在提取之前就产生了，错过采集点就没有第二次。**

**核查**：**第一条命令是固定状态，不是提取数据**。把状态快照作为独立的、带哈希的工件保存：

```bash
adb devices -l | tee adb-devices.txt
{
  echo "=== date ===";  adb shell date
  echo "=== getprop ===";  adb shell getprop
  echo "=== id ===";    adb shell id
  echo "=== getenforce ===";  adb shell getenforce
  echo "=== users ===";  adb shell pm list users
  echo "=== packages ==="; adb shell pm list packages -f -U
} > device-state.txt 2>&1
sha256sum device-state.txt adb-devices.txt
```

判定顺序固定为：固定状态 → 判断加密与访问级别 → 提取。 顺序颠倒时，状态快照就失去了「与提取同一时段」这个唯一的价值属性。

<a id="section-27"></a>

#### 陷阱 9：★ 提取手段本身改变了检材状态却不留记录

**现象**：报告写「提取过程未修改设备数据」，但工作记录显示期间执行过 `adb bugreport`、切换过 SELinux 模式、为测试 root 而运行过 `su`、以及把设备挂载到主机做过写操作测试。

**原因**：取证手段几乎不可能做到零痕迹，而「没改数据」这个判断极容易被当成默认前提。 实际上 `adb bugreport` 会在设备上落一个 bugreport 文件并触发一次全量服务转储；`su` 提权会在系统日志与部分 root 管理工具的授权数据库里留下记录；`adb backup` 会创建备份文件；把 `userdata` 以读写方式挂载会更新挂载点、可能生成 `lost+found`；切换 `setenforce` 属于显式的系统配置变更。这些操作绝大多数是「无害」的，问题是报告把「无害」当成了「无痕」。 更隐蔽的是时间基准：提取过程本身耗时可观，期间应用可能继续运行、继续同步、继续写库——**取到的已经不是「设备交付时」的状态**。

**影响**：**这是结论表述层的系统性问题，且不可逆。** 「未修改检材」在报告里是一句会被反复引用和摘录的陈述；若后续因设备状态变化产生纠纷，这句话构成不实陈述。而时间基准的偏移是**无法事后修正**的——你没法证明提取开始时那台设备处于什么状态。

**核查**：把设备状态变更当成取证的既定事实记录，而不是当成意外。报告中单列一节「检材状态变更说明」，逐项写清：执行过的写操作或状态变更动作、发生时间（同时记录设备侧 `date` 与分析机 `date` 及两者时差）、**`userdata` 未被改动的依据是什么**（操作前后哈希比对，还是仅凭操作行为推断——**推断的证据强度必须标注清楚**）：

> 检材状态变更说明：本次提取执行了 `adb bugreport`（在 `/data/misc/` 下生成转储文件）
> 与 3 次 `su` 提权（系统日志与 root 授权记录中可见）。除上述内容外，
> 未对 `userdata` 执行写操作。该判断依据为关键文件提取前后 SHA-256 比对，
> 其中 `/data/user/0/com.digiforensics.sample/databases/` 目录为全量比对，
> 其余目录为抽样比对。设备侧时间与分析机时间时差记录于 `time-baseline.txt`。

**同时固定时间基准**：`adb shell date`、`date`、`getprop persist.sys.timezone` 三者一并记录。**取证时几乎不存在默认时区，默认精度也不可信。**

<a id="section-28"></a>

### 4.4 结论表述

<a id="section-29"></a>

#### 陷阱 10：把设备本地时间直接当案发时间

**现象**：从数据库或日志里读出一个时间戳就直接写进时间线，与其他证据交叉比对时发现对不上，于是反复调整时区，最后选了一个「看起来对得上」的时区。

**原因**：Android 设备上的时间戳至少存在三种语义完全不同的形态，混用它们必然错位：**① Unix 时间戳**（秒级 UTC，数据库里最常见，本身不含时区）；**② UTC 字符串**（`2024-06-02T14:40:55Z`，带 `Z` 标记）；**③ 本地时间字符串**（`2024-06-02 22:40:55`，通常取自设备时区设置）。**而设备时区是用户可改的**，`persist.sys.timezone` 属性和系统设置界面都能改，改完不影响任何已有数据里的时间戳。数据库里 `datetime('now')` 之类生成的是 UTC，而 `strftime` 不带 `%z` 格式化出来的又是另一种。分析人员往往先按本地时间读，跨设备比对时再「凭感觉」加减小时——**每一次凭感觉的换算都在制造一个新的错误。**

**影响**：**时间线一旦错位，案件叙事就跟着错位。** 行为先后顺序被颠倒（谁先发起转账、谁后回复）、同一天内的行为被拆到不同天、或者两个本该相关的行为被认为无关。这类错误的隐蔽性在于——**时间线看起来完全合理，只是错了几小时**，不会有人质疑一份排版整齐的时间表。

**核查**：**三步固定时间基准，再谈时间线**：

```bash
# ① 提取当时同时记录两套时间与时区
adb shell date ; date ; adb shell getprop persist.sys.timezone

# ② 解析任何时间戳时先判定其类型，转换时显式指定时区
#    Unix 时间戳 → 显式按 UTC 转换后再落到目标时区
#    带 Z 的 ISO 串 → 已是 UTC
#    无时区标记的字符串 → 判定它由谁写入（app 代码 / 系统日志 / 应用自身时区）
```

**报告里的每个时间都必须标注时区**，写作 `2024-06-02 22:40:55 (UTC+8)` 而不是 `2024-06-02 22:40:55`。无法确定时间语义的时间戳，宁可标注「时区未确定」，也不要猜。 另外记住：`packages.xml` 里的 `firstInstallTime` 这类系统记录值同样受设备时钟影响，**它是系统记录值，不是可信的绝对时间锚点**——只有当它与下载目录文件时间、服务器侧时间等**独立来源**互相印证时，结论强度才够。

<a id="section-30"></a>

#### 陷阱 11：把「不可达」写成「未发现」

**现象**：设备未 root、`/data/data/` 报 `Permission denied`，报告结论部分写「未发现聊天记录」。

**原因**：这两句话的信息量差了一个数量级。「未发现」是一个关于设备内容的事实断言，隐含「我完整地看过了」；「不可达」是一个关于访问权限的状态描述，隐含「我根本没看到」。 混写通常发生在写报告的阶段——提取时的挫败感（`Permission denied` 连着十几次）被简化成了结论里的一个词。 更麻烦的是「未发现」这个词在中文语境里天然带有「查过了、确实没有」的意味，读者（包括委托方和后续承办人）几乎不会追问它背后的覆盖范围。

**影响**：阴性发现的表述不当，比阳性发现的错误更容易带偏案件方向。

「未发现」会让案件沿着「没有聊天记录 → 可能是诬告、可能记错、可能走了别的渠道」走，而真实原因只是取证手段不够。委托方基于这个结论做出的决定——质疑举报、撤销调查、认定无证据——无法挽回。

复核场景下更直接：一份写了「未发现」却拿不出覆盖清单的报告，会被整体质疑可信度。

**核查**：**阴性发现写成三段式：范围 + 检查 + 限定**，并把「未覆盖范围」显式列出：

> **聊天记录**：在本次检材 `/data/user/0/`（userId 0，单用户，`pm list users` 确认无工作资料）
> 范围内，通过 root + 目录级 tar 提取的 187 个应用私有目录中检索，
> **未发现**目标应用 `com.digiforensics.chat` 的数据目录。
> **未覆盖范围**：① 检材未 root，`/data/user_de/0` 已提取但该应用无 DE 层数据；
> ② 目标应用可能存在的 work profile（`/data/user/10/`）在本机不存在；
> ③ 已卸载应用的数据残留未恢复（见 `packages.xml` 存在卸载记录但内容不可取）；
> ④ 应用服务器端数据不在本次委托范围。
> 该结论为阴性发现，效力上限即上述范围，不代表设备内不存在相关数据。

**最后一句「不代表设备内不存在相关数据」不能省。** 另外要记住一条原则：阴性发现的取证能力与阳性发现的取证能力不是同一件事——没找到东西永远不能证明东西不存在，**只能证明「在这个范围里、按这个方法、没有找到」**。
<a id="section-31"></a>

## 五、案例示例

<a id="section-32"></a>

### 5.1 未 root 设备的状态固定与侧载应用时间线重建

**场景**

查获一台 Android 13 手机（8 GB RAM / 128 GB），检材已由委托方解锁，**未 root**，USB 调试开启但授权记录已清除。委托方提出三项要求：确认是否安装赌博类应用、是否有转账行为、提取聊天记录。

这个场景的关键在于：**三项委托里有一项在技术上无法完成。**

正确处置不是勉强给一个答案，也不是只做能做的部分然后沉默。而是当场记录限制、转做可行部分、书面告知不可行项。

**处置过程**

第一步，设备状态一次性固定并哈希。**这一步必须在任何提取动作之前完成**，否则状态快照证明不了提取时的状态：

```bash
$ { echo "=== getprop ==="; adb shell getprop; echo "=== id ==="; adb shell id
    echo "=== getenforce ==="; adb shell getenforce
    echo "=== users ==="; adb shell pm list users; } > device-state.txt 2>&1
$ sha256sum device-state.txt
```

```bash
$ adb shell id
uid=2000(shell) gid=2000(shell)                ← 非 root
$ adb shell ls /data/data/
ls: /data/data/: Permission denied             ← 私有目录不可达
```

第二步，判读决定提取路线的关键属性：

| 属性 | 值 | 对委托的影响 |
|---|---|---|
| `ro.build.version.release` | `13` | `adb backup` 在该版本已不可依赖 |
| `ro.crypto.type` | `file` | **FBE 文件级加密** |
| `ro.crypto.mountstate` | `mounted` | **已解锁**，`/data/user/0` 可读（若有权限） |
| `ro.product.cpu.abi` | `arm64-v8a` | 决定 native 库架构 |
| `getenforce` | `Enforcing` | 强制模式，无绕行空间 |
| `pm list users` | 仅 `UserInfo{0:机主:13}` | **单用户，无工作资料夹** |

**关键决策点**：`/data/data/` 完全不可达 → **委托要求的"提取聊天记录"在本机上无法完成。** 这不是"暂时没做"，是"在未 root 前提下不存在可行路径"。

第三步，提取所有实际可取的部分，并对每个文件取哈希：

```bash
$ adb shell pm list packages -f -U > packages.txt      # 187 行
$ adb pull /sdcard/Download/ extracted/Download/
$ adb pull /sdcard/Tencent/    extracted/Tencent/
$ find extracted -type f -exec sha256sum {} \; > hashes-external.txt
$ adb bugreport device-bugreport.zip
```

`bugreport` 在未 root 设备上可用，而且信息量很大。 它含 `packages.xml` 的完整副本、`dumpsys package` 输出、各服务运行状态。

本次侧载判定就靠它。

第四步，从 bugreport 提取安装元数据并建表：

```bash
$ unzip -o device-bugreport.zip -d bugreport-out/
$ grep -o 'package="[^"]*".\{0,200\}' bugreport-out/packages.xml \
    | grep -E 'firstInstallTime|installerPackageName' | head -20
```

```text
com.digiforensics.sample    firstInstallTime=2024-03-11 09:22:41  installerPackageName=com.android.vending
com.digiforensics.lottery  firstInstallTime=2024-06-02 22:41:07  installerPackageName=null
com.digiforensics.chat     firstInstallTime=2024-06-02 22:43:19  installerPackageName=null
```

**三个字段的组合才是判据，单看任何一个都不够。**

第五步，**用独立来源印证**。时间戳不能单独定案，必须有第二来源：

```bash
$ ls -l extracted/Download/
-rw-rw---- 1 shell sdcard_rw 8412371 2024-06-02 22:40:55 apkg_bundle_xxx.zip
```

`apkg` 包的 mtime 是 22:40:55，早于 `lottery` 的 `firstInstallTime`（22:41:07）12 秒。

第六步，用 `packages.xml` 交叉验证 bugreport 的解析结果 —— **两个来源必须一致**：

```bash
# packages.xml 通常是单行长 XML，用 grep -o 截取片段而非 -A/-C
$ grep -o 'package="com.digiforensics.lottery".\{0,160\}' extracted/packages.xml
package="com.digiforensics.lottery" ... firstInstallTime="2024-06-02T22:41:07" ...
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 提取时设备为 Android 13 + FBE + 已解锁 + SELinux Enforcing + 单用户 + 非 root | `device-state.txt` 快照 + 哈希 | 强 |
| 安装了赌博类应用 `com.digiforensics.lottery` | `pm list packages` + `packages.xml` + bugreport 三源 | 强 |
| 该应用为侧载（无安装来源） | `installerPackageName=null`，三源一致 | 强 |
| `lottery` 与 `chat` 相隔 2 分 12 秒连续安装 | 两个 `firstInstallTime` | 中（时间戳可被改写） |
| 下载—侧载—立即安装链条成立 | `apkg` mtime 22:40:55 早于安装 22:41:07，三源互证 | 强 |
| **聊天记录** | — | **未获取（`/data/data/` 权限不可达）** |
| **转账行为** | — | **未获取（依赖应用私有数据）** |

**能证明的**：设备状态快照；三个应用的存在与安装来源；侧载时间线的三源印证。

**不能证明的**：
- **不能证明有人主动下载并安装**。侧载只能证明"非商店渠道"，操作者可能是机主也可能是他人
- **不能证明应用被使用过**。安装 ≠ 使用
- **不能得出任何关于聊天内容或转账的结论** —— 数据未获取

**未覆盖范围**：`/data/data/` 全部内容（权限不可达）、已删除且未回收的 SD 卡文件、其他用户分区（本次仅 user 0）、SELinux 域外的系统分区、以及转账相关的第三方支付 App 状态。

**误判对照**

这个案例的误判有三个层次，第二个最值得写。

**其一，把"未获取"写成"未发现"。**

这是委托沟通里最伤的一种表述。

委托方听到「未发现聊天记录」，理解成「查过了，没有」；实际情况是「没权限看」。

差别是决定性的：前者指向「无问题」，后者指向「需要换方案」。

判据是**阴性结论的成因分类**，报告里必须区分三种：

| 表述 | 含义 | 正确写法 |
|---|---|---|
| 未发现 | 查了，没有 | — |
| 未获取 | 想查，**没有权限/条件** | 必须写明限制原因 |
| 不适用 | 查了，该项在本机不成立 | 必须写明判定依据 |

本案"聊天记录"属于第二类。正确写法：「因设备未 root，`/data/data/` 私有目录不可达（`ls: Permission denied`），**本次未获取**聊天记录。**不能据此得出"该机无聊天记录"的结论。** 若需提取，应在已 root 设备或经委托方授权的其他方式下重做。」

其二，把 `installerPackageName = null` 直接读成"人为侧载"。

判据在**这个字段的失效模式**。`null` 可能来自四种完全不同的情形：

| 成因 | 判据 | 本案是否适用 |
|---|---|---|
| 通过 `adb install` 或文件管理器安装 | 无 installer 记录 | ✅ 适用 |
| 安装时 Google Play 服务不可用 | `installerPackageName` 未被写入 | 可能 |
| 系统升级/迁移导致记录丢失 | 升级记录与安装时间接近 | ❌ 不适用（2024-06-02 无升级） |
| 应用被禁用/卸载重装 | 卸载记录与安装时间接近 | ❌ 不适用（无卸载记录） |

**`null` 本身只证明"非商店安装渠道"。** 本案结论强度能到"侧载"，靠的是**三个字段的组合**：

1. `installerPackageName = null`（无来源）
2. `firstInstallTime = 2024-06-02 22:41:07`（**该时间点无系统升级、无批量卸载重装**）
3. `Download/apkg_bundle_xxx.zip` 的 mtime = `22:40:55`，**早于安装 12 秒**（独立来源印证）

第三条是决定性的 —— **它证明安装包就在设备上、且在安装前不久被写入。** 没有这一条，前两条只能给出"弱到中"的侧载判断。

其三，把 `firstInstallTime` 当作绝对可靠的时间证据。

`firstInstallTime` 是系统记录的值，存在被改写的可能（恢复出厂、部分 ROM 的时区处理、时钟回拨）。判据是**它必须与独立来源形成交叉**。本案的独立来源有两个：`apkg` 文件的 mtime（文件系统时间戳，与系统记录不同源）与 `packages.xml`/`bugreport` 的两份独立副本。三个来源的时间相互一致且量级合理（差异 12 秒与 2 分 12 秒），结论才成立。

按错误判据走的代价：若只靠 `firstInstallTime` 单源定案，委托方质疑"时间戳可以被改"时，报告无从应对。**而这三源结构在报告里只多写两行字。**

**第四个实操细节**：`packages.xml` 是单行长 XML，用 `grep -A`/`grep -C` 拿不到可用上下文（会输出整行长文本），必须用 `grep -o 'pattern.\{0,N\}'` 截取片段。判据是**输出可读性**：如果 `grep -A2` 输出了几十万字符的一行，说明用错了工具。

<a id="section-33"></a>

### 5.2 通知层与联系人层的降级取证

**场景**

承接 5.1。委托方对"未能提取聊天记录"不满意，提出折中方案：既然 `/data/data/` 不可达，能否从其他位置重建聊天记录的部分信息 —— 联系人列表、通知内容、账号标识？

这个场景的难点：未 root 条件下能拿到的都是碎片，而且极易被误读成完整记录。

委托方要的是聊天内容。我们最多能证明「有对话发生过」。

**处置过程**

第一步，先定可达性矩阵，再动手 —— 不要边试边决定：

| 目标信息 | 可达路径 | 未 root 可行性 |
|---|---|---|
| 联系人列表 | `content://com.android.contacts`（shell 有读权限） | 可行 |
| 通知内容（前台驻留时） | `dumpsys notification --noredact` | 仅当前驻留 |
| 聊天账号标识 | 通知 `EXTRA` 字段、`pm list packages` | 可行 |
| 聊天正文 | `/data/data/<pkg>/databases/*.db` | 不可行 |
| 会话缩略图 | `/data/data/<pkg>/files/` 或 `cache/` | 不可行 |
| 已消失的通知历史 | 无 | 不可行 |

第二步，取联系人：

```bash
$ adb shell content query --uri content://com.android.contacts/phones \
    --projection display_name:number | head -5
Row: 0 display_name=<已脱敏A>, number=+8613xxxx1234
Row: 1 display_name=<已脱敏B>, number=wxid_****
$ adb shell content query --uri content://com.android.contacts/phones | wc -l
238
```

238 条联系人，其中一条 `number` 字段形态是 `wxid_****` 而非电话号码 —— 这是 IM 账号 ID 被存进了联系人表。

第三步，取通知。这是本案信息价值最高的一项 —— 通知由 `system_server` 持有，不受 app 沙盒限制：

```bash
$ adb shell dumpsys notification --noredact > notifications.txt 2>&1
$ grep -c 'NotificationRecord' notifications.txt
12
$ grep -oE 'pkg=[a-z0-9._]+|android\.text=String \([^)]*\)' notifications.txt \
    | paste - - 2>/dev/null | head -14
pkg=com.digiforensics.chat     android.text=String (<已脱敏B>: 你把上次说的那份文件发我一下)
pkg=com.digiforensics.chat     android.text=String (<已脱敏B>: 收到)
pkg=com.digiforensics.lottery  android.text=String (双十一活动，最后一小时)
pkg=com.android.mms            android.text=String (<已脱敏C>: 在吗)
```

第四步，立刻查清通知的时效边界：

```bash
$ adb shell dumpsys notification | grep -A5 'com.digiforensics.chat' \
    | grep -iE 'postTime|android.when'
postTime=2026-03-14 09:22:41
$ adb shell dumpsys usagestats | grep -A3 'com.digiforensics.chat' | head -8
eventTime=2026-03-14 09:22:38
```

`postTime` 只有一个时间点，且 `usagestats` 的最近使用事件与它相差 3 秒。 说明这是当前驻留的那条通知，不是历史列表。

第五步，确认通知历史功能状态 —— 这是判定阴性边界的硬字段：

```bash
$ adb shell dumpsys notification | grep -iE 'mLastNotificationTime|historySize'
mLastNotificationTime=0
historySize=0
$ adb shell dumpsys notification | grep -c 'com.digiforensics.chat'
2
```

**`historySize=0`** —— 该 ROM 未启用通知历史，**已消失的通知在系统里不留任何记录**。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 该机安装 `com.digiforensics.chat` | `pm list packages` + bugreport | 强 |
| 该 app 在采集时刻处于活动状态 | 通知驻留 + `usagestats` 事件 09:22:38 | 强 |
| 采集时刻该 app 有 2 条通知，内容为聊天消息片段 | `dumpsys notification --noredact` | 强（仅限此刻） |
| 联系人表含 IM 账号形态记录 | `content query` 检出 `wxid_****` 形态 | 强 |
| 该机有 238 个联系人 | `content query` 行数 | 强 |
| **聊天历史** | — | **不可得**（`historySize=0`） |

**能证明的**：应用存在与活动状态；采集时刻的 2 条通知内容；联系人表内容。

**不能证明的**：
- **不能证明通知所示对话发生于何时。** `postTime=09:22:41` 是通知投递时刻，对话可能更早
- **不能证明对话另一方的账号身份**（通知只有称呼，无账号 ID）
- **不能证明消息由机主本人查看或发送**
- **不能推断通知总量。** 2 条不代表只发生过 2 次对话

**未覆盖范围**：全部历史通知（`historySize=0`）、`/data/data/` 内数据库与缓存、app 后台存活状态、推送服务端记录（需运营商侧配合）、聊天内容完整上下文。

**误判对照**

这个案例的误判发生在「拿到了一些东西」之后 —— 这比什么都没拿到更危险，因为委托方会以为委托项已经完成。

其一，把 2 条通知读成"该 app 只有 2 条消息"。

判据是**通知的数据模型**：Android 通知是"每 app 一个槽位"的显示系统，新通知会**替换**该 app 的旧通知。`dumpsys` 展示的是**当前槽位驻留内容**，不是消息队列。`historySize=0` 是硬判据 —— 被替换掉的通知在系统里被直接丢弃。

| 观察 | 能证明 | 不能证明 |
|---|---|---|
| 2 条 `chat` 通知 | 此刻驻留 2 条 | 只发生过 2 次对话 |
| `postTime=09:22:41` | 该通知投递时刻 | 对话发生时刻 |
| `historySize=0` | 已消失通知无残留 | — |

按错误判据走的代价：委托方看到"聊天记录只有 2 条且内容平淡"，可能判断"没查出实质问题"而降低关注度。**而这 2 条片段可能来自一段长达数月的对话。**

**其二，把通知内容当作"聊天记录提取成功"。**

两者在字段层面的区别很具体：

| 维度 | 通知（本次可得） | 聊天记录（未获取） |
|---|---|---|
| 数据源 | `system_server` 通知槽 | app 私有 SQLite 库 |
| 完整性 | 仅显示文案，无时间戳/发送方 ID/已读态 | 完整消息链 |
| 范围 | 每 app 1–N 条当前驻留 | 全历史 |
| 可重复性 | 瞬时快照，不可重现 | 稳定可重复 |

报告里必须写"取得 2 条通知内容样本"，不能写"取得聊天记录"。

**其三，把通知文案直接作为"通信内容"结论。**

通知文案是**发送方提供的字符串**，只能证明"该字符串在该时刻被请求显示"，不能证明送达、对方收到、或内容未被篡改。本次还有个具体限制：通知里只有称呼（已脱敏），**提取不到发送方账号 ID** —— 而账号 ID 才是把对话关联到具体人的关键。

**第四个实操细节**：`dumpsys notification` 默认会把 `android.text` 替换为 `String (###)` 形式的省略标记，**必须加 `--noredact`**。判据是看 `android.text=String (` 后面跟的是实际文字还是 `###`。这是"拿到了空内容而不自知"的常见原因。

<a id="section-34"></a>

### 5.3 反例：外部存储残留文件的时间戳陷阱

**场景**

承接 5.1。委托方注意到 `extracted/Download/` 里有个 `apkg_bundle_xxx.zip`，mtime 是 `2024-06-02 22:40:55`，早于两个应用的安装时间。委托方据此认为「安装包在设备上留存至今」，并推断「用户长期保留该文件」。

这个推断需要检验。外部存储的 mtime 在文件系统层面不等于「文件被写入的时刻」，尤其是在经历过多次插拔、恢复出厂、部分恢复之后。

**处置过程**

第一步，把该文件的全部时间维度取出来，不要只看 mtime：

```bash
$ stat extracted/Download/apkg_bundle_xxx.zip
  File: extracted/Download/apkg_bundle_xxx.zip
  Size: 8412371        Blocks: 16432       IO Block: 4096   regular file
Device: 10305h/66213d  Inode: 284177       Links: 1
Access: (0644)  Uid: (  0  root)   Gid: ( 201  sdcard_rw)
Access: 2024-06-02 22:40:55.000000000 +0800
Modify: 2024-06-02 22:40:55.000000000 +0800
Change: 2026-03-14 09:17:33.482115000 +0800
 Birth: 2024-06-02 22:40:55.000000000 +0800
```

**四个时间戳的语义完全不同**：

| 时间戳 | 值 | 语义 |
|---|---|---|
| `Access` | 2024-06-02 22:40:55 | 最后读取（可能不可靠，见下） |
| `Modify` | 2024-06-02 22:40:55 | **内容最后修改** |
| `Change` | **2026-03-14 09:17:33** | **元数据最后变更**（含权限、所有者、链接数） |
| `Birth` | 2024-06-02 22:40:55 | inode 创建 |

`Change` = 2026-03-14 09:17:33，比内容修改时间晚一年多，落在委托方制作镜像的时段内。 该值只能说明 inode 元数据在此期间被改动过（`adb pull` 到不同文件系统、或 SELinux 标签变更，都会触发 `Change` 更新），成因需另行判定。

第二步，验证 `Access` 时间是否可信：

```bash
$ mount | grep -E 'sdcard|fuse'
sdcardfs on /storage/emulated/0 type sdcardfs (rw,relatime,...)

# FUSE 文件系统的 atime 可能被内核挂载选项关闭更新
$ adb shell mount | grep -oE 'relatime|noatime|strictatime'
relatime
```

`relatime` 语义下，`Access` 时间只在「访问时间早于 mtime 或超过 24 小时」时才更新。 所以 `Access=2024-06-02` 只能说明「上次更新 atime 是在那时」，**不能说明文件此后从未被读取过**。

第三步，用其他独立来源核实文件是否真被长期保留。

`/sdcard/Download/` 只有 412 KB、三个文件，这一条就把「长期保留大量文件」否掉了。下面三条来源都指向同一个结论。

```bash
# 来源一：文件系统中的目录项计数
$ ls -la extracted/Download/ | wc -l
3
# 目录极小，不支持"长期积累"的判断

# 来源二：ext4/f2fs 的目录哈希树顺序（提取后的顺序可能反映原始排序）
$ ls -U extracted/Download/
apkg_bundle_xxx.zip
invoice_2024Q2.pdf
screenshot_20240602.png
# 三个文件的时间接近，形态一致：这是一次性下载后未再整理

# 来源三：设备端 sdcard 的 quota 与使用统计
$ adb shell dumpsys diskstats | grep -A2 '/storage/emulated/0'
/storage/emulated/0: total 128821 MB, used 41203 MB
$ adb shell du -sh /sdcard/Download/
412K
```

`/sdcard/Download/` 整个目录只有 412 KB，三个文件。 和「长期保留大量文件」这个假设不符。

第四步，检查是否存在部分恢复或恢复出厂的痕迹：

```bash
$ adb shell getprop ro.runtime.firstboot
# 空 → 非恢复出厂重置
$ adb shell getprop sys.boot_count
3
$ adb shell dumpsys user | grep -iE 'UserInfo|RESTARTING|partial'
Partial pin: com.digiforensics.chat
UserInfo{0:机主:13} state=RUNNING_UNLOCKED
```

`Partial pin: com.digiforensics.chat` —— 该包处于"部分固定"状态，这是移动设备管理（MDM）域应用在设备迁移时的典型状态。说明该设备曾经历过 MDM 迁移或设备迁移流程。

第五步，量化结论。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 该 `apkg` 文件的内容最后修改于 2024-06-02 22:40:55 | `stat` 的 `Modify` | 强 |
| 该文件 inode 元数据在 2026-03-14 09:17:33 被变更 | `stat` 的 `Change` 时间 | 强（变更事实）；成因待定 |
| `Access` 时间不可作为"最后读取时刻"的可靠证据 | `relatime` 挂载语义 | 强（方法论） |
| `/sdcard/Download/` 目录仅 412 KB、3 个文件 | `du -sh` + `ls` | 强 |
| 该设备曾经历 MDM 迁移流程 | `Partial pin: com.digiforensics.chat` | 中 |
| **该文件被长期保留** | — | **不成立（无证据支持）** |

**准确的表述**：「`apkg_bundle_xxx.zip` 的内容最后修改时间为 2024-06-02 22:40:55，该时间早于 `com.digiforensics.lottery` 的 `firstInstallTime`（22:41:07）12 秒，构成侧载链路的独立印证。**但该文件的存在不证明它被长期保留**：其所在目录 `/sdcard/Download/` 总量仅 412 KB、含 3 个时间接近的文件，符合一次性下载后未再整理的形态；且 `atime` 受 `relatime` 语义限制不可靠，无法据此推断读取历史。」

**未覆盖范围**：文件删除记录（无 USN 等价物）、外部存储的物理写入顺序（需块级分析）、目录项的原始排序（`ls -U` 仅反映提取后顺序）、以及该文件是否曾被复制到其他位置。

**误判对照**

这个案例的误判点在于**四个时间戳被当成了同一个东西**。

`stat` 输出四个时间。它们各自独立，而且各有失效模式：

| 时间戳 | 可靠含义 | 常见误读 |
|---|---|---|
| `Modify` | 内容最后写入 | 被误读为"文件创建时间" |
| `Change` | inode 元数据最后变更 | 被忽略 |
| `Access` | 最后读取（受挂载选项影响） | **被误读为"最后一次打开"** |
| `Birth` | inode 创建 | 被误读为"文件下载时间" |

本次最关键的判断是 `Change=2026-03-14 09:17:33` 这个值。

只盯 `Modify` 和 `Birth`（都是 2024-06-02）的话，会认为所有时间维度一致、文件状态稳定。看到 `Change` 才发现，**至少有一个时间维度在镜像制作时被改动了**。

**但这也不必然是问题。** `adb pull` 会把文件写到分析机的文件系统，目标文件系统不支持保留某些属性、或者 SELinux 标签被重写，`Change` 必然更新。

判据是**看 `Change` 是否早于镜像制作时间**：

| `Change` 时间 | 判读 |
|---|---|
| 早于镜像制作时间 | 元数据在设备上就已变更，元数据本身有证据价值 |
| 等于/晚于镜像制作时间 | 提取过程导致，不可作为设备侧证据 |

本次 `Change=09:17:33` 与镜像制作时段重合，**倾向判为提取过程导致，不可用于推断设备侧状态**；若委托方能提供早于该时点的设备侧元数据（如另一份物理镜像），才可重新判断其成因。

报告里必须写明这一点，否则等于引入了一条自相矛盾的时间线。

第二个误判：用 `Access` 时间证明「用户打开过这个文件」。 `relatime`（readmostly）挂载语义下，atime 只在满足两个条件之一时更新：访问时间早于 mtime，或距上次访问超过 24 小时。这意味着一个在 2024 年创建、当天被读取多次的文件，其 `Access` 会停留在首次读取之后的某个时刻，之后的所有读取都不更新它。

 本案 `Access` 与 `Modify` 相同（都是 22:40:55），正是 atime 从未更新过的典型形态 —— 两个值相同不是「这两个事件同时发生」，是「atime 机制没有运行」。

按错误判据走的代价：报告写「该文件于 2024-06-02 被下载，此后持续保留并在 2026 年仍可访问」。其中「持续保留」由目录体积反驳，「此后被访问」由 atime 机制反驳。**两个论断都是从不可靠字段推出来的。**

**第三个方向**：`Partial pin` 这个字段值得单独提一句。

它在本次分析里只被用来佐证「设备经历过 MDM 迁移」，**但它同时意味着该设备可能受企业 MDM 管控**。若真受管控，设备上的部分数据可能由服务端下发而非本机产生，取证范围也可能要与 MDM 服务方协调。

发现这类字段后，先与委托方确认设备的管控状态，再决定分析范围。不要把它当作一条普通的元数据记录。

<a id="section-35"></a>

## 六、扩展阅读方向

本篇是移动取证的第一站，把大量后续工作压在「能不能读」这一个判断上。

下面几组文章按「你要解决的下一个问题」分组回答，不是按主题罗列。

**先把存储层看懂：拿到数据之前需要知道的东西**

- [应用私有数据与 SharedPreferences](mobile-android-sharedpreferences.md) —— 本篇说 `/data/user/0/<包名>/` 是主战场，这篇拆开这个目录里 XML 键值文件的实际形态与读法。读完它你才会知道 `adb pull` 出来那一堆 `.xml` 各自是什么。
- [SQLite 基础与结构](../mobile-database/mobile-database-sqlite.md) —— 移动端最常见的证据载体。`app.db` 是二进制单文件，读法与 NTFS、ext4 完全不同。
- [SQLite WAL 取证](../mobile-database/mobile-database-sqlite-wal.md) —— **与本篇的传输完整性直接相关**：`-wal` 与 `-shm` 文件如果没和主库一起提取，数据库会呈现"最近记录凭空消失"的假象。
- [ext4 结构与 inode](../../filesystem/filesystem-unix/filesystem-unix-ext4-inode.md) 与 [F2FS 结构](../../filesystem/filesystem-mobile-fs/filesystem-mobile-fs-f2fs.md) —— 早年 Android 用 ext4，近年转向 F2FS。本篇只讲分区与路径，这两篇讲你拿到 `userdata` 镜像后怎么在块层面解析。

**设备状态判定的延伸：从「可读」到「可采」**

- [TWRP 恢复分区取证](mobile-android-twrp.md) —— 设备已锁定、逻辑路线走不通时的物理镜像方案，以及 recovery 提取本身会在检材上留下什么痕迹。
- [Android/Linux 内存取证](../../memory/memory-artifact/memory-artifact-linux-android.md) —— 已 root 设备上的进程内存与 SQLite 页缓存明文残留。**它是文件级提取的补充，不是替代。**
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 本篇「授权 + 最小化 + 状态变更如实记录」三条纪律的来源。
- [证据保管链与委托证明](../../fundamentals/fundamentals-chain/fundamentals-chain-chain-of-custody-and-authorization.md) —— 设备状态快照、`tar` 导出包、哈希文件如何组成一条可复核的保管链。

**时间基准与反取证：结论能不能站住**

- [时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md) —— `firstInstallTime`、Unix 时间戳、设备本地时间三种形态的归一。陷阱 4.1 里那个"凭感觉加减小时"的错误，本文给不出解法，这篇给。
- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— 设备侧的时间戳同样可被改写。读这篇之后回头看 `packages.xml` 的 `firstInstallTime`，你会知道它单独能支撑多强的结论。
- [时间线重建](../../computer/computer-log/computer-log-linux-timeline-reconstruction.md) —— 拿到多源时间戳之后，如何在设备时钟不可信的前提下拼出可辩护的顺序。

**相邻议题：同源数据的其他入口**

- [iOS 备份与沙盒提取](../mobile-ios/mobile-ios-ios-backup-and-sandbox-extraction.md) —— Android 侧的完整对应物。`Manifest.db` 的索引模型与 `packages.xml` 有可比之处，路径与解锁前提则完全不同。
- [SIM 卡取证](../mobile-sim/mobile-sim-sim.md) —— 设备之外最容易被忽略的一层：它证明的是"这张卡在这个时期在这个地方"，不是应用数据。
- [iOS 系统痕迹与 DFU 恢复](../mobile-ios/mobile-ios-dfu.md) —— 当 Android 侧全部数据都在 FBE 密钥后面拿不出来时，同一案件里 iOS 设备往往还有出口。

**判据与反例**

- [SQLite 数据库取证通用方法](../mobile-database/mobile-database-database-forensics-methods.md) —— 移动端数据库的通用核查清单与阴性发现表述模板。
<a id="section-36"></a>

## 七、命令速查

```bash
PKG=com.digiforensics.sample

# ===== 环境与设备状态 =====
adb version && adb devices -l | tee adb-devices.txt    # 授权状态本身是检材信息
{
  echo "=== date ===";  adb shell date;              echo "=== getprop ===";  adb shell getprop
  echo "=== id ===";    adb shell id;                echo "=== getenforce ==="; adb shell getenforce
  echo "=== users ==="; adb shell pm list users;     echo "=== packages ==="; adb shell pm list packages -f -U
} > device-state.txt 2>&1
sha256sum device-state.txt

# ===== 加密状态判断（最关键）=====
adb shell getprop ro.crypto.state ; adb shell getprop ro.crypto.type   # encrypted/unencrypted；block(FDE)/file(FBE)/aes/legacy
adb shell getprop ro.crypto.mountstate                                  # mounted → 已解锁
adb shell mount | grep -iE 'fscrypt|/data/user'
adb shell getprop | grep -iE 'crypto|encrypt|keystore|vold'

# ===== 机型与架构（getprop 不接受多属性名，需逐条取）=====
adb shell getprop ro.build.version.release ; adb shell getprop ro.build.version.sdk
adb shell getprop ro.product.model ; adb shell getprop ro.product.cpu.abi
adb shell getprop ro.serialno

# ===== SELinux / root =====
adb shell getenforce                       # Enforcing / Permissive
adb shell su -c id
adb shell su -c "id -Z"                    # 验证 su 后的 SELinux 域
adb shell su -c "ls -Z /data/data/$PKG"

# ===== 多用户 =====
adb shell pm list users
adb shell su -c "ls -d /data/user/*"; adb shell su -c "ls -d /data/user_de/*"

# ===== 分区（注意 _a / _b 双槽）=====
adb shell ls -l /dev/block/by-name/ ; adb shell cat /proc/partitions
fdisk -l DigiForensics.dd ; partx -s -o START,SECTORS,NAME DigiForensics.dd

# ===== 应用数据提取 =====
adb shell su -c "du -sh /data/data/$PKG"
adb shell su -c "tar -cf - -C /data/data $PKG" > extracted-$PKG.tar   # 推荐（目录级，tar 不可被权限截断）
tar -tf extracted-$PKG.tar | head -50
adb pull /data/data/$PKG/databases extracted/                          # 分目录，tar 不可用时
adb shell "run-as $PKG" ls -la                                        # 仅 debuggable 应用

# ===== 系统工件 =====
adb pull /data/system/packages.xml extracted/ ; adb pull /sdcard/Download/ extracted/
adb bugreport device-bugreport.zip

# ===== 固定与验证 =====
find extracted -type f -exec sha256sum {} \; > hashes.txt
adb shell date; date                     # 必须同时记录，评估时差
sqlite3 extracted/$PKG/databases/app.db ".tables"
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 移动与数据库取证 — Android 数据存储总览」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《Android 数据存储总览》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.vc` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
