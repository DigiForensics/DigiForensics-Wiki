---
title: "TWRP 恢复分区取证与物理镜像提取"
slug: "mobile-android-twrp"
canonical: "https://www.digiforensics.cn/wiki/mobile-android-twrp"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:50+08:00"
source_url: null
source_type: "wiki-sync"
category: "mobile"
space: "移动取证"
node_path: ["Android"]
---

# TWRP 恢复分区取证与物理镜像提取

> **定位**：本文讨论**在设备已锁定、ADB 无 root、无法常规提取**的条件下，如何通过第三方 recovery 拿到全分区物理镜像，以及拿到之后如何把它变成可用的取证材料。
>
> **前置警告**：本流程会**改变设备状态**（在 recovery 或 boot 分区写入一个 recovery 镜像）。这些操作在多数情形下不触碰 `userdata`，但**并非绝对安全**，且可能触及 `FRP`（出厂重置保护）锁、运营商锁、引导加载器锁等状态。**本文的读者是已取得合法授权的取证人员**；授权范围、设备所有权、以及「是否允许改变设备状态」必须事先确认。
>
> **与本板块其他文章的关系**：[Android 数据存储总览](mobile-android-android-data-storage-overview.md) 讲了数据在哪，本文讲**怎么把它完整取出来**；[应用私有数据与 SharedPreferences](mobile-android-sharedpreferences.md) 讲的是拿到之后怎么分析应用数据。

**关键词**：TWRP · NANDroid 备份 · recovery · A/B 分区 · 动态分区 super · lpunpack · FBE 文件级加密 · metadata 分区 · Odin · fastboot · boot 镜像


<a id="section-1"></a>

## 一、概述

Android 设备的提取难度是分层的。常见的可用手段按「对设备状态的改变」从轻到重排列：

| 手段 | 需要条件 | 对设备状态的影响 | 拿到的证据 |
|---|---|---|---|
| **常规逻辑提取** | 已解锁 + ADB 授权 | 几乎无（开关一次 USB 调试） | 应用数据、文件、数据库、日志 |
| **root 提取** | 已 root | 无（但使用痕迹会留在系统里） | 完整 `/data`，可读取其他应用私有目录 |
| **recovery 物理镜像** | bootloader 已解锁，或具备经过验证的授权采集通路；对锁定设备执行标准解锁通常会触发数据清除，不能作为保全既有用户数据的默认步骤 | **会写入 recovery / boot 分区** | **全分区原始镜像（含已删除内容）** |
| 硬件提取（JTAG / ISP / 芯片脱焊） | 需拆机、专业设备 | 物理破坏 | 全部 flash，含被锁死的分区 |

**原始分区读取不等于能解密 FBE 用户数据。** recovery、JTAG/ISP 等路径是否可读，取决于密钥可用性、锁定状态和设备实现；不能以取得原始字节推定已绕过锁屏。 具体来说：

- 锁屏密码与屏幕锁定（PIN / 图案 / 密码）会加密 `userdata`（FBE 场景下还涉及 `metadata` 分区）。recovery 若能成功解密，锁屏就等于被绕过了——因为 recovery 走的是启动早期的路径，不经过 Android 的锁屏凭据输入流程。
- FRP 锁（Factory Reset Protection）与 bootloader 锁**是另一回事**：FRP 锁的是「恢复出厂后需原 Google 账号」，bootloader 锁的是「能否刷写分区」。recovery 提取不需要解锁 bootloader（部分机型），但可能触碰 FRP 状态。
- 加密等级（`FLAG_SECURE_BOOT` / `Verified Boot`）在部分新机型上会阻止第三方 recovery 启动。

所以适用场景是明确的：设备屏幕锁定、用户要求提取设备内数据、且已确认 recovery 路径可行。

拿到物理镜像有三条路，各有明确的适用边界：

| 路线 | 适用设备 | 前提 | 输出 |
|---|---|---|---|
| **NANDroid 备份**（TWRP 内置功能） | 绝大多数可进 recovery 的设备 | recovery 可启动 | tar / 压缩 / 加密的备份文件 |
| **`dd` 直读块设备** | 同上 | recovery 可启动、能挂载外部介质 | 与物理镜像等价的整盘 dump |
| **网络传输**（netcat / adb） | 同上 | 有 USB 数据线、无外部 SD 卡槽 | 通过 adb 端口转发传到工作站 |

三条路不冲突。常见做法是先做 NANDroid 备份（快、可靠、带元数据），再对需要的分区做 `dd` 直读。`dd` 的优势是能精确控制读哪几个分区，不至于把巨大的 `system` 一起拉出来。

有三件事不在这条路径的范围内：不讨论如何解锁 bootloader、不提供 FRP 绕过、不涉及任何移除 FRP 锁的技巧。理由不是技术做不到，而是绕过 FRP 的实质是**在未获授权的情况下取得他人设备数据**，这不属于取证范畴。

设备若因 FRP 或运营商锁无法处理，正确的做法是**停止操作、记录设备状态、回到委托方沟通**，而不是寻找技术手段。判据很简单：一个取证流程如果需要绕过设备所有者的保护机制，那它本质上已经是攻击而非取证。

真正要处理的技术内容是三块：recovery 的分区原理、备份产物格式、以及拿到备份后如何正确解析成可分析的材料。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 Android 分区布局的三个演进阶段

要理解 recovery 能做什么，必须先理解现代 Android 的分区布局。

它经历了三个阶段。不同年代的设备差异极大，这是 recovery 步骤对不上号的主要原因：

阶段一：单槽固定分区（Android 6 及更早）

```
userdata   boot   system   cache   recovery   ...
```

每个分区都是 GPT 里的物理分区，尺寸固定。`recovery` 是独立分区。

**阶段二：A/B 双槽（Android 7–9）**

```
boot_a   boot_b
system_a system_b
...      （关键分区成对出现）
userdata（只有一个）
```

引入 A/B 是为了「无缝更新」：更新写进非活动槽，重启切换，失败可回滚。A/B 设备开始，`recovery` 分区可能被取消，recovery 内容并入 `boot`。

阶段三：动态分区 super（Android 10+）

```
super（一个物理分区，里面装着一堆逻辑分区）
    ├── system_a   system_b
    ├── vendor_a   vendor_b
    ├── product_a  product_b
    ├── system_ext_a
    └── odm_a
userdata
metadata
```

`system`、`vendor` 等变成了 `super` 里的**逻辑分区**，尺寸可动态调整。

这对取证有直接影响：GPT 里不再有 `system` 分区，只有一个 `super`。 拿到裸镜像后，必须用 `lpunpack` 把 `super` 拆开才能看到里面的逻辑分区（见 3.8）。

关键转折点是 Android 12/13 引入的 `init_boot` 与 `vendor_boot` 分离，以及 Android 11+ 的 **Virtual A/B**（快照机制）——后者让 OTA 不再需要完整的第二份副本，而是用写时复制快照，进一步改变了分区布局。

<a id="section-4"></a>

### 2.2 A/B 双槽：为什么恢复镜像会「消失」

这一节解释一个常见现象：**明明刷了 TWRP，重启一次就没了。**

原因在 2.1 的阶段二里。Android 有一个机制叫**启动时的完整性校验与恢复**：

1. 官方 ROM 的 `boot` 分区里带有一个恢复出厂 recovery 的逻辑（在某些机型上是 `boot` 里包含 stock recovery ramdisk，或由 `vbmeta` 校验）；
2. 官方系统每次正常启动时，会检查 recovery 是否被修改，若检测到非官方 recovery 并配置了自动还原，会**用 stock recovery 覆盖回去**；
3. 因此正确的操作纪律是：刷完 TWRP 后不要让它正常启动进 Android，直接手动按键进入 recovery。

对取证而言这条纪律有另一层意义：TWRP 只要停留在 recovery 里不被启动还原，就不影响 `userdata`。

反过来说，如果设备已经被重启进 Android 且 TWRP 被覆盖，需要重新刷一次。但这个「重刷」动作本身会在设备上留下痕迹（见 2.7），所以**尽量一次做对**。

<a id="section-5"></a>

### 2.3 动态分区 super 与逻辑分区

`super` 分区里的逻辑分区由一套「元数据」描述。这套元数据是取证时必须单独提取的东西：

- **几何元数据（geometry）**：描述 `super` 的几何布局（块大小、几何版本号）。
- **LP 元数据（metadata）**：一个头部 + 若干分区表项，列出每个逻辑分区的名字、**起始块号、大小、属性、group**。

**提取方法**：`lpdump` 打印元数据，`lpunpack` 解出逻辑分区镜像。

**取证价值**：`LP 元数据` 是一个体积很小、信息量集中的工件。

它记录了设备的完整分区布局与更新组划分，是重建设备系统结构的依据，体积只有几 KB。**把它单独导出并哈希留档**。

**A/B 设备的元数据是两份**（每个 slot 一份），互相对应的分区名带 `_a` / `_b` 后缀。**分析时两个 slot 都要导出**，否则只能看到一半的布局。

<a id="section-6"></a>

### 2.4 文件级加密 FBE：能不能读取决于 recovery 能力

这一节说明备份格式识别及其限制。

FBE（File-Based Encryption，Android 7+）的工作方式：

- 密钥不是一个全盘密钥，而是**按文件派生**。每个文件有自己的加密密钥，密钥本身用「用户凭据派生密钥」再加密一次（称为「凭据加密」）。
- 密钥材料存放在 **`metadata` 分区**（加 `/data` 下的 `metadata` 目录，以及 `/data/misc/keystore`）。`metadata` 分区本身是被整体加密的，需由 TWRP/系统解密。
- 每个文件的密钥还与**路径名**绑定——**同一个文件被改名后，其密钥派生就变了**。这是 FBE 的一个重要特征（见陷阱 3.11）。

**因此对取证的实际影响是：**

| 情况 | recovery 能否解密 userdata |
|---|---|
| 用户从未设置过锁屏密码 | **能**（凭据加密层不生效或用默认密钥） |
| 设置了锁屏密码，但设备已解锁过一次 | **能**（TWRP 拿到的是已解锁态的密钥） |
| 设置了锁屏密码，设备重启后未解锁 | **取决于 recovery 构建版本** |

**最后一行是 2026 年的现实。** 新 Android 版本对 FBE 做了加固，部分 TWRP 构建已无法解密。

表现是：进 recovery 后 `userdata` 显示挂载成功，但 `Android/data` 下的文件名是乱码、文件打不开，或者整个 `/data` 读出来全是零。

遇到这种情况，正确的做法不是继续折腾 recovery，而是：

1. **记录现象**（挂载成功但文件名乱码 / 读取返回 `EIO` / 大小为 0）——这是可写入报告的观察结果；
2. **转向其他分区**——`system`、`vendor`、`cache`、`persist`、`efs` 等分区往往不受 FBE 保护，仍有取证价值；
3. **评估是否需要硬件提取**（JTAG/ISP）——**这是一个成本与授权的决策，不是技术尝试**。

**绝对不要在报告里写「已提取全部用户数据」**——除非 TWRP 明确显示解密成功且文件可读、可校验。

<a id="section-7"></a>

### 2.5 NANDroid 备份的三种产物与它们的区别

TWRP 的备份不是单一格式，而是按分区的**文件系统类型**选择不同的备份方式。解析前需区分：

| 备份方式 | 内部枚举 | 适用分区 | 产物形态 |
|---|---|---|---|
| **BM_FILES** | 文件级备份 | 挂载为文件系统的分区（`data` / `system` / `cache` 等） | **tar 归档**（可选 gzip 压缩） |
| **BM_DD** | 块级备份 | `boot`、`recovery`、无文件系统的分区 | **原始镜像**（raw image） |
| **BM_FLASH_UTILS** | MTD 备份 | NAND/MTD 闪存设备（老机型） | 厂商工具格式 |

**NANDroid 产物文件名的编码规则**（这决定了怎么判断产物类型）：

```
{分区名}.{文件系统类型}.win{分片号}
{分区名}.{文件系统类型}.win{分片号}.{压缩或加密标记}

实例：
  data.ext4.win000              ← 未压缩未加密
  data.ext4.win000.gz           ← gzip 压缩
  data.ext4.win000.enc          ← AES 加密
  boot.emmc.win000              ← 块级原始镜像
  cache.ext4.win000             ← 同 data
```

> ⚠️ 注意 `.win` 里的数字是分片序号，不是大小。 超过单个文件大小限制的 tar 会被切成 `win000`、`win001`、`win002`……**多个分片必须按序号拼回一个完整归档才能解包**，顺序错了会解出垃圾。见陷阱 4.6。

**TWRP 备份还会自动排除一部分路径**（如缓存目录、系统预装的部分应用）。这些排除规则在 `metadata/exclude.list` 里。

做完整性评估时要把它读出来——被排除的内容在备份里根本没有，报告里不能宣称「已备份全部分区内容」。

<a id="section-8"></a>

### 2.6 备份加密的机制与现实约束

TWRP 支持对备份做加密（编译期可用 `TW_EXCLUDE_ENCRYPTED_BACKUPS` 关闭）。机制是：

```
用户密码 P
    → PBKDF2 派生密钥 K（salt 与迭代次数存在备份元数据里）
    → AES-256 加密备份数据流
```

**关键现实约束：**

1. **密码丢了，备份就永久不可恢复。** 没有后门、没有暴力破解的「技术后门」（PBKDF2 迭代次数虽有限，但面对高质量密码仍是天文数字级）。
2. **TWRP 官方不建议、也不鼓励对取证备份加密。** 因为一旦出事，**分析人员自己也打不开**。
3. **如果检材方提供了加密备份的密码**，正确做法是让**设备方或委托方在 TWRP 里执行恢复操作解密**，而不是让分析方离线破解。

工业实践是：备份不加密，取证过程的保密靠访问控制与保管链，不靠加密备份。

**对本文读者的实操建议**：**取证备份一律不加密。** 如果 TWRP 提示是否加密，选「否」。需要保护数据的话，**在工作站侧对整个备份目录做加密**（比如加密卷或归档加密），这样既能保护数据，又不影响后续分析。

<a id="section-9"></a>

### 2.7 检测层：设备被做过 TWRP 操作后留下什么

取证人员要清楚一个双向问题：既要知道怎么用 TWRP，也要知道**别人用过 TWRP 会留下什么**。

**设备上会留下的痕迹：**

| 位置 | 痕迹 | 说明 |
|---|---|---|
| `recovery` / `boot` 分区 | recovery 镜像被替换 | 与官方镜像哈希不符 |
| `backup` 目录 | `/data/media/0/TWRP/BACKUPS/…` | 如果用户之前做过 NANDroid 备份，会留下完整备份 |
| `TWRP` 目录 | `/data/media/0/TWRP/` 下的配置与日志 | 可能含操作历史 |
| 挂载点 | recovery 挂载分区时写入的 `lost+found` | 证明该分区曾被以读写方式挂载 |
| 系统分区 | 若用户刷过包，`system` 下有第三方应用 | 需与官方镜像对比 |

**关键洞察**：如果一台可疑设备上已经存在 `TWRP` 目录和 NANDroid 备份，这些备份本身就是重要的证据。

它们可能由**另一个人、同一套流程**在更早的时间点提取过，**时间点可能早于本次委托**。

发现这类遗留备份时，先停下自己的备份操作，把原始备份完整保留下来。

反过来，如果本方做了 TWRP 提取，必须在报告里如实记录这次设备状态改变。 见陷阱 4.1。

---

<a id="section-10"></a>

## 三、操作步骤

<a id="section-11"></a>

### 3.1 采集前的状态固定与合法性确认

全文容易被跳过、且后果不可逆的一步。

**★ 不可逆操作，进入前必须确认。**

```bash
# 1. 确认设备当前状态并留档（此步不改变设备）
#    记录：屏幕锁定状态、USB 调试状态、bootloader 状态、连接电脑时的设备标识
```

**确认清单（逐项打勾，任一不满足则停止）：**

- [ ] **已取得书面授权**，且授权范围**明确包含「改变设备状态」**（不只是「提取数据」）
- [ ] 已告知委托方本操作会写入 recovery / boot 分区及其风险
- [ ] **已在同型号的备用机上完整跑通流程**（见 3.3 陷阱）
- [ ] 设备电量充足（见 3.4）
- [ ] 设备外观已拍照留档（操作前状态）
- [ ] 已记录设备型号、序号、IMEI 等标识

**设备状态记录的具体内容**（在连接电脑时采集）：

```bash
# Android 侧（若能连上）
adb devices -l
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release
adb shell getprop ro.boot.verifiedbootstate      # green / orange / red
adb shell getprop ro.boot.flash.locked          # 1 = 已锁
adb shell getprop ro.boot.vbmeta.device_state   # locked / unlocked
adb shell getprop ro.boot.slot_suffix            # _a / _b

# bootloader 侧
fastboot devices
fastboot getvar current-slot                   # a / b
fastboot getvar slot-count                      # 通常 2
fastboot getvar is-userspace                    # 区分 bootloader fastboot 与 fastbootd
fastboot getvar product                        # 确认机型，**必须与 recovery 镜像型号一致**
```

> ⚠️ `ro.boot.verifiedbootstate` 是关键前置判断：值为 `red` 表示启动链校验失败，第三方 recovery 很可能无法启动；`orange` 表示 bootloader 已解锁但校验被破坏，recovery 通常可启动。**这个值要在动设备之前就记录下来**，作为后续分析「为什么 recovery 启动失败」的依据。

<a id="section-12"></a>

### 3.2 用 fastboot 只读导出分区布局

在**任何写操作之前**，先用只读命令把分区布局取出来。这是一份纯读取的、高价值的工件：

```bash
# 进入 bootloader（不是 fastbootd）
adb reboot bootloader

# 列出所有分区（只读）
fastboot getvar all 2>&1 | tee device-vars.txt

# 读 GPT 表（物理分区布局）
fastboot getvar partition-type:boot
fastboot getvar partition-size:userdata
fastboot getvar has-slot:boot

# 动态分区设备需要进 fastbootd
fastboot reboot fastboot
fastboot getvar is-userspace          # 应为 yes
fastboot getvar snapshot-update-status # none / snapshotted / merging
```

把 `fastboot getvar all` 的完整输出保存下来。 它包含分区大小、slot 状态、校验状态、机型标识，是后续所有分析的事实基础。

**这个动作完全不改变设备**（只读），所以即使后续因授权问题终止，这一步的产物依然有效。

<a id="section-13"></a>

### 3.3 安装 recovery 的三条路径与选择依据

★ 这一步会写入设备，`bootloader` / `recovery` 分区内容会改变。

**先判断设备布局类型：**

```text
Q: fastboot getvar has-slot:boot 返回什么？
   返回 1 / true           → A/B 设备，按 A/B 流程
   返回空或无此变量        → A-only 老设备，按老流程

Q: fastboot getvar is-userspace 返回 yes？
   是                      → 动态分区设备（super），刷写需在 fastbootd 里做

Q: fastboot getvar current-slot 返回什么？
   a / b                   → 记下当前 slot，**不要盲目 --slot=all**
```

路径一：A-only 设备（独立 `recovery` 分区）—— 最简单

```bash
fastboot flash recovery twrp.img
# 不要 fastboot reboot！直接拔线，手动按键进 recovery
```

路径二：A/B 设备（无独立 recovery 分区，recovery 在 boot 里）

```bash
# 方案 A：一次性启动（推荐，不写设备）
fastboot boot twrp.img

# 方案 B：永久写入 boot（会覆盖该 slot 的 boot）
fastboot flash boot twrp-boot.img
# 注意 --slot=all 会同时覆盖两个 slot 的 boot
```

**路径三：Samsung 设备（Odin 路线）**

Samsung 不走标准 fastboot，用 Odin + Download 模式：

```text
1. 下载对应机型的 TWRP .tar 或 .img.tar（**型号必须完全匹配**）
2. 关机 → 按 Volume Down + Bixby + Power 直到显示 "DOWNLOADING"
3. USB 连接运行 Odin 的 PC
4. Odin → AP 槽 → 选择 twrp.tar
5. **取消勾选 Auto Reboot**（关键，见 2.2）
6. Start → 等待 PASS
7. 拔线，手动进 recovery（Volume Up + Bixby + Power）
```

**三条路径的选择依据：**

| 情况 | 选择 |
|---|---|
| 不确定能不能成功 | **优先用 `fastboot boot`（一次性）**，失败不留痕 |
| 不想覆盖 `boot` 分区（保留原状） | `fastboot boot`（一次性） |
| 需要长期重复操作 | 永久刷入，但**必须记录原始 boot 镜像已备份** |
| Samsung 机型 | 只能用 Odin |

**无论哪条路径，刷入前务必先备份原始镜像**（见 3.2 的只读导出 + 3.8 的 `dd` 提取），这样即使 recovery 启动失败，也能把设备恢复到原始状态。

<a id="section-14"></a>

### 3.4 备份前的关键检查：充电、SD 卡、设备号

进 recovery 之后、做备份之前，有几个**必须提前处理**的细节：

**① 设备电量。** 备份 / `dd` 直读是耗电大户，中途断电会**留下损坏的备份文件并可能损坏分区表**。**必须接充电器操作。**

**② 移除所有可移除介质。** 如果手机插着 SD 卡（或 microSD），TWRP 可能把备份写到 **SD 卡**上。

这既是数据泄露风险（备份脱离设备控制），也会让后续取回搞不清来源。 操作前把 SD 卡拔掉。

**③ 确认备份目标位置。** 默认备份路径形如：

```
/data/media/0/TWRP/BACKUPS/{设备序列号}/{备份名}/
```

设备序列号与备份名（通常是时间戳）是归档时的关键标识。 取回后要保留完整的目录结构，否则后期无法对应设备与时间。

**④ 加密选项。** 见 2.6——**取证备份一律不加密**。

**⑤ 确认 TWRP 的构建版本与设备匹配。** recovery 主界面会显示版本。不匹配的构建会导致触摸无响应、存储识别失败、或解密失败。

<a id="section-15"></a>

### 3.5 执行 NANDroid 备份

在 TWRP 里：**Backup → 勾选要备份的分区 → 滑动确认**。

**分区选择建议：**

| 分区 | 是否建议备份 | 理由 |
|---|---|---|
| `data` | **必须** | 用户数据主体，取证价值集中在这里 |
| `boot` | **必须** | 内核 + ramdisk，含构建信息与可能的调试符号 |
| `system` / `super` | 建议 | 系统镜像，用于与官方镜像做差异分析（查是否被改装） |
| `vendor` | 建议 | HAL 组件，OEM 定制信息 |
| `cache` | 建议 | **可能有残留的用户数据片段**，未清理的缓存常含可恢复内容 |
| `EFS` | **必须** | **含 IMEI、基带校准等设备身份信息** |
| `persist` | **必须** | 含 WiFi/BT 地址、传感器校准、部分设备配置 |
| `metadata` | 视情况 | FBE 密钥材料，加密相关分析的关键 |
| `modem` / `radio` | 视情况 | 基带固件 |

> ★ **`cache` 分区经常被忽略但仍有残留内容。** 它是系统清理不彻底时的残留区，包含最近使用过的配置文件、临时下载、网页缓存片段。部分「已删除」的内容在 cache 里能找到痕迹。 备份时不要因为它「看起来没用」就跳过。

**备份完成后立刻做两件事：**

1. **在 recovery 里校验备份的完整性**（TWRP 提供 restore 前校验，或至少确认文件大小合理、非 0 字节）
2. 记录每个备份文件的大小、mtime、SHA-256——**在设备上直接算哈希，比取回后再算更有证据价值**（证明文件在离开设备前就是完整的）

<a id="section-16"></a>

### 3.6 拉取备份到工作站

**方案 A：TWRP 内置 ADB 拉取（推荐）**

```bash
# TWRP 里：Advanced → Terminal，确认设备处于 recovery 且 adb 已连接
adb devices                        # 应显示 recovery 状态
adb pull /data/media/0/TWRP/BACKUPS/<设备序列号>/ ./TWRP-Backup/
```

**方案 B：外部介质（无网络时）**

```text
TWRP → Mount → 勾选 External SD
TWRP → Advanced → Terminal
~# dd if=/data/media/0/TWRP/BACKUPS/<序列号>/<备份名>/data.ext4.win000 of=/external_sd/data.tar bs=4M
```

方案 C：网络传输（大备份、无 SD 卡槽）—— 见 3.9

**取回后的第一件事：算哈希。**

```bash
# 在工作站侧对整个备份目录做 SHA-256 清单
find ./TWRP-Backup -type f -exec sha256sum {} \; > backup-sha256.txt

# 与设备侧记录的哈希比对，确认传输完整
```

比对不一致时不要重传整个备份，而是重传不匹配的那几个文件——完整备份动辄几十 GB，重传成本高，且**第一次传输成功的文件哈希已经留档，不受重传影响**。

<a id="section-17"></a>

### 3.7 解析备份：分片、压缩、加密的识别顺序

拿到备份后的解析有**严格的先后顺序**，顺序错了会得到垃圾数据：

```text
第 1 步：识别分片     —— 按 .win000 / .win001 序号排序拼接
第 2 步：识别加密     —— 看有没有 .enc 后缀
第 3 步：识别压缩     —— 看有没有 .gz 后缀，或检测 gzip 魔数
第 4 步：解包 tar     —— 得到原始文件系统内容
```

**第 1 步容易出错。** 正确做法：

```bash
# 只取分片序号部分排序，再按序拼接
ls data.ext4.win* | sort -t. -k4 -V | while read f; do cat "$f"; done > data.ext4.tar

# 验证拼接结果（gzip 魔数 1f 8b，tar 头部在 offset 257 处）
file data.ext4.tar
```

**第 2、3 步的识别**（按优先级，**加密优先于压缩判断**）：

```bash
# 检查是否加密（有 OAES 头或 .enc 扩展名）
ls *.enc 2>/dev/null && echo "存在加密分片"

# 检查是否 gzip 压缩
file data.ext4.win000                          # 会显示 "gzip compressed data"
xxd -l 2 data.ext4.win000                      # 1f 8b = gzip 魔数

# 解压
gzip -d -c data.ext4.win000 > data.ext4.tar
```

**第 4 步解包。** TWRP 生成的 tar 有几处与标准 tar 不同：

| 差异点 | 表现 | 应对 |
|---|---|---|
| 可能含稀疏文件 | 解包报 "sparse file" 或空间不足 | 用 `tar -x --sparse` |
| 扩展的 pax 头 | 某些 tar 实现报错 | 用 GNU tar（BSD tar 常直接失败） |
| 权限/属主 | 恢复时需 UID/GID 映射 | 提取时 `-p --same-owner`（需 root） |

```bash
# 用 GNU tar 解包，保留权限与属主
tar -xpf data.ext4.tar -C ./extracted/

# 验证解包结果
find ./extracted -type f | wc -l
du -sh ./extracted/
```

**解包后立刻验证可用性**——这一步能提前发现「备份是空的/全是零/解密失败」这类问题：

```bash
# 检查是否有实际内容（不是全零）
find ./extracted -type f -size +0 | wc -l

# 抽几个已知位置抽查（数据库完整性等）
sqlite3 ./extracted/data/com.android.providers.contacts/databases/contacts2.db "PRAGMA integrity_check;"
```

<a id="section-18"></a>

### 3.8 处理动态分区与 A/B 双槽

拿到 `super` 或裸镜像后，动态分区设备需要额外一步拆解：

```bash
# 1. 读 super 的 LP 元数据（不改动文件）
lpdump super.img

# 2. 拆出所有逻辑分区
lpunpack super.img out-dir/

# 3. 验证
ls -la out-dir/
# 预期看到：system_a.img system_b.img vendor_a.img vendor_b.img ...

# 4. 两个 slot 都要处理
lpdump --slot 0 super.img
lpdump --slot 1 super.img
```

**A/B 双槽的分析要点：**

- **两个 slot 的内容可能不同**——当前 slot 是最新系统，非活动 slot 可能是旧版本。**这本身是有价值的观察**（比如非活动 slot 上有已卸载的版本）。
- **两个 slot 的 `boot` 都要导出并对比**——差异可能包含调试开关、root 状态、构建配置。
- `fastboot getvar slot-successful:a` 返回 `yes`/`no` 能说明哪个 slot 被标记为成功启动，**这是判断「设备实际在跑哪个系统」的直接证据**。

```bash
# 对比两个 slot 的 boot 分区
sha256sum boot_a.img boot_b.img
cmp boot_a.img boot_b.img && echo "两个 slot 的 boot 完全相同" || echo "存在差异，需进一步分析"
```

<a id="section-19"></a>

### 3.9 网络传输方案及其适用边界

无 SD 卡槽的设备可用网络传输。**两种实现，安全性差异很大**：

实现一：adb 端口转发 + netcat（工作站侧监听）

```bash
# 工作站侧：转发端口
adb forward tcp:8888 tcp:8888

# 手机侧（recovery 的 Terminal 或 adb shell）：
# 读块设备并通过网络发送
dd if=/dev/block/mmcblk0 | busybox nc 127.0.0.1 8888

# 工作站侧另开一个终端接收
nc 127.0.0.1 8888 > DigiForensics-phone.bin
```

**实现二：工作站主动连接手机（反向）**

```bash
# 手机侧监听
dd if=/dev/block/mmcblk0 | busybox nc -l -p 8888

# 工作站侧连接
nc 192.168.1.100 8888 > DigiForensics-phone.bin
```

> ★ 安全警告：这两种方式都是明文传输，无加密、无认证。 在公共网络或不可信网络环境下，这等于把整个设备的数据（含已加密但可能被离线破解的内容、以及未加密的 EFS 身份信息）敞开通听。
>
> **核查**：
> 1. **只在隔离的物理网络里做**（直连网线，或独立的无线路由器网络，不接入任何办公网络）；
> 2. **传输的是加密后的整个归档**——先在设备上把备份打包加密，再传输；
> 3. **优先用 `adb pull`（走 USB 通道）** 而不是网络——USB 至少是点对点的物理连接。

**接收端的完整性验证**（必做）：

```bash
# 一边收一边算哈希，与设备侧算出的哈希比对
nc 127.0.0.1 8888 | tee >(sha256sum > recv.sha256) > DigiForensics-phone.bin
# 或收完后算
sha256sum DigiForensics-phone.bin
```

**`dd` 没有进度显示是个真实问题**——大分区读几十 GB 会长久无输出，容易误判为卡死。务必在另一个终端用 `adb shell ps | grep dd` 或观察文件增长确认进度：

```bash
# 另一个终端：观察接收文件是否在增长
watch -n 5 'ls -lh DigiForensics-phone.bin'
```

---

<a id="section-20"></a>

## 四、常见陷阱

<a id="section-21"></a>

### 4.1 设备状态与合法性

<a id="section-22"></a>

#### 陷阱 1：未确认「改变设备状态」的授权就动手

**现象**：接手一台锁屏的涉案手机，为提取数据直接刷入 TWRP，过程中未与委托方确认这一操作是否被允许。

**原因**：很多委托书的措辞是「提取设备内数据」，**并没有明确包含「可以修改设备」**。

刷 recovery 写的是 `boot` / `recovery` 分区，**这在技术上是对设备的所有权状态产生了改变**，且部分机型会因此变砖。

取证人员往往认为「恢复出厂都是允许的，刷个 recovery 不算什么」——但这两者的风险量级完全不同。

**影响**：**这类错误的后果不可逆。**

设备变砖意味着**全部用户数据永久无法提取**，包括那些本可以合法提取的数据。委托方会要求为「本来能取到的东西没取到」负责；法律上，若设备属于他人且未获明确授权，可能构成对财物的破坏。

**更隐蔽的代价**：设备状态被改变后，**它已经不再能证明「操作前的原始状态」**——而这恰恰是取证的基本要求。

**核查**：**动手前把三件事写进工作记录，缺一不动手**。

(1) 授权文书中明确包含改变设备状态的条款，或已获委托方口头/书面补充确认；

(2) 已在**同型号备用机**上完整跑通全流程（**在真机上第一次尝试 = 拿委托方的设备做实验**）；

(3) 已向委托方书面说明：可能写入 `boot`/`recovery` 分区、可能触发 FRP 状态、极小概率变砖、变砖后数据不可恢复。

这三条不是免责流程，是把不可逆风险提前摊开让决策者知情。

<a id="section-23"></a>

#### 陷阱 2：把 TWRP 提取当成「无损」操作

**现象**：报告里写「已通过 TWRP 提取全部数据，设备状态未受影响」。

**原因**：TWRP 提取确实**不动 `userdata` 的内容**——这部分是对的。

但它**改变了其他东西**：`recovery` 或 `boot` 分区被写入了第三方镜像、设备的启动完整性校验状态可能变化、部分机型在 recovery 挂载分区时会在目标分区写入 `lost+found`。

「用户数据没被改动」和「设备状态没被改变」是两件不同的事，前者成立不代表后者成立。

**影响**：报告被当作「设备原封不动」的证明使用，而实际上设备已被改动。

若后续因设备问题（如变砖、FRP 状态异常）产生纠纷，报告的这句表述会成为不实陈述——而报告是会被反复引用和摘录的，一句不准确的表述会被放大。

**核查**：**把设备状态改变当作取证过程的一部分如实记录**，在报告里单列一节「设备状态变更说明」。

写清四件事：刷入的 recovery 镜像及其版本与哈希、写入的分区（`boot` / `recovery`）、设备启动状态的变化（`verifiedbootstate` 从何值变成何值）、**`userdata` 未被改动的依据**（是操作前后哈希比对，还是仅凭 TWRP 的行为推断——**推断的证据强度要标清**）。

**「未改动」这个结论必须有依据，依据的强度要写明。**

<a id="section-24"></a>

### 4.2 安装与刷写操作

<a id="section-25"></a>

#### 陷阱 3：recovery 镜像型号不匹配

**现象**：刷入后设备无法进入 recovery，或者进入后触摸无响应、存储识别失败。

**原因**：recovery 镜像是严格按设备型号（codename）编译的，不是「通用版」。

看起来「都是同一系列」「都是同一个品牌」，但实际上不同型号、不同区域版本（如国行/港版/美版）、甚至同一型号的不同 SoC 变体，recovery 都可能不兼容。

**更隐蔽的是格式问题**：Samsung 用 `.tar`（Odin），其他品牌用 `.img`（fastboot），A/B 设备用的可能是「打过补丁的 boot 镜像」而不是标准 recovery 镜像——**三者不通用，混用会失败**。

**影响**：**写错分区会导致设备变砖**（例如把 A-only 的 recovery 镜像写进 A/B 设备的 `boot`，或反过来）。变砖后若无原始镜像备份，**设备基本报废**。

即使没变砖，**反复试错本身也会在设备上留下大量写入痕迹**（每次刷写都推进分区状态、生成日志），污染后续分析。

**核查**：**型号确认必须在刷入前完成，且要三重核对**。

(1) `fastboot getvar product` 输出的 codename，与 recovery 文件名里的 codename 逐字符比对；

(2) 型号与 SoC 变体（同一型号可能有不同芯片版本）；

(3) **设备页面明确指定的文件格式**（`.img` / `.tar` / `.zip` 三者不通用）。

**并且——先在备用机上验证，再上真机。**

<a id="section-26"></a>

#### 陷阱 4：刷完 recovery 后让它正常启动进 Android

**现象**：TWRP 刷入成功，手动进 recovery 也没问题，但**重启进系统后 TWRP 消失了**，下次想进进不去。

**原因**：这是**设计如此，不是故障**（见 2.2）。Android 的完整性校验机制会在正常启动时检测到 recovery 被修改，若配置了自动还原，就用 stock recovery 覆盖回去。

很多教程会提「刷完不要重启」，但操作者容易在「看到 TWRP 界面成功了」之后顺手重启验证，然后就丢失了 recovery。

**影响**：**主要是时间成本和设备状态**——需要重新刷一遍，每次刷写都增加设备被改动的程度。

更麻烦的是，如果这次是为了提取数据，中途重启进 Android 会导致数据状态发生变化（应用可能同步数据、清理缓存、系统日志滚动），**提取到的不再是「设备交付时」的状态**。

**核查**：刷入 TWRP 后的下一步不是重启，是立刻做备份。 完整的操作序列应该是：刷入 → 手动进 recovery → 立刻备份 → 拉取备份 → 确认备份可用 → **最后**才考虑是否恢复设备原状。若必须验证能否正常启动，**在数据提取完成后再做**。

<a id="section-27"></a>

#### 陷阱 5：Backup 过程中断电或拔线

**现象**：备份做到一半手机没电或 USB 断了，TWRP 报错，重新备份时报文件已存在或空间不足。

**原因**：`/data` 分区通常容量有限（128 GB 手机扣掉系统后可用空间可能只有 100 GB 出头），而含 `system` 的完整备份轻松超过这个数。

**TWRP 不会自动清理旧的失败备份**，它就静静躺在 `BACKUPS` 目录里占着空间，导致后续备份因空间不足失败。

**影响**：**较坏的情况是分区表受损。**

中断的写操作可能留下不完整的备份文件，**更严重的是中断发生在系统元数据写入时**。虽然 TWRP 备份本质是只读源分区、只写目标位置，风险相对低，但**长时间高负载写入下确实存在文件系统层面受损的可能**。而一旦 `/data` 受损，用户数据就真的没了。

**核查**：**三条纪律**。

**一、接充电器**，不依赖电池续航。

**二、备份前先算所需空间**——`data` + `system` + `super` 全备往往超容量，优先备份 `data` + `boot` + `EFS` + `persist`（数据价值集中、体积最小）。

**三、中断后先清理再重试**：

```bash
# 查看备份占用
du -sh /data/media/0/TWRP/BACKUPS/*
# 删除失败或不完整的备份目录
rm -rf /data/media/0/TWRP/BACKUPS/<设备序列号>/<失败的备份名>
```

**删除前务必确认这批备份不是本案要保留的证据**——`/data/media/0/TWRP/` 下的**历史备份可能来自更早的、与当前委托无关的提取**，它们本身可能就是线索。**清理自己的失败产物之前，先看一遍别人的。**

<a id="section-28"></a>

### 4.3 备份产物与解析

<a id="section-29"></a>

#### 陷阱 6：分片备份没有按序号拼接

**现象**：把 `data.ext4.win000`、`win001`、`win002` 三个分片用 `cat *.win*` 拼起来解压，得到一堆 "Unexpected EOF" 或 "Cannot open: Not a directory"，或者解出来了但文件全是乱码。

**原因**：`cat *.win*` 依赖**文件名字典序**，而 `.win000`、`.win001`、`.win002` 这种零填充格式恰好字典序等于数值序，**这让问题在文件少时看不出来**。

真正出错的情况是分片序号进入两位数时——`.win010` 的字典序排在 `.win002` 前面，拼接结果就是 000, 001, 010, 002…。

**影响**：解出来的归档**看起来解开了（没报错），但内容顺序全错**。

这种错误难以自查——它不会明显报错，只会让后续所有分析基于错误的文件边界。可能解出半截的数据库、半截的图片，日志里看不出异常，但结论完全不可信。

**核查**：**始终按分片序号数值排序拼接**，不用通配符：

```bash
# 提取序号、排序、拼接（-V = 版本化排序，正确处理 .win010 vs .win002）
for f in $(ls data.ext4.win* | sed 's/.*\.win\([0-9]*\).*/\1 &/' | sort -n -k1 | cut -d' ' -f2); do
    cat "$f"
done > data.ext4.tar

# 验证：应是有效 gzip 或 tar
file data.ext4.tar
tar -tf data.ext4.tar > /dev/null && echo "拼接正确" || echo "拼接错误，分片顺序或完整性有问题"
```

**拼接后必须验证**——`tar -tf` 能列出内容说明归档结构完整。**验证失败时先查分片是否齐全**（序号是否连续、有无缺失）。

<a id="section-30"></a>

#### 陷阱 7：用 BSD tar / 7-Zip 解 TWRP 归档

**现象**：在 macOS 上用系统自带的 `bsdtar` 解 TWRP 备份，报 "tar: Damaged tar archive" 或直接卡住；换 Linux 用 GNU tar 就正常。

**原因**：TWRP 用的是 Android 自带的 **toybox/busybox 版 tar**，它对 tar 格式的扩展头（pax 记录）的写法与标准不完全一致。

GNU tar 足够宽容，能忽略不认识的扩展头继续解；BSD tar（macOS 默认）以及部分图形工具则严格校验，遇到不认识的格式直接报错。

这不是备份损坏，是**解包工具的兼容性问题**。

**影响**：轻则换个工具重解；**重则是错误地得出「备份损坏」的结论**——而这个结论一旦写进报告，后续会转向其他取证方向，**而实际上数据是完好的**。

在时间紧张的案件里，这个误判的代价可能是错过关键数据。

**核查**：**统一用 GNU tar**（Linux 上直接用，macOS 上用 `gtar`（brew install gnu-tar）或在 Linux/WSL 环境里解）。**解不开时先换工具排除工具因素，再判断是否损坏**：

```bash
# GNU tar（正确）
tar -xpf data.ext4.tar -C ./extracted/

# 若报 "Damaged archive"，用宽松模式再试
tar -xpf data.ext4.tar -C ./extracted/ --ignore-zeros --warning=no-unknown-keyword

# 还不行，尝试流式解包，跳过损坏的成员
tar -xpf data.ext4.tar -C ./extracted/ --ignore-failed-read
```

`--ignore-failed-read` 能解出大部分内容——个别成员损坏不影响其余文件。解完后统计解出的文件数与预期对比，缺失的部分要在报告里说明。

<a id="section-31"></a>

#### 陷阱 8：把 cache 分区当无用空间跳过

**现象**：做备份时只勾 `data`、`boot`、`system`，认为 `cache` 目录「只是缓存，没价值」。

**原因**：`cache` 分区在出厂时确实用途单一，但**日常使用中它承载了大量未被清理的残留**：WebView 缓存、未完成的下载、临时解压的文件、日志缓冲、甚至**被删除但未被覆盖的数据库片段**。

在部分案件里，`cache` 里能找到 `data` 中已经被删除的证据——因为删除操作只改元数据，**数据块在未被新数据覆盖前仍留在原处**。

**影响**：`data` 里干净，报告写「未发现相关文件」，而证据其实在 `cache` 里。这类阴性结论在自查时不易被发现。

**核查**：**`cache` 必备份，且要单独分析。** 恢复出来之后：

```bash
# 看 cache 里有什么（按修改时间排序，最近期优先）
find ./cache-extracted -type f -printf '%T@ %p\
' 2>/dev/null | sort -rn | head -50

# 关注常见残留位置
ls -la ./cache-extracted/cache/          # WebView / 下载残留
ls -la ./cache-extracted/lost+found/     # 挂载时可能残留的已删除文件片段
```

**`lost+found` 目录值得单独看**——它是文件系统检查点遗失文件时放的地方，**里面的文件常与「被删除但仍可恢复」的那批相关**。

<a id="section-32"></a>

#### 陷阱 9：备份不完整就宣称「已提取全部数据」

**现象**：备份过程因空间不足中断，或部分分区挂载失败，报告却写「已完成全部分区备份」。

**原因**：TWRP 的备份界面在部分分区失败时**不会阻断整个流程**，它可能只是跳过并继续，导致备份看起来「完成了」但缺了几个分区。操作者的注意力在「备份按钮变绿了」，不在「每个分区都勾了、每个都成功了」。

**影响**：**这是结论表述层的问题：报告声称的覆盖范围大于实际覆盖范围。**

报告声称的覆盖范围大于实际覆盖范围，一旦对方（辩护方、审计方）发现缺失的分区，整个报告的可信度都会受影响。而且这种缺失往往**很难在事后补全**——设备状态可能已经变化。

**核查**：**备份完成后逐项核对，并与预期清单比对**：

```bash
# 列出实际产物，与预期分区清单比对
ls -la ./TWRP-Backup/<序列号>/<备份名>/

# 检查每个预期分区是否有对应文件
for p in data boot system EFS persist cache; do
    ls ./TWRP-Backup/*/$p.* 2>/dev/null || echo "缺失: $p"
done
```

报告里必须写明实际备份了哪些分区、哪些没备份、为什么没备份。 「已提取全部数据」这种表述**只在能逐分区列清单并全部对上时才能用**。

<a id="section-33"></a>

### 4.4 加密与完整性

<a id="section-34"></a>

#### 陷阱 10：把「recovery 能进」当成「数据能解密」

**现象**：TWRP 成功启动，`userdata` 挂载成功，看起来一切正常，报告写「已提取用户全部数据」。直到分析阶段才发现 `Android/data` 下的文件名全是乱码、文件打不开。

**原因**：**「挂载成功」和「解密成功」是两件事。**

较旧的 TWRP 构建在 FBE 设备上能挂载 `/data`，但用户目录（`/data/user/0/`）加密，文件名显示为随机字符。

操作者看到挂载成功、能看到目录结构，就认为数据拿到了——直到真正要读文件时才发现问题。这个错误往往在设备已经交还、报告已提交之后才暴露。

**影响**：**报告的核心结论失效。**

它还会误导案件走向——分析人员基于「已解密」的假设去找特定文件，找不到就得出「设备上没有」的结论，**而实际上文件存在，只是没解开**。

**这是典型的「把工具局限当成事实阴性」**。

**核查**：在 recovery 里就要验证解密状态，不要等到分析阶段。

具体做法是**实际打开几个文件看内容**（比如用 TWRP 的文件管理器打开 `data/system/packages.xml`，这是个明文 XML，一定能打开就说明系统部分可读；再试 `data/data/<某应用>/shared_prefs/`，如果文件名正常但打不开或内容乱码，说明用户目录没解密）。

**只有验证通过，才能在报告里写「已提取」。**

验证不通过时，报告要写「recovery 启动成功但 `userdata` 用户目录未能解密，已提取其余可读分区」——**把「没做到的事」和「做到的事」分开写清楚**。

<a id="section-35"></a>

#### 陷阱 11：把备份的 `.info` 元数据当作次要产物丢掉

**现象**：取回备份后只保留了 `.win` 归档文件，把 `.info` 文件和其他元数据当作「配置文件」随手删了。

**原因**：`.info` 文件里记录的是**这次备份的核心事实**：备份时用的分区大小、备份方法（BM_FILES / BM_DD）、**TWRP 版本与构建时间**、设备型号、以及**各分片的校验信息**。

这些不是辅助信息，而是「这份备份是什么、什么时候、用什么设备、以什么参数产生的」的唯一记录。 没有它，备份在证据链上就是一个来源不明的压缩包。

**影响**：**证据链断裂。**

复核者无法确认这个备份的来源，也无法确认它与哪个设备、哪个时间点对应。更实际的问题是：如果 `.info` 里有分区大小的记录，而实际 `.win` 文件大小与之不符，你就发现了备份不完整——而这个证据随着 `.info` 一起丢失了。

**核查**：**整个备份目录原样归档，一个字节都不删。** 包括：

```
TWRP-Backup/
└── <设备序列号>/
    └── <备份名>/
        ├── backup.info          ← 备份元数据，必留
        ├── data.ext4.win000     ← 数据
        ├── boot.emmc.win000     ← 数据
        ├── ...                  ← 其余分片
        └── metadata/            ← 排除规则等（若存在）
```

**归档时对整个目录做哈希清单**（不只是数据文件），并在工作记录里说明每一项的来源与取得方式。

<a id="section-36"></a>

#### 陷阱 12：网络传输未做完整性校验

**现象**：用 `nc` 从手机传输物理镜像，收到文件后直接投入使用，没有做哈希比对。

**原因**：`dd | nc` 这条管道**没有任何完整性保证**——传输中断、网络抖动、nc 异常退出，都会导致**静默截断**。而 `nc` 不会报错，它只是把收到的字节写出去。

**问题出在「静默截断」**：文件看起来有内容（几十 GB），但末尾缺了一大截，而后续的分析工具在解析不完整镜像时可能只分析已读到的部分，剩下的当作「未使用空间」跳过——**不报错，但结论悄悄变成了错的。**

**影响**：**这与陷阱 6（分片拼接错）同类，但更难被发现**。

分片拼接错至少解压会报错，传输截断则**可能完全不报错**。最终后果是：分析基于一份不完整的镜像，报告中「未发现 X」的结论实际是「只分析了部分镜像，未发现 X」。

**核查**：**三步**。

**一、传输前在设备侧算哈希**：

```bash
# 手机侧（recovery terminal）
dd if=/dev/block/mmcblk0 | tee >(sha256sum > /external_sd/source.sha256) | busybox nc 127.0.0.1 8888
```

**二、传输后接收侧算哈希并比对**：

```bash
# 工作站侧
nc 127.0.0.1 8888 | tee >(sha256sum > recv.sha256) > DigiForensics-phone.bin
diff source.sha256 recv.sha256 && echo "传输完整" || echo "传输不完整，必须重传"
```

**三、验证镜像的分区完整性**（这步比哈希更严格，因为它能发现哈希一致但内容本身有问题的情况）：

```bash
# 检查 GPT 头是否在（NTFS/标准分区表设备）
dd if=DigiForensics-phone.bin bs=512 count=1 | xxd | head -5
# 尾部也应完整
dd if=DigiForensics-phone.bin bs=512 skip=$(( $(stat -c%s DigiForensics-phone.bin)/512 - 1 )) | xxd
```

**三步缺一不可。** 只做哈希不做结构验证，会漏掉「设备侧本来就读错了分区」的情况。

<a id="section-37"></a>

### 4.5 结论表述

<a id="section-38"></a>

#### 陷阱 13：把「设备原有状态」与「提取后状态」混为一谈

**现象**：报告里描述设备数据状态时，用的是提取后（甚至提取过程中）观察到的状态，却表述为「设备内数据表明……」。

**原因**：TWRP 提取**本身就改变了一些东西**：挂载分区会写 `lost+found`、备份会在 `/data/media/0/TWRP/` 下生成新文件、recovery 启动本身会更新某些系统状态。

如果操作者在提取过程中打开过某些应用数据（有些 recovery 版本的文件管理器会更新访问时间），那部分数据的状态就变了。

**影响**：报告描述的「设备原始状态」实际上是「提取后的状态」。

这是一个系统性的证据失真。它不是某一个点错，而是**整个状态描述的基准偏移了**。当辩护方追问「你怎么知道这是操作前的状态」，答案是无法回答的。

**核查**：**在报告里明确区分时间基准**：

> 设备数据状态描述基于 TWRP recovery 环境下的只读访问，采集时间为 2026-10-05 14:32（UTC+8）。
> 需要说明：TWRP 备份过程会在 `/data/media/0/TWRP/BACKUPS/` 目录下创建备份文件，
> 并可能在挂载的目标分区创建 `lost+found` 目录。除上述内容外，`userdata` 分区数据未被修改。
> 上述「未被修改」的判断依据为 [操作前后哈希比对 / TWRP 行为特性推断]，**其中推断的证据强度弱于直接比对。**

**这一段限制应当主动写出。**

<a id="section-39"></a>

#### 陷阱 14：把 TWRP 备份当成「原始证据」

**现象**：报告里把 TWRP 备份直接称为「设备原始镜像」或「原始证据」。

**原因**：TWRP 备份是经过处理的产物，不是原始块设备镜像。

它的加工环节至少包括：tar 归档（可能有稀疏文件处理）、gzip 压缩、可选的 AES 加密、**TWRP 内置的路径排除规则**。

每一步都意味着**备份不是字节级的设备原始状态**——**被排除的路径不在里面，稀疏文件被特殊处理过**。

**影响**：在需要「原始证据」的场景（涉及证据资格争议、需要向法庭证明「这就是设备上的东西」）这个表述与材料性质不符。

更实际的问题是：报告基于备份做的分析，**无法直接说「设备上有 X」**——只能说「备份里有 X」，而备份与设备原状之间有加工环节。

**核查**：**严格区分三种材料，并在报告里用准确的名称**：

| 材料 | 术语 | 说明 |
|---|---|---|
| 完整块设备 dump | **物理镜像 / raw image** | 字节级，**取证意义上的「原始」** |
| NANDroid 归档 | **备份文件 / backup archive** | **经过归档、压缩、排除处理的产物** |
| 单个提取的文件 | **提取物 / extracted artifact** | 从上面两者中取出的具体文件 |

**优先产出第一种。** 若只能做 NANDroid 备份，报告要写明「本次提取产出的是 NANDroid 备份文件，其内容经过归档与压缩处理，并受 TWRP 内置排除规则影响（排除清单见 `metadata/exclude.list`）；**未获取字节级完整物理镜像**」。

---

<a id="section-40"></a>

## 五、案例示例

> 本节示例检材均为虚构构造，用于说明判定逻辑，不代表真实案件数据。

<a id="section-41"></a>

### 5.1 案例 A：FRP 锁定下的 data 分区提取

**背景**：某案委托方提供一台 Samsung Galaxy A 系列手机，屏幕已锁定（6 位 PIN），要求提取设备内聊天记录。设备已开启 USB 调试但未 root，bootloader 状态未知。

**第一步：状态确认（只读，不改变设备）**

```bash
$ adb devices -l
0a1b2c3d    device product:a55jfx model:SM_A556E device:a55q transport_id:3

$ adb shell getprop ro.product.model
SM_A556E
$ adb shell getprop ro.build.version.release
13
$ adb shell getprop ro.boot.verifiedbootstate
orange                    ← bootloader 已解锁，第三方 recovery 可启动
$ adb shell getprop ro.boot.flash.locked
0
$ adb shell getprop ro.boot.vbmeta.device_state
unlocked
```

```text
记录：型号 SM_A556E · Android 13 · verifiedbootstate = orange · bootloader 已解锁
FRP 状态：本机无法通过 adb 直接读取（见报告未覆盖范围说明）
```

**★ 授权确认记录**（这一步的缺失会导致前面所有工作失效）：

> 委托书授权范围：提取设备内数据。
> 补充确认（口头，已记录）：同意修改设备 recovery 分区以完成提取。
> 已告知风险：可能写入 boot/recovery、可能影响 FRP 状态、极小概率变砖。
> 已用同型号备用机完整验证流程。

第二步：进入 download 模式并提取分区布局

```text
1. 关机 → Volume Down + Bixby + Power → 显示 "DOWNLOADING"
2. USB 连接运行 Odin 的工作站
3. Odin 中设备显示 ID:COM 端口 → 读取分区信息并记录
```

```bash
$ fastboot getvar all 2>&1 | tee device-vars.txt
current-slot: a
slot-count: 2
slot-successful:a: yes
slot-successful:b: no
is-userspace: no            ← bootloader fastboot，非 fastbootd
product: a55q
has-slot:boot: 1            ← A/B 设备
has-slot:system: 1
```

**关键判读**：`has-slot:boot: 1` 确认是 A/B 设备 → 不能按 A-only 的方式刷 `recovery` 分区。

这直接决定了 3.3 的路径选择。

**第三步：选择路径并刷入**

因是 Samsung + A/B 设备，选择 Odin 路线：

```text
1. 下载对应 codename（a55q）的 TWRP 镜像，格式为 .tar（Odin 专用）
2. 三重确认：文件名 codename == fastboot product == 设备型号
3. Odin → AP 槽 → 加载 twrp-a55q.tar
4. **取消勾选 Auto Reboot**（2.2 的关键纪律）
5. Start → 等待 PASS
6. 拔线 → Volume Up + Bixby + Power 手动进 recovery
```

第四步：recovery 内验证解密状态（3.4 陷阱的关键动作）

进 TWRP 后，**在备份之前先验证**：

```text
TWRP → Mount → 勾选 Data → 挂载成功
Advanced → File Manager →
  /data/system/packages.xml          → 打开成功，明文 XML     ✓ 系统部分可读
  /data/data/                          → 目录名显示为随机字符   ✗ 用户目录未解密
```

**结论：系统部分可读，用户目录未解密。**

这一刻就必须确定——**不能写「已提取全部数据」。**

**第五步：调整备份范围并执行**

既然用户目录不解密，**按「能拿什么拿什么」重新规划**：

| 分区 | 状态 | 决定 |
|---|---|---|
| `data`（用户目录） | 未解密 | 备份，但预期内容受限 |
| `system` | 可读 | 备份，用于差异分析 |
| `EFS` | 不受 FBE 保护 | **必备份**（IMEI、基带校准） |
| `persist` | 不受 FBE 保护 | **必备份**（WiFi/BT 地址等） |
| `cache` | 部分可读 | **必备份**（可能含残留数据） |
| `boot` | 块级 | **必备份** |

**第六步：执行备份并取回**

```text
TWRP → Backup → 勾选上述分区 → 滑动开始
（不加密，见 2.6）
完成后：Advanced → Terminal
```

```bash
~# ls -la /data/media/0/TWRP/BACKUPS/
~# du -sh /data/media/0/TWRP/BACKUPS/*/*

# 设备侧先算哈希（3.5 步骤）
~# find /data/media/0/TWRP/BACKUPS/ -type f -exec sha256sum {} \; > /external_sd/backup.sha256

# 拉取
$ adb pull /data/media/0/TWRP/BACKUPS/R5CT30XXXXX/2026-10-05--14-32-07/ ./TWRP-Backup/
```

**第七步：解析与验证**

```bash
# 按分片序号拼接（4.3 陷阱 6）
for f in $(ls data.ext4.win* | sed 's/.*\.win\([0-9]*\).*/\1 &/' | sort -n -k1 | cut -d' ' -f2); do
    cat "$f"
done > data.ext4.tar
tar -tf data.ext4.tar > /dev/null && echo "拼接正确"

# 用 GNU tar 解包（4.3 陷阱 7）
tar -xpf data.ext4.tar -C ./extracted/

# 验证可读性
$ find ./extracted -type f -size +0 | wc -l
18437
$ sqlite3 ./extracted/data/system/packages.xml > /dev/null 2>&1 || head -3 ./extracted/data/system/packages.xml
<?xml version="1.0" encoding="utf-8" standalone="yes"?>
```

**第八步：结果评估与报告表述**

```text
实际产出：
  data.ext4.tar      → 18437 个非空文件，但 /data/user/ 与 /data/data/ 下
                        文件名为随机字符，内容不可读（FBE 未解密）
  boot.emmc.win000   → 完整块级镜像，可解析
  EFS.emmc.win000    → 完整，可提取 IMEI / 基带校准数据
  persist.emmc.win000→ 完整，可提取设备标识
  cache.ext4.*       → 部分可读，含残留文件
  system.ext4.*      → 完整，可用于差异分析
```

**报告表述（区分「做到」与「没做到」）**：

> 设备型号 SM_A556E（`fastboot product: a55q`），Android 13，bootloader 状态 unlocked，`ro.boot.verifiedbootstate = orange`。
> 采集时间：2026-10-05 14:32:07（UTC+8）。
>
> **已提取内容**：
> - `boot`、`EFS`、`persist`、`system`、`cache` 分区完整备份（字节级 tar 归档，分区明细见附件 1）
> - `data` 分区备份已获取，但用户目录（`/data/user/0/`、`/data/data/`）未成功解密，文件内容不可读
>
> **未提取内容**：
> - 用户目录内的应用私有数据、聊天记录、数据库文件 —— 因设备启用了文件级加密（FBE）且所使用 TWRP 构建未能解密
> - FRP（出厂重置保护）状态无法通过本方法读取
>
> **未覆盖范围**：
> - 未获取字节级完整物理镜像（本次为 NANDroid 归档，受 TWRP 内置排除规则影响，排除清单见 `metadata/exclude.list`）
> - 硬件层提取（JTAG / ISP）未进行，该方式需另行评估授权与技术条件
> - 基带固件（`modem`）分区未备份
>
> **设备状态变更**：已在 `boot` / `recovery` 分区写入 TWRP 镜像（版本与哈希见附件 2）。`userdata` 分区内容未修改 —— 依据为 TWRP 备份机制的只读特性推断，**未做操作前后哈希比对**。

**这段表述的价值**：三段分开写清了「做到了什么」「没做到什么」「没查什么」，并且**明确标注了「未修改」的依据强度是推断而非比对**。

<a id="section-42"></a>

### 5.2 案例 B：A/B 双槽设备上恢复镜像「消失」

**背景**：某团队为客户提取一台 OnePlus 设备的数据。按社区教程操作，`fastboot flash boot twrp.img` 成功，进入 TWRP 完成了备份。

但**为验证设备状态正常**，操作者重启进了 Android，随后发现 TWRP 已消失，无法再次进入。

**分析**：这是陷阱 4.4 描述的典型场景。**OnePlus 属于 A/B 设备**（`has-slot:boot: 1`），recovery 内容在 `boot` 分区里，官方系统启动时会检测并还原。

**为什么会发生**：教程的顺序是「刷入 → 重启验证 → 再进 recovery」，而正确顺序应是「刷入 → 立刻备份 → 拉取 → 验证 → 最后才考虑恢复原状」。

操作者把「验证设备能正常启动」当成了自然的下一步，而这个动作恰恰触发了 recovery 被覆盖。

**实际影响评估**：

| 项 | 状态 |
|---|---|
| 首次备份 | **已完成并取回，未丢失** |
| `userdata` 数据 | 首次备份在重启前完成，数据完整 |
| 设备状态 | `boot` 分区已被还原为 stock，**TWRP 已移除** |
| 再次提取 | 需要重新刷入 TWRP（设备又要被改一次） |

**关键结论：数据没丢，因为备份在重启前就完成了。**

如果备份尚未完成就重启，则**已完成的分片会被孤立**——TWRP 被还原不影响已写入 `/data` 的备份文件，但**正在进行的备份会中断**。

**报告中的说明**：

> 本次提取过程中，设备在完成 NANDroid 备份并取回备份文件后，因验证启动状态执行了一次重启。
> 该重启导致 `boot` 分区被系统完整性校验机制还原为官方镜像，TWRP 已从设备移除。
> 此操作发生在备份完成之后，未影响已获取的备份数据的完整性与可用性。
> 设备当前 `boot` 分区内容为官方版本，设备状态与提取前一致。

**流程改进建议**（本案例的真正价值）：

```text
修正后的操作序列：
1. 刷入 TWRP
2. 立即进入 recovery（不重启）
3. **立刻执行备份**              ← 数据在这里就已经拿到
4. 拉取备份到工作站并校验哈希
5. 验证备份内容可用性（解包抽查）
6. （可选）恢复设备原状：刷回原始 boot 镜像
7. **最后**才做「能否正常启动」的验证

关键：把「验证设备能开机」这个看起来无害的动作，放到流程最后。
```

**这个案例说明了一件事**：recovery 提取流程里的每一步顺序都有后果。

数据获取的时点应该在所有「可能触发系统行为」的操作之前，而不是之后。

<a id="section-43"></a>

### 5.3 阴性发现的表述方式

移动取证里**大量结论是阴性的**——设备没解锁、目录没解密、分区没备份、应用数据不存在。

阴性结果怎么写，直接决定报告能不能用。

**不可接受的写法：**

| 写法 | 问题 |
|---|---|
| 「已提取设备全部数据」 | 实际未解密用户目录时使用，**结论强度远超事实** |
| 「设备中未发现聊天记录」 | 未解密时这样说，等于用工具局限冒充事实 |
| 「TWRP 无法解密 FBE」 | 结论太笼统，且未区分「数据不可读」与「数据不存在」 |
| 「设备状态未受影响」 | 实际 `boot` 分区已被改写 |

**可接受的分层写法：**

**第一层：设备与操作事实**

> 设备型号 SM_A556E（`fastboot product: a55q`），Android 13，bootloader 状态 unlocked，slot 状态 `current-slot: a`、`slot-successful:a: yes`、`slot-successful:b: no`。
> 采集方式：通过 TWRP 执行 NANDroid 备份，采集时点 2026-10-05 14:32:07（UTC+8）。

**第二层：已获取内容（逐项列举，可核查）**

> | 分区 | 获取 | 形态 | 可读性 |
> |---|---|---|---|
> | `boot` | 是 | 块级 tar 归档 | 完整可解析 |
> | `EFS` | 是 | 块级 tar 归档 | 完整可解析 |
> | `persist` | 是 | 块级 tar 归档 | 完整可解析 |
> | `system` | 是 | 文件级 tar 归档 | 完整可解析 |
> | `cache` | 是 | 文件级 tar 归档 | 部分可读 |
> | `data` | 是 | 文件级 tar 归档 | **系统目录可读，用户目录未解密** |

**第三层：明确未获取的内容及其原因**

> **未获取内容**：
> - `/data/user/0/` 与 `/data/data/` 下的应用私有数据 —— 设备启用了文件级加密（FBE），所使用 TWRP 构建未能解密。表现为：目录可挂载，文件名显示为随机字符，文件内容不可读。
> - **重要区分**：上述状态表示**数据存在但不可读**，**不能据此认定相关数据不存在**。
> - `modem` / 基带固件分区未纳入备份范围。
> - FRP 状态无法通过本方法获取。

**第四层：未覆盖范围与方法限制**

> **未覆盖范围与方法限制**：
> - 本次产出为 **NANDroid 归档文件**，非字节级完整物理镜像。归档过程受 TWRP 内置排除规则影响（排除清单见 `metadata/exclude.list`）。
> - 未进行硬件层提取（JTAG / ISP / 芯片脱焊）。该方式可绕过屏幕锁定与 FBE，但需评估拆机授权与设备后续可用性。
> - 未检查已删除文件的恢复空间。归档方式对已删除内容的保留能力有限，若需恢复已删除文件，应使用块级 `dd` 镜像配合文件雕刻。

**第五层：设备状态变更（不可省略）**

> **设备状态变更记录**：
> - 已向 `boot` 分区写入 TWRP recovery 镜像（版本 / 构建 / SHA-256 见附件 2）。
> - 备份过程在 `/data/media/0/TWRP/BACKUPS/` 下创建了备份文件。
> - 备份过程可能在挂载的目标分区创建 `lost+found` 目录。
> - `userdata` 分区内容**未被修改**。该判断依据为 TWRP 备份机制的只读特性推断，**未进行操作前后的哈希比对**。

**把这五段拼起来读，检查三件事：**

1. **「未获取」和「不存在」是否被明确区分了？** —— 第四段那句「数据存在但不可读，不能据此认定相关数据不存在」是整段的核心
2. **产出物的性质是否说清了？** —— 「NANDroid 归档」与「物理镜像」不是一回事
3. **设备状态改变是否如实记录了？** —— 且**判断依据的强度**是否标注清楚

只写前三段在形式上完整，第四、五段则决定报告的结论边界。

移动取证的阴性结果容易被误读成「设备里什么都没有」，所以「拿不到 ≠ 不存在」要在每处阴性结论里写清。

---

<a id="section-44"></a>

## 六、扩展阅读方向

**前置与基础。** 拿到物理镜像之前得先知道分区布局长什么样：
`system` / `vendor` / `data` 各自的职责，以及 FBE 加密在 `user` 分区上落到了哪一层。
分区的块级镜像怎么解析，取决于它用的是什么文件系统——近年设备多是 F2FS，
早期设备与外置 SD 卡仍是 FAT 家族，两者的块映射与元数据位置完全不同。见
[《Android 数据存储总览》](mobile-android-android-data-storage-overview.md)、
[《F2FS 结构》](../../filesystem/filesystem-mobile-fs/filesystem-mobile-fs-f2fs.md)、
[《FAT 系列结构》](../../filesystem/filesystem-mobile-fs/filesystem-mobile-fs-fat.md)。

**同层深入。** 解包出 `data` 分区之后，真正的证据大头在应用私有目录里。
但这里有个绕不开的前提：**FBE 的密钥与路径绑定，路径一变密钥就变**，
所以「换了提取路径就读不出文件」是机制本身导致的，不是解密失败。
应用侧怎么走见[《内部存储与 SharedPreferences》](mobile-android-sharedpreferences.md)，
系统 APK 从 `system` 分区怎么提见[《APK 逆向与 Manifest 分析》](mobile-android-apk-manifest.md)。

**相邻议题。** `data` 分区里常见的证据载体是 SQLite，而 SQLite 的 WAL 场景有它自己的一整套坑，
见[《SQLite-WAL 取证》](../mobile-database/mobile-database-sqlite-wal.md)。
iOS 侧有个严格对应物值得对照：**旧版本快照保留原始状态**这个概念，
在 APFS 上的实现与 Android 的 recovery 分区思路是同一类问题的两种解法，
见[《APFS 容器与快照》](../../filesystem/filesystem-apple-fs/filesystem-apple-fs-apfs.md)。

**工具与判据。** 分区镜像挂到工作站这一步的纪律，与第三章 3.7 的解包处理属于同一类操作，
写保护与只读是前提，见[《只读挂载与安全接入》](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md)。
物理接触不可行时的替代路径见[《远程勘验与在线取证》](../../imaging/imaging-acquire/imaging-acquire-remote-evidence-collection.md)。
FBE 与 BitLocker 值得对照读：前者是**凭据层**加密、后者是**全卷层**加密，
密钥存放位置与解密前提完全不同，直接影响取证能做到哪一步，
见[《BitLocker 全卷加密取证》](../../crypto/crypto-volume/crypto-volume-bitlocker.md)。

**判据与反例。** 恢复分区里能读到内容，不等于当前 `user` 分区的数据就完整存在——
recovery 走的是另一套挂载与加密路径，两者的可见范围不同。
本篇案例 A 中「`/data` 部分实际不可用」时的表述方式就是按这个前提写的：
阴性结论必须写清是哪个分区、哪个时间点、用什么路径读到的，
不能笼统写成「未获取到数据」。原则来源见
[《取证流程与原则》](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md)。

---

<a id="section-45"></a>

## 七、命令速查

**设备状态确认（只读，优先执行）**

```bash
adb devices -l
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release
adb shell getprop ro.boot.verifiedbootstate      # green / orange / red
adb shell getprop ro.boot.flash.locked          # 1 = 已锁
adb shell getprop ro.boot.vbmeta.device_state
adb shell getprop ro.boot.slot_suffix            # _a / _b

fastboot devices
fastboot getvar product                        # 必须与 recovery 镜像 codename 一致
fastboot getvar current-slot
fastboot getvar slot-count
fastboot getvar slot-successful:a
fastboot getvar is-userspace                    # yes = fastbootd
fastboot getvar has-slot:boot                  # 1 = A/B 设备
fastboot getvar all 2>&1 | tee device-vars.txt
```

**recovery 刷入（★ 改变设备状态）**

```bash
# A-only 设备：独立 recovery 分区
fastboot flash recovery twrp.img

# A/B 设备：推荐一次性启动，不写设备
fastboot boot twrp.img

# A/B 设备：永久写入（会覆盖该 slot 的 boot）
fastboot flash boot twrp-boot.img
fastboot --slot=all flash boot twrp-boot.img   # 同时覆盖两个 slot

# 动态分区操作必须在 fastbootd 里做
fastboot reboot fastboot
fastboot getvar is-userspace
```

**备份产物处理**

```bash
# 设备侧：查看备份占用与完整性
ls -la /data/media/0/TWRP/BACKUPS/
du -sh /data/media/0/TWRP/BACKUPS/*/*

# 设备侧：算哈希（离开设备前先留档）
find /data/media/0/TWRP/BACKUPS/ -type f -exec sha256sum {} \; > /external_sd/backup.sha256

# 拉取
adb pull /data/media/0/TWRP/BACKUPS/<序列号>/<备份名>/ ./TWRP-Backup/

# 工作站侧：整体哈希清单
find ./TWRP-Backup -type f -exec sha256sum {} \; > backup-sha256.txt
```

**分片拼接与解包**

```bash
# 按序号数值排序拼接（-V 正确处理 .win010 vs .win002）
for f in $(ls data.ext4.win* | sed 's/.*\.win\([0-9]*\).*/\1 &/' | sort -n -k1 | cut -d' ' -f2); do
    cat "$f"
done > data.ext4.tar

# 验证拼接
tar -tf data.ext4.tar > /dev/null && echo "拼接正确" || echo "拼接错误"

# 识别压缩与加密
file data.ext4.win000
xxd -l 2 data.ext4.win000          # 1f 8b = gzip
ls *.enc 2>/dev/null               # 加密分片

# 解压（GNU tar，macOS 用 gtar）
gzip -d -c data.ext4.win000 > data.ext4.tar
tar -xpf data.ext4.tar -C ./extracted/
tar -xpf data.ext4.tar -C ./extracted/ --ignore-failed-read   # 容忍局部损坏
```

**动态分区处理**

```bash
# 读 LP 元数据
lpdump super.img
lpdump --slot 0 super.img
lpdump --slot 1 super.img

# 拆出逻辑分区
lpunpack super.img out-dir/
ls -la out-dir/

# 对比两个 slot
sha256sum boot_a.img boot_b.img
cmp boot_a.img boot_b.img && echo "两 slot 相同" || echo "存在差异"
```

**块设备直读与网络传输**

```bash
# 设备侧：读块设备（先用 ls -l 确认设备名，mmcblk 还是 sda 因机而异）
ls -l /dev/block/by-name/
dd if=/dev/block/mmcblk0 of=/external_sd/phone.bin bs=4M

# adb 转发 + netcat（★ 明文传输，仅限隔离网络）
adb forward tcp:8888 tcp:8888
# 设备侧：
dd if=/dev/block/mmcblk0 | busybox nc 127.0.0.1 8888
# 工作站侧：
nc 127.0.0.1 8888 | tee >(sha256sum > recv.sha256) > DigiForensics-phone.bin

# 进度观察（dd 无进度显示）
watch -n 5 'ls -lh DigiForensics-phone.bin'
```

**已删除内容与残留检查**

```bash
# cache 残留（按时间排序）
find ./cache-extracted -type f -printf '%T@ %p\
' 2>/dev/null | sort -rn | head -50

# lost+found：文件系统检查点遗失文件的存放处
ls -la ./extracted/lost+found/

# 备份排除规则
cat ./TWRP-Backup/*/*/metadata/exclude.list
```

---

**版权与引用声明**

本文档采用知识共享署名-相同方式共享 4.0 国际许可协议（CC BY-SA 4.0）发布，允许他人复制、传播与改编本作品，衍生作品须以相同协议发布并保留署名。

本文档内容为基于公开技术知识撰写的原创方法学说明，**未复制、摘录或改写任何第三方站点的具体文本内容**。文中提及的一切商业软件、命令行工具、库、分区名称、API 与产品，包括但不限于 TWRP、Odin、Android Bootloader、fastboot、fastbootd、ADB、NANDroid、lpdump、lpunpack、pigz、OpenAES、PBKDF2、AVB（Verified Boot）、SAMSUNG、Google、OnePlus、netcat / busybox，以及 Android 系统的 `super`、`dynamic partitions`、`Virtual A/B`、`FBE`、`metadata` 等专有概念与标识，**其名称、商标与权利归各自权利人所有**，本文仅出于技术说明与事实引用的目的提及，不暗示与任何权利人存在合作、授权或认可关系。

文中示例检材 `DigiForensics.dd`、`DigiForensics-usb.e01`、`DigiForensics-phone.bin` 及涉及的文件名、设备型号、设备序列号、IMEI、IP 地址、账号、路径、哈希值与时间戳数值，**均为为说明技术方法而虚构或脱敏构造的示例数据**，不指向任何真实的个人、机构、设备或案件。示例中出现的分析方法与判定逻辑仅用于教学与能力建设。

本文档所讨论的技术操作**具有改变设备状态的能力**，包括向设备的 `boot` / `recovery` 分区写入镜像。相关操作必须在取得合法授权、明确告知风险、并在同型号备用设备上完成流程验证的前提下进行。本文档不提供任何用于绕过设备所有者保护机制（如出厂重置保护 FRP、运营商锁、引导加载器锁）的方法。
