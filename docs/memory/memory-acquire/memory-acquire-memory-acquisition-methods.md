---
title: "内存采集方法"
slug: "memory-acquire-memory-acquisition-methods"
canonical: "https://www.digiforensics.cn/wiki/memory-acquire-memory-acquisition-methods"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:51+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "memory"
space: "内存与专项取证"
node_path: ["镜像采集"]
---

# 内存采集方法

<a id="section-1"></a>

## 一、概述

内存只有一次采集机会，而"能不能采到"这件事在不同平台上的答案完全相反。

Windows 加载一个签名驱动就能拿到全量物理内存。Linux 静态二进制扔过去就能跑。Android 需要 root 加上放行 SELinux。

现代 macOS 则在默认状态下**技术上已近乎不可行**。

如果你把这四者当成同一件事处理，结果通常是：在 Windows 上采到了但把 minidump 当物理镜像解析，在 Linux 上采到了但被地址空洞坑了结构偏移，在 Android 上耗掉两小时试 `dd if=/dev/mem`，在 macOS 上把整晚时间花在 kext 签名研究上。最后交出一份没有内存证据的报告。

要解决的就是：在动手之前先判断这条平台该走哪条路，以及每条路的失败方式长什么样。

这一步落在**采集环节的执行**，紧接在[内存取证总览](memory-acquire-memory-forensics-overview.md)的现场判断之后、Volatility 分析之前。上游是"目标机还开着吗、有没有存储、能不能授权"，下游是"镜像能不能被读进去"。一个必须先分清的边界在[二、核心原理](#section-2)开头：这里只管"把内存搬出来"，搬出来之后能不能读是 Profile 与框架的问题。

硬件采集（PCIe FPGA）是这条执行路径的替代方案，不属于它的组成部分。

四个平台的读取通道、产物与硬约束各不相同：

| 平台 | 读取通道 | 产物 | 关键约束 |
|---|---|---|---|
| Windows | 释放签名驱动 → SCM/`NtLoadDriver` 加载 → 读物理地址空间 | `DigiForensics-mem.raw`、`DigiForensics-mem.aff4`、`lsass.dmp` | raw 与 minidump 是两种地址空间语义 |
| Linux | `AVML` 读 `/dev/crash`；`LiME` 加载 `lime.ko` | `format=lime` / `raw` / `padded`、Snappy 压缩包 | `lockdown` 非 `none` 时 AVML 静默失败 |
| macOS | `osxpmem` 依赖 kext | `hiberfil` 类休眠镜像 | SIP + kext 签名使在线采集不可行 |
| Android | adb + root + SELinux 放行 | `/sdcard/DigiForensics-mem.raw` | `/dev/mem` 自 5.x 起默认不可用 |

`format=lime` 与 `format=raw` 的差别决定了后续结构偏移是否可信。 `.aff4` 与 `.raw` 的差别决定了证据完整性论证的便利度。

据此能回答的是这些：这台机器在采集区间内有哪些进程在跑、有哪些网络连接还挂着、内存里有没有可执行私有页、已解密的会话密钥是否驻留。更重要的是，能回答"哪些信息在采集后彻底消失"——这决定了后续分析必须在镜像里找什么。

回答不了的是这些：用户在采集区间内具体看到什么、精确到秒的行为顺序、以及采集前已经发生的行为。另外，采集成功判据本身也回答不了"镜像为什么没有某样东西"——那需要回到内容级验证，而不是这里的判据。

动手之前，先确认你已经掌握：目标平台的基本提权路径（Windows 驱动加载、Linux 内核模块、Android root 与 `su`）、命令行参数转义的基本规则（`insmod` 的引号问题就出在这里）、以及哈希与保管链的记录方式。内核模块与 root 提权这两块不熟，先看[Linux Shell 痕迹与命令历史](../../computer/computer-shell/computer-shell-shell.md)；

对镜像格式（raw / AFF4 / E01）的区别还不确定，先看[证据格式与转换](../../imaging/imaging-acquire/imaging-acquire-evidence-image-formats.md)。采完之后不知道怎么把镜像接进分析环境，回[只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md)。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 读物理内存的三条路

所有采集工具本质上只有三种实现路径：

| 路径 | 机制 | 代表工具 | 干扰程度 |
|---|---|---|---|
| **驱动 / 内核模块** | 在内核态打开设备对象，直接读物理地址空间 | WinPmem、DumpIt、FTK Imager、LiME | 低 |
| **特殊设备节点** | 读内核暴露的字符设备 | AVML（`/dev/crash`） | 低 |
| **内存总线 / 硬件** | 绕过 CPU，直接经 PCIe 读内存控制器 | PCIe FPGA 采集卡 | **极低（几乎不影响系统）** |

> **硬件采集为什么最"干净"**：软件采集无论怎么做，都要占用目标机的内存（镜像缓冲区）、要加载代码、要把页 pin 住。

而 FPGA 采集卡是用独立硬件通过 DMA 读内存，目标机 CPU 完全不知道自己被读了，**连镜像缓冲区都不需要**。

代价是需要专用硬件、且只支持 x86/x64 台式与服务器。

<a id="section-4"></a>

### 2.2 Windows 侧：驱动加载是必经之路

Windows 没有暴露"读物理内存"的普通用户态接口。WinPmem、DumpIt、FTK Imager 的工作方式都一样：

```
1. 把一个签名驱动从资源段释放到 %TEMP%
2. 用 SCM 或直接调用 NtLoadDriver 加载它
3. 驱动在内存里扫描物理地址范围（通过 \\.\PhysicalDrive0 或内存管理接口）
4. 把读到的数据流式写入目标文件
5. 驱动卸载，临时文件删除
```

**这条路径的取证含义**：

| 观察点 | 取证价值 |
|---|---|
| `%TEMP%` 下的随机名驱动文件 | 若现场被查获残留，说明有人采过内存 |
| 事件日志中的服务安装记录（System.evtx，事件 ID 7045） | 记录了驱动服务名与路径 |
| `C:\Windows\System32\drivers\` 下的异常 `.sys` | 部分工具会留下驱动 |
| MemProcFS / `vol.py windows.modules` 中的匿名模块 | 内核里可能有未在磁盘上的驱动 |

> **这些痕迹本身是"有人做过内存采集"的证据**——与[第 10 篇](../memory-artifact/memory-artifact-memory-evidence-and-reporting.md)讲的 Sysmon 事件互为印证。

<a id="section-5"></a>

### 2.3 Linux 侧：LiME 与 AVML 的取舍

| 维度 | LiME | AVML |
|---|---|---|
| 实现方式 | **内核模块**（`lime.ko`） | **用户态静态编译二进制** |
| 编译依赖 | 需要目标机的内核头文件（`/lib/modules/$(uname -r)/build`） | **不需要**，编好的静态二进制直接跑 |
| 输出格式 | `lime`（带地址范围表）/ `raw` / `padded` | LiME 格式（未压缩时），`--compress` 用 Snappy |
| 压缩 | 无（可后处理） | `--compress` 采集时即压缩 |
| 远程推送 | 支持（`path=tcp:...`） | 支持（`--url` / `--sas-url` / `stream tcp`） |
| 风险 | 加载内核模块会在内核里留痕迹，且可能与安全模块冲突 | 纯用户态，痕迹少 |

> **实战选择建议**：能在联网环境提前把 LiME 编译好就用 LiME（格式生态最成熟）；目标机在内网/断网、或内核头文件与运行内核不匹配时，用 AVML（静态二进制，扔过去就能跑）。

LiME 的三种输出格式：`raw` 是纯物理内存、地址=文件偏移但**丢失地址映射表**；`padded` 是 raw + 对未映射区补零；**`lime` 带地址范围元数据，是首选**。

> **为什么推荐 `format=lime`**：物理内存并非全地址空间连续存在。`lime` 格式在文件头记录了每个分段的地址范围，分析工具据此正确映射。raw 格式遇到"空洞"（MMIO 区间、设备保留区）时，偏移与地址的对应关系就断了。

<a id="section-6"></a>

### 2.4 Android：三重锁

```
第一重：root —— 没有 root，读不了 /dev/mem 也不能加载模块
第二重：SELinux —— 即便 root 了，Enforcing 模式下也禁止访问内存设备
第三重：设备指纹 —— 不同厂商 ROM 对上述机制的实现不同，通用命令常常失效
```

**SELinux 是最容易踩坑的一环**：

```bash
# 确认当前状态：Enforcing（拦截）/ Permissive（记录但不拦截）/ Disabled
adb shell getenforce
adb shell su -c "setenforce 0"                      # 方式 A：临时切 Permissive（会留状态变更痕迹）
adb shell su -c "setsebool -P allow_execmem 1"      # 方式 B：Enforcing 下的正规做法
# 方式 C（最彻底）：内核编译时完全关闭 SELinux，仅适用于自建 ROM 或专用设备
```

> ⚠️ `setenforce 0` 本身会改变系统安全状态。如果后续要对该设备做其他取证，这一状态变更必须记录在报告里；恢复为 `setenforce 1` 后再取证更规范。

**`/dev/mem` 为何不可用**：新内核（自 5.x 起）默认限制 `/dev/mem` 只暴露前 1 MB 甚至完全禁止，这是一项针对 `/dev/mem` 攻击面长期存在的加固措施。所以不要在 Android 上指望 `dd if=/dev/mem`。

<a id="section-7"></a>

### 2.5 macOS：SIP 与 kext 签名

Apple 从 OS X 10.11 起引入 SIP（System Integrity Protection），默认阻止加载未签名或未授权的第三方 kext。`osxpmem` 这类工具依赖一个内核扩展（kext）来读物理内存，因此：

| 系统状态 | 可行性 |
|---|---|
| 完全默认的现代 macOS + SIP 开启 | **不可行**，且技术上难以绕过 |
| 需重启进入恢复模式降低安全策略 | 降低后仍需 kext 通过签名校验 |
| 企业环境通过 MDM 下发并授权了取证工具 | 可行（Apple 为此在企业场景留了正式通道） |

> 结论：现代 macOS 的在线内存采集在技术上已近乎不可行。 若确需 macOS 内存证据，现实路径是**关机后取证休眠镜像**（`/private/var/vm/sleepimage`，或 12 点后改为 `hibernation` 相关文件）——休眠本质是压缩后的内存转储，虽然是"休眠那一刻"而非"关机那一刻"，但仍是有效的内存证据。macOS 侧的其他工件见[计算机取证 macOS 板块](../../computer/computer-security/computer-security-security-artifact-map.md)。

Linux 与 Android 的具体采集命令、AVML 与 LiME 的取舍、root 与 SELinux 的门槛，见[第 09 篇](../memory-artifact/memory-artifact-linux-android.md)。

---

<a id="section-8"></a>

## 三、操作步骤

<a id="section-9"></a>

### 3.1 Windows：三种采集方式

方式 A：WinPmem（推荐，开源、支持 raw / AFF4 / ELF）

```powershell
# raw 格式（最通用，Volatility 可直接读）
E:\kit\winpmem.exe -o E:\evidence\DigiForensics-mem.raw --format raw

# AFF4 格式（容器格式，自带采集元数据，可用 7-Zip 解包出内部 raw 流）
E:\kit\winpmem.exe -o E:\evidence\DigiForensics-mem.aff4

# 指定线程数加速（默认 2）
E:\kit\winpmem.exe -o E:\evidence\DigiForensics-mem.aff4 --thread 4

# 查看完整帮助
E:\kit\winpmem.exe -h
```

> **格式选择建议**：`.raw` 兼容性最好，任何工具都能读；`.aff4` 自带元数据（采集时间、工具版本、范围表），**在法庭上更利于证据完整性论证**，但部分老工具不认。`--format elf` 支持稀疏区间，不常用于取证场景。

方式 B：DumpIt（Comae / Magnet 旗下，操作极简）

```powershell
DumpIt.exe /O E:\evidence\DigiForensics-mem.raw /T RAW   # /O 目标路径，/T RAW 输出 raw
DumpIt.exe /O E:\evidence\DigiForensics-mem.dmp            # 默认为 Windows 崩溃转储格式
```

> **注意版本**：老版 DumpIt 在较新的 Windows 10 上可能产生不完整的转储。遇到解析失败优先换 WinPmem。

方式 C：FTK Imager（GUI，商业，机构常用）

菜单路径：`File → Capture Memory…`，选目标介质，可勾选 `Include pagefile`（**建议勾上**，页缓存里的数据价值很高），输出 `.mem` 文件（raw）。

**方式 D：ProcDump（进程级，不是全量）**

```powershell
procdump64.exe -accepteula -ma <PID> E:\evidence\lsass.dmp          # 按 PID
procdump64.exe -accepteula -ma lsass.exe E:\evidence\lsass.dmp     # 按进程名
procdump64.exe -accepteula -ma <PID> \\analyst-pc\share\lsass.dmp  # 远程 UNC
```

> ProcDump 输出的是 Windows 崩溃转储格式（minidump full），不是物理内存镜像。它可以用 Windbg/IDA 分析，但不能直接当 `vol.py -f` 的输入。它的价值在于**只关心一个进程时，能拿到该进程全部内存**（包括 LSA Secret），且体积远小于全量镜像。

方式 E：LiveAcquire（FTK 的商业一体化方案）

以采集代理方式运行在目标机（需安装为服务），提供计划任务、告警回调、自动归档到 FTK 平台。适合企业常态化采集，**不适用于司法现场的一次性取证**（部署本身就改动了目标机）。

<a id="section-10"></a>

### 3.2 Linux：AVML 优先

```bash
# ===== 前提：确认环境 =====
uname -r                          # 记录内核版本（分析时需要匹配符号）
cat /proc/meminfo | head -3        # 确认内存总量
id                                 # 确认 root
cat /sys/kernel/security/lockdown # 若非 none，AVML 会静默失败

# ===== 方式 A：AVML（推荐，无需内核模块）=====
./avml /media/usb/DigiForensics-mem.raw                        # 基础采集（LiME 格式）
./avml --compress /media/usb/DigiForensics-mem.raw.compressed   # Snappy 压缩
./avml --source /dev/crash /media/usb/DigiForensics-mem.raw     # 指定内存源
./avml --url https://analyst-pc:9000/ --delete /tmp/DigiForensics-mem.raw  # 上传并删本地
```

> **AVML 的重要限制**：若目标机开启了内核的 **lockdown** 安全特性（部分发行版默认开），AVML **无法采集**。此时需先确认 `cat /sys/kernel/security/lockdown` 的返回值，或改用 LiME 等其他方式。

**AVML 压缩镜像的转换**（分析前必须解压）：

```bash
./avml-convert /media/usb/DigiForensics-mem.raw.compressed /work/DigiForensics-mem.raw
# 或使用新版的子命令形式
avml convert ./compressed.lime ./uncompressed.lime
```

**方式 B：LiME（内核模块）**

```bash
# ===== 构建（在与目标机同版本内核的机器上做）=====
sudo apt install -y build-essential linux-headers-$(uname -r) git
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src && make               # 产出 lime.$(uname -r).ko

# ===== 加载并采集（目标机上执行，需 root）=====
# 注意 path= 和 format= 必须带引号（否则 insmod 解析失败）
sudo insmod ./lime.ko "path=/media/usb/DigiForensics-mem.raw format=lime"
sudo insmod ./lime.ko "path=tcp:analyst-pc 9000 format=lime"   # 远程推送
# 采集端同时执行：nc -l 9000 > DigiForensics-mem.raw

# 卸载模块（务必卸载，否则在 /proc/modules 留下记录）
sudo rmmod lime
lsmod | grep lime        # 应无输出
```

> ⚠️ **`insmod` 引号是硬性要求**。不带引号时 shell 会在 `=` 处分词，导致参数被拆开，加载失败或写入异常路径。**这是 LiME 最常见的错误**。

方式 C：`/proc/kcore` 与 `/dev/mem`（为什么实际少用）

| 方法 | 问题 |
|---|---|
| `/proc/kcore` | **体积巨大**（包含全部物理地址空间，含大量未使用区域），**速度慢**（要逐页读），且需要 `CAP_SYS_RAWIO`；某些内核配置下根本打不开 |
| `dd if=/dev/mem` | **现代内核基本失败**：自 5.x 起 `/dev/mem` 默认只暴露前 1 MB；`CONFIG_STRICT_DEVMEM` 进一步限制；即使能读也极慢 |

> **结论**：这两条路在取证实践中基本不作为首选。`/proc/kcore` 只在"没有其他手段且机器空闲"时作为最后选项，且要预估数倍于物理内存的磁盘占用。推荐顺序：AVML > LiME > 其他专用工具 >> `/proc/kcore` / `/dev/mem`。

<a id="section-11"></a>

### 3.3 macOS

```bash
# 传统方式（需 kext 通过签名 + SIP 放行，现代系统上基本不可行）
sudo ./osxpmem -o DigiForensics-mem.raw
sudo ./osxpmem -h

# 现实可行的替代路径：休眠镜像（本质是压缩的内存转储）
ls -la /private/var/vm/sleepimage      # 旧版系统路径
ls -la /var/vm/                        # 新版系统路径（需 root 读取）
```

> **休眠镜像的局限**：它是**休眠时**的内存，而非**查获时**的内存；且新版本系统中该文件受保护、可能被加密。要在报告中明确说明这个时间差。

<a id="section-12"></a>

### 3.4 Android

```bash
# ===== 第 1 步：确认 root 与安全状态 =====
adb shell su -c "id"                  # 期望 uid=0(root)
adb shell getenforce                  # Enforcing / Permissive / Disabled
adb shell su -c "setenforce 0"        # 若为 Enforcing，临时放行（记录这一状态变更！）
adb shell su -c "getenforce"          # 确认已是 Permissive

# ===== 第 2 步：确认内存源 =====
adb shell su -c "ls -l /dev/crash"   # AVML 首选源；/dev/mem 在新内核上不可用

# ===== 第 3 步：采集（方式 A：AVML 静态二进制）=====
adb push avml /data/local/tmp/
adb shell su -c "chmod 755 /data/local/tmp/avml"
adb shell su -c "/data/local/tmp/avml /sdcard/DigiForensics-mem.raw"

# 方式 B：LiME 模块（需针对该设备内核版本编译）
adb push lime.ko /data/local/tmp/
adb shell su -c "insmod /data/local/tmp/lime.ko \"path=/sdcard/DigiForensics-mem.raw format=lime\""
adb shell su -c "rmmod lime"            # 立刻卸载，避免留痕

# ===== 第 4 步：拉取并清理 =====
adb pull /sdcard/DigiForensics-mem.raw
adb shell su -c "rm -f /sdcard/DigiForensics-mem.raw /data/local/tmp/avml /data/local/tmp/lime.ko"
```

<a id="section-13"></a>

### 3.5 采集的验证（每种方法都适用）

```bash
# 1) 立即哈希——不要做任何其他操作
sha256sum DigiForensics-mem.raw | tee acquisition-hash.txt

# 2) 大小核对：应与物理内存接近
wc -c < DigiForensics-mem.raw
grep MemTotal /proc/meminfo

# 3) 确认可解析（这是最有效的"镜像没坏"验证）
python3 vol.py -f DigiForensics-mem.raw -q windows.info
python3 vol.py -f DigiForensics-mem.raw -q linux.pslist
```

```powershell
# Windows 侧对应操作
Get-FileHash -Algorithm SHA256 E:\evidence\DigiForensics-mem.raw
(Get-Item E:\evidence\DigiForensics-mem.raw).Length
systeminfo | Select-String 'Total Physical Memory'
```

---
<a id="section-14"></a>

## 四、常见陷阱

采集失败的方式比采集成功的方式多得多，而且**失败往往不报错**——文件写出来了、大小看着差不多、唯独内容不对。

本章按参数与权限、输出格式、采集痕迹与状态变更、验证与交付四个环节展开。陷阱全部落在本文给出的具体命令行为与工具限制上。

<a id="section-15"></a>

### 4.1 参数与权限门槛

<a id="section-16"></a>

#### 陷阱 1：LiME 的 `path=` / `format=` 不带引号

**现象**：`insmod ./lime.ko path=/media/usb/DigiForensics-mem.raw format=lime` 报错，或者模块加载了但目标路径莫名其妙，出现一个名为 `format=lime` 的文件。

**原因**：shell 不把 `=` 当特殊字符，会按空白分词，把 `path=/media/usb/...` 和 `format=lime` 当成两个独立的参数传给 `insmod`。LiME 解析的是单个 `key=value` 字符串，拆开后就只剩下 `path=/media/usb/DigiForensics-mem.raw` 一个有效键。模块把数据写到那里并以默认值收尾，或者干脆因为参数表解析异常而拒绝加载。

**注意这不会报"权限错误"或"参数错误"。** 它报的是路径相关的失败，容易被误判为存储问题。

**影响**：最常见的后果不是采不到，而是**采到了错误的位置**——文件落在 `format=lime` 这个相对路径下（当前工作目录，通常是目标机本地盘）。

采集成了，但目标机上多了一个莫名其妙的文件，同时外接盘是空的。分析员往往反复检查外接介质容量和权限，方向完全错了。

**核查**：整个参数串用双引号包住，`insmod ./lime.ko "path=/media/usb/DigiForensics-mem.raw format=lime"`。

**Android 上还有第二层**：命令要经 `adb shell` 传给设备端 shell，引号需要在外层再转义一次，写成 `adb shell su -c "insmod /data/local/tmp/lime.ko \"path=/sdcard/DigiForensics-mem.raw format=lime\""`。

执行后立刻 `ls -la` 确认文件真的出现在了预期路径。

<a id="section-17"></a>

#### 陷阱 2：LiME 加载后忘卸载，把采集动作留在内核里

**现象**：采集完成，文件拉回来了，但 `lsmod` / `/proc/modules` 里还有 `lime`，目标机重启后依然在。

**原因**：`rmmod` 是一个独立的、需要主动执行的动作，采集结束不等于模块卸载。2.2 已经把「`/proc/modules` 留下记录」列为「有人做过内存采集」的直接证据，而**这条记录在系统运行期间一直存在，在重启前不会消失**。它的迷惑性在于采集本身是"合法授权下"的行为，但痕迹的存在会被后续分析或对方的自查当成入侵迹象。

**影响**：双向代价。

其一，你自己的采集痕迹可能被对方或委托方当成入侵证据，报告需要额外解释。

其二，后续在这台机器上做其他取证时，模块本身是一个未知的内核代码在运行，行为不可控。

其三，如果采集目的是取证而不是减损，**留着痕迹等于改变了被检系统状态**。

**核查**：采集完成立刻 `sudo rmmod lime`，并用 `lsmod | grep lime`（应无输出）验证。

更严谨的做法是采集前先对 `/proc/modules` 做全量快照，采集后再次快照做差分，把「本次操作引入的模块变化」明确写进报告。

案例第 5 步的结论表把这条定为「中」强度并注明需结合全量快照，是正确的表述方式。

<a id="section-18"></a>

#### 陷阱 3：AVML 在内核 lockdown 开启时静默失败

**现象**：`./avml /media/usb/DigiForensics-mem.raw` 返回了，看起来执行了，但产出的文件极小或为空，命令行没有明显报错。

**原因**：内核 lockdown 特性（部分发行版默认开启）会阻止用户态读取物理内存相关接口，包括 `/dev/crash` 的大部分区域。**这类失败的特征是"不给你明确的拒绝理由"**——工具可能正常打印了启动信息、初始化了输出文件，然后在读取阶段被拒。分析员看到的是"文件创建成功"，自然推断采集已经进行。

**影响**：拿到一个几 MB 的文件，`wc -c` 与 `MemTotal` 一比就发现不对。但如果当时赶时间或只看了"文件已生成"，这个镜像会被送进分析流程。

后续 `linux.pslist` 之类的解析要么失败要么输出极少内容。而根因——**采集根本没成功**——被埋在了几小时之后。

**核查**：采集前先 `cat /sys/kernel/security/lockdown`，返回非 `none` 就直接换方案，不要先试后判。

**采集后必须做内容级验证**（3.5 第 3 步：能跑出 `linux.pslist` 结构化结果），只看文件存在和大小是不够的。

若必须硬采，需要明确记录这是绕过了内核安全机制的操作。

<a id="section-19"></a>

#### 陷阱 4：Android 上还在试 `dd if=/dev/mem`

**现象**：在 Android 或较新的 Linux 上执行 `dd if=/dev/mem of=/sdcard/mem.raw`，得到几 KB 数据或 `Permission denied`，反复调整权限无效。

**原因**：2.4 已经解释了机制——新内核对 `/dev/mem` 做了长期加固，默认只暴露前 1 MB 甚至完全禁止，另有 `CONFIG_STRICT_DEVMEM` 进一步限制。**这不是权限不足，是接口本身被设计成不可用**。反复 `chmod 777` 或换 root shell 都不会改变结果，因为限制来自内核配置而非文件权限位。

**影响**：耗掉大量现场时间，还会连带产生可疑的 root 操作痕迹（多次 su 提权、尝试访问敏感设备的记录可能进入日志或触发审计）。

真正的可用路径 `/dev/crash` 就在旁边。

**核查**：直接用 `/dev/crash`——AVML 默认会尝试该源，也可用 `--source /dev/crash` 显式指定。`/proc/kcore` 是更差的选择（3.2 已列：体积是物理内存的数倍、速度极慢、需 `CAP_SYS_RAWIO`），只在没有其他手段时作为最后选项并预先规划数倍存储。

<a id="section-20"></a>

#### 陷阱 5：SELinux 处于 Enforcing 时直接采集

**现象**：root 已经拿到，命令也发了，但读内存的操作返回 `avc: denied` 或 `Permission denied`，而错误信息里看不出是 SELinux 拦的。

**原因**：2.4 的三重锁里，root 只是第一重。Enforcing 模式下 root 同样被策略拦截，`su -c id` 返回 `uid=0` 给人"权限已解决"的错觉，但 SELinux 的强制访问控制在 DAC 之上生效。排查时容易沿着"权限/组属/ capability"方向找，而真正的原因是 MAC 策略。

**影响**：现场时间被无谓消耗。

更麻烦的是有些越权尝试会触发系统的审计记录或安全告警。在你自己制造的告警里再分辨哪些是采集行为造成的，成本远高于先查 `getenforce`。

**核查**：采集前第一步就 `adb shell getenforce`。Enforcing 下优先用 `setsebool -P allow_execmem 1` 这类策略级放行。

必须 `setenforce 0` 时，**按案例第 2 步做双向记录**（变更前后的 `getenforce` 输出各存一份），并在报告的采集方法章节明示这一状态变更。

<a id="section-21"></a>

#### 陷阱 6：为了采集而绕过的安全机制没被记录

**现象**：为了拿到内存，关闭了 SELinux、放行了某个 boolean、进入了恢复模式降低安全策略，采集完成后报告里对此只字不提。

**原因**：这是**流程性的漏项而非技术错误**，但它有独立的技术后果。2.4 的警告框和 3.1 的 `setenforce 0` 注释都指向同一件事：安全状态的变更会影响该设备上**其他所有取证动作**。SELinux 处于 Permissive 时，daemon 的行为可能与 Enforcing 下不同（例如某些组件的访问行为被记录但不拦截，采集期间发生的其他行为集合也不同），**这使"采集期间的状态"和"正常状态"不可直接比较**。

**影响**：报告的可辩护性受损。

对方完全可以主张"取证过程改变了系统安全状态，采集结果不能代表案发时的状态"。同时后续取证若不恢复 `setenforce 1`，等于在非标准环境下取下一批证据。

**核查**：任何安全状态变更做**双向记录 + 时间戳**，采集完成后按原状恢复，并在报告的"局限"部分写明采集期间系统安全状态与常态的差异。

这不是"诚实但不利"的说明，而是让所有后续结论有明确的前提。

<a id="section-22"></a>

### 4.2 输出格式与工具选择

<a id="section-23"></a>

#### 陷阱 7：把压缩镜像直接喂给 Volatility

**现象**：`./avml --compress` 采完，文件几百 MB（远小于物理内存，看起来"压缩率不错"），直接 `vol.py -f` 后报解析错误或输出为空。

**原因**：AVML 的 `--compress` 使用 **Snappy** 压缩，产出的是压缩流，不是 raw 或 LiME 布局。**文件变小恰恰是压缩生效的证据**，不是采集不完整的证据——这两个现象需要区分。压缩镜像的字节流里没有可识别的内存结构，解析器在前几百字节就失败。

**影响**：容易误判为"镜像损坏"，进而怀疑采集通道、存储介质、目标机稳定性，把排查方向带偏。

真实原因只是一步预处理。

**核查**：分析前先转换。`./avml-convert <compressed> <uncompressed>`，或新版子命令形式 `avml convert ./compressed.lime ./uncompressed.lime`。

**注意转换后才能核对大小**——用压缩文件的大小与 `MemTotal` 比较是本主题最常见的无效验证。

同时建议保留**未压缩的原始文件哈希**，因为压缩与解压不是可逆性有保证的操作，转换链本身也是保管链的一部分。

<a id="section-24"></a>

#### 陷阱 8：LiME 用 `raw` 格式采集后遇到地址空洞

**现象**：`format=raw` 采完，在某些机器上解析出的结构位置整体错位，或者对 MMIO 区间附近的解析结果明显异常。

**原因**：2.3 的引文块已经点明——**物理内存并非全地址空间连续存在**。`raw` 格式下"地址 = 文件偏移"，一旦遇到空洞（MMIO 区间、设备保留区），偏移与物理地址的对应关系就断了。此时文件大小可能完全正常（工具补了零或跳过了空洞），**解析失败往往表现为"部分结构能读出、值是错的"**，而不是报错。这类错误比直接解析失败更危险。

**影响**：解析出的"看似合理实则错误"的值会被写进报告。

这类错误不会在任何验证环节暴露——哈希一致、大小吻合、插件能出结果。

只有当某个值与磁盘侧证据冲突时才会被发现，而那时结论已经成型。

**核查**：默认用 `format=lime`，它把每个分段的地址范围记录在文件头，分析工具据此正确映射。只有在明确知道镜像无空洞且下游工具只认 raw 时才用 `raw`。拿到 `raw` 镜像后，至少用 `windows.info` / `linux.bash.Bash`（含实际地址的关键结构）做一次定位校验，确认地址与物理地址的对应关系成立。

<a id="section-25"></a>

#### 陷阱 9：选错了 Windows 侧工具，把 minidump 当成物理内存镜像

**现象**：`DumpIt.exe` 不带 `/T RAW` 输出 `.dmp`，`procdump64 -ma` 输出 `.dmp`，然后直接 `vol.py -f x.dmp` 解析失败或结果明显不对。

**原因**：3.1 的四个引文块区分了三种不同的产物——**物理内存镜像**（WinPmem raw / AFF4、DumpIt `/T RAW`、FTK Imager）、**Windows 崩溃转储格式**（DumpIt 默认输出、ProcDump `-ma`，即 minidump full）、**进程级转储**（ProcDump 按 PID）。这三者的页面语义完全不同：minidump 记录的是**虚拟地址空间**，物理镜像记录的是**物理地址空间**。混淆两者时，工具报的是"找不到 KDBG/DTB"这类看似符号或损坏问题，实则是地址空间类型不对。

**影响**：Volatility 3 确实支持读取 minidump，但它是**另一个分析路径**——需要走 `--virtaddr` 之类的显式指定或依赖相应的层，行为与物理镜像分析结果不可直接对比。

混用得到的两类结果放在同一份报告里，读者无法分辨哪个来自哪个工件。

**核查**：**先明确自己要的是哪一类工件**。

需要全机物理内存用于池扫描、结构链表遍历 → 用 raw 或 AFF4。

只关心某一个进程（比如 lsass 的 LSA Secret）→ ProcDump `-ma` 体积小得多且完全够用，此时就明确按进程转储的方式分析，不按物理镜像的方式分析。

文件名也要能自证类型（案例统一用 `DigiForensics-mem.raw` 表示物理镜像，进程级用其他名字）。

<a id="section-26"></a>

#### 陷阱 10：老版 DumpIt 在新系统上产出不完整转储

**现象**：DumpIt 执行完成、文件大小合理，但解析时结构不全或某些插件无输出。

**原因**：3.1 的方式 B 已经给出提示——老版 DumpIt 在较新的 Windows 10 上可能产生不完整的转储。**不完整在这里不体现为报错**，而体现为解析结果的缺失，这极难与"该结构确实不存在"区分。版本与系统版本的兼容性是一个不可见变量。

**影响**：分析员倾向于相信"工具跑成功了"，于是在不完整镜像上得出阴性结论——"未发现注入痕迹""未发现可疑连接"。

这些结论的可靠性实际是零。

**核查**：Windows 侧优先用 WinPmem（3.1 方式 A 标注为推荐），开源、格式可控、支持指定线程数加速。

任何一次采集失败后的重试都必须换工具或换格式，而不是重跑同一个工具——同工具同参数的重试不会改变结果。

解析结果明显偏少时，先怀疑转储完整性，再怀疑符号。

<a id="section-27"></a>

### 4.3 采集副作用与现场干扰

<a id="section-28"></a>

#### 陷阱 11：把采集工具残留的自身痕迹当成可疑证据

**现象**：在镜像或事后检查中发现未签名的驱动、随机名临时文件、指向外接盘的命令行，判定"该机存在恶意驱动/可疑工具"。

**原因**：3.1 方式 A 到 E 每一个工具都会在目标机上留下自己的东西：WinPmem 类工具把签名驱动从资源段释放到 `%TEMP%`、安装服务、加载后再卸载；FTK Imager 与 LiveAcquire 的部署本身就是常驻；LiME 是显式加载的内核模块。**这些痕迹与你正在找的入侵痕迹在形态上高度相似**——未签名驱动、临时目录下的可执行文件、服务安装记录（7045）。

**影响**：2.2 的观察点表明确列出了 `%TEMP%` 随机名驱动与 7045 事件作为"有人采过内存"的证据。现在你自己制造了同样的痕迹。

分析阶段若不先排除，报告里会出现自己造成的假阳性。而且**它比真实发现更难排除**——因为它由一个已知合法、由你授权的动作产生。

**核查**：采集前记录工具的完整路径、文件名、哈希、驱动名、服务名、临时文件命名模式，**在分析阶段作为已知排除项**，并在报告的采集方法章节显式声明"本次采集引入了 X 驱动 / Y 临时文件"。

真实性的另一面同样重要：2.2 强调这些痕迹对**判断目标机过去是否被第三方采集过**有独立价值，与本次采集痕迹要分开表述。

<a id="section-29"></a>

#### 陷阱 12：把镜像写到目标机系统盘

**现象**：采集路径写成了 `C:\mem.raw` 或 `/tmp/mem.raw`，采完再想办法拷走。

**原因**：这在语法上完全正常，工具不会报错。但它同时触发了三个后果：占用与物理内存等量的目标机存储空间（可能撑爆分区，导致采集中断或系统异常）、覆盖或占用了系统文件所在区域（**改动证据本体**）、以及在目标机上留下一个巨大的易发现文件。3.1 和案例通篇使用 `E:\evidence\`、`/media/usb/`、`/sdcard/` 就是在规避这三点。

**影响**：不可逆的那部分最贵。

分区被撑爆导致采集失败是常见结局。即使成功，在被改动过的系统上继续取证，后续所有磁盘侧结论都要附加说明。

这一条属于不可逆操作。

**核查**：路径参数在执行前逐字复核，确保落点是外接介质或远程推送目标。

`avml --url ... --delete` 这种"上传即删"的模式在带宽允许时能同时避免本地落盘。

**存储容量至少按物理内存的 1.2 倍规划**，给工具的中间开销留余量。

<a id="section-30"></a>

#### 陷阱 13：采集期间长时间高强度操作且不作现场说明

**现象**：在 32 GB 内存的工作站上采集 12 分钟，目标机界面卡顿，用户或在场人员反复询问"是不是出问题了"。

**原因**：软件采集必然吃 I/O 和内存带宽——1 提到工具要分配缓冲区、pin 页，`--thread 4` 之类加速参数会进一步压榨系统。这不是异常，是**方案本身的固有代价**，但从现场表现看就是"机器变得很卡"。执行人容易把它当成工具出问题的征兆，或者为了避免被察觉而中途终止采集，反而造成更差的结果。

**影响**：两种都糟。

被察觉可能影响现场配合与后续询问的合法性。自行终止则丢失唯一的易失性证据。

若因卡顿而反复重试，采集区间被人为拉长，镜像的时间归属更加模糊。

**核查**：采集前告知现场人员即将进行的操作、预计耗时、以及系统会短暂变卡，把可预期的卡顿转化为"已告知的正常现象"。

采集期间若系统出现非预期的严重异常（蓝屏、自动重启、目标进程消失），应立即记录现象并评估是否中止。

**中止决定本身也要记录**，因为它决定了镜像的完整性声明。

<a id="section-31"></a>

#### 陷阱 14：用 `/proc/kcore` 采高内存量服务器

**现象**：对 1 TB 内存的服务器图省事，用 `cat /proc/kcore > mem.raw` 采集，跑到一小时后被迫中止。

**原因**：3.2 的对照表说明得很直接——`/proc/kcore` **包含全部物理地址空间，含大量未使用的区域**，因此体积是物理内存的数倍，且要逐页读、速度慢，还需 `CAP_SYS_RAWIO`。它的"完整"是真的，"可用"是假的：数倍膨胀的部分基本是未使用区，对取证几乎无价值。

**影响**：时间与存储双倍损失，中止后可能留下一个巨大的半成品文件占满磁盘。

**最坏情况下中止动作发生在磁盘即将写满时**，可能连带损坏目标机上的其他数据。

**核查**：按 3.2 给出的优先级 `AVML > LiME > 其他专用工具 >> /proc/kcore、/dev/mem` 执行。确实需要用 `/proc/kcore` 时，先在同型号机器上实测速率并按预估的数倍体积规划存储，同时确保输出落外接介质。

<a id="section-32"></a>

### 4.4 验证与交付

<a id="section-33"></a>

#### 陷阱 15：只核大小，不核内容

**现象**：`wc -c` 得到的值与 `MemTotal` 偏差在 5% 以内，判定镜像完整，直接进入分析。

**原因**：3.5 的三步验证里，第 3 步"确认可解析"才是最有效的完整性判据，而第 1、2 步只是快速筛查。偏差在 5% 以内可以对应两种完全不同的情况：**采集正常，仅有正常的空洞填充**；采集在中途静默中断，剩余部分被补零或文件截断得不明显。**大小不是内容**，工具在异常退出时不会保证做正确的事。

**影响**：把筛查指标当成确认指标。

后续在缺页镜像上做阴性结论——"未发现某类结构"——而正确表述应是"因采集完整性未经确认，该阴性结果不可采信"。

这个区别在质证时是决定性的。

**核查**：三步验证都要跑并都记录，尤其第 3 步：`vol.py -f 镜像 -q windows.info` / `linux.pslist` 能输出结构化结果。

案例第 4 步同时记录了 `MemTotal` 与实际字节数并算出 4.6% 偏差，这是好的范式。

**更完整的做法是再核一次核心结构能否完整遍历**（如模块链表、进程链表的项数与 `tasklist` 快照的数量是否吻合），这能发现"尾部缺页"这类内容级问题。

<a id="section-34"></a>

#### 陷阱 16：不记录工具哈希就交付

**现象**：镜像交到了分析环节，采集用的可执行文件已删除或被覆盖，报告里写"使用 WinPmem 采集"。

**原因**：1 提到同名工具不同版本行为可能不同——这一点在 3.1 方式 B 的"注意版本"里已经具体化了：老版 DumpIt 与新版在转储完整性上就有差异。**工具名不是版本标识**，"WinPmem"至少对应多个差异明显的版本，各版本对 ACPI 页、物理地址范围的扫描策略可能不同，直接影响镜像里有没有关键数据（如 KDBG）。

**影响**：可复现性崩塌。任何一次复核都无法确认"当时用的是哪个构建"，而这直接关系到镜像的证据属性是否成立。案例把工具哈希写进 `custody.txt` 的做法应当作为最低要求。

**核查**：采集**前**对全部工具文件做 SHA-256（旧工具只有 MD5 时记录 MD5 并注明），工具哈希与镜像哈希、起止时间一起进入保管链。工具本体**随证据一并归档**，不要在现场"清理干净"——你删掉的是可复现性的锚点。

<a id="section-35"></a>

#### 陷阱 17：把 macOS 当成能在线采内存的目标

**现象**：对一台现代 macOS 设备尝试 osxpmem，花大量时间研究 kext 签名与 SIP 绕过，最终交付一个没有内存证据的报告。

**原因**：2.5 的结论表已经明确——默认状态的现代 macOS **不可行且技术上难以绕过**，SIP 从 10.11 起阻止未签名 kext，而 Apple 留给企业的正式通道（MDM 下发授权）不适用于司法现场。这个限制是**平台性的**，不是"换个更厉害的工具"能解决的。

**影响**：机会成本。

它占用了本可以用在 Linux/Android 可采场景上的时间。更重要的是，**放弃得太晚**——如果拖到设备被关机的时刻，休眠镜像这条现实路径也失去了。

macOS 的在线采集与休眠镜像采集有完全不同的可行性，必须在方案阶段就分流。

**核查**：方案阶段先分流。现代 macOS 直接走休眠镜像路径：`/private/var/vm/sleepimage`（旧版）或 `/var/vm/` 下（新版，需 root），并在报告中明写**它是休眠时的内存而非查获时的内存**——3.3 的局限引文已经要求说明这个时间差。若设备已正常关机且从未休眠，这条路径同样不可用，只能在报告里写明内存证据不可得。
<a id="section-36"></a>

## 五、案例示例

<a id="section-37"></a>

### 5.1 已 root Android 设备的 AVML 采集与 SELinux 状态回滚

**场景**

查获一台已 root 的 Android 手机（Samsung SM-G991B，Android 13，8 GB RAM），处于开机锁屏状态。委托方要求确认两件事：该机是否安装了监控类应用，以及采集当时是否处于被远程控制状态。

已 root + Android 13 这个组合有一个必须先处理的前置条件：SELinux 处于 `Enforcing` 时，AVML 这类需要访问内核接口的用户态采集器会静默失败（不报错，只是产出 0 字节或半截镜像）。

**先判 SELinux 状态，再决定用哪个工具。** 这是 Android 采集的第一道分叉。

**处置过程**

确认连接、型号与 root 可用性：

```bash
$ adb devices
# List of devices attached
# R58Mxxxxxxx    device          ← 正常连接，非 unauthorized

$ adb shell getprop ro.product.model; adb shell getprop ro.build.version.release
SM-G991B
13

$ adb shell su -c "id"
uid=0(root) gid=0(root) groups=0(root) context=u:r:su:s0

$ adb shell su -c "getenforce"
Enforcing                     # ← 分叉点：Enforcing 下 AVML 会静默失败
```

SELinux 状态变更必须**双向留痕**，这是取证动作对被检设备状态的改变，不能隐去：

```bash
$ adb shell su -c "getenforce" | tee evidence/android-selinux-before.txt
Enforcing

$ adb shell su -c "setenforce 0"

$ adb shell su -c "getenforce" | tee evidence/android-selinux-after.txt
Permissive
```

采集前读取 `MemTotal` 作为体积预期基线：

```bash
$ adb shell su -c "cat /proc/meminfo" | head -1
MemTotal:        8112404 kB      # 7.74 GiB
```

推送 AVML 并采集。AVML 走 `/proc/kcore` 与 `/dev/kmem` 的替代路径，不需要像 LiME 那样加载内核模块，因此不产生模块残留：

```bash
$ adb push avml /data/local/tmp/
$ adb shell su -c "chmod 755 /data/local/tmp/avml"
$ adb shell su -c "/data/local/tmp/avml /sdcard/DigiForensics-mem.raw"
[+] Starting acquisition...
[+] Dumping memory to /sdcard/DigiForensics-mem.raw

$ adb shell su -c "ls -la /sdcard/DigiForensics-mem.raw"
-rw------- 1 root root 8302384128 ...     # 7.73 GiB
```

拉取、哈希、核体积：

```bash
$ adb pull /sdcard/DigiForensics-mem.raw
$ sha256sum DigiForensics-mem.raw        # 完整值记入 evidence/custody.txt
$ wc -c < DigiForensics-mem.raw
8302384128                       # 7.73 GiB vs MemTotal 7.74 GiB，偏差 0.13%
```

体积吻合还不足以证明可用，必须实跑插件验证：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -q linux.pslist
```

正常列出 `init`、`system_server`、`zygote64` 等 Android 核心进程，**镜像完整性验证通过**。

采集完成后回滚状态并清理：

```bash
$ adb shell su -c "rm -f /sdcard/DigiForensics-mem.raw"
$ adb shell su -c "rm -f /data/local/tmp/avml"
$ adb shell su -c "setenforce 1"          # 恢复原状态
$ adb shell su -c "getenforce"
Enforcing
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 内存镜像完整可用 | 8302384128 B vs MemTotal 8112404 kB，偏差 0.13%，`linux.pslist` 正常 | 强 |
| 采集期间设备安全状态被改变 | `android-selinux-before.txt` = Enforcing、`-after.txt` = Permissive 双向留痕 | 强（作为局限明示） |
| 采集未在目标机加载内核模块 | 采用 AVML 而非 LiME，`/proc/modules` 无新增 | 中 |
| 镜像仅代表采集时刻的瞬时状态 | AVML 无 LiME 的 `/proc/kcore` 连续性说明 | 强（适用区间限定） |

**能证明的**：采集窗口内设备的进程、内存映射与网络连接状态。

**不能证明的**：不能证明设备"从未"被远程控制。

内存是瞬时快照，锁屏状态下后台保活进程与已退出的会话连接都不在其中。

另外，SELinux 转 Permissive 期间若有其他进程运行，其行为约束被放宽，这属于取证动作的副作用，**必须在报告中作为独立局限段落写出**。

**误判对照**

本案例最容易踩的错，是**把 AVML 采集成功当作"没有环境限制"**，进而省略后续对 LiME 路线的评估。

判据在采集工具的加载机制上：AVML 是纯用户态，通过 `/proc/kcore` 读取物理内存，在 `Enforcing` 下对多数目标会因 SELinux 域权限被拒而**返回 0 或极小文件，且不打印错误**。

本次之所以成功，前提是我们已把 SELinux 置为 `Permissive`。

如果目标机是未 root 的设备、或有 Magisk Hide 这类模块级屏蔽，`setenforce 0` 会失败。此时应改走其他路径，而非反复重试。

判据落到具体字段上，检查清单是：

1. `getenforce` 的返回值 —— `Enforcing` 意味着任何用户态采集器的结果都需额外验证，不能采信
2. 采集产物字节数 —— 与 `MemTotal` 偏差超过 5% 即判定采集失败，不要拿半截镜像做分析
3. `su -c id` 的输出 context 字段 —— `u:r:su:s0` 说明走的是 Magisk/su 域；若是 `u:r:magisk:s0` 可能有额外模块拦截

按"AVML 采到了就说明环境干净"的判据走，代价是：SELinux 变更未记录，报告声称检材状态未被改变，而复核方在设备日志里看到 `setenforce` 事件。

**整份报告的可信度会被连带质疑** —— 这比单个技术点出错更严重。

反向也要注意：不要因为 AVML 成功就断言"目标机无内核模块残留"。

AVML 自己不加载模块，不等于设备上没有其他模块存在。要下这个结论，必须额外采一份 `/proc/modules` 全量快照并与可信基线比对。

<a id="section-38"></a>

### 5.2 LiME 在 lockdown 内核上的加载失败与降级

**场景**

同一批设备中的另一台：一台已 root 的 Android 12 测试机，内核启用了 `CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY`（`/sys/kernel/security/lockdown` 读回 `[integrity]`）。委托方要求确认设备在事发时段是否有正在进行的数据外传，因此必须拿到内存镜像。

这台设备是 AVML 路线的对照实验：同样 root、同样 Permissive，**差别只在 lockdown 状态**。

这个变量直接决定 LiME 能否加载。

**处置过程**

先判 lockdown，这是选路线的第一判据：

```bash
$ adb shell su -c "cat /sys/kernel/security/lockdown"
[integrity] none confidentiality  ← 强制完整性模式，不可关闭
```

lockdown 为 `[integrity]` 时，禁止加载未签名模块，而绝大多数未签名的第三方 `.ko`（包括预编译的 LiME）都不在内核信任链内。强行加载的典型表现是：

```bash
$ adb push lime /data/local/tmp/
$ adb shell su -c "insmod /data/local/tmp/lime.ko"
# 无输出 ← 静默失败，不是成功

$ adb shell su -c "lsmod | grep -i lime"
# 无输出 ← 模块未加载
```

**`insmod` 无输出不代表成功。** 这是 LiME 路线最常见的坑：内核在 lockdown 下对未签名模块的拒绝是静默的，必须用 `lsmod` 独立验证。

验证 `/proc/lime` 节点是否存在，这是 LiME 真正的就绪判据：

```bash
$ adb shell su -c "ls -la /proc/lime/"
ls: /proc/lime/: No such file or directory    # ← 未就绪
```

降级到 AVML，并把 lockdown 状态记录在案：

```bash
$ adb shell su -c "cat /sys/kernel/security/lockdown" | tee evidence/lockdown-state.txt
[integrity] none confidentiality

$ adb shell su -c "/data/local/tmp/avml /sdcard/DigiForensics-mem.raw"
$ adb shell su -c "ls -la /sdcard/DigiForensics-mem.raw"
-rw------- 1 root root 6341256704 ...     # 6.3 GiB
```

采集前读取 `MemTotal` 做体积核对：

```bash
$ adb shell su -c "grep MemTotal /proc/meminfo"
MemTotal:        6123456 kB      # 5.84 GiB
```

**注意这里出现了一个矛盾**：镜像 6.3 GiB 大于 `MemTotal` 5.84 GiB。

这不是错误——AVML 会把 `/proc/kcore` 映射的稀疏空洞也写进去，产出的是"虚拟布局展开后的镜像"，体积可以超过物理内存。

因此 AVML 镜像的体积判据不是"小于等于 MemTotal"，而是"不小于 MemTotal 且能被插件正常解析"。

这一条与 5.1 中 8 GB 设备上"必须小于 MemTotal"的直觉判据正好相反。是本次排查最花时间的地方。

拉取并实跑验证：

```bash
$ adb pull /sdcard/DigiForensics-mem.raw
$ python3 vol.py -f DigiForensics-mem.raw -q linux.pslist | head -8
```

**结论**

LiME 路线在本机不可用，降级为 AVML 成功。降级原因明确、可复现、已留痕（`lockdown-state.txt` + `lsmod` 空输出 + `/proc/lime` 不存在三项互相印证）。

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 设备处于强制完整性 lockdown | `/sys/kernel/security/lockdown` = `[integrity] none confidentiality` | 强 |
| LiME 在本机不可加载 | `insmod` 无输出 + `lsmod` 无 lime + `/proc/lime` 不存在，三项一致 | 强 |
| AVML 采集成功，镜像可用 | `linux.pslist` 正常解析核心进程 | 强 |
| 镜像体积 6.3 GiB > MemTotal 5.84 GiB 属正常 | AVML 展开稀疏空洞，非转储重复 | 中（需结合解析结果） |

**能证明的**：设备内核的 lockdown 配置状态，以及在本设备上 LiME 与 AVML 两条路线的可用性判定。

**不能证明的**：不能证明"设备没有被篡改"。lockdown 为 `[integrity]` 只说明内核拒绝加载未签名模块，与用户态/已签名模块的完整性无关。

**误判对照**

这个案例里有一个非常容易犯的反向错误：**把 `insmod` 无输出当作加载成功**。

`insmod` 的返回值在内核模块加载失败时，很多 Android 内核版本仍然返回 0（尤其是被 lockdown 拦截时），只在 `dmesg` 里留一行 `module verification failed: signature and/or required key missing`。判据必须落到三个可独立验证的点：

1. `lsmod | grep lime` 有输出 —— 模块在列表里
2. `/proc/lime/` 目录存在 —— 模块已注册 `procfs` 接口
3. `cat /proc/lime/maps | head` 有内容 —— 内存映射机制可用

三条全过才算 LiME 就绪。本次三条**全部不满足**，因此降级是正确决策。

若只看第 1 条或只看 `insmod` 的退出码，就会拿着一个"看起来采到了、实则没有"的 `/proc/lime/maps` 去做分析。

得到的要么是空文件，要么是上一次残留的旧节点。后者更危险——它会产出一份**时间归属错误**的镜像，而报告里看不出任何异常。

另一个误判点：把 lockdown 状态当作**已 root 的证明**。

`/sys/kernel/security/lockdown` 在未 root 设备上也可读（`adb shell` 无需 root 即可 `cat`），所以读到 `[integrity]` 与否都不能推断设备 root 状态。root 判据只能来自 `su -c id` 的输出。

<a id="section-39"></a>

### 5.3 反例：压缩镜像直接喂给 Volatility 导致的空结果

**场景**

委托方送来一份 Linux 服务器的内存转储，文件名为 `DigiForensics-mem.raw.lz4`，大小 4.2 GB。委托方的问题是：该服务器在 03:40–04:10 之间是否被入侵。执行 `linux.pslist` 得到的输出只有 3 行（`init`、`kthreadd`、`ksoftirqd`），与一台跑着 Web 服务的机器明显不符。

这类"镜像看起来能打开、结果却少得离谱"的问题，是交付环节最常见的失败模式。

**处置过程**

第一步，判断文件真实类型，不能信扩展名：

```bash
$ file DigiForensics-mem.raw.lz4
DigiForensics-mem.raw.lz4: LZ4 compressed data (v1), block size 8, max block size 4
```

文件确实是 LZ4 压缩流，只是扩展名多带了 `.raw`。 交接时对压缩包做了改名以表明"解压后是内存镜像"，但压缩本身没有解开。

第二步，检查 Volatility 是否静默接受了压缩流。Volatility 3 的某些发行打包会对输入做格式探测，压缩流无法被识别为物理内存时，**不会报"格式错误"，而是只解析出极少量可映射的页**：

```bash
$ python3 vol.py -f DigiForensics-mem.raw.lz4 -q linux.pslist
OFFSET(PID)   PPID  COMM             UID  GID  EUID  EGID  CREATION TIME
0x0 (1)       0     init             0    0    0     0     2026-05-11 03:12:44
0x0 (2)       0     kthreadd         0    0    0     0     2026-05-11 03:12:44
0x0 (3)       2     ksoftirqd        0    0    0     0     2026-05-11 03:12:44
```

注意 `OFFSET(PID)` 列全是 `0x0`。三个不同 PID 的物理偏移全部为 0，这在物理内存转储里不可能出现 —— 真实的转储中每个进程结构体位于不同物理页。这是格式不被识别的硬指标。

第三步，用符号表探测确认内核版本线索是否存在：

```bash
$ python3 vol.py -f DigiForensics-mem.raw.lz4 -q banners.banners
# 无任何 banner 输出
```

第四步，解压后重试：

```bash
$ lz4 -d -f DigiForensics-mem.raw.lz4 DigiForensics-mem.raw
$ ls -la DigiForensics-mem.raw
-rw-r--r-- 1 foren foren 17179869184 ...   # 16 GiB
$ file DigiForensics-mem.raw
DigiForensics-mem.raw: data
$ python3 vol.py -f DigiForensics-mem.raw -q banners.banners
Linux banner 5.15.0-91-generic (Ubuntu 22.04.3 LTS)
```

第五步，重跑进程与网络插件：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -q linux.pslist | wc -l
214
$ python3 vol.py -f DigiForensics-mem.raw -q linux.netscan | head -20
OFFSET   PID   TASK_COMM   FAMILY  SOCK_TYPE  PROTO  LADDR                          LPORT  RADDR                          RPORT  STATE         UID
0x...   1     systemd      AF_INET  SOCK_STREAM  TCP    0.0.0.0                        0     0.0.0.0                        0     LISTEN        0
```

**结论**

原文件为 LZ4 压缩流，Volatility 未识别其格式，`linux.pslist` 输出的 3 个进程是解析器在无效输入上凑出的伪结果，`OFFSET(PID)` 全为 `0x0` 是关键判据。解压后 16 GiB 镜像可正常解析，得到 214 个进程与完整 banner。

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 交付文件为压缩流而非物理内存镜像 | `file` 判定 LZ4；`banners.banners` 无输出 | 强 |
| 首次 `linux.pslist` 的 3 行为无效结果 | `OFFSET(PID)` 全部 `0x0`，物理偏移不可重复 | 强 |
| 解压后镜像完整可用 | 16 GiB，banner 正常，214 进程 | 强 |
| 03:40–04:10 区间分析可行 | 解析后插件输出完整 | 强 |

**不能证明的**：不能证明委托方交付时**故意**提供压缩流。归档打包是常见操作，`file` 判定为压缩流只说明格式，不说明意图。报告中应记作"检材格式与扩展名不符，经解压处理后使用"，不做动机推断。

**误判对照**

这个案例的核心误判是：看到 `linux.pslist` 有输出，就认为镜像可用。

Volatility 3 在输入格式不被识别时的行为不是报错，而是尽力解析。取到 3 行输出这件事本身就很有迷惑性。

报告作者如果只看"有输出"就继续，会得到一份写着"该服务器在事发时段仅有 3 个进程运行"的结论，而这与服务器实际承载业务的事实直接矛盾。

结论与已知事实冲突时，应该怀疑工具输出而不是怀疑业务事实。

正确判据是三条，任一不满足即判定镜像不可用：

1. `OFFSET(PID)` 或 `PID` 列的物理偏移不能全部为 0（唯一例外是自旋锁等极早期结构）
2. `banners.banners` 应能输出内核版本串；空输出即格式不对
3. 进程数与 `MemTotal` 粗略相关：1 GB 内存的 Linux 主机通常有 100 个以上进程，个位数必然异常

本次三条全部触发异常。若按"有输出即可用"继续，代价是**整份入侵时间线的分析都建立在一份无效镜像上**，且因为工具全程无报错，这个错误极难在复核阶段被发现。

范围限定：本次结论仅针对交付的 4.2 GB 文件本身。**未覆盖范围**包括压缩包内是否还有其他文件、原始采集工具的输出日志、以及该文件是否在传输中被截断（未与委托方提供的采集端哈希核对）。若要做完整的证据链闭合，必须取得采集端的原始哈希值并与解压后文件逐一比对。

<a id="section-40"></a>

## 六、扩展阅读方向

真正决定成败的是**平台约束、格式语义、痕迹交代**三件事，下面五组材料按这三条主线组织。

<a id="section-41"></a>

### 6.1 平台约束：把不可行变成预先知道

这一组解决"在方案阶段就判死这条路"的问题。四个平台的可行性差异是结构性的，见[陷阱 17](#section-35)。

- [内存取证总览](memory-acquire-memory-forensics-overview.md)——易失性等级表决定了采集必须在最前面，本篇所有方法的紧迫性都来自那张表。
- [Linux 与 Android 内存取证](../memory-artifact/memory-artifact-linux-android.md)——`/dev/crash`、ART 堆、厂商 ROM 差异，以及 root 之后的取证顺序。
- [取证装备与写保护器](../../fundamentals/fundamentals-practice/fundamentals-practice-forensics-equipment-and-write-blockers.md)——外接存储、写保护与现场设备清单，决定采集能落在哪里。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md)——root 一台他人设备、绕过 SELinux、改动安全状态，各自的授权边界在哪。

<a id="section-42"></a>

### 6.2 格式语义：产物决定了什么

这一组解决"采到了但读不出来"。`raw` 与 `lime` 的地址映射差别、`.aff4` 与 `.raw` 的元数据差别、物理镜像与 minidump 的地址空间差别，都在这一组。

- [证据格式与转换](../../imaging/imaging-acquire/imaging-acquire-evidence-image-formats.md)——AFF4 容器的结构、转换环节的哈希连续性要求。
- [Volatility 3 框架与插件选择](memory-acquire-volatility3.md)——拿到镜像后的分析入口，压缩镜像为什么不能直接喂进去。
- [Windows 内存 Profile 机制](memory-acquire-windows-profile.md)——`lime` 格式的分段地址表为什么正是 Profile 层需要的输入。
- [APFS 容器与快照](../../filesystem/filesystem-apple-fs/filesystem-apple-fs-apfs.md)——macOS 侧的休眠文件与快照结构，用来评估"休眠镜像能拿到什么"。

<a id="section-43"></a>

### 6.3 痕迹与副作用：自己制造的那部分证据

这一组处理现场执行中最容易被忽略的一层：采集动作本身会在目标机上留下驱动、模块、服务记录和临时文件。这些痕迹与真实入侵痕迹形态高度相似，必须主动区分。

- [远程勘验与在线取证](../../imaging/imaging-acquire/imaging-acquire-remote-evidence-collection.md)——远程执行时的留痕方式，以及为什么在线操作不能假设零影响。
- [事件日志深度分析](../../computer/computer-registry-log/computer-registry-log-windows-event-log-analysis.md)——7045 驱动服务安装记录的读取方式，用于判断目标机过去是否被第三方采集过。
- [Sysmon 与日志聚合](../../computer/computer-registry-log/computer-registry-log-sysmon.md)——进程创建与驱动加载的端点侧记录，可与内存侧痕迹交叉验证。
- [内存证据的可采性与报告](../memory-artifact/memory-artifact-memory-evidence-and-reporting.md)——采集动作本身的可采性风险，以及报告中必须披露哪些改动。

<a id="section-44"></a>

### 6.4 现场与云：不在本机采的几种情况

这一组覆盖目标机不便接触、不允许安装工具、或本身就是虚拟化/云主机的情形。此时采集通道变了，但"零影响"的假设同样不成立。

- [镜像制作](../../imaging/imaging-acquire/imaging-acquire-disk-imaging-and-evidence-preservation.md)——磁盘侧的采集流程，内存与磁盘的顺序关系在这里有对照说明。
- [虚拟机仿真](../../imaging/imaging-mount-simulate/imaging-mount-simulate-virtual-machine-emulation.md)——`.vmem` 快照是天然的内核状态冻结，虚拟化环境下的采集反而更"干净"。
- [Windows Server 环境仿真](../../imaging/imaging-mount-simulate/imaging-mount-simulate-windows-server.md)——服务型环境下的在线取证与证据灭失速度差异。
- [日志深度分析（Linux）](../../computer/computer-log/computer-log-system-log-analysis.md)——当内存已灭失，systemd 日志是判断"当时在跑什么"的主要替代面。

<a id="section-45"></a>

### 6.5 判据与验证：什么算采到了

这一组专门处理验证口径。"文件生成了"和"镜像可用了"是两件事，本篇的[三、操作步骤](#section-8)只给了三步筛查，真正的完整性判据要跨到分析和结论章。

- [进程与注入检测](../memory-analyze/memory-analyze-process-and-injection-detection.md)——用核心链表能否完整遍历来反向验证镜像完整性。
- [哈希与完整性校验](../../fundamentals/fundamentals-concepts/fundamentals-concepts-hashes-and-integrity-verification.md)——镜像哈希、工具哈希如何共同构成可复现性锚点。
- [证据文件格式](../../fundamentals/fundamentals-chain/fundamentals-chain-dd-e01-aff4-evidence-formats.md)——采集产物作为证据文件时必须满足的元数据要求。
- [取证概念与分类](../../fundamentals/fundamentals-concepts/fundamentals-concepts-digital-forensics-concepts.md)——在线采集取得的证据在分类上的位置，以及它与离线镜像的差异。
<a id="section-46"></a>

## 七、命令速查

```bash
# ===== Windows =====
winpmem.exe -o E:\evidence\DigiForensics-mem.raw --format raw   # raw（推荐）
winpmem.exe -o E:\evidence\DigiForensics-mem.aff4                # AFF4 容器（自带元数据）
winpmem.exe -o E:\evidence\DigiForensics-mem.aff4 --thread 4     # 指定线程数加速
DumpIt.exe /O E:\evidence\DigiForensics-mem.raw /T RAW
DumpIt.exe /O E:\evidence\DigiForensics-mem.dmp                  # 崩溃转储格式
procdump64.exe -accepteula -ma <PID> E:\evidence\lsass.dmp      # 进程级（minidump full）

# ===== Linux =====
uname -r ; id ; cat /sys/kernel/security/lockdown              # 采集前确认
./avml /media/usb/DigiForensics-mem.raw                          # AVML 推荐
./avml --compress /media/usb/DigiForensics-mem.raw.compressed
./avml --source /dev/crash /media/usb/DigiForensics-mem.raw
./avml --url https://analyst-pc:9000/ --delete /tmp/DigiForensics-mem.raw
avml convert ./compressed.lime ./uncompressed.lime               # 压缩镜像分析前必做

# LiME —— 关键：path= 与 format= 必须带引号
sudo insmod ./lime.ko "path=/media/usb/DigiForensics-mem.raw format=lime"
sudo insmod ./lime.ko "path=tcp:analyst-pc 9000 format=lime"   # 远程，需先 nc -l 9000
sudo rmmod lime ; lsmod | grep lime                             # 应无输出

# ===== macOS =====
sudo ./osxpmem -o DigiForensics-mem.raw          # 需 kext 签名 + SIP 放行
ls -la /private/var/vm/sleepimage                # 休眠镜像（现实替代路径）

# ===== Android =====
adb shell su -c "id"                    # 确认 root
adb shell getenforce                    # Enforcing / Permissive / Disabled
adb shell su -c "setenforce 0"          # 放行（记录此状态变更！）
adb shell su -c "ls -l /dev/crash"      # 确认内存源存在
adb push avml /data/local/tmp/
adb shell su -c "chmod 755 /data/local/tmp/avml"
adb shell su -c "/data/local/tmp/avml /sdcard/DigiForensics-mem.raw"
# LiME 方式
adb push lime.ko /data/local/tmp/
adb shell su -c "insmod /data/local/tmp/lime.ko \"path=/sdcard/DigiForensics-mem.raw format=lime\""
adb shell su -c "rmmod lime"
adb pull /sdcard/DigiForensics-mem.raw
adb shell su -c "rm -f /sdcard/DigiForensics-mem.raw /data/local/tmp/avml"

# ===== 采集后验证（全平台通用）=====
sha256sum DigiForensics-mem.raw | tee acquisition-hash.txt
wc -c < DigiForensics-mem.raw
python3 vol.py -f DigiForensics-mem.raw -q windows.info
python3 vol.py -f DigiForensics-mem.raw -q linux.pslist
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 内存与专项分析 — 内存采集方法」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《内存采集方法》（CC BY-SA 4.0）`

文中 `DigiForensics-mem.raw`、`lime.ko`、`avml` 等均为示例文件名，指向虚构或已脱敏的检材，与真实案件无关。

---
