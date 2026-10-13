---
title: "进程与注入检测"
slug: "memory-analyze-process-and-injection-detection"
canonical: "https://www.digiforensics.cn/wiki/memory-analyze-process-and-injection-detection"
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

# 进程与注入检测

<a id="section-1"></a>

## 一、概述

进程是内存里最基础也最有价值的工件。它回答三个基本问题：谁在跑、谁启动了谁、运行的这个是不是它自称的那个。

但"进程"这件事在取证上有一个陷阱：**你通过工具看到的进程列表，本身就可能是假的。**

Windows 内核用一个**双向链表**（`PsActiveProcessHead`）串起所有活动进程。常规工具遍历这个链表来列出进程。

但内核态的代码完全有能力把自己从链表上摘下来，同时让进程照常运行——这就是 DKOM（Direct Kernel Object Manipulation）类技术。

摘链之后，任务管理器、任务栏、`tasklist` 全都看不见它。但它的代码正在执行、它的内存还在被使用。

这正是 `pslist` 与 `psscan` 对比的意义：

| 方法 | 原理 | 能发现摘链进程吗 |
|---|---|---|
| `pslist` | **遍历**内核维护的活动进程链表 | ❌ 摘链的进程不在链表上，遍历不到 |
| `psscan` | **扫描**物理内存，搜索进程对象特征 | ✅ 对象还在内存里，扫描得到 |

"psscan 有、pslist 无" = 该进程正在运行但被刻意隐藏 = 强恶意指标。本篇第二节会讲清原理。

除了隐藏，进程层面还要看三件事：**名字是不是真的**（伪装）、**代码是不是自己的**（注入/空化/反射加载）、**权限是不是异常**。本篇逐一展开。

**在取证流程中的位置**：本篇是内存分析的**第一跳**，拿到镜像和符号表（`windows.info`）之后、在任何细查插件之前先跑一遍。它的作用是给后面所有分析提供一份"这台机器上应该有什么"的基线——没有基线，就无法判断哪个进程多余。**上游依赖**是内存镜像采集与符号包：符号版本和镜像对不上时 `pslist` 会直接读不出链表头，这是本领域最常见的翻车点，所以符号校验必须在跑插件之前做完。**下游**是把这份进程清单交给网络连接、凭据、注入三类分析去交叉。

**本篇处理的证据形态**——不是一个文件，而是一组散落在非分页池里的内核结构：

| 证据 | 位置 / 标识 | 本篇用它判断什么 |
|---|---|---|
| 进程对象 | 非分页池，池标签 `Proc` | 进程是否真实存在于内存 |
| 活动进程链表 | 由符号 `PsActiveProcessHead` 解析 | 能否用遍历法枚举 |
| 链上节点 | `_EPROCESS + ActiveProcessLinks` | 遍历与扫描结果的差异来源 |
| 短进程名 | `ImageFileName`，**满 15 字符即截断** | 名字是否被伪装 |
| 完整命令行 | PEB 的 `ProcessParameters → CommandLine` | 长路径程序的真面目 |
| 父进程号 | `InheritedFromUniqueProcessId` | 父子链是否合理 |
| VAD 区权限 | `vadinfo` 的权限位、`malfind` 找到的 `PAGE_EXECUTE_READWRITE` 段 | 是否存在代码注入或空化 |

这些字段的具体偏移随 Windows 版本变动，**不要照抄别处的偏移表**，以当前符号解析出的结构定义为准。

采集那一瞬间有哪些进程在跑、父子关系与完整命令行、可执行文件的完整路径与哈希基线、是否存在摘链或代码注入这两类主动隐藏行为，以及哪些进程的权限明显超出其功能需要。

**进程退出后不留任何痕迹**——`psscan` 没扫到某个程序，不等于它从未运行，只说明采集区间里没有它的对象了。阴性结果必须写成"在非分页池扫描覆盖范围内未见对应的 `Proc` 对象"，同时列出未覆盖范围：对象已释放的残留、非常规内核版本、页面已换出而未被扫到的情况。时间戳锚定的是采集时刻，**证明不了"行为已结束"**。命令行是目标进程自己写的字符串，不是执行事实——它可以伪造。摘链结论证明的是"有人在隐藏一个进程"，**推不出动机**，也分不清是攻击者的手法还是安全软件的正常保护行为。同理，父进程号可被任意指定，**父子链不构成因果证明**。

**读者前提**：你得能读十六进制偏移、照着结构定义在内存里跳指针（这是手工复核 `psscan` 结果的前提），得知道非分页池和内核对象大致怎么分配，知道 `_EPROCESS` 里哪些字段由内核维护、哪些由进程自己填——这个区别直接决定哪些字段能被伪造、哪些不能。只用过任务管理器或进程管理器 GUI 的读者，命令能照抄，但判读会失准。

---
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 pslist vs psscan：两种完全不同的枚举原理

**`pslist` —— 遍历链表**：框架从内核全局变量 `PsActiveProcessHead` 出发，沿着每个 `EPROCESS` 里的 `ActiveProcessLinks` 成员（一个 `LIST_ENTRY`）逐个走。

**这是内核自己维护的"官方名单"。**

> **优点**：得到的是**内核视角的当前活动进程**，包含完整的创建时间、父进程、句柄数等元数据，且顺序反映真实的创建顺序。
> **缺点**：**只信链表**。任何把 `EPROCESS` 从链表上摘掉的操作，都会让它从 `pslist` 的输出里消失。

**`psscan` —— 扫描内存**：框架不信任链表，而是遍历物理内存的每一页，寻找符合 `EPROCESS` 特征模式的字节序列。

判定依据包括：关键成员位置的值是否合理（如 `ExitStatus` 为 0 表示活动、`Pcb` 指针对齐并落在内核范围）、`ImageFileName` 是否是合法的内核字符串、各链表指针是否自洽。

> **优点**：**不看链表也能找到进程对象**。摘链、链表指针被篡改、乃至部分池分配被复用，只要对象还在，就扫得出来。
> **缺点**：**会把已退出的进程也扫出来**。一个刚结束的进程，其 `EPROCESS` 对象可能尚未被内存分配器回收，此时 `psscan` 还能看到它——但它**已经不是活动进程了**。

**两者的差集是核心判据**：

| 现象 | 解释 | 结论强度 |
|---|---|---|
| **psscan 有，pslist 无** | 摘链的隐藏进程，**正在运行** | ★★★★★ 极强 |
| pslist 有，psscan 无 | 刚退出、对象尚未回收，**非隐藏** | ★ 无（属正常现象） |
| 两边完全一致 | 无摘链迹象（但不排除其他隐藏手法） | 中性 |

> **务必注意第二行**：很多人把"pslist 有、psscan 无"也当成异常，**这是误判**。已终止进程在对象池里滞留是 Windows 的正常行为。这条差异**不构成任何结论**。

<a id="section-4"></a>

### 2.2 多视角交叉：`psxview`

手工对比 `pslist` 和 `psscan` 两份输出容易出错。`psxview` 插件（规范位置 `windows.malware.psxview`）**自动比对四种枚举视角**：`pslist`（遍历活动进程链表）、`psscan`（扫描内存中的 EPROCESS）、`thrdscan`（线程枚举反查进程）、`csrss`（会话/桌面相关的进程视图）。

输出中任一列为 `False` 就意味着该视角看不到这个进程。 关键是看**哪一列为 False**：

- `pslist` 列为 False，但其他列为 True → 摘链隐藏，**最典型的 rootkit 特征**
- `psscan` 列为 False，其他为 True → 对象刚被回收，正常
- 多数列为 False → 进程已终止

**它还提供 `Exit Time` 列**：有退出时间的进程是**已经终止的**。`Exit Time` 有值时，**这个进程不是隐藏的，只是不活跃**。

<a id="section-5"></a>

### 2.3 进程名伪装的三种形态

`pslist` 输出有两个名字列，它们**不一致就是线索**：`ImageFileName` 来自 `EPROCESS` 内的字段（**内核记录，15 字符截断**，进程运行期间不变），`Name` 来自 PEB 的进程参数（用户态可写，**理论上可被改**）。

**伪装形态一：模仿系统进程名**——真实系统进程都从 `C:\Windows\System32\` 加载。`pslist` 输出不含完整路径，需配合 `windows.dlllist`（看 DLL 加载路径）或导出进程映像后查 PE 头。

**伪装形态二：Unicode 不可见字符**——用 `svchost.exe `（尾部加空格）、`svchost.exe.`（尾部加点）或插入不可见字符都能骗过粗略的肉眼比对。**判据是名称长度**：`ImageFileName` 字段只有 15 字节，尾部空白会被保留但**显示时可能被吞掉**。必须看字符编码和字节长度，不能只看渲染出来的字符串。

伪装形态三：`ImageFileName` 与 `Name` 不一致——这是**最可靠的判据**，因为两者来自不同位置，要伪造需同时改两处。

<a id="section-6"></a>

### 2.4 注入检测：`malfind` 的原理

`windows.malware.malfind` 列出**可能包含注入代码的进程内存区域**，它不依赖任何已知恶意样本。

**过滤条件（源码 `list_injection_sites`）**：

```
1. 保护字符串含 EXECUTE 且含 WRITE
   —— 或 —— 含 EXECUTE 但不含 WRITE，且区内存在 dirty 页
2. (Private == 1 且 Tag == "VadS")  或  (Private == 0 且 Protection != "PAGE_EXECUTE_WRITECOPY")
3. 排除内容全零或整区因分页不可读的 VAD
```

典型命中的关键字段：`Protection` 为 `PAGE_EXECUTE_READWRITE`（可写+可执行，**正常模块不会有写权限**）、`Private` 为 `1`（非文件 backed）、`Tag` 为 `VadS`、`Hexdump` 以 `4D 5A 90 00` 开头（**MZ 头**）、`Disasm` 为入口点指令。

> **MZ 头是加分项，不是入选条件**。源码里 `MZ header` / `55 8b` / `55 48` / `55 89` 几种标注只填在输出的 `Notes` 列，用于帮助人工判读，**不参与过滤**。把它当入选条件会导致一个常见误判：shellcode 或被抹掉 PE 头的映像同样会被列出，只是 `Notes` 列为空。
>
> 真正的入选逻辑只看保护属性、VAD 类型与内容是否全零——**这些与"像不像 PE"无关**。因此命中项里有 `PAGE_EXECUTE_READWRITE` + `MZ` 头是注入的强特征，但反过来「没有 `MZ` 头」不代表不是注入。
>
> 且**不是所有命中都是恶意**：JIT 引擎（.NET、Java、浏览器 V8）、防病毒软件、部分游戏的合法代码都符合这个模式。**必须结合进程类型判断**——`notepad.exe` 里命中要警惕，`chrome.exe` 里命中很可能是 V8。

因此：`malfind` 的输出必须结合 `pslist` 判断进程是否活动，对已终止进程的命中要谨慎解读。

<a id="section-7"></a>

### 2.5 其他注入手法与各自特征

| 手法 | 内存中的表现 | 检测方式 |
|---|---|---|
| **经典 DLL 注入** | 目标进程加载了非预期 DLL；DOBL 列表与内存映射可能不符 | `windows.dlllist` + `windows.malware.ldrmodules` |
| **反射式 DLL 加载（RDI）** | 内存中有**完整 PE 映像但不在模块列表中**，无标准 DllMain 入口 | `malfind` 命中 + `ldrmodules` 缺失 + 手工分析 |
| **进程空化（Process Hollowing）** | 进程映像名与实际内存内容不符；**主线程起始地址不指向自身 EntryPoint** | `windows.malware.hollowprocesses` |
| **进程伪装（PEB Masquerade）** | 进程参数中的 `ImagePath`/`CommandLine` 被改 | `windows.malware.pebmasquerade` |
| **线程劫持** | 线程起始地址落在非预期模块内 | `windows.malware.suspicious_threads` |
| **原子注入（Atom Bombing）** | 共享内存区出现代码，**权限为可读可写而非可执行** | `malfind` 变体思路 + `vadinfo` 看权限组合 |
| **无文件执行（Fileless）** | 只有内存中的映像，磁盘上无对应文件 | 内存有完整 PE + **磁盘镜像 MFT/USN 查无此文件**（`filescan` 仅为辅助线索） |

**`ldrmodules` 的核心价值**：它把**加载器视角的模块链表**（`PEB->Ldr->InLoadOrderModuleList`）与**内存中的实际映射**做对比。**在内存里有映射、但不在模块链表里**——就是被刻意隐藏的模块。

<a id="section-8"></a>

### 2.6 VAD：理解一切内存区域的基础

VAD（Virtual Address Descriptor，虚拟地址描述符） 是 Windows 内核对一段虚拟内存的记账结构，是理解 `malfind`、`vadinfo`、`vadwalk` 的前提。内核用红黑树维护所有 VAD，按虚拟地址排序。`windows.vadinfo` 显示某进程的 VAD 树（起始地址、大小、保护属性、类型），`windows.vadwalk` 直接遍历 VAD 树原始结构（更底层），`windows.vadyarascan` / `windows.vadregexscan` 用规则扫 VAD 区域内容。

**保护属性对照**：

| 保护值 | 含义 | 是否正常 |
|---|---|---|
| `PAGE_READONLY` / `PAGE_READWRITE` | 普通数据 | 正常 |
| `PAGE_EXECUTE_READ` | 只读可执行（.text 段典型） | 正常 |
| **`PAGE_EXECUTE_READWRITE`** | **可写 + 可执行** | **可疑，正常模块极少有** |
| `PAGE_EXECUTE_WRITECOPY` | 写时复制可执行 | 少见 |

这类可写可执行页也出现在合法的动态插桩场景里。Frida 注入后内存里是什么形态、与常规远程线程注入怎么区分，见[Frida 动态 Hook](../../mobile/mobile-android/mobile-android-frida-dynamic-hooking.md)。

---

<a id="section-9"></a>

## 三、操作步骤

<a id="section-10"></a>

### 3.1 第 1 步：建立基线

```bash
# 先确认符号可用（否则后面全部不可信）
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.info

# 进程基线：完整列表
python3 vol.py -f DigiForensics-mem.raw -r csv windows.pslist > pslist.csv
wc -l pslist.csv
```

**先看几个必须确认的基线项**：

- `System`(PID 0)、`smss.exe`(PID 2)、`csrss.exe` 是否存在
- 进程总数是否合理（正常工作站 150–300 个）
- 有无 `Exit Time` 有值的进程（有值 = 已终止）

<a id="section-11"></a>

### 3.2 第 2 步：摘链检测（核心操作）

**最可靠的做法：直接用 `psxview`**（它在一个插件里交叉比对多个视角）。输出示例（隐藏进程）：

```text
Offset(Virtual)   Name            PID    pslist  psscan  thrdscan  csrss  Exit Time
0x1a3e5000        svc_host.exe    7124   False   True    True      True   N/A
                   ↑ pslist=False：链表里没有，但扫描得到
```

> **两处易错**：① 默认输出的是 `Offset(Virtual)`，只有加 `--physical-offsets` 才是 `Offset(Physical)`；② 最后一列是 **`Exit Time`（带空格）**，写成 `ExitTime` 会匹配不上。

**判读表**：

| pslist | psscan | thrdscan | csrss | Exit Time | 结论 |
|---|---|---|---|---|---|
| False | True | True | True | N/A | **摘链隐藏进程，正在运行** |
| False | True | True | True | 有值 | 已终止，摘链可能是"清理痕迹" |
| True | False | True | True | N/A | 刚退出，对象未回收（**正常**） |
| True | True | True | True | N/A | 无异常 |

> 注意 `pslist` 与 `psscan` 的方向性差异：`pslist` 有、`psscan` 无，通常**不是**隐藏，而是进程刚退出、EPROCESS 对象尚未被回收。只有 `psscan` 有、`pslist` 无才是摘链的经典信号。

**若要用原始输出手工比对**（注意 CSV 有前置的 `TreeDepth` 列）：

```bash
# 列序：TreeDepth,PID,PPID,ImageFileName,Offset,... → PID 是第 2 列，不是第 3 列
# comm -13 集合A 集合B 输出"只在 B 中" → 即 psscan 有、pslist 无
comm -13 \
  <(tail -n +2 pslist.csv  | cut -d, -f2 | tr -d '"' | sort -u) \
  <(tail -n +2 psscan.csv | cut -d, -f2 | tr -d '"' | sort -u)
```

> ⚠️ **两个易错点**：① CSV **第一列是 `TreeDepth`**，所以 PID 在 `$2`、`$3` 是 PPID——**取错列会得到一堆父进程号，完全无意义**；② `comm` 要求输入**已排序**，务必加 `sort -u`。

<a id="section-12"></a>

### 3.3 第 3 步：命令行全量提取

`windows.cmdline` 是**取证价值最高、最容易被忽略的插件**——它能还原每个进程"当初是怎么被启动的"。

```bash
# 快速筛可疑命令行
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.cmdline \
  | grep -iE 'powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|curl|wget|invoke-|iex|bypass|-enc'

# 用 --filters 只匹配 cmdline 列（比 grep 管道精确；注意是子串匹配，不是通配符）
python3 vol.py -f DigiForensics-mem.raw windows.cmdline --filters cmdline,cmdline,powershell
# 需要正则时在模式末尾加 !，例如：--filters cmdline,cmdline,-e[c|n]!
# 排除某些行用前缀 -： --filters -cmdline,conhost
```

<a id="section-13"></a>

### 3.4 第 4 步：父子关系异常

```bash
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.pstree > pstree.txt
# 典型可疑组合（详见第 08 篇）：
#   winword.exe / excel.exe    →  powershell.exe / cmd.exe   （Office 钓鱼）
#   w3wp.exe / wmiprvse.exe    →  powershell.exe             （Web/WMI 触发）
#   svchost.exe（-k netsvcs） →  未知进程                    （服务被滥用）
#   System (PID 0)            →  任何非系统进程              （几乎必为伪造）
# 人工审查时：System→X、Office→shell、svchost→未知，均需逐一解释
```

<a id="section-14"></a>

### 3.5 第 5 步：注入区域排查

```bash
# 扫描注入（先看表头确认列名）
python3 vol.py -f DigiForensics-mem.raw -r csv windows.malware.malfind > malfind.csv
grep -i 'PAGE_EXECUTE_READWRITE' malfind.csv

# 导出命中区域做进一步分析（MZ = 4D 5A）
mkdir -p /work/malfind-dump
python3 vol.py -f DigiForensics-mem.raw -o /work/malfind-dump windows.malware.malfind --dump
for f in /work/malfind-dump/*.dmp; do printf "%s  " "$(basename $f)"; xxd -l 4 -p "$f"; done

# 对命中的进程做 VAD 层确认
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.vadinfo --pid 7124
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.vadwalk --pid 7124 \
  | grep -iE 'EXECUTE|PRIVATE'
```

<a id="section-15"></a>

### 3.6 第 6 步：模块与进程映像一致性

```bash
# 某进程加载的所有 DLL（非系统目录的 DLL 是强信号）
python3 vol.py -f DigiForensics-mem.raw -r csv windows.dlllist --pid 7124 \
  | grep -viE 'C:\\Windows|C:\\Program Files'

# 模块链表 vs 内存映射（发现未登记的模块）
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.malware.ldrmodules --pid 7124

# 进程空化 / PEB 伪装检测
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.malware.hollowprocesses
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.malware.pebmasquerade
```

---
<a id="section-16"></a>

## 四、常见陷阱

进程层分析的每一个结论都建立在"我看到的就是全部"这个假设上，而摘链、伪装、空化都在专门破坏这个假设。

本章按视角交叉、字段判读、注入归因、结论表述四个环节展开。陷阱全部落在 `pslist`/`psscan`/`psxview`/`malfind`/`ldrmodules` 的具体行为上。

<a id="section-17"></a>

### 4.1 视角交叉与方向性

<a id="section-18"></a>

#### 陷阱 1：只跑 `pslist` 就下"无隐藏进程"的结论

**现象**：`pslist` 输出 187 个进程，进程名、路径、命令行都正常，报告写"未发现隐藏进程"。

**原因**：`pslist` 的原理是**遍历**内核维护的活动进程链表（从 `PsActiveProcessHead` 出发沿 `ActiveProcessLinks` 逐个走），它只信链表。而摘链的实质就是把 `EPROCESS` 从链表上摘掉、进程照常运行——1 的表格把它标为"摘链的进程不在链表上，遍历不到"。摘链之后 `pslist` 的输出里根本不会有这个进程，所以"没看到"与"不存在"在 `pslist` 的输出里是同一件事。案例第 1 步结束时明确写了这句话：187 个进程正常，**但这不能证明没有隐藏进程**。

**影响**：摘链是 rootkit 的标志性能力，而**你用的工具在原理上就看不到它**。

案例中真正的发现（PID 7124）如果只跑 `pslist` 会被完全漏掉——它是靠 `psxview` 的 `pslist=False / 其余=True` 才浮出来的。

**核查**：**摘链检测必须用第二视角交叉**。用 `windows.malware.psxview`（一个插件里自动比对四种枚举视角），或至少把 `pslist` 与 `psscan` 两份输出做差集。「`psscan` 有、`pslist` 无」才是摘链的经典信号。

<a id="section-19"></a>

#### 陷阱 2：把"pslist 有、psscan 无"当成异常

**现象**：对比两份输出时，发现有进程在 `pslist` 里而不在 `psscan` 里，标记为可疑并写进报告。

**原因**：**这是方向性误读，两个方向的不对称性是完全不同的**。2.1 的引文块说得很直接——`psscan` 扫描物理内存找 `EPROCESS` 特征，它**会把已退出的进程也扫出来**：一个刚结束的进程，其 `EPROCESS` 对象可能尚未被内存分配器回收，此时 `psscan` 还能看到它，**但它已经不是活动进程了**。反过来 `pslist` 有而 `psscan` 无，只说明对象的特征不再满足扫描的判定条件（字段被复用等），**不指向任何隐藏行为**。

3.2 的判读表把它标注为"刚退出，对象未回收（**正常**）"。

**影响**：假阳性。

更麻烦的是它会**稀释真信号**——如果报告里列了 5 个"异常进程"而其中 4 个是刚退出的正常进程，唯一那个真摘链目标被淹没了。

**核查**：只认一个方向：「`psscan` 有、`pslist` 无」。反向差异在报告里不作为发现，需要提及时只作为"进程已终止"的说明。

<a id="section-20"></a>

#### 陷阱 3：`psxview` 里把 `-` 当成 `False`

**现象**：跑 `psxview` 后用 `grep ',False,'` 筛出所有行，把命中行全部当作"某视角看不到"，据此推断隐藏。

**原因**：2.2 说的是"输出中任一列为 `False` 就意味着该视角看不到这个进程"，但**并非所有视角对所有进程都适用**。案例第 2 步给出了实例：`System`（PID 4）那一行 `thrdscan` 列为 `-`（无值）而不是 `False`，而引文特别提示「**`-` 表示该视角不适用，不等于"看不见"**」。`-` 与 `False` 语义不同，混淆它们会把"这个视角对内核进程无效"读成"这个视角扫不到它"。

**影响**：把大量正常进程误标为可疑。`System`、`Idle`、`Registry`、会话管理器这类系统进程的某些视角天然不适用，`-` 会成片出现。

**核查**：**`False` 与 `-` 分开处理**。

判读时看的是具体哪一列为 `False`、其余是否为 `True`这个组合（3.2 的判读表），而不是"是否存在 False 列"。

摘链的形态是 `pslist=False` + 其余视角 `True` + `Exit Time=N/A`，这个组合的指向性是明确的，与其它形态完全不同。

<a id="section-21"></a>

#### 陷阱 4：不看 `Exit Time` 就判断进程状态

**现象**：在 `psxview` 或 `psscan` 里发现一个可疑进程（名字奇怪、有注入区），直接按"正在运行"分析并定性。

**原因**：2.2 指出 `psxview` 提供 `Exit Time` 列的判读价值——**有退出时间的进程是已经终止的**。3.2 的判读表里，`pslist=False / psscan=True / Exit Time 有值` 这一行的结论是"**已终止，摘链可能是'清理痕迹'**"，与 `Exit Time=N/A` 时的"正在运行"是两种性质完全不同的情况。一个已终止的进程上发现注入区，说明它终止前被注入过——这是历史行为，不是当前行为。

**影响**：时间属性错位。

委托方问的是"该机是否处于被控状态"，你回答的是"该机上曾经运行过某进程"，这是两个问题。

而清理痕迹式的摘链（退出后还摘链）甚至可能是合法软件的正常卸载行为残留。

**核查**：**每次解读前先确认进程是否活动**，`Exit Time` 是最快的判据。

已终止进程的发现改用历史行为表述（"该进程在终止前存在…"），并说明其当前不活跃。

同时它提示"该进程所属的功能在采集前已结束"，可据此调整对当前状态的整体判断。

<a id="section-22"></a>

#### 陷阱 5：把 CSV 的 PID 列取错

**现象**：手工比对 `pslist.csv` 与 `psscan.csv` 时，输出的"差集"里全是父进程号（2、4、488、632 这类），完全无意义。

**原因**：3.2 的代码块注释写明——CSV 的列序是 `TreeDepth,PID,PPID,ImageFileName,Offset,...`，**PID 是第 2 列，不是第 3 列**，而 `$3` 是 PPID。`-r csv` 的输出带一个前置的 `TreeDepth` 列，这个列的存在与否取决于渲染器与插件，凭印象写 `cut -d, -f3` 一定会取到 PPID。案例第 3 步确认 7124 不在 `pslist` 中时用的正是 `-f2`。

**影响**：得到一个"差集"并据此得出错误结论。

更隐蔽的情况是：PPID 与 PID 的取值范围高度重叠（PPID 总是小数字），取错列得到的差集**看起来是合理的进程号集合**，不仔细核对就会当成真结果。

而 `comm` 的方向性（`-13` 是"只在第二个集合中"）一旦再取错列，结论完全颠倒。

**核查**：**先 `head -1` 看表头再切列**。`comm` 要求输入已排序，务必加 `sort -u`。差集方向要显式写出来：`-13 A B` 输出的是"只在 B 中"的行，用它得到 `psscan` 有、`pslist` 无的集合。

<a id="section-23"></a>

### 4.2 字段判读与名称

<a id="section-24"></a>

#### 陷阱 6：忽略 `ImageFileName` 的 15 字符截断

**现象**：发现两个进程的 `ImageFileName` 相同（都显示为 `powershell_6e`），认为它们是同一个进程，或者反过来，认为不同的进程名就是不同的程序。

**原因**：2.3 明确 `ImageFileName` 是**内核记录、15 字符截断**的字段。这带来两个方向的误判：**不同长度的长名会被截成同一个字符串**（两个不同的恶意程序在 `pslist` 里同名），以及**同名的短名进程无法区分**（多个 `powershell` 实例本来就该同名）。案例第 1 步 187 个进程的列表里，`System`、`smss.exe` 这样的短名不受影响，但**长路径程序的服务宿主、容器进程普遍会撞**。

**影响**：可能把两个不同的进程合并成一条证据（丢发现），或把同一个进程的多次出现当成多个可疑实例（虚增发现）。

合并与虚增都会破坏后续的时间线与父子关系分析。

**核查**：**名称只作线索，不作身份**。区分进程靠 PID + `Offset(Virtual)`（物理位置唯一），需要确认"它到底是谁"时导出进程映像查完整路径或 PE 里的原始文件名（3.6 的 `dlllist` 加载路径、`malfind --dump` 出的 PE 头都是佐证）。

<a id="section-25"></a>

#### 陷阱 7：把 `ImageFileName` 与 `Name` 不一致直接当成伪装证据

**现象**：`pslist` 输出里两列名字不同（`ImageFileName` 是 `svchost.exe`、`Name` 是别的），直接记为"PEB 伪装"。

**原因**：2.3 称这个判据"**最可靠**"是有前提的——两者来自不同位置，**要伪造需同时改两处**。但"不一致"本身与"被恶意改过"之间还有距离：`Name` 来自 PEB 的进程参数，而**路径规范化、名称截断、PEB 参数块被正常更新**都可能造成两列看起来不同。反过来，真正的 PEB 伪装手法（`pebmasquerade`）会同时把两处改一致，让它们看起来吻合——一致性同样不是"干净"的信号。

**影响**：把一个可疑判据用成了单向的证据。

有 `pebmasquerade` 这个专门的插件（3.6 有对应命令），它的输出是基于对 `ImagePath`/`CommandLine` 与实际映像的一致性检查，比人眼比对两列字符串可靠得多。

**核查**：**不一致作为线索，定性交给专门的检测手段**。

跑 `windows.malware.pebmasquerade` 拿它的判定，并对命中的进程用 `dlllist` 查实际加载路径（2.3 说"名字可伪造，路径难伪造"）。

报告里写"两列名称不一致"是事实陈述，写"存在 PEB 伪装"是定性结论，**两者不要混用**。

<a id="section-26"></a>

#### 陷阱 8：只比进程名，不看加载路径

**现象**：`pslist` 里看到一个叫 `svchost.exe` 的进程，命令行也正常，认为无异常；或者反过来看到一个陌生进程名就直接定性。

**原因**：**名字是最容易伪造的字段**。2.3 列的三种伪装形态里，模仿系统进程名是最基础的一种——真实系统进程都从 `C:\Windows\System32\` 加载，**路径是这条判据的落点**。`pslist` 输出不含完整路径（这一点 2.3 已经说明），所以只看 `pslist` 在原理上就看不到路径。案例第 3 步正是这样处理的：命令行"完全标准"无法定性，于是转向注入检测和模块分析。

**影响**：伪装得最好的目标恰好是通过这条检查的。系统进程名的模仿成本极低（改个名字），而系统的命令行参数格式（`-k netsvcs`）也容易照抄。

**核查**：**路径优先于名字**。用 `windows.dlllist --pid <PID>` 看 DLL 加载路径，筛掉 `C:\Windows`、`C:\Program Files` 之外的项（3.6 的做法）；需要更硬的证据时导出进程映像查 PE 头的实际路径。命令行"看起来标准"这件事本身，在存在摘链或注入时应当被记为**反常的正常**——案例的结论表把"命令行与服务组显示是伪装"定为"中"强度并注明"需结合模块分析确认"，就是这个分寸。

<a id="section-27"></a>

#### 陷阱 9：用管道 `grep` 代替 `--filters`，误报一片

**现象**：用 3.3 的 `grep -iE 'powershell|cmd\.exe|...'` 过滤 `windows.cmdline`，结果里出现大量与目标无关的行（PID 恰好匹配、地址里含 `iex` 等），分析员抱怨"误报太多"，于是放宽或干脆不用命令行这条线。

**原因**：`grep` 对**整行**做正则匹配，**任何列里出现的匹配都算命中**。`--filters` 是**按列名匹配的子串过滤**（列名也是子串匹配，见[第 03 篇](../memory-acquire/memory-acquire-volatility3.md)陷阱 11），只作用于指定的列。3.6 的引文已经点明"用 `--filters` 只匹配 cmdline 列（比 grep 管道精确）"。两者精度差异是结构性的，不是调参能解决的。

**影响**：命令行是 3.3 标注的"**取证价值最高、最容易被忽略**"的工件。

误报把它淹掉，等于放弃了整条执行历史线索。

而且 `grep` 漏不掉**跨行**的长命令行（渲染成多行时只匹配到第一行）。

**核查**：主过滤用 `--filters cmdline,<子串>`，粗筛用 `grep -iE` 找候选行、再回到 `--filters` 精确确认。需要正则时在模式末尾加 `!`（如 `--filters cmdline,cmdline,-e[c|n]!`），排除用前缀 `-`（`--filters -cmdline,conhost`）。先把 `windows.cmdline` 全量导成 CSV 存档，筛选用 `awk`/`rg` 精确处理，长命令行也不会丢。

<a id="section-28"></a>

#### 陷阱 10：把 `psscan` 的「扫到」当成「还活着」

**现象**：`psscan` 扫出 192 个对象、`pslist` 只有 187 个，多出的 5 个被报告写成「5 个摘链隐藏进程」。

**原因**：`psscan` 的判据是「内存里有一块符合 `EPROCESS` 特征模式的区域」，而它扫的是历史，不是当下。 一个已经退出的进程，其 `EPROCESS` 对象在被内存分配器彻底回收之前仍留在非分页池里，此时 `psscan` 照样命中。2.1 已经把这个方向写清楚：扫描「会把已退出的进程也扫出来」，3.2 的判读表里「`pslist=True / psscan=False`」那行的结论是「刚退出，对象未回收（**正常**）」——**同一个机制的两面**：`psscan` 能扫到已退出对象，所以它的输出里天然混有历史；`pslist` 无不等于对象不存在。

**影响**：摘链结论的方向一旦搞反，报告的强度就从「极强」跌到「无」，但更坏的情况是它虚增了发现数。 五个「隐藏进程」里若有三个是崩溃残留的旧进程，报告的定性被撑大，而真正的摘链目标可能混在其中被当成噪声——因为数量多了，人就倾向于逐条扫一眼了事。

**核查**：`psscan` 的任何命中都要用 `Exit Time` 判活。 有退出时间 → 已终止，改用历史表述（「该对象在终止前存在于内存」），不作为摘链发现；`Exit Time=N/A` 才是活动进程，才有资格进入摘链判据。3.2 的四项组合（`pslist`/`psscan`/`thrdscan`/`csrss` × `Exit Time`）就是为此准备的，逐项对照，不要只比两列。

<a id="section-29"></a>

### 4.3 注入归因与良性排除

<a id="section-30"></a>

#### 陷阱 11：把 `malfind` 的所有命中都当恶意

**现象**：`malfind` 输出 30 多条命中，报告写"发现 30 处注入"。

**原因**：2.4 的源码条件明确——**不是所有命中都是恶意**：JIT 引擎（.NET、Java、浏览器 V8）、防病毒软件、部分游戏的合法代码都会产生「含 EXECUTE 且含 WRITE 的私有 VAD」。这个过滤条件是**功能性描述，不是恶意性描述**——任何运行时生成并执行代码的框架都会命中。更要注意 `MZ` 头只决定 `Notes` 列的标注，**不参与过滤**，所以既不能用它筛出真阳性，也不能因为某条命中 `Notes` 为空就排除它。`chrome.exe` 里命中很可能是 V8，`notepad.exe` 里命中要警惕。

**影响**：假阳性在数量上会淹没真阳性。

`malfind` 在一台安装了 .NET 应用的机器上命中数十条是常态，逐条分析不现实，于是分析员要么草率地全部定为恶意（不可辩护），要么全部忽略（漏掉真目标）。

而 `PAGE_EXECUTE_READWRITE` 这一个条件就足以让 2.6 的对照表给出"可疑，正常模块极少有"的判断——它指向的是"值得看"，不是"是恶意"。

**核查**：**先做进程类型排除，再做数量收敛**。① 查 `dlllist` 有无 CLR / mscoree / java（案例第 4 步用的就是这个检查），排除 JIT；② 查 `pslist` 有无杀软进程，排除其自身注入；③ 对剩余命中按进程聚合，看**哪些进程类型**有命中而非命中了多少条。案例的结论表把"非 JIT / 非安全软件的良性注入"明确标为"**中（排除法，非直接证据）**"——这个定级是对的：排除法能缩小范围，不能证明恶意。

<a id="section-31"></a>

#### 陷阱 12：对已终止进程的 VAD 命中过度解读

**现象**：在 `vadinfo` / `vadwalk` 里发现某进程有 `PAGE_EXECUTE_READWRITE` 私有页，报告描述为"该进程正在执行注入的代码"。

**原因**：2.4 的收尾句写得很清楚——「`malfind` 的输出**必须结合 `pslist` 判断进程是否活动**，对已终止进程的命中要谨慎解读」。已终止进程的 `EPROCESS` 对象及其 VAD 尚未被回收（这正是陷阱 2 里 psscan 会扫到它的同一个原因），VAD 树里的可写可执行页在对象回收后仍留在内存里。它是历史状态，不是当前行为。

**影响**：与陷阱 4 同一个方向的错误——把历史行为写成当前状态。

委托方关心的是"该机现在/当时处于什么状态"，而 VAD 里的残留页既不证明代码还在跑，也不证明它曾经跑过（页可能是分配后从未执行）。

**核查**：任何基于 VAD / malfind 的发现都要先确认进程活动状态，用 `pslist` 交叉（2.4 明确要求）。已终止进程的命中改用历史表述，并注意"存在可写可执行私有页"是**能力**而非"已实施"的证据。

<a id="section-32"></a>

#### 陷阱 13：把摘链直接定性为"一定有 rootkit"

**现象**：`psxview` 发现 `pslist=False` 的进程，报告直接定性为"该机被 rootkit 控制"。

**原因**：`psscan=True / pslist=False / 其余视角 True / Exit Time=N/A` 这个组合（3.2 判读表标为"**摘链隐藏进程，正在运行**"）确实是很强的指标——但**摘链行为本身不等于恶意**。安全软件的保护机制、某些取证与分析工具自身的行为、部分商业软件的自我保护，都可能造成进程从某条枚举路径上不可见。**"这是隐藏"和"这是攻击"是两个不同层级的结论。**

**影响**：定性问题需要承担举证责任。

3.6 之后的内核层面检查（`ssdt`、`callbacks`、`unloadedmodules`、`driverscan`）才是 rootkit 判断的完整依据——**摘链是入口证据，不是结论**。

过早定性会让对方只需举出一个"某安全软件会摘链"的例子就推翻你的核心结论，并牵连报告中所有其他发现。

**核查**：**分层表述**。第一层（事实）：该进程在活动进程链表中不可见，其余三个视角均可见，未退出。第二层（推断）：符合摘链隐藏特征。第三层（定性）：需结合内核层面证据——是否存在 inline hook、异常内核回调、未登记驱动、已卸载模块残留。案例的结论表把第一、二层写成"强"，把"命令行是伪装"写成"中（需结合模块分析确认）"，就是这个分层。

<a id="section-33"></a>

#### 陷阱 14：把 `windows.pstree` 的父子关系当硬证据

**现象**：`pstree` 显示 `System (PID 0) → 某个第三方进程`，报告写"该进程由系统直接创建，必为伪造"，据此定性问题。

**原因**：3.4 列出的可疑组合里 `System (PID 0) → 任何非系统进程` 标注为"几乎必为伪造"，但**父 PID 本身是一个可被伪造的字段**（PPID spoofing）——子进程可以自己声明一个父 PID。`pstree` 展示的是内核记录的父子关系字段，它反映的是"记录的值"，不是"实际发生过的创建关系"。

**影响**：父子关系是时间线重建的重要骨架，错误使用会让整条行为链倒错。

而反过来，一个"看起来正常"的父子关系（案例中 `services.exe → svchost.exe`）也**不能证明关系真实**——PPID 可以被伪造成 `services.exe`，让整条链看起来完全正常。

案例第 3 步明确写了"父进程是 `services.exe`（伪装关系正常），命令行是完全标准的…**单看命令行无法定性**"。

**核查**：**父子关系是线索不是证据**。异常父子关系要**逐一解释**（3.4 的原话），且必须由其他证据佐证——创建时间、命令行、模块、后续行为。正常父子关系也不能被当作清白证明，**它与异常父子关系享有同等的伪造可能性**。

<a id="section-34"></a>

#### 陷阱 15：摘链后仍用 `pstree` 去找它的父进程

**现象**：确认某进程 `pslist=False` 后，跑 `windows.pstree` 查它的父进程，输出为空或找不到这一行，分析员据此写「无法确定其父进程，可能为无父进程」。

**原因**：`pstree` 与 `pslist` 走的是同一类入口。 `pstree` 展示的是进程树，而进程树是沿活动进程链表构建的——一个被摘链的进程不在链表上，它在树里同样没有位置。3.2 案例里能看到 `pstree` 能查到 7124，是因为 `pstree` 除了链表路径，还支持从其他视角反查（`thrdscan`/`psscan`），但它展示的父子关系字段仍是 `EPROCESS` 里记录的 `InheritedFromUniqueProcessId`，摘链动作本身不会去改这个字段。也就是说：查得到不等于它出现在主链上。

**影响**：父进程是行为链的骨架，也是「谁启动了你」的答案。这个字段空了，等于丢掉整条归因路径——而它恰恰是一个摘链进程身上**最可能还完整、也最有价值**的字段（攻击者摘链是为了隐藏自己，不是为了改自己的父进程号）。

**核查**：摘链进程的父进程从 `EPROCESS` 字段直接读，而不是从树里找。 用 `psscan`/`thrdscan` 视角定位该进程，再从它的 `EPROCESS` 结构里取 `InheritedFromUniqueProcessId`，然后回到 `pslist` 里查那个 PID 是谁——注意那个父进程很可能在链路表上、可见。

```bash
# 定位摘链进程在 psscan 视角下的记录
python3 vol.py -f DigiForensics-mem.raw -r csv windows.psscan | grep ',7124,'
# 取其 InheritedFromUniqueProcessId，再回 pslist 查该 PID
python3 vol.py -f DigiForensics-mem.raw -r csv windows.pslist | grep ',632,'
```

报告里区分「树中位置」与「父进程字段」两件事：摘链导致它在进程树中无位置，但其 `InheritedFromUniqueProcessId` 为 `<PPID>`，该 PID 对应 `<进程名>`。

<a id="section-35"></a>

### 4.4 结论表述

<a id="section-36"></a>

#### 陷阱 16：把"各视角均 True"写成"未发现其他隐藏进程"

**现象**：`psxview` 里除目标进程外所有行的各视角都是 `True`/`-`，报告写"未发现其他隐藏进程"。

**原因**：案例的引文特别点了这一条——其他进程"各视角均为 True"这一点不构成"未发现其他隐藏"的依据，因为阴性结果的检出能力有限。四种枚举视角覆盖的是进程对象的四个发现路径，**它们都不覆盖的隐藏手法是存在的**：比如对象本身被移出所有可扫描的池分配、进程在链表中被替换成另一个进程的 `EPROCESS`（对象替换而非摘链），或隐藏发生在 `csrss` 侧对应的会话数据结构里。视角一致只说明"这四个路径都看到了它"。

**影响**：把有限的阴性覆盖包装成全面的排除性结论。

这类表述在质证时极易被推翻——**只需要举出一种这四个视角都覆盖不到的手法**，你的"未发现其他"就站不住了。

**核查**：**阴性发现必须写明检查范围与方法**。表述形态：「本次以 `psxview` 对镜像内进程做四视角交叉比对（活动进程链表 / 内存扫描 / 线程反查 / 会话视图），在 [采集起止时间] 区间的镜像内未发现第二个摘链进程」，并列出未覆盖范围——仅覆盖进程对象层面的隐藏，不含内核对象替换、模块级隐藏、内核态 rootkit。同时把"检出能力有限"这个前提写明，而不是留给读者默认。

<a id="section-37"></a>

#### 陷阱 17：把 `malfind` 未命中写成「该进程没有被注入」

**现象**：对 187 个进程逐个跑 `malfind`，目标进程 PID 7124 那一列没有命中，报告写「PID 7124 未发现代码注入」。

**原因**：`malfind` 的过滤只看保护属性、VAD 类型和内容是否全零（2.4 的源码条件），覆盖不到若干形态——手动映射（self-inject）的映像若停在可读可写页上，没有 `EXECUTE` 位就被直接 `continue` 掉；`VirtualAlloc` + `WriteProcessMemory` 注入后若未调用 `VirtualProtect`，整段是 `PAGE_READWRITE`，同样出不来；被释放、已换出或整区为零的 VAD 也会被跳过。**注意反过来的情形**：注入代码即便被报出，`Notes` 列也可能因为没有 `MZ` 头而为空——所以既不能用 `Notes` 非空来证明注入，也不能因为它为空就当作阴性。

**影响**：这与陷阱 14 是同一个错误的镜像版本——把有限的检出当成全称否定。 摘链（进程层）+ `malfind` 未命中（内存层）会组合出「有隐藏进程但它内部干净」这个结论，而它恰恰是本案里最需要继续查的情形。委托方会据此认为隐藏进程不构成实质威胁。

**核查**：阴性结论必须写成「`malfind` 判据下未命中」，并列出该判据覆盖不到的手法。 具体三条：① 无 `MZ` 头的纯 shellcode；② 手动映射或未改页保护的可读写区；③ 已被释放或换出的区域。补充手段是 `windows.vadinfo --pid` 查全部 VAD 的保护属性（不限于 `EXECUTE`）、`windows.vadyarascan` 扫 VAD 内容，以及 `windows.malware.ldrmodules` 比对加载器视角与实际映射。

句式：「PID 7124 在 `malfind`（无文件映射 + 含 `PAGE_EXECUTE` + PE 头）判据下无命中；**未覆盖**：无 MZ 头的 shellcode 片段、手动映射且未设 `PAGE_EXECUTE` 的可读写区、已换出或已释放的区域。`vadinfo` 显示该进程含 `<M>` 个 `PAGE_READWRITE` 私有区，`<K>` 个含 `PAGE_EXECUTE`」。

<a id="section-38"></a>

#### 陷阱 18：用符号缺失下的插件输出作为阴性依据

**现象**：镜像符号没配好，`psxview` 只输出了前几行或干脆报错，分析员改用 `pslist`（同样受影响）做了一份「未发现摘链进程」的结论，报告里没有提符号这件事。

**原因**：符号不匹配时插件不一定报错，它会输出结构完整、数值合理的错误数据——这是[第 03 篇](../memory-acquire/memory-acquire-windows-profile.md)陷阱 9 与陷阱 10 的核心：`windows.info` 部分字段为空、进程名乱码、链表走不通，都会以「少了几行」而不是「崩了」的形式出现。一份被截断的 `psxview` 输出，在视觉上与「就只有这么多进程」的正常输出无法区分，尤其当它恰好列出了 `System`、`smss`、`csrss` 这几个看起来正确的头几行时。

**影响**：这是一次「没跑成功」被当成「跑了没找到」。摘链进程如果正好落在链表遍历之后、因为结构解析错误而中断的那一段之后，它就不会出现在输出里——**而阴性结论恰恰写在这个输出上**。这类错误极难自查，因为报告里的数字读起来完全正常。

**核查**：任何插件的阴性结论，前置条件是符号与镜像的匹配已被验证。 顺序固定：`windows.info` 逐字段过一遍 → `windows.pslist` 做结构级验证（进程树顺序 `System → smss → csrss → wininit → services` 正确、进程名非乱码、数量在 150–300 区间）→ 才轮到 `psxview`。输出行数异常偏少（明显少于该机角色应有的量级）就是中断的信号，不是「干净」的信号。

```bash
# 前置验证不过就不要往下走
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.info
python3 vol.py -f DigiForensics-mem.raw -q windows.pslist | wc -l   # 明显偏小即异常
```

报告里凡涉及阴性发现的，写明「本次分析在符号匹配已验证（`windows.info` 输出见附件 X）的前提下执行，进程总数 N」。

<a id="section-39"></a>

#### 陷阱 19：把「进程已终止」与「内存已释放」当成同一件事

**现象**：某进程不在 `pslist` 输出里，报告写「该进程已退出，相关内存已释放，未留痕迹」。

**原因**：进程退出与它占用的物理内存被回收之间有延迟，而且残留内容往往还在镜像里。 `EPROCESS` 对象在退出后仍留在非分页池（这就是 `psscan` 能扫到它的原因）；进程的用户态地址空间在进程对象完全释放前也可能保留部分页内容——尤其是被换出到页文件、或被某个内核引用（如挂起调试、崩溃转储、`ProcDump` 之类）继续持有时。「不在 `pslist` 里」是链表状态，不是内存状态。

**影响**：把「没有进程记录」升级成「没有残留」，会直接关闭掉一条真实的调查线——若该进程曾持有凭据或解密后的数据，残留页就是唯一证据。这一条与陷阱 11 是同一族错误（VAD 残留被当成不存在），但方向更隐蔽，因为它用的是「已释放」这个听起来很确定的词。

**核查**：「进程不存在」与「内存无残留」是两句话，分别需要各自的判据。 前者由 `pslist`/`psxview` 回答；后者要看非分页池里是否还有该 `EPROCESS`、以及被换出区域（`windows.pagefile`、swap 文件）里是否留有可恢复内容。

```bash
# 该 PID 是否仍有对象残留
python3 vol.py -f DigiForensics-mem.raw -r csv windows.psscan | grep ',<PID>,'
# 有残留 → 改用历史表述；无残留 → 才可写「未发现残留」
```

句式：「PID `<N>` 不在 `pslist` 输出中（已不在活动进程链表）；`psscan` 视角下**仍可见其 `EPROCESS` 对象**（偏移 `<addr>`），表明进程对象尚未被内存分配器回收——**不能据此认定其内存内容已释放**」。

<a id="section-40"></a>

#### 陷阱 20：把 `dlllist` 的空结果当成「该进程没加载任何非系统模块」

**现象**：`windows.dlllist --pid 7124` 输出里过滤 `C:\Windows` 与 `C:\Program Files` 之后没有剩余行，报告写「PID 7124 未加载任何非系统 DLL，模块侧未见异常」。

**原因**：过滤掉两条路径之后剩下的空集，与插件本来就没输出模块是两件完全不同的事，而输出形态可能一样。`dlllist` 依赖 `PEB->Ldr` 的三条模块链表（InLoadOrder / InMemoryOrder / InInitializationOrder），而这正是 `pebmasquerade` 一类手法会动的地方——2.5 把「在内存里有映射、但不在模块链表里」明确写成**被刻意隐藏的模块**特征。换句话说，`dlllist` 为空恰恰可能是隐藏发生过的信号，而不是「没有可疑模块」的信号。另外反过来说，若进程刚被创建、加载器结构尚未完全建立，输出也可能为空。

**影响**：模块侧是 2.3「路径优先于名字」的落点，也是陷阱 8 里区分伪装进程的关键手段。这个阴性结论会让「命令行正常 + 模块干净」两条弱证据合起来，把一个摘链进程的伪装程度评估成「轻度」。

**核查**：先确认 `dlllist` 本身有效，再看它有没有命中。 有效性检查：输出行数与该进程线程数、内存占用是否相称（一个 19 线程的 `svchost` 至少应有几十个模块），以及与 `windows.getsids`/模块基线的对照。确认有效之后，空结果才可以写成「`dlllist` 输出 `<M>` 个模块，全部位于 `C:\Windows` 与 `C:\Program Files` 之下」。若怀疑加载器结构被改，用 `windows.vadinfo --pid` 反查 `FILE_MAPPED` 类型的 VAD，与 `dlllist` 的模块集做差集——差集里出现、模块链表里没有的，就是 2.5 说的隐藏模块。

<a id="section-41"></a>

## 五、案例示例

<a id="section-42"></a>

### 5.1 svchost 摘链与 PAGE_EXECUTE_READWRITE 注入的交叉定性

**场景**

查获一台 Windows 11 工作站的内存镜像 `DigiForensics-mem.raw`（16 GB RAM）。委托方要求确认"该机是否存在恶意代码注入"。初步 `pslist` 枚举 187 个进程，数量与工作站角色相符，**未见明显异常进程**。

这条路径的价值在于说明：**进程数量正常不能作为阴性结论的依据。**

摘链隐藏的进程在 `pslist` 里根本不存在，"没有异常进程"恰恰是摘链的预期表现。

要发现它，必须换一个不依赖活动链表入口的视角。

**处置过程**

先固化基线与符号：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -q windows.info | sed -n '1,4p'
Variable      Value
Symbols       ntkrnlmp.pdb/8C4A1B2D-3E5F-4A6B-9C7D-1E2F3A4B5C6D/1
NtBuildLab    22631.3155.amd64fre.ni_release.241203-1105
SystemTime    2026-03-14 10:29:52

$ python3 vol.py -f DigiForensics-mem.raw -r csv windows.pslist > /work/pslist.csv
$ echo "进程总数: $(($(wc -l < /work/pslist.csv) - 1))"
进程总数: 187
```

`psxview` 是本案的关键插件，它一次给出四个独立视角的交叉结果：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -r csv windows.malware.psxview > /work/psxview.csv
$ head -1 /work/psxview.csv
TreeDepth,Offset(Virtual),Name,PID,pslist,psscan,thrdscan,csrss,Exit Time

$ grep ',False,' /work/psxview.csv
1,0x1a3e5000a00,svchost.exe,7124,False,True,True,True,N/A
1,0x1a3f2200800,System,4,True,True,-,True,N/A
```

**PID 7124 的四个字段组合是核心**：`pslist=False`（活动链表无）、`psscan=True`（内存池扫描有）、`thrdscan=True`（线程存在）、`csrss=True`（会话可见），且 `Exit Time=N/A`（未退出）。

> 第二行 `System`（PID 4）的 `thrdscan` 为 `-` 而非 `False`。

`-` 表示该视角对此进程不适用，不等于"看不见" —— System 的线程不通过 `thrdscan` 枚举，判读时把 `-` 当成阴性会引入假异常。

三视角独立确认，并取父进程与命令行：

```bash
# pslist 中确认没有（列序：TreeDepth,PID,PPID,ImageFileName,Offset,...）
$ tail -n +2 /work/pslist.csv | cut -d, -f2 | tr -d '"' | grep -x 7124
（无输出）

$ python3 vol.py -f DigiForensics-mem.raw -r pretty windows.pstree | grep -A1 '7124'
PID    PPID  ImageFileName   Threads  Processes
7124   632   svchost.exe     19       services.exe

$ python3 vol.py -f DigiForensics-mem.raw -r pretty windows.cmdline | grep '7124'
7124   C:\Windows\system32\svchost.exe -k netsvcs -p -s
```

父进程 `services.exe` 符合 svchost 的正常拉起关系，命令行 `-k netsvcs -p -s` 与标准服务宿主完全一致。命令行正常恰恰是伪装的意图所在，不能拿它当无罪证据。

注入检测，取出注入区并验证其内容类型：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -r csv windows.malware.malfind \
    | grep '7124'
PID   Process     Start       VAD              Size    Protection
7124  svchost.exe 0x1a3e5000  0x7ff712345000   0x2a000  PAGE_EXECUTE_READWRITE

$ python3 vol.py -f DigiForensics-mem.raw -o /work/malfind-dump \
    windows.malware.malfind --dump
$ xxd -l 16 /work/malfind-dump/pid.7124.vad.0x7ff712345000.dmp
00000000: 4d5a 9000 0300 0000 0400 0000 ffff 0000    MZ................
```

`MZ` 头确认注入区是一个完整的 PE 映像，`Size = 0x2a000`（172 KB）远大于任何正常 DLL，排除片段化代码。

最后排除良性注入解释：

```bash
# JIT：.NET / Java 运行时会产生大量 RWX 私有页
$ python3 vol.py -f DigiForensics-mem.raw -r csv windows.dlllist --pid 7124 \
    | grep -iE 'clr|mscoree|mscorlib|java|jvm'
（无输出）
# 安全软件自身注入
$ python3 vol.py -f DigiForensics-mem.raw -r csv windows.pslist \
    | grep -iE 'MsMpEng|defender|kaspersky|eset|avp|360|huorong'
（无命中）
```

**结论**

三条**相互独立**的证据交叉，构成定性：

| 证据线 | 观察 | 证明的环节 |
|---|---|---|
| 摘链 | `psxview`：`pslist=False`，其余三视角 `True`，`Exit Time=N/A` | 该进程活跃但被移出活动链表 |
| 注入 | `malfind` 命中 `PAGE_EXECUTE_READWRITE` 私有页，`Size=0x2a000`，`MZ` 头 | 存在非映像的完整 PE 代码 |
| 伪装 | 命令行 `-k netsvcs -p -s` 与父进程关系均正常 | 有意隐藏，非误操作 |
| 排除良性 | 无 CLR/Java 模块，无安全软件进程 | 排除 JIT 与杀软注入 |

| 结论 | 强度 |
|---|---|
| PID 7124 正在运行且被摘链隐藏 | 强 |
| 该进程内存在注入的 PE 映像 | 强 |
| 命令行与服务组显示为伪装 | 中（需模块基线比对确认） |
| 非 JIT / 非安全软件的良性注入 | 中（排除法，非直接阳性证据） |

**不能证明的**：不能仅凭内存镜像认定"入侵行为已发生"。

摘链与注入证明的是**该机当时存在被刻意隐藏的可执行代码**，至于该代码是被谁部署、经什么通道进入、是否已外传数据，需要结合磁盘、网络与日志证据。

**误判对照**

本案有两个高代价的误判方向。

方向一：把 `pslist` 数量正常读成阴性结论。

187 个进程对工作站完全正常，若就此收工，摘链进程会作为"不存在"被写进报告。

判据是必须引入不依赖 `PsActiveProcessHead` 的视角 —— `psscan` 走内存池扫描、`thrdscan` 走 `ETHREAD` 反查、`csrss` 走会话结构反查，三者入口各不相同。

只有多视角交叉才能把"入口可信"这个前提坐实。

方向二：把摘链直接定性为"一定有 rootkit"。 摘链的良性成因至少有三个：某些杀软/EDR 的自我保护会临时摘链；某些系统组件的更新残留会留下已退出但未摘干净的 `_EPROCESS`；调试器附加时会有临时摘链。判据要看三个字段的组合：

| 观察组合 | 判读 |
|---|---|
| `pslist=False` + `Exit Time` 已填（已退出） | 系统更新残留，非异常 |
| `pslist=False` + `Exit Time=N/A` + `thrdscan=True` | 进程活跃且被摘链，需进一步定性 |
| `pslist=False` + 多视角均 `-`/`False` | 视角覆盖不足，判据不成立 |

本次命中第二行，且叠加了 `malfind` 的 RWX + `MZ` 头，两条独立证据互证，**定性依据不是摘链本身，而是摘链与注入的共现**。

还有一个反向的判读错误值得写进报告：其他进程"各视角均为 True"**不构成"未发现其他隐藏进程"的依据**。因为摘链型隐藏可以做到对 `pslist`、`psscan`、`psxview` 三者同时不可见（三个插件都可能依赖同一个被篡改的入口）。

正确表述是「本次交叉比对未发现其他摘链进程」，并注明未验证 `PsActiveProcessHead` 链表头本身的完整性。

<a id="section-43"></a>

### 5.2 JIT 编译区被误判为注入的假阳性

**场景**

同一台工作站的另一起委托：委托方怀疑某业务应用（一个 Electron 应用，内嵌 V8 引擎）被植入了木马。分析方跑完 `malfind` 后得到 47 条命中，全部是 `PAGE_EXECUTE_READWRITE` 的私有页，报告初稿写"发现 47 处代码注入"。

委托方当场质疑：这台机器上跑的每一个 Electron 应用都会这样，47 条对不上"一处植入"的怀疑。

注入检测启发式在 JIT 应用上可能产生大量误报；实际假阳性率依赖插件版本、过滤规则与样本集，需要用测试数据评估，而 `malfind` 默认输出不做任何区分。

**处置过程**

先看命中的分布特征 —— JIT 注入与恶意注入在分布上有明显区别：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -r csv windows.malware.malfind \
    > /work/malfind-all.csv
$ python3 - <<'PY'
import csv, collections
rows = list(csv.DictReader(open('/work/malfind-all.csv', encoding='utf-8')))
c = collections.Counter(r['Process'] for r in rows)
for name, n in c.most_common():
    sizes = [int(r['Size'], 16) for r in rows if r['Process'] == name]
    print('%-24s 命中 %2d  尺寸 %x-%x' % (name, n, min(sizes), max(sizes)))
PY
app.exe                命中 31  尺寸 0x1000-0x1c000
chrome.exe             命中  9  尺寸 0x2000-0x9000
w3wp.exe               命中  4  尺寸 0x1000-0x3000
svchost.exe            命中  3  尺寸 0x2a000-0x2a000
```

**四个特征指向 JIT**：

1. **命中集中在少数几个进程**，而非分散 —— 恶意注入通常针对单个目标进程
2. **尺寸跨度大**（`0x1000` 到 `0x1c000`），JIT 代码块大小随函数复杂度变化
3. **进程名是解释器宿主**（`app.exe` 是 Electron、`chrome.exe`、`w3wp.exe` 是 IIS worker）
4. **单进程内命中数多**（31 条），一个进程里塞 31 段 RWX 代码，正常业务不会有

验证 Electron/V8 特征：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -r csv windows.dlllist --pid 8840 \
    | grep -iE 'v8|libcef|nw\.js|node\.dll|chrome_elf'
0x7ff9...  0x480000  C:\Program Files\app\resources\libcef.dll
0x7ff9...  0x120000  C:\Program Files\app\resources\v8_context_snapshot.bin
```

`libcef.dll` + `v8_context_snapshot.bin` 是 Electron 应用的标准构成，JIT 引擎在进程内，运行期必然产生大量可执行私有页。

验证 .NET 侧（Electron 不走 CLR，两条路都要排）：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -r csv windows.dlllist --pid 8840 \
    | grep -iE 'clr\.dll|mscoree\.dll|mscorlib'
（无输出）
```

区分真注入 —— 看 PE 头之后的节表与熵：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -o /work/dump windows.malware.malfind \
    --pid 8844 --dump
$ for f in /work/dump/pid.8844.vad.*.dmp; do
    printf '%s  ' "$(basename "$f")"
    xxd -l 2 -p "$f"
  done
pid.8844.vad.0x7ff712340000.dmp  4d5a
pid.8844.vad.0x7ff712360000.dmp  55
pid.8844.vad.0x7ff712380000.dmp  55
```

只有第一段以 `MZ` 开头（完整 PE），其余是 `55`（`push ebp`，即 `mov rbp, rsp` 序言）。后两段是编译出来的函数代码块，不是 PE 映像 —— 这是区分 JIT 代码块与注入 PE 的决定性判据。

再看真正需要关注的 `svchost.exe` 那 3 条：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -r csv windows.malware.malfind \
    | grep 'svchost'
PID   Process     VAD              Size    Protection
1264  svchost.exe 0x7ff712345000   0x2a000  PAGE_EXECUTE_READWRITE
```

三段尺寸**完全相同**（`0x2a000`），且落在同一个 svchost。这个"尺寸齐一"的形态与 JIT 的"尺寸参差"正好相反，是手工映射映像的典型特征。

**结论**

47 条命中拆分为两类：

| 类别 | 条数 | 判据 | 结论 |
|---|---|---|---|
| Electron/V8 JIT 代码块 | 44 | 尺寸 `0x1000`–`0x1c000`（4 KB–112 KB）参差，44 条中仅 1 条以 `MZ` 开头 | 良性 |
| `svchost.exe` 内注入 PE | 3 | 尺寸齐一 `0x2a000`，以 `MZ` 开头 | **异常** |

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| `app.exe`/`chrome.exe`/`w3wp.exe` 的 44 条命中为 JIT 代码块 | `libcef.dll` + `v8_context_snapshot.bin` 在列；`MZ` 头仅 1/44 | 强 |
| `svchost.exe`(PID 1264) 内 3 段为注入的 PE 映像 | `MZ` 头 + 尺寸齐一 + `PAGE_EXECUTE_READWRITE` 私有页 | 强 |
| 该应用未被植入木马 | 44 条良性命中已逐条归因 | 中（限于采集窗口） |

**范围限定**：本次仅在采集窗口内、对 `malfind` 的 47 条命中做了 PE 头与模块归属核验。

**未覆盖**：`app.exe` 中未被 `malfind` 命中的其他注入形态（原子注入不产生 RWX 私有页）、已被释放的 VAD、以及应用自身的安装包完整性。

**误判对照**

这个案例的核心误判是：把 `malfind` 的命中数直接当成注入点数。

`malfind` 的过滤条件写在插件源码里（`volatility3/plugins/windows/malware/malfind.py` 的 `list_injection_sites`），与"看起来像不像 PE"无关：

1. 页保护字符串同时含 `EXECUTE` 与 `WRITE`；**或**含 `EXECUTE` 但不可写、且区内存在 dirty 页（用于发现用提权 `WriteProcessMemory` 注入到 `PAGE_EXECUTE_READ` 的情形）
2. 再叠加类型条件：`(Private==1 且 Tag=="VadS")` **或** `(Private==0 且 Protection != "PAGE_EXECUTE_WRITECOPY")`
3. 最后排除内容全零（分页不可读或整区为零）的 VAD

三点需要与输出列区分开：

- **`MZ` 头不是过滤条件**。它只是输出里的 `Notes` 列（另有 `55 8b`/`55 48`/`55 89` 几种函数序言标注），命中与否**不影响该 VAD 是否被列出**。所以"带 MZ 头"是加分项，不是入选前提。
- **不存在页对齐检查**。源码里没有任何 `Start % 0x1000` 之类的判断，VAD 起点是否页对齐与是否报出无关。
- `Private` 与 `Tag` 是一对而非单个 `Private` 标志，`Private==0` 的非 WRITECOPY 可执行区同样会被列出。

这些条件**与恶意性无关**——任何运行时生成并执行代码的框架（JIT、.NET、浏览器引擎）都会满足。所以"47 条命中"这个数字本身不含任何指向性。

正确的判据要落到三个字段的组合上：

1. **PE 头**（`xxd -l 2` 取前两字节）—— `4d5a`（MZ）说明是完整映像，`55`/`48` 等说明是裸代码块。这一条最快、也最有区分度
2. **尺寸分布** —— JIT 尺寸参差（0x1000–0x1c000），手工映射尺寸齐一
3. **模块归属** —— 进程内是否有 `libcef.dll`/`clr.dll`/`jvm.dll` 这类 JIT 引擎

本次 44 条中 43 条以 `55` 开头、尺寸从 4 KB 到 112 KB、跨度约 28 倍、进程内有 `libcef.dll`，三条判据一致指向 JIT；而 `svchost.exe` 的 3 条在三条上全部相反。

同一份输出里两类命中并存，正是必须逐条核验而不能整体采信的原因。

反向也要注意：不要因为一个进程"大部分命中是 JIT"就整体排除它。

JIT 与注入可以在同一进程内并存 —— 恶意代码完全可以注入进一个 Electron 应用的 JIT 环境里。**排除必须逐条做，不能按进程打包。**

本案若按进程排除 `app.exe`（31 条，占多数），那 1 条真正的 `MZ` 命中就会被漏掉。

<a id="section-44"></a>

### 5.3 反例：只跑 pslist 下的无隐藏进程结论

**场景**

委托方送来一台 Windows Server 2019 宿主机镜像，问题是"在采集时刻是否有未登记的进程在运行"。分析方按常规流程跑完 `pslist`，输出 96 个进程，与该机角色（文件服务器）相符，报告中写下"未发现异常进程"。

这份报告在复核阶段被退回。退回理由是：分析方从未说明 `pslist` 的工作原理依赖哪个内核结构，因此阴性结论没有任何检出能力说明。

这条路径要处理的是**阴性结论的表述纪律**：阴性发现的强度不来自工具没报错，而来自检查范围被明确界定。

**处置过程**

第一步，把阴性结论落到具体的检查范围上：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -r csv windows.pslist > /work/srv-pslist.csv
$ echo "pslist 进程数: $(($(wc -l < /work/srv-pslist.csv) - 1))"
pslist 进程数: 96
```

第二步，界定 `pslist` 的检出边界 —— 它遍历 `PsActiveProcessHead` 链表，所以它的阴性结论**只在这个链表完整时成立**：

```bash
# 独立验证链表头的自洽性：链表长度应与扫描到的进程数同量级
$ python3 vol.py -f DigiForensics-mem.raw -q windows.psscan -r csv \
    | wc -l
101
```

`psscan` 走内存池扫描，**不依赖链表入口**，得到 101 个。差值 5 说明链表中确有缺项。

第三步，逐条归因这 5 条差集：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -q windows.malware.psxview -r csv \
    > /work/srv-psxview.csv
$ grep ',False,' /work/srv-psxview.csv
1,0x1b2e4000a00,sqlservr.exe,4480,False,True,True,True,2026-03-14 02:14:33
1,0x1b2e5000a00,dllhost.exe,5120,False,True,True,True,2026-03-14 03:51:07
1,0x1b2e6000a00,spoolsv.exe,5560,False,True,True,True,2026-03-14 04:02:55
1,0x1b2e7000a00,TrustedInstaller,5904,False,True,True,True,2026-03-14 04:02:58
1,0x1b2e8000a00,wmiprvse.exe,6216,False,True,True,True,2026-03-14 04:33:12
```

5 条全部 `Exit Time` 已填（均已退出），且时间集中在 02:14–04:33，符合 Windows Update 期间服务批量重启退出的模式。

`psscan` 多列这 5 条，是因为内存池里还留着它们的 `_EPROCESS` 池块，属于退出后的残留。

第四步，验证这 5 个进程确实已终止：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -q windows.thrdscan -r csv \
    | grep -cE ',(4480|5120|5560|5904|6216),'
0
$ python3 vol.py -f DigiForensics-mem.raw -q windows.certscan -r csv | wc -l
0
```

`thrdscan` 零命中（无残留线程）、`certscan` 零命中（无残留签名）——两条独立于进程链表的视角同时确认这 5 个 PID 不再活跃。

第五步，限定未覆盖范围：

```bash
# 明确本次未做内核回调表与 ObCallback 快照
$ python3 vol.py -h 2>&1 | grep -cE 'windows.(callbacks|objscan|driverlist)'
3
# 插件存在但本次未执行
```

**结论**

在 `DigiForensics-mem.raw` 采集窗口内：

- `pslist` 枚举 96 个进程，与该文件服务器角色相符
- `psscan` 多出的 5 条经 `psxview` 的 `Exit Time`（02:14–04:33）+ `thrdscan` 零线程 + `certscan` 零签名，**三条独立证据确认均已退出**，属池块残留
- **在采集时刻未发现活跃的未登记进程**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 采集时刻 96 个活跃进程与服务器角色相符 | `pslist` 96 条 + 服务类进程构成 | 强 |
| `psscan` 多出的 5 条为已退出进程的池块残留 | `Exit Time` 已填 + `thrdscan` 0 + `certscan` 0 | 强 |
| 采集时刻未发现活跃的未登记进程 | 三视角交叉（链表/内存池/线程/签名） | 中 |

**未覆盖范围（必须写进报告）**：
- `PsActiveProcessHead` 链表头自身的完整性未独立验证（被篡改时三视角可同时失效）
- 未采集 `windows.callbacks` / `windows.objscan` / `windows.driverlist` 内核回调与对象表快照
- 已退出且 `_EPROCESS` 池块被释放的进程不可见
- 镜像之外的磁盘与事件日志证据不在本次结论范围

**误判对照**

这个案例要纠正的是**阴性结论的默认写法**。

错误判据是"工具没报异常 → 没有异常"。

`pslist` 是一个**枚举型插件**，它的阴性结果只有一个含义：**在这条链表上没有看到东西**。

它没有能力说明"没看到"是因为真的不存在，还是因为没被这条链表覆盖。

正确写法必须包含三个要素，缺一个这个阴性结论就不成立：

1. **范围限定** —— 「在 `DigiForensics-mem.raw` 采集窗口内、经 X/Y/Z 三个视角比对」
2. **检出能力说明** —— 每个视角的入口是什么，因此阴性覆盖了什么、没覆盖什么
3. **未覆盖清单** —— 明确列出本次没做的检查项

对比两种表述：

| 错误表述 | 正确表述 |
|---|---|
| 未发现异常进程 | 在采集窗口内，经 `pslist`（活动链表）/ `psscan`（内存池）/ `thrdscan`（线程）/ `certscan`（签名）四视角比对，未发现活跃的未登记进程；`pslist` 多出的 5 条为已退出进程的池块残留 |
| 无隐藏进程 | 本次交叉比对未发现其他摘链进程；`PsActiveProcessHead` 链表头完整性未独立验证 |

按错误判据走的代价很具体：报告进入复核后，对方只需引用一条公开的摘链技术说明，就能指出"活动链表遍历是单点依赖，你的阴性结论无法覆盖链表被篡改的情形"，进而**整份报告的结论部分被要求重做**。

而实际检材没有任何问题 —— 损失的是可信度与时间。

反向的代价也存在：把阴性结论写得过于保守（"本次检查无法排除任何可能"），会让委托方拿不到可用的结论。

分寸在于**把范围划清楚，而不是把结论说软**。

<a id="section-45"></a>

## 六、扩展阅读方向

**前置与基础。** 反射加载是这一层里最需要手工确认的一类。
malfind 导出的 PE 要逐个字段比对：`e_lfanew` 是否落在合理区间、
`SizeOfImage` 与实际映射是否一致、导入表与磁盘上的样本能否对应上。
工具给的是候选，人工比对给出的才是结论。

**同层深入。** 进程空化要落到地址层面，`hollowprocesses` 的输出只是入口，
真正过证据的是主线程起始地址与映像 EntryPoint 的比对结果。
无文件执行的证明更严格：`filescan` 确认磁盘没有对应文件，
同时内存里躺着一份完整的 PE，两条独立来源同时成立才算立住。
YARA 规则可以针对本案组织定制，再用 `vadyarascan` 做全镜像扫描兜底。

**相邻议题。** 走到内核层，SSDT 钩子、内核回调、驱动扫描结果
与未加载模块这四类证据要合起来判断——任何单一指标都能被有意伪造。
跨平台的同类思路也要并排看，Linux 侧的 `pslist`、`psscan`、`modxview`
覆盖的是同样的问题，见 [《Linux与Android内存取证》](../memory-artifact/memory-artifact-linux-android.md)。

**工具与判据。** 从 LOLBin、无文件执行到线程劫持的痕迹解读与交叉验证，
在 [《注入执行与免杀痕迹》](memory-analyze-memory-injection-and-evasion.md) 里展开。
进程发现的外联行为要与内核池里的连接记录对上才算闭合证据链，
这一步见 [《网络连接与流量痕迹》](../memory-artifact/memory-artifact-memory-network-artifacts.md)。

**判据与反例。** 「内存里有一段像 PE 的数据」远不等于「执行了恶意代码」：
内存中的可执行映像可能来自正当的进程注入、也可能只是取证工具
自身加载的模块。报告里必须写出是哪条证据支撑哪个环节，
把「发现注入痕迹」写成「确认执行」是最常见的越界。

---

<a id="section-46"></a>

## 七、命令速查

```bash
# ===== 0. 前置：确认符号可用 =====
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.info

# ===== 1. 基线 =====
python3 vol.py -f DigiForensics-mem.raw -r csv windows.pslist  > pslist.csv
python3 vol.py -f DigiForensics-mem.raw -r csv windows.psscan  > psscan.csv
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.pstree > pstree.txt

# ===== 2. 摘链检测（核心）=====
python3 vol.py -f DigiForensics-mem.raw -r csv windows.malware.psxview > psxview.csv
head -1 psxview.csv                      # 先看表头确认列名
grep -E ',False,' psxview.csv            # 任一列为 False = 该视角看不到
# 判读：pslist=False 而其余=True 且 Exit Time=N/A → 摘链隐藏，正在运行
#       pslist=True 而 psscan=False      → 刚退出，正常，非异常

# 手工比对 pslist 与 psscan
# 注意：-r csv 第一列是 TreeDepth，PID 在第 2 列（第 3 列是 PPID，别取错）
comm -13 <(tail -n +2 pslist.csv | cut -d, -f2 | tr -d '"' | sort -u) \
         <(tail -n +2 psscan.csv | cut -d, -f2 | tr -d '"' | sort -u)
#   → 输出"psscan 有、pslist 无"的进程

# ===== 3. 命令行（价值最高）=====
python3 vol.py -f DigiForensics-mem.raw -r csv windows.cmdline > cmdline.csv
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.cmdline \
  | grep -iE 'powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|invoke-|iex|bypass|-enc'
python3 vol.py -f DigiForensics-mem.raw windows.cmdline --filters cmdline,cmdline,powershell

# ===== 4. 注入检测 =====
python3 vol.py -f DigiForensics-mem.raw -r csv windows.malware.malfind > malfind.csv
grep -i 'PAGE_EXECUTE_READWRITE' malfind.csv
mkdir -p /work/malfind-dump
python3 vol.py -f DigiForensics-mem.raw -o /work/malfind-dump windows.malware.malfind --dump
for f in /work/malfind-dump/*.dmp; do printf "%s " "$(basename $f)"; xxd -l 4 -p "$f"; done
#   → 4d5a = MZ 头 = PE 映像

# ===== 5. VAD 与模块 =====
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.vadinfo --pid <PID>
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.vadwalk --pid <PID>
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.dlllist --pid <PID>
python3 vol.py -f DigiForensics-mem.raw -r csv windows.dlllist --pid <PID> | grep -viE 'C:\\Windows|C:\\Program Files'
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.malware.ldrmodules --pid <PID>
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.malware.hollowprocesses
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.malware.pebmasquerade
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.malware.suspicious_threads

# ===== 6. 内核层面（rootkit 判断）=====
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.ssdt
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.callbacks
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.unloadedmodules
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.driverscan
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 内存与专项分析 — 进程与注入检测」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《进程与注入检测》（CC BY-SA 4.0）`

文中 `DigiForensics-mem.raw` 为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。

---
