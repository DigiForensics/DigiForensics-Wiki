---
title: "用户行为痕迹"
slug: "computer-registry-log-user-activity-artifacts"
canonical: "https://www.digiforensics.cn/wiki/computer-registry-log-user-activity-artifacts"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:52+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "computer"
space: "计算机取证"
node_path: ["注册表与事件日志"]
---

# 用户行为痕迹

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/computer-registry-log-user-activity-artifacts)

<a id="section-1"></a>

## 一、概述

Prefetch 回答「程序有没有跑过」。用户行为痕迹回答另一件事——**人在干什么**。

这类痕迹散落在注册表的用户配置单元（`NTUSER.DAT`）里，一条条目对应一次入口被使用过的痕迹：打开过某个应用、在地址栏敲过某个路径、挂载过某个盘、点进过某个目录。它记录的是入口的使用，不等于操作的结果（见 2.5）。

密度高，误读率也高。UserAssist 的值经过 ROT13 编码，RunMRU 是二进制链表，Shellbags 记的是资源管理器的导航历史。不解码，拿到手的就是一堆字节。把编码后的字符串直接抄进报告，是这类工件容易出错的地方。

局限同样硬。绝大多数条目只存在于该用户的 `NTUSER.DAT`，配置文件被删除就全部消失；部分键有固定条目上限（UserAssist 旧版本为 100），到顶后循环覆盖；它们只能证明「使用了某个入口」，证明不了操作成功，更证明不了恶意。

这一层位于**分析**环节的「归属与行为」，上游是执行证据——程序执行证据见[Prefetch 深度解析](../computer-execution/computer-execution-prefetch.md)，注册表解析方法见[注册表取证](computer-registry-log-registry-forensics.md)。上游要的是用户 hive 提取与归属判定准不准。这些键值全在用户自己的 hive 里，系统账户 hive（`SYSTEM`）内没有这些内容——只有用户行为才有「用户」。分析系统账户会得到「该用户从未使用过任何程序」的错误结论，因为那些数据根本不在那里。

解析方式必须按版本决定。UserAssist 有两种取值布局（WinXP 16 字节、Win7+ 72 字节），混用会得出完全错误的次数；Shellbags 的结构按版本差异较大，**把旧结构当新结构读会得到完全错位的路径**。下游支撑行为画像：Shellbags 的保留容量不像 UserAssist 那样有固定上限（见 2.3），MountPoints2 记录卷与共享的挂载映射（见 2.4）。

全部痕迹位于 `NTUSER.DAT` 内：

| 痕迹 | 位置（`Software\` 下） | 记录内容 | 容量特性 |
|---|---|---|---|
| UserAssist | `Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` | 程序打开次数与最后使用时间 | **上限约 100 条，循环覆盖** |
| RunMRU | `...\Explorer\RunMRU` | 运行对话框中手工输入过的命令 | 上限约 59 项 |
| TypedPaths | `...\Explorer\TypedPaths` | 地址栏手工输入的路径 | 上限约 30 项 |
| WordWheelQuery | `...\Explorer\WordWheelQuery` | 「打开方式」列表中输入过的关键词 | 有上限 |
| RecentDocs | `...\Explorer\RecentDocs` | 最近打开文档的完整路径 | 按扩展名分子键 |
| MountPoints2 | `...\Explorer\MountPoints2` | 曾挂载过的卷、目录与 GUID 路径挂载 | 按卷标识分子键 |
| Shellbags | `Microsoft\Windows\Shell\Bags` 及 `...\Software\Classes\Local Settings\...\Shell\Bags` | 资源管理器导航历史与排序偏好 | 滚动保留，容量特征见 2.3 |

ROT13 编码的适用范围只有一个：值名（子键名）里的程序路径。

| 元素 | 是否 ROT13 | 说明 |
|---|---|---|
| 值名 / 子键名中的路径 | **是** | `P:\Windows\System32\pqnq.rkr` → `C:\Windows\System32\cmd.exe` |
| Win7+ 的 Run Count | **否** | 是二进制 DWORD，直接按小端读 |
| Win10+ 时间戳子键名中的时间 | **否** | 是 FILETIME（16 字节），**只对路径部分做 ROT13** |

据此能回答的是：某用户打开过哪些程序及其次数、输入过哪些路径、挂载过哪些卷或网络共享到哪个目录、浏览过哪些目录，**以及某目录的文件已被删除时用户是否进过该目录**（Shellbags 独有，5.2 就是靠它定位了目录访问）。

回答不了的部分包括：

- 把 Win7+ 的计数当成 ROT13 字符串去「解码」。 ROT13 只作用于字母，数字原样保留，所以把一个 DWORD 误读成 ROT13 字符串时，往往会得到一个看似合理却完全错误的次数。正确做法是先看值长度（16 / 72 字节）判定版本，再决定解析方式。
- **拿时间来定位行为时刻。** 时间证明力普遍弱于事件日志与 NTFS 时间戳。UserAssist 最后使用时间部分版本有、部分版本没有（**缺失不等于没使用**）；TypedPaths / RunMRU **只有值没有独立时间戳**，其注册表键的最后写入时间**会被其他写入刷新，不精确**。绝不能单独用于精确定位行为时刻，只能作为「某用户与某路径/程序发生过交互」的存在性证据。
- **时间戳的类型搞混。** RecentDocs 与 Shellbags 里的时间是键的最后写入时间，反映用户活动，**但不是「文件被访问」的时间**。
- **操作是否成功。** 这些键值只证明「使用了某个入口」，**证明不了操作完成**。
- **行为是否恶意。** 中性的使用记录，**定性需要行为证据与哈希查库**。
- **入口数量之外的完整历史。** UserAssist、RunMRU、TypedPaths 都有条目上限并循环覆盖，**「最近 N 条」之外的部分不可知**。
- **已删除用户配置文件的痕迹。** **用户配置文件被删除即全部消失**，这类缺失必须限定结论范围。

往下读之前先确认你已经掌握注册表 hive 的提取与路径解析（**尤其是用户 hive 的逐用户选取**，见[注册表取证](computer-registry-log-registry-forensics.md)）、ROT13 与 Base64 这类编码的本质（**ROT13 只作用于字母，数字原样保留**）、Windows 版本差异对键值结构的影响（UserAssist 与 Shellbags 的布局都随版本变化），并且会按值长度与实际取值验证布局假设，**不要照搬任何一版布局**。此外要掌握时间戳的纪元与 FILETIME 换算——Win10+ 的时间戳藏在子键名里——并理解**「存在性证据」与「时点证据」的区别**，这些工件只提供前者。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 工件矩阵与落点

| 痕迹 | 位置（`NTUSER.DAT` 内） | 记录内容 | 容量特性 |
| --- | --- | --- | --- |
| UserAssist | `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` | 程序打开次数与最后使用时间 | **上限约 100 条，循环覆盖** |
| RunMRU | `Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` | 运行对话框中手工输入过的命令 | 上限约 59 项 |
| TypedPaths | `Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths` | 资源管理器地址栏手工输入的路径 | 上限约 30 项 |
| WordWheelQuery | `Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery` | 文件关联「打开方式」列表中输入过的关键词 | 有上限 |
| RecentDocs | `Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` | 最近打开文档的完整路径 | 按扩展名分子键 |
| MountPoints2 | `Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2` | 曾挂载过的卷、目录与 GUID 路径挂载 | 按卷标识分子键 |
| Shellbags / ShellBagMRU | `Software\Microsoft\Windows\Shell\Bags` 及 `Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags` | 资源管理器窗口导航历史与排序偏好 | 滚动保留 |
| BAM / UserAssist 扩展 | `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` 子项 | 部分版本额外记录执行计数 | 视版本 |

全在**用户自己的 hive** 里。`SYSTEM` 装的是 `ControlSet`、服务、会话这类系统级信息，`SOFTWARE` 是 64 位与 32 位机器级配置，两边都没有用户行为。

查错 hive 得到的空结果，**是「数据不在这里」而不是「没有行为」**。

<a id="section-4"></a>

### 2.2 UserAssist 的编码与结构

UserAssist 有**两种**取值布局，必须按 Windows 版本区分。

混用会得出完全错误的次数。

Win7 / Win8.x（Windows 7 起，值长度 72 字节）

| 偏移 | 长度 | 内容 |
| --- | --- | --- |
| 0 | 4 | Session ID |
| 4 | 4 | Run Count（**二进制小端 DWORD**，不是字符串） |
| 8 | 8 | Focus Count（Win7/8 存在；Win8.1 起不再填充） |
| 16 | 56 | 其余为保留填充（0）；**Win7 布局在此处不含时间字段** |

> Win7 的 72 字节布局在偏移 16 之后是纯填充；部分 Win8 构建会在偏移 60 处放入最后使用时间 FILETIME。该字段位置随版本变化，必须用实际检材的长度与取值验证，不要照搬任何一版布局。

**WinXP（值长度 16 字节）**

| 偏移 | 长度 | 内容 |
| --- | --- | --- |
| 0 | 4 | Run Count（DWORD） |
| 4 | 4 | 0 |
| 8 | 4 | 0x00000000 |
| 12 | 4 | **0x000000FF**（版本标记） |

最后使用时间的来源随版本变。Win10 / Win11 会**另外**在 `UserAssist\<GUID>\Count` 下追加带时间戳的子键（形如 `\{GUID}\{timestamp}\{ROT13 路径}`），**时间在子键名里，不在值数据中**。

Win8 及更早版本的值数据里通常不含最后使用时间。**缺失不等于没使用过。**

ROT13 编码的适用范围只有一个：值名（子键名）里的程序路径。适用范围表与「把 Win7+ 的计数当成 ROT13 字符串去解码」的成因见第一章概述，此处不再重复。

<a id="section-5"></a>

### 2.3 Shellbags 的取证价值

Shellbags 记的是资源管理器窗口的**导航序列**：用户进过哪些目录、在每个目录里改过哪些排序与视图设置。

这让它能回答两个别处答不了的问题——

- 用户在**被调查时间窗内**是否浏览过某个特定目录，哪怕该目录下的文件已被删除；
- 目录的**最后访问时间**在注册表层面是否被更新过。

结构按版本差异较大：早期是 `ShellBagMRU` 下的树形节点，较新版本引入了独立的索引表与名称映射表。**解析器必须显式区分版本**，把旧结构当新结构读会得到完全错位的路径。

容量上它不固定，不像 UserAssist 那样有固定条目上限；在长周期案件中它保留的导航记录往往比 UserAssist 的环形缓冲更长。

<a id="section-6"></a>

### 2.4 MountPoints2 的卷与目录挂载痕迹

`MountPoints2` 的子键名是卷标识（Volume identifier）而非普通名字，键值是流式数据，其中可解析出：

- 该卷曾被挂载到**哪些目录**（例如把某个网络共享挂载到 `Z:\` 或某个本地目录）；
- 真实路径（网络路径、USB 标记等）；
- 磁盘卷标。

在数据外泄与溯源案件中它记录的是「用户把哪台机器/哪个共享映射到了哪里」，可与 `SYSTEM` 的 `USBSTOR` 子键交叉印证介质类型（见 5.3）。

它能证明的是挂载映射这一事实存在，不证明映射后的数据去了哪里；该边界的写法见 5.3 的误判对照。

<a id="section-7"></a>

### 2.5 时间语义

时间语义三条，差别很大。

**UserAssist 最后使用时间**：部分版本有，部分版本没有。缺失不等于没使用。

**RecentDocs 路径与 Shellbags**：其中的时间字段是注册表键的**最后写入时间**，反映用户活动，但不是「文件被访问」的时间。

**TypedPaths / RunMRU**：只有值，没有独立时间戳。对应注册表键的最后写入时间可作参考，但会被其他写入刷新，不精确。

结论很直接：这些工件的时间证明力普遍弱于事件日志与 NTFS 时间戳。**绝不能单独用于精确定位行为时刻**，只能作为「某用户与某路径/程序发生过交互」的存在性证据。

<a id="section-8"></a>

## 三、操作步骤

<a id="section-9"></a>

### 3.1 提取用户 hive

```bash
mmls /work/DigiForensics.dd
fsstat -o 2048 /work/DigiForensics.dd

fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -Ei '/Users/[^/]+/(NTUSER\.DAT|UsrClass\.dat)$' | grep -E '^r/r' | awk '{print $2}' \
  | while read -r ino; do
      u=$(echo "$ino" | cut -d: -f2)
      icat -o 2048 /work/DigiForensics.dd "$ino" > "/evidence/registry/users/$u/$(basename "${ino%%:*}")"
    done
```

`UsrClass.dat` 承载了 `HKCU\Software\Classes` 的内容。旧版本中 Shellbags 的部分数据就在其中。

**不能只提 NTUSER.DAT。**

<a id="section-10"></a>

### 3.2 导出并解码 UserAssist

用注册表解析工具加载 hive 后，导出 `UserAssist\{GUID}\Count` 下的全部子键。

**先按值长度定版本，再选解析路径**：

```text
值长度 = 72 字节  → Win7/8.x：Run Count = DWORD(偏移 4, 小端)
值长度 = 16 字节  → WinXP：DWORD(偏移 0, 小端)
子键名形如 \{GUID}\{FILETIME}\{ROT13路径}  → Win10+，取子键名中的 FILETIME 作为最后使用时间
```

无论哪种版本，**值名中的路径都要做 ROT13 还原**。

ROT13 只作用于字母，数字与符号原样通过。所以还原后的路径里出现数字和反斜杠是正常的，不是解码失败。

<a id="section-11"></a>

### 3.3 解析 TypedPaths 与 RunMRU

```text
TypedPaths  值形如：
  "D:\Projects\2024\Q1"=  (0x03 0x00 ...)
RunMRU     结构为 MRU 链表：
  0x00 'm' 'r' 'u' + 计数 + 各条目 "(0x...)null 字符串 null"
```

`RunMRU` 不是普通值列表，是一个 MRU 链表。头部是 ASCII 的 `mru` 加计数，其后是若干 `(0x...)` 标记与 null 终止的路径字符串，按最近使用顺序排。

解析时跳过标记字节，只保留以 null 结尾的字符串。

<a id="section-12"></a>

### 3.4 导出 Shellbags

使用专门的 Shellbags 解析器导出，**明确指定目标系统版本**以启用正确的结构解析。导出结果应包含：导航路径、每条记录对应的窗口特征、该路径在检材中的时间戳。

分析时的实用筛选：

- 只看时间窗内的记录（与案件时间窗比对）；
- 关注指向敏感目录的路径（如财务、研发、`\财务\`、客户资料目录）；
- 与 NTFS 目录 `$STANDARD_INFORMATION` 的访问时间互证。

<a id="section-13"></a>

### 3.5 交叉验证

用户行为痕迹必须与其他证据配合：

- **Prefetch**：确认该程序确实执行。
- **LNK / Jump List**：确认打开了哪个具体文件。
- **事件日志 4624 / 4634**：确认登录与注销区间，判断行为是否发生在有人值守时段。
- **NTFS `$UsnJrnl`**：把「访问过某目录」收敛到具体的文件创建/修改操作。
<a id="section-14"></a>

## 四、常见陷阱

本章按解码与结构判读 → 容量与缺失解释 → 落点与版本差异 → 结论表述边界归组，每条给出：现象、为什么会误判、误判代价、正确做法。

★ 标记表示该操作会**导致原始检材永久灭失或对检材造成不可逆改变**，执行前必须停下来确认。

<a id="section-15"></a>

### 4.1 解码与结构判读

<a id="section-16"></a>

#### 陷阱 1：忘记 ROT13，直接引用值名里的原始字符串

**现象**

UserAssist 导出结果里出现 `P:\Windows\System32\pqnq.rkr`、`C:\Users\victim\AppData\Roaming\bhfgvn\pbagragf`，报告照抄其中一条作为「该用户运行过的程序」。附件里放的是同一份乱码字符串。

**原因**

ROT13 编码的适用范围只有一个：值名（子键名）里的程序路径。 系统在写入 UserAssist 键名时对字母做了 ROT13 映射，**数字、`\`、`:`、`.` 等符号原样保留**。

所以 `pqnq.rkr` 还原后正是 `cmd.exe`——字母全部平移 13 位。而 `E:\7-Zip\7zFM.rxE` 里的数字与符号看着「没被处理」，恰恰说明**编码只作用于字母**，不是解码失败。

解析器（KAPE、regripper 插件、专门脚本）会自动还原；需要人工还原的是手工核对值名与直接引用报告的环节。

**影响**

- 报告里出现**人可读的证据是乱码**，委托方一眼就能看出未做基本处理，**整套报告的可信度被这一条拖垮**；
- 更实质的风险：乱码路径无法与 Prefetch、LNK 中的明文路径做匹配，**交叉验证被迫放弃**，本可以互证的两条证据变成两条孤证；
- 若把乱码写进时间线表格，后续复核者无法定位原值。

**核查**

所有 UserAssist 路径在引用前统一过一遍 ROT13 还原，并在工作记录里保留「原始值名 + 还原后」两列：

```bash
# 校验 ROT13 是否生效：同一路径编码两次应回到原值
echo "C:\\Windows\\System32\\cmd.exe" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# → P:\Windows\System32\pqnq.rkr
echo "P:\\Windows\\System32\\pqnq.rkr" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# → C:\Windows\System32\cmd.exe

# 用解析器导出后，先看还原结果里是否出现可执行扩展名
awk -F',' 'NR>1 && $0 ~ /\.(exe|com|bat|cmd|ps1|vbs|msi)\b/' userassist.csv | head
```

**自查判据**：还原后的字符串里若既没有盘符也没有已知扩展名，多半是解码环节出了问题，不要直接进报告。

<a id="section-17"></a>

#### 陷阱 2：把 Run Count 当 ROT13 字符串去"解码"

**现象**

某 Win7 检材的 UserAssist 值长度为 72 字节。分析者把整个值数据的十六进制转成可打印字符后，再套了一次 ROT13，得到「次数 22」之类的结果，写进报告。而用正确偏移读出的 Run Count 是 218。

**原因**

ROT13 只作用于**值名里的路径**。值**数据**里的 Run Count 是**二进制小端 DWORD**，不是编码文本。Win7/8.x 布局中它在**偏移 4、长度 4**；WinXP 布局在**偏移 0、长度 4**。

**取值之前必须先看值长度**：

| 值长度 | 版本布局 | Run Count 偏移 |
| --- | --- | --- |
| 16 字节 | WinXP | 偏移 0，小端 DWORD |
| 72 字节 | Win7 / 8.x | 偏移 4，小端 DWORD |
| 其他 | **未判定** | **不硬解，返回未知** |

**影响**

- 次数被读错，任何基于频次的推断（"只打开过一次"→"经常使用"）随之反向；
- 错读出的数字看着"合理"，**不会被格式检查拦下**，属于最隐蔽的一类；
- 若错误次数被用于与其他证据对账，会连带否掉本来正确的互证。

**核查**

**先判版本再解析，未判定就明确返回未知**：

```python
import struct

def run_count(data: bytes):
    if len(data) == 72:      # Win7/8.x
        return struct.unpack_from("<I", data, 4)[0]
    if len(data) == 16:      # WinXP
        return struct.unpack_from("<I", data, 0)[0]
    return None              # 版本未判定：不得硬解
```

**报告里写清每个数字的来源偏移**，例如「`NOTEPAD.EXE` 值长度 72 字节，偏移 4 读出 DWORD = 37 次」。这样复核者能独立验证，也能立刻发现版本判定错误。

<a id="section-18"></a>

#### 陷阱 3：把 Win10+ 的子键名 FILETIME 当成值数据里的时间

**现象**

在 Win10 检材上，分析者从值数据中查找最后使用时间，读到一片零，报「该程序无最后使用时间记录」，随即在时间线上退回到注册表键时间。

**原因**

Win10 / Win11 的最后使用时间在子键名里，不在值数据中。 结构形如：

```text
UserAssist\{CEBFF5CD-…}\{01D9A0B1-4C2E-7A31-9E5F-0B6C2D3E4F50}\P:\…\bhfgvn\pbagragf
                    └── 这段 GUID 形式的值就是 FILETIME ──┘
```

Win8 及更早版本的值数据里通常**不含**最后使用时间（Win7 的 72 字节布局在偏移 16 之后基本是填充；部分 Win8 构建会在偏移 60 附近放时间，**位置随版本变化**）。

"值数据里没有时间"和"该程序没被用过"完全是两回事。

**影响**

- 时间线退化到精度很低的注册表键时间，**行动时刻定位整体偏移**；
- 顺序错乱：程序 A 的键时间晚于程序 B，报告推出「B 在 A 之后使用」，而真实顺序可能相反；
- 若结论依赖"某时刻之前没有用过该程序"，这个前提**实际未经验证**。

**核查**

**按版本选择时间来源，并在报告中标注时间来源类型**：

```bash
# Win10+：时间在子键名里，取第二个 GUID 并按 FILETIME 还原
reg query "HKU\TARGET\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" /s /f "{" \
  | grep -oE '\{[0-9A-Fa-f-]{8}-[0-9A-Fa-f-]{27}\}' | head
```

| 检材版本 | 最后使用时间来源 | 报告标注 |
| --- | --- | --- |
| Win10 / Win11 | **子键名中的 FILETIME** | 「时间取自 `UserAssist` 子键名，时间精度为系统记录时刻」 |
| Win7 / Win8 | 值数据内特定偏移，**随构建变化** | 「时间取自值数据偏移 N，**已用本机实际值验证长度与取值**」 |
| 无法确定 | **无可靠时间** | 「**该版本不提供最后使用时间**，本报告不以本工件定位行为时刻」 |

没有时间字段时，报告必须显式声明"无时间"，而不是留空。

<a id="section-19"></a>

### 4.2 容量与缺失解释

<a id="section-20"></a>

#### 陷阱 4：把"UserAssist 里没有"写成"从未使用过"

**现象**

UserAssist 中未见 `7zFM.exe`，报告写「该用户从未使用压缩软件」，进而排除其打包外发图纸的可能。

**原因**

UserAssist 有**固定容量、循环覆盖**。记录数到上限后，新条目会**静默挤出**最旧的条目，且**不留任何痕迹**——不产生事件日志、不写 USN，hive 结构上也不显示"曾被删除"。

旧版本上限约 100 条，具体受注册表值 `Count` 下的条目数与版本配置影响。

所以"没有记录"至少有四种成因：

| 成因 | 正确表述 |
| --- | --- |
| **循环覆盖挤出** | 「该条目**可能已被覆盖**；本工件仅覆盖最近 N 个条目」 |
| 记录策略或优化工具清理 | 「**存在清理可能**，需结合 hive 事务日志与键时间判断」 |
| 通过非标准入口启动（服务、计划任务、脚本调用其他二进制） | 「**UserAssist 不覆盖此类启动方式**，不可用于否定」 |
| 确实未使用 | 「在 UserAssist 正常记录且未被覆盖的前提下，未见使用记录」 |

**影响**

用一个容量有限的缓存去证明一个全称否定：委托方据此排除核心嫌疑，而实际证据只是被冲掉了。

**核查**

**报告必须先声明容量前提，再给结论**：

```powershell
# 统计该 GUID 下现存条目数，与已知上限对照
reg query "HKU\TARGET\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" /s \
  | Select-String -Pattern 'Count' | Measure-Object | Select Count
```

报告前提句模板：

> `UserAssist` 固定容量约 100 条并循环覆盖，**记录被挤出时不留任何痕迹**。本节中「未见某程序」一律解读为「**该工件未覆盖**，不构成未使用的证据」。此类否定性结论均需由 Prefetch、Amcache、ShimCache 另行支持。

任何 UserAssist 的阴性结论都必须配至少一个独立的执行类工件。

<a id="section-21"></a>

#### 陷阱 5：把注册表键的最后写入时间当作行为发生时间

**现象**

Shellbags 中某路径的键时间显示为 `2024-06-11 23:04`，报告写「用户在 6 月 11 日 23:04 访问了该目录」，并把它作为精确时间线上的锚点。

**原因**

注册表 hive 里记录的是**键/值的最后写入时间**。它回答的是"**这条记录最后被改动的时间**"，不是"**用户做了这个动作的时间**"。

两者之间至少有四类干扰：

| 干扰源 | 说明 |
| --- | --- |
| 后续无害写入 | 用户再次打开同一目录、改变排序/视图，都会刷新该键时间 |
| 系统或软件行为 | 资源管理器、组策略、登录脚本触碰相关键 |
| hive 事务与合并 | 事务日志回放、缓存刷新都可能改动时间 |
| 键被删除后重建 | 重建时间与原始行为时间无关 |

**TypedPaths / RunMRU 更弱**：它们只有值没有独立时间戳，键时间是**共享**的——任何一次对该键的写入，都会同时刷新所有条目。

**影响**

- 时间线精度被高估，**"23:04 访问"这种表述在复核时站不住**；
- 多条记录共用同一键时间时，**先后顺序是编的**，据此建立的因果链无效；
- 若案发时段与该键时间不符，可能被误当成"行为发生在案发前，与案件无关"，从而**丢掉真实关联**。

**核查**

把键时间当"不晚于"或"不早于"的边界，而不是时刻本身：

| 想说的话 | 应写的表述 |
| --- | --- |
| 用户在案发窗内有过该目录交互 | 「该路径的注册表键**最后写入时间为 `T_key`**，落在案发窗 `[T0, T1]` 内，**存在交互记录**」 |
| 行为早于某时点 | 「键时间 `T_key` **不早于** `T`，**不能据此断定行为发生在 `T` 之后**」 |
| 精确定位行为时刻 | **不做此类结论**，改由事件日志、Prefetch、USN 提供时刻 |

精确时刻只从事件日志、Prefetch 时间槽、`$UsnJrnl` 记录取，用户行为痕迹只提供存在性与范围。

<a id="section-22"></a>

### 4.3 落点与版本差异

<a id="section-23"></a>

#### 陷阱 6：在系统账户 hive 里找用户行为，得出"该用户从未使用任何程序"

**现象**

用 `SYSTEM` 与 `SOFTWARE` 分析目标用户的活动，UserAssist、TypedPaths、Shellbags 全部为空，报告写「该账户无任何程序使用记录」。

**原因**

**这些键只存在于用户自己的 hive 里。** `SYSTEM` hive 装的是 `ControlSet`、服务、会话、`Select\Current` 这类系统级信息；`SOFTWARE` hive 是 64 位与 32 位机器级配置。

用户行为痕迹一律在 `NTUSER.DAT`（以及旧版本的 `UsrClass.dat`）中。 查错 hive 得到的空结果，**是"数据不在这里"而不是"没有行为"**。

**影响**

空结果极易被读成阴性结论，而**这个阴性结论的成因是流程错误，不是数据缺失**。

这类错误如果发生在报告初稿阶段，后续所有基于它的推理都会跟着塌。

**核查**

**先按 SID 建立 hive 映射，再动手**：

```bash
# 1) 从 SOFTWARE hive 取目标用户 SID
rip.exe -p /evidence/registry/SOFTWARE -a profile.txt profilelist
#    → 从 ProfileList 找到该 SID 对应的 %SystemRoot%\system32\config\systemprofile 等

# 2) 按 SID 定位用户 profile 目录
fls -o 2048 -r -p /work/DigiForensics.dd | grep -E '/Users/[^/]+/$'

# 3) NTUSER.DAT 与 UsrClass.dat 都要提
fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -Ei '/Users/[^/]+/(NTUSER\.DAT|UsrClass\.dat)$' | grep -E '^r/r' | awk '{print $2}'
```

**报告前提句**：

> 用户行为痕迹存放于各用户 profile 下的 `NTUSER.DAT`（`HKCU\Software`）与 `UsrClass.dat`（`HKCU\Software\Classes`）。本次分析覆盖用户 `U1`（SID `S1`）与 `U2`（SID `S2`）的 hive，`SYSTEM` / `SOFTWARE` hive 不含用户行为数据。

<a id="section-24"></a>

#### 陷阱 7：只提 NTUSER.DAT，漏掉 UsrClass.dat

**现象**

提取了全部用户的 `NTUSER.DAT`，Shellbags 导出的导航历史**只有零星几条**，与委托方描述的"长期使用该目录"明显不符，报告据此外推"该用户极少访问敏感目录"。

**原因**

`UsrClass.dat` 承载了 `HKCU\Software\Classes` 的内容。Shellbags 的部分数据在旧版本中位于其中。

缺失 `UsrClass.dat` 会让导航历史出现**系统性空洞**——不是随机丢几条，而是某个版本下的整块记录缺失。

在受控上线的环境中，**部分 Shellbags 记录按策略分散在两者**，只提一个 hive 得到的路径集合是不完整的。

**影响**

- 把**提取不完整**读成**行为稀少**，方向性错误且难以自查；
- 敏感目录的访问记录可能恰好落在缺失的那一半里，**漏掉正是最需要的那部分**；
- 后续分析若基于不完整的 Shellbags 做排除，**排除结论同样不成立**。

**核查**

**两个 hive 一次提全，并分别记录来源**，不合并去重：

```bash
fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -Ei '/Users/[^/]+/(NTUSER\.DAT|UsrClass\.dat)$' | grep -E '^r/r' \
  | awk '{print $2}' \
  | while read -r ino; do
      u=$(echo "$ino" | cut -d: -f2)
      b=$(basename "${ino%%:*}")
      mkdir -p "/evidence/registry/users/$u"
      icat -o 2048 /work/DigiForensics.dd "$ino" > "/evidence/registry/users/$u/$b"
    done
# 校验：两个文件都应存在且大小合理
ls -l /evidence/registry/users/*/
# 魔数确认是注册表 hive（"regf"）
file /evidence/registry/users/*/NTUSER.DAT /evidence/registry/users/*/UsrClass.dat
```

Shellbags 解析时**两个 hive 的结果并列呈现并标注来源**，不做静默合并：

> Shellbags 导航记录来自两个落点：`NTUSER.DAT`（`HKCU\Software\Microsoft\Windows\Shell\Bags`）N 条，`UsrClass.dat`（`HKCU\Software\Classes\Local Settings\...\Bags`）M 条。**两个落点均已提取**，本报告未做跨 hive 去重。

<a id="section-25"></a>

#### 陷阱 8：Shellbags 用错版本解析，得到错位路径

**现象**

Shellbags 解析器按默认版本输出，路径列表里出现大量拼接错乱、含乱码字符的条目，指向不存在的目录。分析者筛选后只保留"看起来正常"的部分。

**原因**

Shellbags 的结构随 Windows 版本差异很大：早期是 `ShellBagMRU` 下的树形节点，较新版本引入独立的索引表与名称映射表。

**用错版本会把偏移读错，产出看似合理的错误路径**——解析器通常不会报错，因为字节本身格式合法。

更隐蔽的是"**看起来正常的那部分**"：拼接错位后仍有一批条目恰好拼出了真实存在的路径，分析者若不做校验就会把它们当真。

**影响**

- **用假路径做排除**：把不存在的路径写进报告，反而成了"证明用户没去过那里"的依据；
- 真实路径被错位噪声淹没，**关键的那条导航记录恰好在噪声里**；
- 解析器版本与系统版本需一致这件事**在报告里通常不写**，复核者无从发现。

**核查**

解析前先确定系统版本，并用交叉验证确认路径真实存在：

```bash
# 1) 从 SOFTWARE hive 读产品名与当前版本号
rip.exe -p /evidence/registry/SOFTWARE -a product.txt currentversion
rip.exe -p /evidence/registry/SOFTWARE -a prodid.txt productid
#    关注 ProductName / CurrentVersion / CurrentBuild / 注册表键时间

# 2) 报告里必须写明解析器与目标版本
#    ShellBagMRU.exe -f NTUSER.DAT -o out.csv      # Win7/8
#    ShellBags.exe  -f NTUSER.DAT -o out.csv -d    # 输出时带路径明细

# 3) 关键路径必须在 NTFS 上找得到，否则先当作存疑
fsstat -o 2048 /work/DigiForensics.dd
icat -o 2048 /work/DigiForensics.dd INODE | head -c 4 | xxd   # 目录项以 FILE 开头
```

报告标注：

> Shellbags 解析器版本 X，目标系统 `ProductName` = …（`CurrentBuild` = …，取自 `SOFTWARE\Microsoft\Windows NT\CurrentVersion`）。导出路径共 N 条，**其中 M 条经 NTFS 目录树验证存在**，其余标记为**未验证**，不用于否定性结论。

<a id="section-26"></a>

### 4.4 结论表述边界

<a id="section-27"></a>

#### 陷阱 9：把 MountPoints2 子键名当卷标或路径

**现象**

MountPoints2 下出现子键 `##?#c496ff0123456789`，分析者把它写成"用户挂载过盘符 Z:"，报告据此推论存在网络共享映射。

**原因**

子键名是卷标识（Volume identifier），不是盘符、不是卷标、也不是路径。

真正有意义的信息在**键值数据**里，那是一段流式数据，需要按结构解析才能得到：卷的真实路径形态（UNC 网络路径、USB 标记）、曾被挂载到哪些目录、磁盘卷标。

看到一串十六进制就当成路径，是把**内部标识**当成了**用户可见名称**。

**影响**

- 卷标与挂载目标对不上，**数据外泄案件里的溯源链条断在这里**；
- 「挂载过 Z:」这类未经解析的结论，若与实际挂载点不同，**方向、时点、行为主体都可能全错**；
- 由于 MountPoints2 的挂载事实常被直接当作结论依据，**基于它写错的结论会被当成强证据采信**。

**核查**

**子键名只作标识用，挂载事实从值数据解析**：

```powershell
reg query "HKU\TARGET\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" /s
# /s 递归会输出每个子键的值数据；值数据是二进制，需按结构解析：
#   含网络路径形态（如 \\server\share）与本地目录挂载点标记

# 按卷标反查（若已知卷标）
reg query "HKU\TARGET\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" /s /f "MOBILE_BACKUP"
```

报告表述模板：

> `MountPoints2` 下存在子键 `##?#<卷标识>`。**解析其值数据后得到**：真实路径形态为 `\\fileserver01\engineering`，挂载目标为 `Z:\`，卷标 `MOBILE_BACKUP`。
>
> **子键名本身仅为卷标识，不作为路径或卷标引用。** 该条目证明**该用户曾创建此挂载映射**；**不证明**映射曾成功建立、曾被访问，或其中的数据已被复制。

<a id="section-28"></a>

#### 陷阱 10：把 UserAssist 条目直接当作恶意行为证据

**现象**

UserAssist 解码后出现 `rundll32.exe`（计数 47）与一个位于 `AppData\Local\Temp` 下的可执行文件名，报告写「用户运行了位于临时目录的可疑程序，执行恶意载荷」。

**原因**

UserAssist 只能证明一件非常窄的事：**用户通过某个 Shell 入口使用过该程序。**

三重限制：

| 限制 | 说明 |
| --- | --- |
| **只覆盖 Shell 启动入口** | 服务、计划任务、脚本内调用其他二进制**根本不写 UserAssist** |
| **只记路径不记命令行** | 无参数、无脚本内容、无落地文件信息 |
| **不记执行结果** | 启动失败、被杀、被拦截，都会留下同样的记录 |

而 `rundll32` 被 Office、安装程序、杀软、显卡工具大量正常使用；`AppData\Local\Temp` 是**许多正常安装器的默认解压位置**。

把这些元素叠加成"恶意载荷"，是**语义补全**而非证据推导。

**影响**

- **"恶意"是法律与业务判断，不是工件能给出的结论**，一旦写进报告就要承担证明责任；
- 一旦被委托方或对方质疑，后续所有技术结论的可信度都会被牵连；
- 更实际的风险：把注意力引向 `rundll32` 这个无关线索，而**真正的落地点（LNK、命令行、文件哈希）被跳过了**。

**核查**

**三层表述分离：存在性 → 技术事实 → 定性**：

| 层级 | 表述 | 依据 |
| --- | --- | --- |
| **存在性** | 「UserAssist 记录该用户经 Shell 启动过 `C:\...\Temp\setup_helper.exe`，现存计数 47，最后使用时间 `T`」 | UserAssist 本工 |
| **技术事实** | 「该文件在 Prefetch 中有 `T-2` 的执行记录；对应 LNK 指向 `C:\ProgramData\…\config.dll`；Sysmon 事件 3 记录其于 `T+1min` 向 `203.0.113.x:443` 发起连接」 | Prefetch / LNK / Sysmon |
| **定性** | 「上述行为与常见安装器行为一致，也与恶意载荷行为一致；本报告不就此定性，需委托方结合软件清单与网络侧确认」 | 独立证据 |

「使用过某程序」与「实施了恶意行为」之间，至少隔着命令行、文件落地、网络通信、文件哈希四类独立证据。

任何只靠 UserAssist 得出的定性结论，都不该写进报告。
<a id="section-29"></a>

## 五、案例示例

<a id="section-30"></a>

### 5.1 UserAssist 与 Prefetch 互证压缩程序的使用

**场景**

某制造企业 IP 电话交换机遭受一起疑似商业间谍访问，需确定是否有员工将 CAD 图纸目录复制到外接存储。卷偏移 2048，提取的用户 hive 为 `Users\	wang\NTUSER.DAT` 与 `Users\	wang\UsrClass.dat`。

**处置过程**

第一步，提取用户 hive 并按 SID 确认归属：

```bash
icat -o 2048 /work/DigiForensics.dd <inode-NTUSER.DAT> > /evidence/hives/twang.NTUSER.DAT
icat -o 2048 /work/DigiForensics.dd <inode-UsrClass.dat> > /evidence/hives/twang.UsrClass.dat
xxd -l 4 -p /evidence/hives/twang.NTUSER.DAT   # → 72656766 ("regf")
rip.exe -p /evidence/hives/SYSTEM -a /tmp/pl.txt profilelist
```

```text
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-…-1107
  ProfileImagePath = C:\Users\	wang
→ 与镜像中的目录名一致，SID 归属确认
```

第二步，读取 `UserAssist` 并做 ROT13 解码：

```bash
rip.exe -p /evidence/hives/twang.NTUSER.DAT -a /tmp/ua.txt userassist
python3 - <<'PY'
import codecs, re
# UserAssist 值名以 ROT13 编码，路径字符本身保留
raw = "R:\\7-Zip\\7zFM.exe"
print("ROT13 解码:", codecs.decode(raw, "rot_13"))
PY
```

```text
ROT13 解码: E:\7-Zip\7zFM.exe
UA 计数 = 4
```

第三步，把 ROT13 的适用范围限定清楚：

```bash
python3 - <<'PY'
import codecs
for s in ("E:\\7-Zip\\7zFM.exe", "C:\\Windows\\explorer.exe", "C:\\Program Files\\7-Zip\\7z.exe"):
    print(f"{s:36s} → ROT13: {codecs.decode(s,'rot_13')}")
print("\
→ ROT13 只应用于值名（程序路径），时间戳是二进制 FILETIME，不参与编码")
PY
```

第四步，与 Prefetch 交叉验证：

```bash
PECmd.exe -d /evidence/Prefetch --csv /evidence/out
```

```text
7ZFM.EXE-2A9B8C7D.PF | runs = 4 | last = 2024-06-11 23:41:18
   prev: 2024-06-11 23:12:03, 2024-06-10 22:50:44, 2024-06-10 22:31:19
   path: E:\7-Zip\7zFM.exe
```

第五步，做计数与时间的双一致校验：

```bash
python3 - <<'PY'
print("UserAssist 计数 = 4      Prefetch RunCount = 4   → 一致")
print("UserAssist 末次 ≈ 23:41  Prefetch 末次 = 23:41:18 → 同分钟一致")
print("UserAssist 路径 = E:\\7-Zip\\7zFM.exe")
print("Prefetch    路径 = E:\\7-Zip\\7zFM.exe          → 完全一致")
PY
```

**结论**

`twang.NTUSER.DAT` 魔数为 `regf`，提取有效。`ProfileList` 中 SID `S-1-5-21-…-1107` 的 `ProfileImagePath = C:\Users\	wang` 与镜像目录一致，归属确认。

`UserAssist` 中 ROT13 解码后出现 `E:\7-Zip\7zFM.exe`，计数为 4。Prefetch 中 `7ZFM.EXE-2A9B8C7D.pf` 的 `Run Count = 4`、末次运行 2024-06-11 23:41:18，路径同为 `E:\7-Zip\7zFM.exe`。

两处独立工件在路径、执行次数与时间三个维度一致（计数 4 = 4，末次时间同分钟，路径字符级相同），使单侧解析出错的可能显著降低。可认定该用户通过图形界面的 7-Zip 打开过压缩程序。

需注意 ROT13 仅应用于 UserAssist 的值名（程序路径），二进制 FILETIME 时间戳不参与编码。

**误判对照**

最容易出错的解读，是把 `E:\7-Zip\7zFM.exe` 中的 `E:\` 直接当作外接存储。

盘符本身不含物理介质类型信息。`E:\7-Zip\` 也完全可能是固定磁盘上的第二个分区，或者系统保留分区。

判定介质类型必须查 `MountPoints2` 的卷标识、`SYSTEM` hive 的磁盘设备栈，或卷序列号的对应关系。

按错误判据把 `E:\` 当作移动盘，会在 `E:` 是普通分区的场景中凭空制造一条「外接存储」线索，并进而把整条行为链定性为数据外带。本案正是靠后续 `MountPoints2` 解析才确认 `E:` 为移动存储的。

第二处易错点是把 UserAssist 的计数当成「压缩了 4 个文件」。这个计数记录的是**该程序被启动的次数**——每次启动，用户可以压缩任意数量的文件，也可以做任意次数的添加/删除操作。而且该计数在注册表键被删除或值被清除时会归零。

写成「压缩了 4 个文件」，是把启动次数误读成了文件数量。正确表述是「图形界面启动 7-Zip 共 4 次」——与 Prefetch 的 `Run Count = 4` 互证的，也只是启动次数。

第三处易错点是在两源不一致时选择相信其中一方。UserAssist 与 Prefetch 的计数机制不同：UserAssist 依赖注册表值，写入时机受注册表缓存与关机落盘影响，计数在程序异常崩溃或被强杀时可能不更新；Prefetch 由系统在程序启动后写入 `.pf` 文件，写入时点与注册表不同，因此两者的计数本就可能相差一两次。

遇到不一致就丢弃其中一个来源，会在真实的数据缺失场景中损失证据。正确做法是把差异本身当成信息记录下来，例如「UserAssist 计数为 4 而 Prefetch 为 3，说明有一次执行未触发注册表更新」，而不是单方面采信。

<a id="section-31"></a>

### 5.2 TypedPaths 与 Shellbags 还原目录访问路径

**场景**

已确认该用户使用 7-Zip。需要确定「压缩的是哪些目录」以及「这些路径是主动输入还是从快捷方式跳转而来」——这决定行为的主动性。

**处置过程**

第一步，读取 `TypedPaths`（记录地址栏手工输入过的路径）：

```bash
rip.exe -p /evidence/hives/twang.NTUSER.DAT -a /tmp/tp.txt typedpaths
```

```text
TypedPaths
  1  E:\2024Q1\ProjectX\Cad_Release
  2  \\fileserver01\engineering\ProjectX\Cad_Release
```

第二步，把 `TypedPaths` 的语义限定清楚：

```bash
python3 - <<'PY'
tp = [("E:\\2024Q1\\ProjectX\\Cad_Release", "本地路径手工输入"),
      ("\\\\fileserver01\\engineering\\ProjectX\\Cad_Release", "UNC 路径手工输入")]
for p, n in tp: print(f"TypedPaths: {p}  → {n}")
print("\
TypedPaths 只记录在资源管理器地址栏手工输入的路径。")
print("从快捷方式、任务栏跳转、最近访问跳转均【不产生】TypedPaths 条目。")
print("→ 条目存在 = 主动输入定位")
PY
```

第三步，解析 Shellbags，提取目录访问行为：

```bash
python3 - <<'PY'
# ShellBags 结构：ItemPos / ItemName / ItemLogical / Datetime 三元组
bags = [
 ("2024-06-10 22:28:11", "\\\\fileserver01\\engineering\\ProjectX\\Cad_Release"),
 ("2024-06-10 22:31:19", "\\\\fileserver01\\engineering\\Drawings_2024Final"),
 ("2024-06-11 23:12:03", "E:\\2024Q1\\ProjectX\\Cad_Release"),
]
for t, p in bags:
    print(f"{t}  导航 → {p}")
PY
```

第四步，做三方路径交叉比对：

```bash
python3 - <<'PY'
server = "\\\\fileserver01\\engineering\\ProjectX\\Cad_Release"
local  = "E:\\2024Q1\\ProjectX\\Cad_Release"
print("Shellbags 服务器侧 :", server)
print("Shellbags 本地侧   :", local)
print("TypedPaths 两条     :", server, "|", local)
print("→ 三处路径的末两段完全一致（ProjectX / Cad_Release）")
print("→ 本地副本 E:\\2024Q1\\ 的存在说明内容曾被取到本地，")
print("   而 Shellbags 的导航顺序（服务器 22:31 → 本地 23:12）给出取回方向")
PY
```

第五步，把访问时间与压缩时间对齐：

```bash
python3 - <<'PY'
ev = [
 ("2024-06-10 22:31:19", "Shellbags 导航到 \\\\fileserver01\\…\\Drawings_2024Final"),
 ("2024-06-10 22:50:44", "Prefetch 7ZFM.EXE 第 3 次启动"),
 ("2024-06-11 23:12:03", "Shellbags 导航到 E:\\2024Q1\\ProjectX\\Cad_Release"),
 ("2024-06-11 23:41:18", "Prefetch 7ZFM.EXE 第 4 次启动"),
 ("2024-06-11 23:56:40", "E:\\ 根目录 ProjectX_Final.zip 创建"),
]
for t, d in sorted(ev): print(f"{t}  {d}")
PY
```

**结论**

`TypedPaths` 中存在两条手工输入的路径：`E:\2024Q1\ProjectX\Cad_Release` 与 `\\fileserver01\engineering\ProjectX\Cad_Release`。

`TypedPaths` 记录的是资源管理器地址栏中**手工输入**的路径，快捷方式、任务栏或最近访问跳转一般不写入该键。因此条目支持「这些路径曾被输入定位」，但它不能给出输入发生的时刻，也不能排除经由其它入口访问同一路径。

Shellbags 解析给出四次目录导航：2024-06-10 22:28:11 与 22:31:19 导航到 `\\fileserver01\engineering\` 下的 `Cad_Release` 与 `Drawings_2024Final`；2024-06-11 23:12:03 导航到本地 `E:\2024Q1\ProjectX\Cad_Release`。

三方路径的末两段（`ProjectX` / `Cad_Release`）完全一致，且导航顺序（服务器侧在前、本地侧在后）给出了内容自服务器取回本地的方向。

Shellbags 与 TypedPaths 提供的目录行为信息，Prefetch 与 UserAssist 都不记录（后两者只到程序入口这一层）。

**误判对照**

最容易产生的误读，是把 `TypedPaths` 条目当作「访问记录」。

它记录的是**用户主动输入过的路径**。条目可以保留很久（该键下的条目数有上限，被覆盖前一直存在），而且一次输入可能发生在很久之前，与具体某次访问没有对应关系。

把条目时间当作访问时间，会把一个历史遗留的路径当成事发当天的行为证据。更严重的是，`TypedPaths` 中的条目**不记录时间戳**，根本无法与 Shellbags 的导航时间对应——本案正是靠 Shellbags 的 `ItemName` + `Datetime` 三元组提供时间维度。

第二处易错点，是看到本地 `E:\2024Q1\ProjectX\Cad_Release` 目录存在，就断定「内容已从服务器复制到本地」。

Shellbags 记录的是**目录导航**，不是复制操作。本地目录的存在与内容取回可由多种途径造成：同步客户端、之前的正常下载、或他人复制。

从目录存在直接推出「复制」，会把一条需要 NTFS 层证据支撑的推断写成事实。本案真正闭合这个环节的，是 `E:\` 卷的 `$UsnJrnl` 中 `Cad_Release` 下文件的数据写入记录，以及压缩包 `ProjectX_Final.zip` 的创建记录。

第三处易错点是把 Shellbags 当作完整的文件访问历史。它记录的是资源管理器**被导航过的目录**，粒度是目录而非文件。用户在目录内打开了哪些文件、复制了哪些内容，Shellbags 完全不记录——它只能说明「用户到过这个目录」。

用 Shellbags 证明「用户复制了这些具体文件」，在需要列举具体文件清单时会完全无法支撑。正确做法是：Shellbags 定目录、NTFS 与 `$UsnJrnl` 定文件、Prefetch 与 UserAssist 定程序执行，三层配合。

<a id="section-32"></a>

### 5.3 MountPoints2 确认外接存储类型与阴性结论的边界

**场景**

需要确认「E 盘是物理固定分区还是外接存储」，以及综合全部工件后这份报告能证明到什么程度。

**处置过程**

第一步，解析 `MountPoints2` 的子键流式数据：

```bash
rip.exe -p /evidence/hives/SYSTEM -a /tmp/mp2.txt mountpoints2
python3 - <<'PY'
# MountPoints2 子键名的 \\?\Volume{GUID}\ 是值；名称中的 {GUID} 记录卷标识
import struct
data = open("/evidence/mp2.bin","rb").read()
print("子键名 : \\\\?\\Volume{6b3f8a21-4d5e-4c7b-9a8f-1e2d3c4b5a69}\\")
print("值(GUID): 6b3f8a21-4d5e-4c7b-9a8f-1e2d3c4b5a69")
print("关联卷序列号: A1B2C3D4   卷标: MOBILE_BACKUP")
PY
```

```text
子键名 : \\?\Volume{6b3f8a21-4d5e-4c7b-9a8f-1e2d3c4b5a69}\
值(GUID): 6b3f8a21-4d5e-4c7b-9a8f-1e2d3c4b5a69
关联卷序列号: A1B2C3D4   卷标: MOBILE_BACKUP
```

第二步，从 `SYSTEM` 的设备栈确认介质类型：

```bash
rip.exe -p /evidence/hives/SYSTEM -a /tmp/usb.txt usbstor
```

```text
USBSTOR\Disk&Ven_SanDisk&Prod_Ultra_Fit\4C530001120611105253
  FirstInstallDate = 2024-06-11 22:03:17
  LastArrivalDate   = 2024-06-11 23:58:40
→ 与 MOBILE_BACKUP 的接入时间窗吻合
```

第三步，在 NTFS 层找压缩包并核对创建时间：

```bash
fls -o 2048 -r -p /work/DigiForensics.dd 2>/dev/null | grep -i 'ProjectX_Final'
# → E:\ProjectX_Final.zip   (1.2 GB)
icat -o 2048 /work/DigiForensics.dd <inode> > /evidence/ProjectX_Final.zip
ls -la /evidence/ProjectX_Final.zip
```

```text
-rw-r--r-- 1288490188  ProjectX_Final.zip
```

第四步，用 `$UsnJrnl` 串起完整行为链：

```bash
python3 - <<'PY'
print("2024-06-11 22:03:17  USBSTOR 首次安装（SanDisk Ultra Fit）")
print("2024-06-10 22:28:11  Shellbags 导航 \\\\fileserver01\\…\\Cad_Release")
print("2024-06-10 22:31:19  Shellbags 导航 …\\Drawings_2024Final")
print("2024-06-11 23:12:03  Shellbags 导航 E:\\2024Q1\\ProjectX\\Cad_Release")
print("2024-06-11 23:41:18  7ZFM.EXE 启动（UserAssist 计数 +1）")
print("2024-06-11 23:56:40  E:\\ProjectX_Final.zip  FILE_CREATE  (1.2 GB)")
print("→ 导航(23:12) → 启动压缩(23:41) → 生成压缩包(23:56)：间隔 15 分 37 秒")
PY
```

第五步，界定不可证边界：

```bash
python3 - <<'PY'
lim = [
 ("压缩包内具体内容",     "zip 内目录结构与文件哈希需另证，且原文件可能已变更"),
 ("复制内容的授权状态",   "Shellbags/UserAssist 不含权限语义，需企业授权清单比对"),
 ("外接存储是否带离现场", "无资产盘点与门禁记录，无法确认最终去向"),
 ("压缩操作的数据来源完整","Shellbags 记目录导航，不记具体选了哪些文件"),
 ("是否全部图纸被压缩",   "1.2 GB 与源目录总量需比对，本案未完成"),
]
for a, b in lim: print(f"✗ {a}\
    {b}\
")
PY
```

**结论**

`MountPoints2` 中的卷标识 `6b3f8a21-4d5e-4c7b-9a8f-1e2d3c4b5a69` 解析出卷序列号 `A1B2C3D4` 与卷标 `MOBILE_BACKUP`。

`SYSTEM` hive 的 `USBSTOR\Disk&Ven_SanDisk&Prod_Ultra_Fit\4C530001120611105253` 记录 `FirstInstallDate = 2024-06-11 22:03:17`，与 `MOBILE_BACKUP` 的接入时间窗吻合，印证 E 盘为移动存储而非固定分区。NTFS 层 `E:\ProjectX_Final.zip` 大小 1288490188 字节（1.2 GB）。

完整行为链：USB 接入（22:03:17）→ 服务器目录导航（前一晚 22:28、22:31）→ 本地目录导航（23:12:03）→ 7-Zip 启动（23:41:18，UserAssist 计数 +1）→ 压缩包创建（23:56:40）。**导航到生成压缩包间隔 15 分 37 秒。**

可认定用户 `twang` 经 7-Zip 图形界面将 `fileserver01` 上 `ProjectX\Cad_Release` 目录内容压缩为 `ProjectX_Final.zip` 并写入移动存储。UserAssist、TypedPaths、Shellbags、MountPoints2、Prefetch、NTFS、`$UsnJrnl` 七类工件相互印证。

**误判对照**

最容易产生的误判，是把「卷标 `MOBILE_BACKUP` 看起来像移动盘」当作介质类型的判定依据。

**卷标是使用者可任意填写的字符串**，与介质类型无关。

判定必须依靠 `MountPoints2` 中的卷标识与 `SYSTEM` 的设备栈（`USBSTOR` 子键的存在即证明该卷由 USB 总线枚举），或磁盘驱动层的 `DiskDrive` 类型字段。

凭卷判定，在本案中恰好也会得到正确结论——但一旦对方把卷标改成 `SYSTEM` 或 `Backup_2024`，同样的判据就会把移动存储误判为系统盘，从而漏掉整条外接存储线索。

第二处易错点是把「压缩包创建在外接存储上」写成「数据已外带出公司」。

外带需要两个动作：写入外接存储（本案已证实），以及该存储被带离现场（本案无证据）。后者需要资产盘点、门禁记录或回收记录。

写「数据已外带」，是把一个可证的动作与一个不可证的后果混为一谈。委托方据此对外发布风险通报、启动监管上报流程后，若发现 U 盘仍在公司内，会造成不必要的处置成本与信任损失。

第三处易错点是把 1.2 GB 的压缩包直接等同于「1.2 GB 的 CAD 图纸被外带」。

zip 文件的大小取决于压缩率与内容构成。同一批图纸压缩后可能是原大小的 20%，也可能混入大量其它文件。而 Shellbags 只记录目录导航，**不记录用户在目录内具体选择了哪些文件**。

写「1.2 GB 图纸外泄」，同时错误地把压缩后大小当作原始数据量。正确表述需分两步——先写压缩包大小与位置，再写「内含内容的具体构成需通过 zip 目录结构与文件哈希另证」。

---
<a id="section-33"></a>

## 六、扩展阅读方向

<a id="section-34"></a>

### 前置基础：同一批 hive，两类读法

- [注册表取证](computer-registry-log-registry-forensics.md) —— 本篇负责「这些键值分别意味着什么」，那一篇负责「怎么正确读 hive」。用户 hive 的逐用户选取与 `ControlSet001` 的判定规则都在那一篇。
- [时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md) —— Win10+ 的 UserAssist 时间戳藏在子键名里，是 FILETIME，换算错误会直接算错使用时刻。

<a id="section-35"></a>

### 同层深入：同属「用户行为」的其它工件

- [LNK 快捷方式与 Jump List 跳转列表](../computer-execution/computer-execution-lnk-jumplist.md) —— **同一问题的另一种答案**。UserAssist 说「打开过这个程序」，LNK 与 Jump List 说「打开过这个文档」，后者的证明力更强（带路径与时间），本篇的能力是它的补充而非替代。
- [Shell 痕迹与命令历史](../computer-shell/computer-shell-shell.md) —— **跨平台对照**。两边的「用户行为」载体完全不同：Windows 落在注册表键值，Linux 落在用户目录里的历史文件，**而且 Linux 侧默认连时间戳都没有**。
- [Prefetch 深度解析](../computer-execution/computer-execution-prefetch.md) —— **执行侧的第一顺位**。本篇只给「用了哪个入口」，执行次数与精确时间要靠 Prefetch。
- [SRUM 数据库分析](../computer-browser-behavior/computer-browser-behavior-srum.md) —— 它的 `UserId` 与本篇的用户 hive 是同一套 SID 体系，两条线可以按用户合并。

<a id="section-36"></a>

### 相邻议题：时间线与事件侧

- [事件日志深度分析](computer-registry-log-windows-event-log-analysis.md) —— **本篇的时间证明力弱，事件日志的时间证明力强**，两者互补：注册表给「这个人有这个习惯」，事件日志给「他在某时做了什么」。
- [取证工件地图](computer-registry-log-windows-artifact-map.md) —— 用户配置文件在工件地图中的位置，**以及它被删除时其它工件是否还在**。
- [浏览器取证](../computer-browser-behavior/computer-browser-behavior-browser-forensics.md) —— RecentDocs 记「打开过文档」，浏览器历史给的是「访问了哪些 URL」，两者是不同维度的浏览行为。

<a id="section-37"></a>

### 工具与规范：解析与保全

- [只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md) —— 用户 hive 的提取前提。
- [证据文件格式](../../fundamentals/fundamentals-chain/fundamentals-chain-dd-e01-aff4-evidence-formats.md) —— 解析结果的归档格式。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md) —— 这些键值指向用户的个人浏览与操作习惯，摘录必须与授权范围一致。

<a id="section-38"></a>

### 判据与反例：哪些推论不能成立

- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— **本篇 4.4 的结论边界来源**：「存在性证据」不能写成「时点证据」，条目上限之外的部分必须写成「不可知」。
- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— **清 UserAssist 是反取证软件的第一件事**，而它留下的痕迹与本篇的容量上限特征结合时能形成判据。
- [取证技能树](../../fundamentals/fundamentals-process/fundamentals-process-forensics-learning-path.md) —— 本篇属于「把工件翻译成行为」这一层，**它建立在注册表解析能力之上**。
<a id="section-39"></a>

## 七、命令速查

```bash
# 1) 提取全部用户 hive（NTUSER 与 UsrClass 都要）
fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -Ei '/Users/[^/]+/(NTUSER\.DAT|UsrClass\.dat)$' | grep -E '^r/r' | awk '{print $2}'
```

```python
# 2) UserAssist 解码：ROT13 还原路径 + 按值长度选 Run Count 偏移
import codecs, struct, re
def rot13(s):
    return codecs.decode(s, "rot_13")

for raw in ["P:\\Windows\\System32\\pqnq.rkr", "E:\\7-Zip\\7zFM.rxE"]:
    print(raw, "->", rot13(raw))          # -> C:\Windows\System32\cmd.exe

def run_count(data: bytes):
    if len(data) == 72:                     # Win7/8.x
        return struct.unpack_from("<I", data, 4)[0]
    if len(data) == 16:                     # WinXP
        return struct.unpack_from("<I", data, 0)[0]
    return None                             # 版本未判定，不要硬解

# Win10+ 的最后使用时间在子键名里：\{GUID}\{FILETIME}\{ROT13 路径}
for key in [r"{CEBFF5CD-...}\{01D9A0B1-4C2E-7A31-9E5F-0B6C2D3E4F50}"]:
    ts = re.search(r"\{([0-9A-Fa-f-]{36})}", key)
    print("filetime:", ts.group(1) if ts else "无（Win8 及更早不记录）")
```

```powershell
# 3) 一次性导出目标用户的所有行为痕迹键
reg load HKU\TARGET "C:\evidence\registry\users\	wang\NTUSER.DAT"
reg query "HKU\TARGET\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" /s
reg query "HKU\TARGET\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
reg query "HKU\TARGET\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /v
reg query "HKU\TARGET\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /s
reg query "HKU\TARGET\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" /s
reg query "HKU\TARGET\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags" /s
reg unload HKU\TARGET

# 4) 与 Prefetch 交叉验证（程序确实执行过）
PECmd.exe -d "C:\evidence\Prefetch" --csv "C:\evidence\out\pf" --csvf "pf.csv"

# 5) 确认登录区间（★ 用 ToXml 按字段名取，不要写死 Properties[N]）
Get-WinEvent -Path "C:\evidence\Logs\Security.evtx" -FilterHashtable @{Id=4624,4634} |
  ForEach-Object {
    [xml]$x=$_.ToXml(); $d=@{}; $x.Event.EventData.Data | %{ $d[$_.Name]=$_.'#text' }
    "$($_.TimeCreated)  Id=$($_.Id)  User=$($d['TargetUserName'])  Type=$($d['LogonType'])"
  } | Sort-Object

# 6) 检查外接存储是否曾被挂载（配合 Shellbags 结论）
reg query "HKU\TARGET\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" /s /f "MOBILE_BACKUP"
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 用户行为痕迹」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《用户行为痕迹》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-mem.raw` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。

---
