---
title: "Windows 11 与 Recall"
slug: "computer-browser-behavior-windows11-recall"
canonical: "https://www.digiforensics.cn/wiki/computer-browser-behavior-windows11-recall"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:50+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "computer"
space: "计算机取证"
node_path: ["浏览器行为"]
---

# Windows 11 与 Recall

<a id="section-1"></a>

## 一、概述

Windows 11 带来的取证变化里，最需要重新认识的是 Recall。

它不是普通的活动日志，而是**周期性截屏 + 本地 OCR + 向量索引**构成的时间线。被快照捕获并成功识别的内容可能留下可搜索痕迹，包括密码、令牌、终端命令和内部后台页面。

对取证分析者来说，Recall 是少数能重建「用户看到了什么」的工件。传统取证只能证明「打开过什么文件」「访问过什么网站」，Recall 能证明**屏幕上的具体内容**。这些记录可为密码泄露、界面取证、内部后台访问调查提供线索。

它同时也是新的证据风险面。一份检材上只要存在 Recall 数据库，**其敏感度远高于常规用户工件**；**取证封装与传递必须按最高敏感级别对待**，且需先确认提取时刻的卷解锁状态——设备已解锁与已关机对 Recall 数据的可获取性完全不同（判据见 2.5）。

这里讲的是 Windows 11 与 Recall 相关的取证要点，常规 Windows 工件见同板块其它篇目。这一块的位置在**排期阶段**：它决定该工件是否列入优先提取。

- **上游依赖** Windows 版本与硬件的判定。「这台机器能不能有 Recall 数据」是可以从硬件与固件配置推断的，这决定了它是「优先提取项」还是「直接排除」。判定方法见[Windows 取证工件地图](../computer-registry-log/computer-registry-log-windows-artifact-map.md)。
- **它自己**要按顺序做三件事：**先读构建号**（`CurrentBuild` / `UBR` 与区域设置，Recall 的可用性、默认开关、存储路径与留存策略都随构建号、型号与地区变化）；**再确认 ESS 状态**；**最后才按多候选路径检索**。
- **下游支撑** 三件事。Recall 里的 OCR 文本是时间线的**高价值输入**；截图用于确认文本上下文与版面；Recall 与 BitLocker 的关系决定了封装要求，见[BitLocker 全卷加密取证](../../crypto/crypto-volume/crypto-volume-bitlocker.md)。
- **它与 Windows Timeline 必须分开**——**两者不是同一个东西，混淆会导致取错工件或下错结论**。

Recall 的处理链路是：周期性屏幕快照 → 本地 AI 处理（OCR + 界面检测）→ 提取文本、窗口标题、应用名、时间戳 → 生成向量嵌入 → 写入本地 SQLite 索引与图像存储（链路图见 2.1）。

| 内容 | 形态 | 取证价值 |
|---|---|---|
| OCR 提取文本 | 可经授权接口查询或分析的索引化内容；实际持久化数据受产品版本相关的加密与访问控制保护 | **时间线主键，最易检索** |
| 应用名与窗口标题 | 索引字段 | 定位行为发生的应用上下文 |
| 时间戳 | 索引字段 | 时间线构建的基础 |
| 截图图像 | 图像文件 | 确认文本上下文、版面与不可识别内容 |
| 候选路径 | `%LOCALAPPDATA%\Microsoft\Recall\`、`%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}\ImageStore\` | 路径随构建版本与型号变化明显，不同观察来源给出的形态并不一致——必须多候选同时检索 |
| Windows Timeline（**不是 Recall**） | `%LOCALAPPDATA%\Microsoft\Windows\Timeline\`，含 `ActivitiesCache.db` | 应用与文档的**活动记录缓存**，不含屏幕内容 |

Recall 依赖的 ESS 不是软件开关：传感器证书在制造阶段烧录，**后期加装外接生物识别设备无法满足 ESS 条件**，所以「能不能有 Recall 数据」是硬件层面的事实。

Recall 数据的存储路径必须多候选检索；Recall 与 Windows Timeline 是两个不同工件（2.6 有对照表）。

据此能回答的是：用户在某个时段屏幕上出现过什么内容、当时使用的是哪个应用、窗口标题是什么、以及据此能回答的是：用户在某个时段屏幕上出现过什么内容、当时使用的是哪个应用、窗口标题是什么、以及**通过语义搜索找到「只停留过几秒的敏感信息」**。向量嵌入做到了传统文本日志做不到的事：搜索「昨天看到的关于 Kerberos 的 PDF」，能命中屏幕上写着「Active Directory 票据授予概述」的快照。

回答不了的部分，外加四个必须先写进报告的判断：

- Recall 的可用性、默认开关、存储路径与留存策略都随 Windows 构建号、Copilot+ 型号与地区而变化。分析时必须先读取检材的 `CurrentBuild` / `UBR` 与区域设置；无法确认构建号时，报告中应写明「Recall 实现随版本变化，路径为多候选检索结果」，**不针对任何单一构建号做断言**。
- 「BitLocker 完全离线加密、Recall 不可读」是错的。BitLocker 只在设备关机或未解锁状态下保护 Recall 数据；用户登录和卷解锁并不等于任意同用户进程可读取 Recall 受保护数据，还需核查 Windows Hello ESS、VBS Enclave、授权与版本条件。
- **ESS 门槛不是软件开关。** 传感器证书在制造阶段烧录，**后期加装外接生物识别设备无法满足 ESS 条件**——所以「能不能有 Recall 数据」是硬件层面的事实。
- **屏幕内容的语义正确性。** OCR 会出错，**截图上的文字与识别结果不一致时以截图为准**，且需保留原始图像作为核对依据。
- **「用户看到了」与「用户看到了并理解了」的差别。** Recall 证明**屏幕内容出现过**，不证明阅读、确认或理解。
- **Retina 之外的行为。** Recall 只记屏幕，**摄像头、打印、外接设备输出等不在记录范围**。

本章依赖的前置知识：Windows 版本与构建号体系，**这是第一个必须做的判断**，基础在[Windows 取证工件地图](../computer-registry-log/computer-registry-log-windows-artifact-map.md)；VBS（虚拟化基于安全）、TPM 2.0、安全启动、IOMMU/SMMU 这几个概念的基本含义，**否则无法判断 ESS 的前置条件是否满足**；SQLite 查询，能读取索引库中的文本与时间字段；以及 BitLocker 的工作前提（**它保护的是静态存储，卷解锁后不再提供保护**），见[BitLocker 全卷加密取证](../../crypto/crypto-volume/crypto-volume-bitlocker.md)。

还有一条处置纪律不能松：Recall 数据属最高敏感级别，**摘录、传递、留存都需按最高敏感标准处理**，见[合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md)。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 Recall 的工作模型

Recall 随 Windows 11 24H2 在 Copilot+ PC 上提供，其处理链路是：

```text
周期性屏幕快照
    ↓ 本地 AI 处理（OCR 文本识别 + 对象/UI 检测）
    ↓
提取文本 + 窗口标题 + 应用名 + 时间戳
    ↓ 生成向量嵌入（embedding）
    ↓
写入本地 SQLite 索引 + 图像存储
```

因此它能支持**语义搜索**：用户搜索「昨天看到的关于 Kerberos 的 PDF」，即使屏幕上的文字是「Active Directory 票据授予概述」，也能通过向量相似度命中。这是它与传统文本日志的本质差异。

对取证的意义是：Recall 数据库中同时存在**可读的 OCR 文本**与**原始截图**。文本便于快速检索与时间线构建，截图用于确认文本上下文与版面。

<a id="section-4"></a>

### 2.2 硬件与系统门槛

Recall 随 Windows 11 24H2 在 Copilot+ PC 上提供。这些门槛直接决定检材上**是否可能出现** Recall 数据：

| 条件 | 说明 | 版本敏感性 |
| --- | --- | --- |
| Copilot+ PC 认证硬件 | 需具备足够算力的 NPU（常见表述为 40+ TOPS） | 硬件认证名单随时间变化 |
| Windows 11 24H2 及后续更新 | Recall 随 24H2 提供，之后随功能更新与地区分批推送 | **★ 随构建号与区域变化** |
| VBS（虚拟化基于安全） | ESS 的前置条件，必须可用 | 随构建号与策略变化 |
| TPM 2.0 + 安全启动 | ESS 必需 | 较稳定 |
| 固件满足相应要求 | 含 IOMMU/SMMU、SDEV ACPI 表等制造侧配置 | 取决于厂商实现 |
| ESS 支持的生物识别传感器 | 相机或指纹传感器需在制造时内嵌微软签发证书 | 取决于厂商实现 |

> **★ 版本边界（必须写进报告）**：Recall 的可用性、默认开关、存储路径与留存策略都随 Windows 构建号、Copilot+ 型号与地区而变化，微软也在不同版本间调整过实现细节。本篇给出的是通用工作模型与多候选路径，不针对任何单一构建号断言。分析时必须先读取检材的 `CurrentBuild` / `UBR` 与区域设置，再据此判断适用形态；无法确认构建号时，报告中应写明「Recall 实现随版本变化，路径为多候选检索结果」。

**这些门槛不是可绕过的软件开关**：ESS 依赖的传感器证书在制造阶段烧录，后期加装外接生物识别设备无法满足 ESS 条件。因此「这台机器能不能有 Recall 数据」是**可以从硬件与固件配置推断的**，这是排期阶段就能做的关键判断。

<a id="section-5"></a>

### 2.3 ESS 的作用与验证

Enhanced Sign-in Security（ESS）本身是安全特性：它用 VBS 隔离并保护生物识别数据通道，使面部与指纹数据在受信任的硬件路径上处理，抵御欺骗与中间人攻击。

但对取证而言，它的意义在于**它是 Recall 的认证前提**——Recall 要求系统已配置 Windows Hello 且处于增强签入安全状态。

验证 ESS 状态的方法是查看生物识别日志通道：

```text
Applications and Services Logs
  └─ Microsoft
      └─ Windows
          └─ Biometrics
              └─ Operational
```

该通道中的特定事件 ID（不同版本 ID 可能不同，**以实际系统为准**）表明 ESS 是否处于启用并正常工作状态。若查不到相应事件，应先排除「设备或驱动不支持」这一正常情况，而不是直接得出「未启用」。

注册表侧的相关配置位于：

```text
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio
```

该键下的具体值名与取值含义随系统版本变化，不要在未验证的情况下假设某个 DWORD 的 0/1 极性；以日志通道与实际设置界面为准。

<a id="section-6"></a>

### 2.4 数据位置

Recall 的数据在用户配置文件内，公开研究中观察到的路径形态包括：

```text
%LOCALAPPDATA%\Microsoft\Recall\
%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}\
    └─ ImageStore\        （截图图像）
```

路径随 Windows 构建版本与 Copilot+ 型号变化明显，不同观察来源给出的形态并不一致。实操中不应只按某一个固定路径去搜，而应在用户配置文件下按多个候选路径同时检索（见陷阱 2），并注意 `CoreAIPlatform` 这类名称在不同版本中可能不同。

数据内容与形态同概述表：OCR 提取文本（索引化内容，实际持久化数据受产品版本相关的加密与访问控制保护）、应用名与窗口标题、时间戳、截图图像四类。

<a id="section-7"></a>

### 2.5 与 BitLocker 的关系

一个必须明确写入报告的判断：

BitLocker 只在设备关机/未解锁状态下保护 Recall 数据。 用户一旦登录，卷被解锁，Recall 数据库即可被该用户上下文中的任何进程读取——**不需要管理员权限**。

因此：拿到一台已解锁的 Windows 11 设备，攻击者或取证分析者都能直接访问 Recall 数据；BitLocker 在这个场景下不提供任何额外保护。这与「Recall 数据完全离线加密、不可读」的误解截然相反。

<a id="section-8"></a>

### 2.6 Windows Timeline：不要与 Recall 混淆

Windows 11 上另有一个较早的功能 **Windows Timeline**，其工件位于用户配置文件下（如 `%LOCALAPPDATA%\Microsoft\Windows\Timeline\`），保存的是应用与文档的**活动记录缓存**（如 `ActivitiesCache.db`、`CachedActivities` 目录）。

两者必须区分：

| | Windows Timeline | Recall |
| --- | --- | --- |
| 记录内容 | 应用/文档活动记录 | **屏幕快照与 OCR 文本** |
| 是否含屏幕内容 | 否 | **是** |
| 是否需 Copilot+ 硬件 | 否 | 是 |
| 敏感度 | 中 | **高** |

把 Timeline 的活动记录说成「Recall 记录了屏幕内容」，或反过来把 Recall 数据当作普通活动缓存，都会导致结论与报告中的敏感度评级出错。

<a id="section-9"></a>

## 三、操作步骤

<a id="section-10"></a>

### 3.1 先判断是否具备 Recall 可能性

在动手提取前，先做门槛判断，避免无效工作并为报告写明前提：

```bash
# 1) 确认系统版本（Recall 随 Windows 11 24H2 提供）
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v DisplayVersion
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuild

# 2) 检查 VBS / 内存完整性状态（ESS 前置条件）
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
  Select-Object VirtualizationBasedSecurityStatus, SecurityServicesConfigured, SecurityServicesRunning

# 3) 检查 TPM
Get-Tpm | Select-Object TpmPresent, TpmReady

# 4) 查看生物识别配置与相关注册表键
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio"
```

<a id="section-11"></a>

### 3.2 确认 ESS 状态

```powershell
# 生物识别 Operational 通道：ESS 状态的关键证据
Get-WinEvent -ListLog "Microsoft-Windows-Biometrics/Operational" |
  Select-Object LogName, IsEnabled, RecordCount

Get-WinEvent -Path "Microsoft-Windows-Biometrics/Operational" -MaxEvents 50 |
  Select-Object TimeCreated, Id, @{n='Msg';e={($_.Message -split "`n")[0]}}
```

**注意**：若该通道未启用或无事件，先检查设备是否具备 ESS 硬件条件，再下「未启用」的结论。ESS 依赖制造时烧录证书的传感器，普通外接摄像头设备不具备条件。

<a id="section-12"></a>

### 3.3 定位与提取 Recall 数据

因路径随版本变化，采用多候选路径并行检索：

```bash
mmls /work/DigiForensics.dd
fsstat -o 2048 /work/DigiForensics.dd

# 遍历用户配置文件下的候选 Recall 路径
fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -Ei '/Users/[^/]+/AppData/Local/(Microsoft/Recall|CoreAIPlatform[^/]*)' \
  | grep -E '^r/r' | awk '{print $2}' \
  | while read -r ino; do
      icat -o 2048 /work/DigiForensics.dd "$ino" > "/evidence/recall/$(printf '%s' "${ino%%:*}").bin"
    done
```

提取后立即：

1. 计算 SHA-256 并记入证据登记表；
2. 按**最高敏感级别**封装与传递，不要放入普通案件共享目录；
3. 记录提取时的卷解锁状态（决定 BitLocker 是否还提供保护）。

<a id="section-13"></a>

### 3.4 解析 Recall 索引

数据库为 SQLite，可直接查询：

```bash
# 列出数据库文件并确认结构
sqlite3 "file:/evidence/recall/index.db?immutable=1" ".tables"

# 常见表结构随版本变化，先确认列名再写查询
sqlite3 "file:/evidence/recall/index.db?immutable=1" "PRAGMA table_info(activations);"
```

确认列名后构建时间线，例如（列名以实际检材为准）：

```sql
-- 提取含时间戳与应用名的记录
SELECT timestamp, app_name, window_title
FROM activations
ORDER BY timestamp;

-- 检索敏感关键词（按实际列名调整）
SELECT timestamp, app_name, window_title
FROM activations
WHERE lower(window_title) LIKE '%payroll%'
   OR lower(window_title) LIKE '%内部%'
ORDER BY timestamp;
```

<a id="section-14"></a>

### 3.5 处理截图

`ImageStore` 目录中的图像按时间顺序命名，命名规则随版本不同。处理原则：

- **按时间戳与索引记录对齐**，把图像归入时间线的正确位置；
- 对关键帧做**脱敏标注**（谁能看到、是否已在报告中体现敏感信息）；
- 报告中只呈现与案件事实相关的帧，**不把完整屏幕历史直接附入报告**。

<a id="section-15"></a>

### 3.6 与其他工件交叉

Recall 记录「看到了什么」，需与行为工件对齐确认「做了什么」：

- **事件日志 4624**：确认登录主体与时间区间，判断屏幕内容归属哪个账户。
- **浏览器工件**：若 Recall 中出现某网站，浏览器 `History` 可确认实际访问时间与 URL，Recall 提供页面内容。
- **LNK / Jump List**：若 Recall 中出现某文档，LNK 可确认打开动作与目标路径。
- **UsnJrnl**：确认相关文件在系统层面的创建与修改。
<a id="section-16"></a>

## 四、常见陷阱

<a id="section-17"></a>

### 4.1 门槛判定与路径检索

<a id="section-18"></a>

#### 陷阱 1：不判断 Copilot+ PC 与 ESS 门槛，就把"未发现 Recall 数据"当作发现

**现象**

在检材里按几个候选路径搜了一遍，没找到 Recall 数据库，报告写下「未发现 Recall 数据，据此推断用户在离职前未查看敏感信息」。

**原因**

Recall 有**严格的硬件与系统门槛**，而且这些门槛**大多可以从配置推断出来**：

| 条件 | 说明 | 门槛性质 |
| --- | --- | --- |
| Copilot+ PC 认证硬件 | 需足够算力的 NPU（常见表述 40+ TOPS） | 硬件认证名单随时间变化 |
| Windows 11 24H2 及后续更新 | 之后随功能更新与地区**分批推送** | **★ 随构建号与区域变化** |
| VBS（虚拟化基于安全） | ESS 的前置条件 | 随构建号与策略变化 |
| TPM 2.0 + 安全启动 | ESS 必需 | 较稳定 |
| 固件要求 | 含 IOMMU/SMMU、SDEV ACPI 表等制造侧配置 | 取决于厂商实现 |
| **ESS 支持的生物识别传感器** | 相机或指纹传感器需在**制造时内嵌微软签发证书** | 取决于厂商实现 |

最后一条最关键：**这些不是可绕过的软件开关**。

ESS 依赖的传感器证书在制造阶段烧录，后期加装外接设备无法满足条件。

所以「搜不到数据」至少有两种截然不同的成因：

- 设备**具备条件但数据不存在** → 这是有意义的发现
- 设备**本来就不具备运行条件** → 这不是发现，只是预期

**影响**

- **逻辑错误的方向性最强的一种**：把"不具备条件"写成"没有查看"，等于用一个不存在的数据源得出了行为结论
- 委托方可能据此认为该员工清白，而这个结论建立在错误的排除推理上
- 与 Recall 相关的调查方向可能被整体放弃

**核查**

**先做门槛判定，再谈数据有无**：

```bash
# 系统版本与安全特性
reged -x /evidence/registry/SOFTWARE.hive "Microsoft\Windows NT\CurrentVersion" | \
  grep -iE 'DisplayVersion|CurrentBuild|UBR|EditionID'
# 同时读区域设置（Recall 分批推送随区域变化）
```

| 门槛判定结果 | 数据缺失的表述 |
| --- | --- |
| **不满足任一门槛** | 「**该设备不具备运行 Recall 的条件**（原因：XXX）。Recall 数据本就不可能存在，**此为预期状态，不构成发现**。」 |
| 满足全部门槛 | 「设备具备运行条件，**未发现 Recall 数据**，此为有意义的阴性发现。可能原因：功能未启用 / 数据已清除 / 该版本将数据存于未覆盖的路径。」 |

**门槛判定过程与中间结果必须写进报告**，这是让「未发现」可解释的唯一方式。

<a id="section-19"></a>

#### 陷阱 2：只按一个固定路径搜索就宣布"无 Recall 数据"

**现象**

按 `AppData\Local\Microsoft\Recall` 搜了一遍没有命中，报告直接下结论。而同一台机器上 `AppData\Local\CoreAIPlatform.00\UKP\{...}\` 目录下实际存在完整的 SQLite 索引与 `ImageStore`。

**原因**

Recall 的存储路径随 Windows 构建号、Copilot+ 型号与地区而变化，微软也在不同版本间调整过实现细节。同一功能在不同版本下可能落在：

```text
%LOCALAPPDATA%\Microsoft\Recall\
%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{...}\
%LOCALAPPDATA%\CoreAIPlatform\<版本号>\UKP\...
```

目录名里的 `CoreAIPlatform` 这类命名本身就不稳定，后缀数字、层级深度都可能不同。

而**「路径没搜到」这件事本身没有信息量** —— 你无法区分「这里没有」和「这里不是这里」。

这与判读 APFS 卷边界、SRUM 路径是同一类错误：**用查询失败代替存在性判定**。

**影响**

- 漏掉唯一能重建「用户看到了什么」的工件，这类案件往往因此无法推进
- 报告写「该设备无 Recall 数据」，而数据一直在检材里，一旦被复核发现，报告可信度严重受损

**核查**

**多候选路径并行检索，并做全盘兜底**：

```bash
# 多候选路径并行
fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -Ei '/Users/[^/]+/AppData/Local/(Microsoft/Recall|CoreAIPlatform[^/]*)' \
  | grep -E '^r/r' | awk '{print $2}' \
  | while read -r ino; do
      icat -o 2048 /work/DigiForensics.dd "$ino" \
        > "/evidence/recall/$(printf '%s' "${ino%%:*}").bin"
    done

# 兜底：全盘按内容特征与扩展名兜底检索
fls -o 2048 -r /work/DigiForensics.dd | grep -iE 'Recall|CoreAI|UKP|ImageStore'
```

报告里**必须写明检索了哪些路径**，以及为什么认为覆盖完整：

> 已在 `%LOCALAPPDATA%\Microsoft\Recall\`、`%LOCALAPPDATA%\CoreAIPlatform*\UKP\**` 两个候选路径族下检索，并按 `Recall` / `CoreAI` / `UKP` / `ImageStore` 关键字对全盘做了兜底检索，**未命中**。结合 4.1 节门槛判定结果，结论为【不具备条件 / 具备条件但未启用】。

<a id="section-20"></a>

#### 陷阱 3：以为 BitLocker 保护了 Recall 数据

**现象**

因为设备配置了 BitLocker，报告在敏感度评级里写「Recall 数据受 BitLocker 保护，按一般加密数据处理」，传递与封装按常规加密卷流程走。

**原因**

**BitLocker 只在关机状态提供保护。**

设备一旦登录，卷已解锁，**同用户上下文的任何进程（无需管理员权限）都能读取**这些数据。

Recall 数据的敏感度问题恰恰集中在这里：

- 屏幕快照可能拍到密码、令牌、内部后台、财务数据
- OCR 文本把这些内容以**可搜索的明文**形式存入索引
- 拿到已解锁的检材，**不需要任何特权就能全文检索**

所以「设备有 BitLocker」这句话在案件语境下几乎不提供任何保护承诺 —— 关键变量是**取证时刻的解锁状态**。

**影响**

- 按「受加密保护」处理，导致封装与传递环节的访问控制松于实际需要
- 证据共享环节泄露的风险显著上升，而这类数据一旦外流不可撤回
- 委托方基于错误的敏感度评估决定分发范围

**核查**

**按最高敏感级别处理，并在证据登记中记录解锁状态**：

```bash
# 提取时记录卷解锁状态
diskutil list 2>/dev/null || lsblk -o NAME,ROTA,TYPE | grep crypt   # Linux 侧
# Windows 侧：manage-bde -status <卷>
manage-bde -status D:
```

| 提取时设备状态 | 敏感度评级 | 传递要求 |
| --- | --- | --- |
| **已解锁 / 已登录** | **最高** | 独立封装、不入普通共享目录、逐次访问授权 |
| 已关机 | 高 | 按加密卷流程，但记录「关机状态，BitLocker 有效」 |

标准登记条目：

> 提取时刻：2024-05-20 10:32 UTC；设备状态：**已解锁（已登录 `lzhao` 会话）**，BitLocker **未提供保护**；Recall 数据敏感度定级：**最高**；封装编号 `DigiForensics-RECALL-001`；访问授权人：XXX。

<a id="section-21"></a>

### 4.2 解析与内容判读

<a id="section-22"></a>

#### 陷阱 4：凭记忆假设表名与列名，查询空结果当作"无内容"

**现象**

直接写 `SELECT timestamp, app_name, window_title FROM activations` 执行，返回空结果。以为表里没有数据，或者以为该表名在这个版本不存在。

**原因**

**Recall 的数据库结构随版本变化明显。**

表名可能是 `activations`，也可能是其他命名；列名同样会变。凭记忆或凭其他案例的查询直接套用，结果是：

- 表名不对 → `no such table` 错误，或者
- 表名对但列名不对 → 报错，或者
- 列名对但语义不同 → **返回空结果，看起来像「没有相关内容」**

最后一种最有欺骗性：**它不报错，只是空**。

**影响**

- 空结果被写成「该时段无相关屏幕内容」，而实际是列名不对
- 绕了一圈才回到「先 `PRAGMA table_info`」这一步，浪费大量时间
- 若中途放弃，Recall 这个最有价值的工件就白白损失

**核查**

**先探结构，再写查询，三步顺序固定**：

```bash
# 1. 列出所有表
sqlite3 "file:/evidence/recall/index.db?immutable=1" ".tables"

# 2. 逐表确认列名——不确认不写查询
sqlite3 "file:/evidence/recall/index.db?immutable=1" "PRAGMA table_info(activations);"

# 3. 确认后再构建查询（列名以实际检材为准）
sqlite3 "file:/evidence/recall/index.db?immutable=1" "
SELECT timestamp, app_name, window_title
FROM activations
ORDER BY timestamp;"
```

报告里的所有 Recall 查询都应附上实际的 `PRAGMA table_info` 输出，这样读者能判断查询是否针对了正确的结构。

<a id="section-23"></a>

#### 陷阱 5：把屏幕快照的存在直接等同于"用户看到了该内容"

**现象**

Recall 中有一条记录，窗口标题为 `SSH Keys`，报告直接写「用户查看了 SSH 私钥」。语义检索还命中了 3 条 OCR 文本含主机名的记录，进一步写成「用户查阅了生产环境数据库地址」。

**原因**

Recall 记录的是**屏幕快照**，而**屏幕快照是当前屏幕的记录，不是用户视线的记录**。多窗口并存时，OCR 文本完全可能来自**未被用户实际注视的窗口**：

- 窗口在后台、内容被渲染进快照，但用户正在看另一个窗口
- 弹窗覆盖了主窗口，快照里两层内容都在
- 多显示器场景下，快照包含未激活显示器的画面

要判断「用户是否看到了」，必须结合**前台窗口记录**（`app_name` 与 `InFocusTime` 类的字段，或与之交叉的系统侧前台切换痕迹）来确认该窗口当时是否处于前台、用户是否有输入活动。

**影响**

- 「看到了」与「看到了并处理了」之间差着理解、复制、记录等一整条链，跳过去就是把内容暴露直接等同于泄密行为
- 在窃取源代码这类案件中，「看到」与「取走」是两个必须分别证明的行为，混淆会让结论站不住
- 对方质证时只需问一句「你怎么知道他在看那个窗口」，整个推论就塌了

**核查**

**分三层表述，每层都有各自的判据**：

| 层次 | 判据 | 表述 |
| --- | --- | --- |
| **屏幕上出现过** | 快照/OCR 文本中存在 | 「该内容在 `T` 时刻出现在屏幕上，窗口标题为 X」 |
| **该窗口处于前台** | 前台窗口记录 + `InFocusTime` | 「该窗口在 `T` 时段处于前台，持续 `InFocusTime`」 |
| **用户有交互操作** | 输入活动记录 / LNK / Jump List | 「`T` 时段检测到用户输入，且 Jump List 中存在对目标文档的打开动作」 |

标准表述：

> Recall 记录显示 `2024-03-14 10:22:15`（本地时间）屏幕上出现窗口标题 `SSH Keys` 的内容，其中 OCR 文本包含私钥材料。**该窗口的前台状态与用户输入活动需另行确认。** 事件日志 `4624` 显示 `lzhao` 在该时段存在交互式登录（LogonType 2）；Jump List 中存在对该窗口对应文档的打开动作。综上可认定该内容在用户登录会话期间处于可见状态。用户是否主动读取或复制，Recall 无法证明。

**能力边界必须显式声明**：Recall 证明的是「看到了什么」，不是「做了什么」，更不是「拿走了什么」。

<a id="section-24"></a>

#### 陷阱 6：把 OCR 文本当作精确原文

**现象**

从 OCR 文本中读到一个账号 `svc_backup_01`、一笔金额 `￥1,284,500.00`、一个 IP `10.24.7.113`，直接写进报告作为准确内容。后续有人手工核对截图，发现 IP 实际是 `10.24.7.1l3`（末位数字与小写 l 混淆）。

**原因**

**OCR 存在识别误差，且误差有明显的规律性**：

| 易错类型 | 典型混淆 |
| --- | --- |
| 字符形近 | `0` / `O`、`1` / `l` / `I`、`5` / `S`、`8` / `B` |
| 特殊符号 | `:` / `;`、`.` / `,`、`/` / `\|` |
| 小字号 | 分辨率不足时整行识别失败或错位 |
| 中文 | 简体/繁体形近字、竖排与横排混排 |
| 版面复杂 | 表格、多窗口叠加、终端等宽字体 |

屏幕截图的分辨率、缩放比例、显示器 DPI 都会影响识别质量。

**OCR 文本的性质是「线索」，不是「原文」。**

**影响**

- 报告里的关键识别信息（账号、金额、IP、证书序列号）如果错误，会直接影响委托方的判断，且**质证时无法自证**
- 一旦被指出有 OCR 误读，整份报告里所有引用 OCR 文本的结论都会被质疑
- 更糟的情况：错误内容被当作证据引用，可能冤枉无辜

**核查**

**关键信息必须回看截图确认，并在报告里区分两类内容**：

```bash
# 语义检索命中后，务必按时间戳定位对应图像
ls -la /evidence/recall/ImageStore/
# 按时间戳与索引记录对齐，把图像归入时间线的正确位置
```

报告的表述规范：

| 内容类型 | 表述方式 |
| --- | --- |
| OCR 文本 | 「OCR 识别文本为（可能存在识别误差）」，并列出原图编号 |
| 截图人工核对结果 | 「经回看原图 `IMG_2024-03-14-1022.png` 确认：`<准确内容>`」 |
| 语义检索命中 | 「语义检索命中 N 条，**结论需经截图确认后引用**」 |

规则：任何进入报告结论的账号、金额、编号、地址，必须有截图人工确认记录；OCR 文本不作为单独定案依据。

<a id="section-25"></a>

#### 陷阱 7：把 Windows Timeline 当成 Recall

**现象**

在检材里找到 Windows Timeline 的活动数据库，报告把它作为「用户屏幕活动」证据引用，写出「Timeline 记录显示用户在 3 月 14 日查看了内部代码仓库」。

**原因**

**这是两个完全不同的工件**：

| 工件 | 记录内容 | 敏感度 |
| --- | --- | --- |
| **Windows Timeline** | 应用与文档的**活动记录缓存**（打开过什么、何时打开） | 中 |
| **Recall** | **周期性屏幕快照 + OCR 文本 + 向量索引** | **最高** |

两者的能力与敏感度差别巨大：

- Timeline 说「这个文档被打开过」，Recall 说「屏幕上出现过这些具体内容」
- Timeline 通常需要相应隐私设置开启才完整记录，Recall 是硬件级能力
- **混淆会导致敏感度评级错误** —— 按 Timeline 的标准处理 Recall 数据，或反过来把 Timeline 当成高价值屏幕证据

**影响**

- 敏感度评级错误，见陷阱 3 描述的传递风险
- 结论失真：把「打开过文档」说成「看到了屏幕内容」，两者的证明力不同
- 若报告基于 Timeline 却宣称有 Recall 支撑，等于虚构了证据能力

**核查**

**先确认工件身份，再按对应能力表述**：

| 要证明的命题 | 用哪个工件 |
| --- | --- |
| 用户打开过某文档 | Timeline、LNK、Jump List |
| 屏幕上出现过某段内容 | **Recall**（含截图） |
| 用户访问过某网站 | 浏览器 `History` |
| 用户与某文档有交互 | Jump List 的最近条目 + 目标文件时间戳 |

报告里**凡引用某个工件，必须写明工件全名与路径**，避免「活动记录」这类模糊表述同时指向两者。

<a id="section-26"></a>

### 4.3 敏感度与结论边界

<a id="section-27"></a>

#### 陷阱 8：把完整屏幕历史原样附进报告

**现象**

把 Recall 的全部关键帧截图导出，作为报告附件一起提交。理由是「这样复核人可以直接看」。

**原因**

Recall 数据的敏感度**远高于常规用户工件**。它可能包含：

- 密码、令牌、一次性验证码（哪怕只停留几秒）
- 内部管理后台、财务数据、人事信息
- 未发布的代码、邮件内容、聊天记录
- 第三方或无关人员的隐私信息

**报告本身会成为泄露源。**

一份原始截图集一旦进入分发链路，就脱离了访问控制体系 —— 而它原本的敏感度是要按最高级别管理的。

同时，**把完整屏幕历史直接附入报告也违反了最小必要原则**：与案件事实无关的屏幕内容不需要出现在法律文书里。

**影响**

- 报告扩散即等于数据扩散，泄露不可撤回
- 与案件无关的第三方隐私进入正式文书，可能引发投诉乃至法律问题
- 大批量截图使报告失去可读性，重点反而被淹没

**核查**

**只附与案件事实直接相关的关键帧，并对敏感内容脱敏**：

| 处理 | 要求 |
| --- | --- |
| 帧选取 | 只附直接支撑案件事实的关键帧（如案例中 213 条命中里只附 6 张） |
| 脱敏 | 凭据类内容做遮蔽，单独标注「该凭据应视为已泄露，建议立即吊销」 |
| 完整集 | 全量帧集单独封装、单独授权访问，**不作为报告附件** |
| 访问控制 | 关键帧集独立编号、逐次授权，登记谁在何时查看过 |

标准表述：

> 报告正文仅附 6 张与案件事实直接相关的关键帧截图（涵盖命中窗口标题与文本区域）。完整屏幕历史（213 条记录对应全量帧集）单独封装为 `DigiForensics-RECALL-FULL-001`，未随报告分发，需单独书面授权调阅。第 4 步识别出的 SSH 私钥相关内容已在报告内做遮蔽处理，并标注「该凭据应视为已泄露，建议立即吊销」。

<a id="section-28"></a>

#### 陷阱 9：不读 `CurrentBuild` / `UBR` 就断言 Recall 的留存策略

**现象**

报告里写「Recall 默认保留 30 天历史，超过后自动删除」，然后据此判断"某段时间的数据已过期，无需追查"。

**原因**

Recall 的可用性、默认开关、存储路径与留存策略都随 Windows 构建号、Copilot+ 型号与地区而变化，微软在不同版本间调整过实现细节。留存天数、开关默认值、分批推送范围都可能在不同版本间不同。

所以任何形如「Recall 保留 N 天」的陈述，如果**没有绑定具体构建号**，就只是一个可能过时的印象。

**影响**

- 用错误的留存期判断「数据已过期」，可能因此不去追查实际存在的数据
- 反向也可能发生：以为已过期而删除证据，或者反复等待「过期」导致证据窗口关闭

**核查**

先读构建号与区域，再据此判断，并对无法确认的情况明说：

```bash
reged -x /evidence/registry/SOFTWARE.hive "Microsoft\Windows NT\CurrentVersion" | \
  grep -iE 'DisplayVersion|CurrentBuild|UBR|EditionID'
# 区域设置（Recall 分批推送随区域变化）
reged -x /evidence/registry/SOFTWARE.hive \
  "Microsoft\Windows\CurrentVersion\International\Setting" 2>/dev/null
```

报告表述按确认程度分档：

| 确认程度 | 表述 |
| --- | --- |
| 构建号已知 | 「该检材 `CurrentBuild=22631` / `UBR=XXXX`，`DisplayVersion=24H2`。本报告的路径与字段描述按此版本核对。」 |
| **构建号无法确认** | 「Recall 实现随 Windows 构建号、Copilot+ 型号与地区变化，路径为多候选检索结果。 本报告未对该检材的具体构建号作断言，字段含义以实际 `PRAGMA` 输出为准。」 |
| 留存策略存疑 | 「该版本留存策略未在检材中直接体现，**未以留存期作为数据缺失的解释**，改以实际检索结果为准。」 |

<a id="section-29"></a>

#### 陷阱 10：把"卷已解锁"当作取证时的常态，不在证据登记里体现

**现象**

检材来源是扣押的笔记本，现场处于已登录状态，报告的证据登记表里只写「Windows 11 笔记本磁盘镜像」，没有记录提取时的设备状态。

**原因**

**解锁状态直接改变证据的可获取性**：

| 设备状态 | BitLocker | Recall 数据可获取性 | 屏幕类易失数据 |
| --- | --- | --- | --- |
| **已解锁 / 已登录** | **不提供保护** | 同用户上下文任何进程可读 | 已存在于镜像中 |
| 已关机 | 提供保护 | 需先取得密钥 | 已丢失 |

两份报告可能描述同一台设备、同一份镜像，但因为提取时状态不同，**可获取的数据量可以差很多**。

不记录这个变量，后续「为什么没有 X 数据」的问题就无法回答。

**影响**

- 「未发现某类数据」无法解释成因，报告出现无法闭合的证据缺口
- 复核人无法判断当时的取证条件是否合理
- 在争议案件中，取证条件不明会影响整份分析的可采性

**核查**

**把设备状态作为证据登记的必填项，与哈希并列记录**：

```text
证据登记条目

| 项 | 值 |
|---|---|
| 证据编号 | DigiForensics-RECALL-001 |
| 来源 | 扣押设备 `LT-ZHAO-01` 磁盘 |
| 提取时刻 | 2024-05-20 10:32 UTC |
| **提取时设备状态** | **已解锁，已登录 `lzhao` 交互会话；BitLocker 未提供保护** |
| 卷解锁方式 | 委托方在场输入登录口令（授权文号 XXX） |
| SHA-256 | `…`（见 `DigiForensics-RECALL-001.sha256`） |
| 敏感度 | **最高**；封装独立；访问需逐次授权 |
```

报告正文的「局限与未覆盖项」章节也必须引用这一状态，用它来解释哪些易失或高敏感数据在什么条件下才能取得。
<a id="section-30"></a>

## 五、案例示例

<a id="section-31"></a>

### 5.1 门槛确认与多候选路径定位 Recall 数据

**场景**

某科技公司指控研发部员工 `lzhao` 在离职前窃取源代码。检材为其 Windows 11 笔记本的磁盘镜像，设备已解锁。委托方希望确认「设备是否具备 Recall 记录能力」，以及「若具备，记录存放在哪里」。

**处置过程**

第一步，逐项确认系统版本与硬件安全特性：

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v DisplayVersion
# → DisplayVersion    REG_SZ    24H2

powershell -NoProfile -Command "Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
  Select-Object VirtualizationBasedSecurityStatus"
# → VirtualizationBasedSecurityStatus = 2   （启用且正在运行）

powershell -NoProfile -Command "Get-Tpm | Select-Object TpmPresent, TpmReady"
# → TpmPresent=True  TpmReady=True
```

第二步，验证 ESS（增强签入安全）与 Recall 可用性：

```bash
wevtutil gli "Microsoft-Windows-Biometrics/Operational"
wevtutil qe "Microsoft-Windows-Biometrics/Operational" /c:5 /rd:true /f:text
# → 记录中包含表示增强签入安全处于工作状态的事件（ID 依版本而定）

reg query "HKLM\SYSTEM\CurrentControlSet\Control\WinBio" 2>&1 | head -3
```

第三步，多候选路径检索 Recall 数据目录：

```bash
python3 - <<'PY'
import os
base = "/mnt/lzhao-laptop/Users/lzhao/AppData"
cands = []
for root, dirs, files in os.walk(base):
    rp = root.lower()
    if "coreaiplatform" in rp or ("recall" in rp and len(cands) < 20):
        cands.append(root)
        if len(cands) > 40: break
for c in sorted(set(cands))[:12]:
    print(c.replace(base, "…"))
PY
```

```text
…\AppData\Local\CoreAIPlatform.00\UKP\{9F2A7C11-4B3D-4E88-A1F0-77C5E2D9B341}
…\AppData\Local\CoreAIPlatform.00\UKP\{9F2A7C11-4B3D-4E88-A1F0-77C5E2D9B341}\ImageStore
…\AppData\Local\Microsoft\Recall
```

第四步，列出候选目录内容并固定哈希：

```bash
find "/mnt/lzhao-laptop/Users/lzhao/AppData/Local/CoreAIPlatform.00/UKP/{9F2A7C11-…}" \
     -maxdepth 2 -type f | head -20
shasum -a 256 "/mnt/lzhao-laptop/Users/lzhao/AppData/Local/CoreAIPlatform.00/UKP/{9F2A7C11-…}"/*.sqlite
```

第五步，先看实际表结构再写查询（列名依版本而异）：

```bash
sqlite3 "file:/evidence/recall/recall.sqlite?immutable=1" "PRAGMA table_info(activations);"
```

```text
cid  name                type
0    id                 INTEGER
1    ts                 INTEGER   -- UTC 毫秒
2    app_executable     TEXT
3    window_title        TEXT
4    text_ocr            TEXT
5    text_semantic       BLOB
```

**结论**

`DisplayVersion` 为 24H2、`VirtualizationBasedSecurityStatus` 为 2（启用且正在运行）、TPM 存在且就绪，三项共同确认该设备满足 Recall 的系统版本与硬件前置条件。`Microsoft-Windows-Biometrics/Operational` 通道存在且有事件记录，确认增强签入安全处于工作状态，`WinBio` 注册表键存在。

至此确认该设备具备运行 Recall 的条件，使后续「未找到数据」具备分析价值——必须把这一门槛确认写进报告，否则「没找到」无法区分「本来就不该有」与「应该有但没找到」。 数据定位于 `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{UUID}\`（含 SQLite 索引与 `ImageStore` 子目录），同时存在 `Microsoft\Recall\` 下的相关文件，提取后按最高敏感级别封装并记录 SHA-256。

实际表结构为 `activations` 表，列名与常见版本略有差异，须以 `PRAGMA table_info` 结果为准。

**误判对照**

最常见的错误结论是「未找到 Recall 数据目录，因此该设备从未启用 Recall」，进而排除这条路。

正确判据是 Recall 的数据路径在版本间存在差异（`CoreAIPlatform.00\UKP\` 与 `Microsoft\Recall\` 均出现过，且 `UKP` 下按会话 UUID 分目录），单一路径缺失不足以支撑否定结论；且必须先完成本案例第一步、二步的门槛确认——只有在版本、ESS、TPM 三项都满足时，「找不到」才成为有意义的事实。

按错误判据处置，本案会在已经找到数据的情况下仍写出「该设备无 Recall 能力」，把最强的一手证据自己排除掉；更糟的情况是委托方据此认为「系统没记录，不用继续查」而中止调查。

第二处易错点是不查 `PRAGMA table_info` 就照抄别处的查询语句。

正确判据是 Recall 的数据库列名随版本演进，`activations` 表在本检材中为 `ts` / `app_executable` / `window_title` / `text_ocr` / `text_semantic`，而另有版本把时间列命名为 `timestamp`、把 OCR 列放在 `text_content`；

照抄 SQL 会得到 `no such column` 错误，此时若误判为「表为空」或「数据库未启用」，就会把一次查询语法错误写成一条证据缺失结论。

第三处易错点是把 UKP 目录下的 UUID 子目录数量当成记录条数。

正确判据是 UUID 子目录按**用户会话**划分，一个会话一个目录，同一用户多次登录会产生多个目录，而单个目录内才有 `activations` 表的逐条记录。

按错误判据用目录数（本案 1 个）冒充记录数，会把「213 条命中」缩写成「1 条」，量级判断严重失真；反之若某些版本按时间片划分，还会误以为「只有一次会话」。

<a id="section-32"></a>

### 5.2 语义检索补齐关键词检索漏掉的记录

**场景**

承接上一步，已确认 Recall 数据可读。委托方要求查明离职前是否查看过源代码、SSH 密钥与生产数据库连接信息。已知关键词检索命中一批记录，但委托方质疑「是否还有遗漏」。

**处置过程**

第一步，按关键词检索并限定时间窗与窗口标题：

```bash
sqlite3 "file:/evidence/recall/recall.sqlite?immutable=1" \
 "SELECT datetime(ts/1000,'unixepoch','localtime'), app_executable, window_title
  FROM activations
  WHERE ts BETWEEN 1781395200000 AND 1782000000000
    AND (window_title LIKE '%RepoInternal%'
      OR window_title LIKE '%SSH Keys%'
      OR window_title LIKE '%DB Migration Plan%')
  ORDER BY ts;"
```

```text
2026-07-08 21:14:02  Code.exe      RepoInternal — lzhao/tree-core
2026-07-08 21:31:47  Code.exe      RepoInternal — payments-service
2026-07-09 10:05:33  WinSCP.exe    SSH Keys
…
（共 213 条）
```

第二步，按语义向量检索同一时间窗内的相关内容：

```bash
python3 - <<'PY'
import sqlite3, struct, math
c = sqlite3.connect("file:/evidence/recall/recall.sqlite?immutable=1", uri=True)
q = "生产环境数据库地址"
qv = struct.unpack(f"{len(q)}f", c.execute("SELECT vec FROM vec WHERE k=?", (q,)).fetchone()[0])
def cos(a, b):
    na, nb = math.sqrt(sum(x*x for x in a)), math.sqrt(sum(x*x for x in b))
    return sum(x*y for x, y in zip(a, b)) / (na * nb)
rows = c.execute("SELECT id, ts, app_executable, window_title, text_semantic FROM activations").fetchall()
hits = [(cos(qv, r[4]), r) for r in rows]
hits.sort(key=lambda t: -t[0])
for score, r in hits[:5]:
    print(f"{score:.4f}  {datetime}  {r[2]:12s} {r[3]}")
PY
```

```text
0.8812  2026-07-14 09:22:41  pgAdmin.exe     Server Connections
0.8604  2026-07-14 09:31:18  DBeaver.exe     PG Connection Manager
```

第三步，回看这 2 条命中记录的 OCR 文本与原始截图：

```bash
sqlite3 "file:/evidence/recall/recall.sqlite?immutable=1" \
 "SELECT window_title, substr(text_ocr,1,160) FROM activations
  WHERE app_executable IN ('pgAdmin.exe','DBeaver.exe') AND ts BETWEEN 1781395200000 AND 1782000000000;"
```

```text
Server Connections      host: db-prod-01.internal.corp  port 5432  db: prod_payments
PG Connection Manager    jdbc:postgresql://db-prod-01.internal.corp:5432/prod_payments
```

第四步，确认这两条的窗口标题为何被关键词检索漏掉：

```bash
python3 - <<'PY'
print("关键词检索条件：window_title LIKE '%DB Migration Plan%' 等")
print("实际 window_title：'Server Connections' / 'PG Connection Manager'")
print("→ 敏感内容在 text_ocr 里，不在 window_title 里 → 标题级关键词必然漏检")
PY
```

第五步，回看对应截图确认 OCR 内容无误（OCR 文本不作为单独定案依据）：

```bash
ls "/evidence/recall/ImageStore/" | head
shasum -a 256 "/evidence/recall/ImageStore/"*
```

**结论**

关键词检索在离职前两周时间窗内命中 213 条窗口标题涉及 `RepoInternal`、`SSH Keys`、`DB Migration Plan` 的记录，可证明该用户查看了内部代码仓库与 SSH 密钥相关界面。以「生产环境数据库地址」为语义查询做向量检索，命中 3 条记录，其中 2 条的 `window_title` 分别为 `Server Connections`（pgAdmin.exe）与 `PG Connection Manager`（DBeaver.exe），相似度 0.8812 与 0.8604，其 `text_ocr` 文本中包含具体主机名 `db-prod-01.internal.corp`、端口 5432 与库名 `prod_payments`。

这 2 条之所以被纯关键词检索漏掉，是因为敏感内容位于 OCR 文本而非窗口标题；向量检索跨过了这层差异，体现了语义索引的取证价值。 回看对应原始截图确认 OCR 内容无误后，方可作为结论依据；OCR 文本本身不作单独定案依据。

**误判对照**

最容易出的错误是「窗口标题里没有『数据库』字样，因此未查看生产数据库信息」。

正确判据是 Recall 记录的敏感内容分布是多处的：`window_title` 只是前台窗口标题，本身不含业务内容；而实际可见的凭据、主机名、库名几乎都落在 `text_ocr` 字段中，pgAdmin 的连接对话框标题恰恰是通用的 `Server Connections`。

按错误判据只用窗口标题过滤，本案的 2 条生产数据库记录会被完全漏掉，结论退化为「未发现生产库信息泄露」——而事实上离职前两天刚被查看过，这是本案时效性最强的证据。

第二处易错点是把语义检索的相似度分数当成证据强度直接写进报告。

正确判据是向量相似度只表示检索相关性，不表示内容重要性或行为意图：0.88 的分数既可能对应一条生产库凭据，也可能对应一条无关的运维界面。

本案之所以把这两条定为有效证据，靠的是回看截图后确认 OCR 文本中确有 `db-prod-01.internal.corp`、`5432`、`prod_payments`，而不是因为 0.8812 这个数字。

按错误判据写成「语义检索命中 3 条高相似度记录」，在复核人追问「相似度高说明什么」时会完全无法回答。

第三处易错点是发现两条记录后就不再回看截图，直接以 OCR 文本定案。

正确判据是 OCR 是识别过程，串码、误识（小写 l 与 1、O 与 0）会导致主机名与端口错一位，而这类错误在后续连接尝试中会被当成真实凭据。

按错误判据以 OCR 文本单独定案，一旦实际连接发现凭据无效，报告的「看过生产库」结论仍成立但「看到的内容是什么」这一细节出错，辩护方会以此质疑整条记录的可信度；本案的做法是截图与 OCR 文本双向确认，并对凭据做脱敏处理。

<a id="section-33"></a>

### 5.3 屏幕快照证明可见性而非主动读取的结论边界

**场景**

委托方要求就「lzhao 是否窃取了生产数据库连接信息并写入移动存储」给出结论。可用工件包括 Recall 记录、事件日志、`$UsnJrnl` 与 USB 接入记录，需要明确各证据能证明到哪一步。

**处置过程**

第一步，事件日志确认会话归属：

```bash
python3 - <<'PY'
# Security 日志 4624 过滤
print("2026-07-14 09:18:33  4624  LogonType=2  lzhao@corp  Interactive")
print("2026-07-08 21:05:11  4624  LogonType=2  lzhao@corp  Interactive")
PY
```

第二步，`$UsnJrnl` 确认对代码仓库的写入：

```bash
python3 - <<'PY'
print("2026-07-14 10:41:57  FILE_NAME  C:\\dev\\repos\\payments-service\\.git\\refs\\heads\\release")
print("2026-07-14 10:42:03  DATA_OVERWRITE  同路径 +2,048 字节")
PY
```

第三步，USB 接入记录确认移动存储：

```bash
# SetupAPI.dev.log / SYSTEM\\CurrentControlSet\\Enum\\USBSTOR
python3 - <<'PY'
print("2026-07-19 18:22:40  USBSTOR  KINGSTON_DT100  serial 60A44C…7F  first-install")
print("2026-07-19 18:22:41  设备安装事件  DRIVER_INSTALL  容量 128,000,385,280 字节")
PY
```

第四步，把 Recall 记录与上述三条证据在时间上对齐：

```bash
python3 - <<'PY'
ev = [("2026-07-08 21:14:02", "Recall: RepoInternal"),
      ("2026-07-09 10:05:33", "Recall: SSH Keys"),
      ("2026-07-14 09:22:41", "Recall: Server Connections（语义命中）"),
      ("2026-07-14 10:41:57", "UsnJrnl: 仓库写入"),
      ("2026-07-19 18:22:40", "USB: KINGSTON_DT100 接入")]
for t, d in ev: print(t, "|", d)
PY
```

第五步，检查移动存储一侧是否有可用的文件系统证据：

```bash
# ★ 该移动存储未随本案扣押 → 无法核对内容与写入时刻
python3 - <<'PY'
print("KINGSTON_DT100 未作为检材提交，无法确认写入内容、写入时刻与是否可恢复")
print("可提交的结论：设备曾被接入且被识别；写入内容与写入时刻不可证明")
PY
```

第六步，按敏感度裁剪附卷材料：

```bash
python3 - <<'PY'
print("附卷截图：6 张（覆盖命中窗口标题与文本区域）")
print("不附：完整屏幕历史（共 21,447 条记录）")
print("SSH 私钥相关内容：报告内脱敏，另附「该凭据应视为已泄露，建议立即吊销」")
PY
```

**结论**

事件日志 `4624`（LogonType 2，交互式）显示 `lzhao` 在各命中时段存在交互式登录；`$UsnJrnl` 显示 2026-07-14 10:41:57 至 10:42:03 对代码仓库路径存在 `FILE_NAME` 与 `DATA_OVERWRITE` 记录；

USB 记录显示离职前一日 2026-07-19 18:22:40 接入名为 `KINGSTON_DT100` 的移动存储（容量 128,000,385,280 字节）。这些与 Recall 记录中 2026-07-08 至 07-14 的代码仓库、SSH 密钥、生产数据库信息屏幕记录在时间上形成序列。

可认定：`lzhao` 账户在该设备上查看了内部代码仓库、SSH 密钥与生产数据库连接信息，并在离职前一日向移动存储写入了数据（写入行为由设备侧证据支持）。但 Recall 记录的是屏幕快照，其内容归属依赖前台窗口判定，只能证明信息曾在该用户会话中显示，不能证明用户主动阅读、记忆或复制；

移动存储中数据的确切内容与写入时刻因该设备未作为检材提交而无法证明。 报告中仅附 6 张与案件事实直接相关的关键帧，未附完整屏幕历史；对 SSH 私钥相关内容脱敏并标注「该凭据应视为已泄露，建议立即吊销」。

**误判对照**

本案例最需要防守的错误结论是「Recall 截图显示用户在看 SSH 私钥，因此用户窃取了私钥」。

正确判据是 Recall 记录的是**屏幕快照**，前台窗口归属只能证明该信息在 `lzhao` 的会话中**被显示过**，而窗口可能是被另一进程调用、可能被他人站在屏幕前看到、也可能是自动切换的前台窗口；用户是否主动打开、是否点击、是否复制，Recall 完全不记录。

按错误判据写「窃取了私钥」，会在质证时因「意图与转存行为均无证据支撑」被推翻；一旦这条被推翻，同段落中其它基于 Recall 的结论也会被连带质疑。

更稳妥的表述是「生产数据库连接信息与 SSH 密钥在该用户会话的屏幕上可见」，并另行出具「该凭据应视为已泄露，建议立即吊销」的安全处置建议——把危害处置与事实认定分开。

第二处易错点是把「USB 设备曾接入」直接写成「数据已被复制到移动存储」。

正确判据是 USB 接入记录（`USBSTOR` 首次安装事件、SetupAPI 日志）只证明**设备曾被系统枚举并驱动加载**，不涉及任何数据流；写入行为必须由该存储设备自身的文件系统证据（`$MFT`、修改时间、目录内容）或端点日志来支撑，而本案中 `KINGSTON_DT100` 未作为检材提交。

按错误判据写「已复制」，是把一条间接线索说成已证事实；委托方据此主张损失赔偿或提起诉讼，却拿不出内容证据，程序上会陷入被动。

正确表述是「设备曾被接入并被识别；写入内容与写入时刻不可证明，需该设备自身文件系统证据补齐」。

第三处易错点是把三处独立证据当成对「窃取」这一单一结论的三重印证。

正确判据是三处证据各自证明的是不同环节——Recall 证明「看过」，`$UsnJrnl` 证明「写过」，USB 证明「接过设备」；三者的交集不等于「把看到的东西拷进了 U 盘」。

中间那一步「把屏幕内容写入 USB」没有任何一处证据直接支撑，本案正确结论也正是把它留作未证明项。

按错误判据把三个环节的证据合并成一条指向「窃取」的证据链，会在报告最关键的定性环节留下一个无法闭合的缺口，而它恰恰是对方最会攻击的位置。

---
<a id="section-34"></a>

## 六、扩展阅读方向

<a id="section-35"></a>

### 前置基础：先判版本与硬件，再谈 Recall

- [Windows 取证工件地图](../computer-registry-log/computer-registry-log-windows-artifact-map.md) —— 构建号、版本差异与工件准备。「这台机器能不能有 Recall 数据」是排期阶段就要做的判断，方法在这一篇。
- [BitLocker 全卷加密取证](../../crypto/crypto-volume/crypto-volume-bitlocker.md) —— BitLocker 只在关机或未解锁状态下保护 Recall 数据；卷一旦解锁，数据库对该用户上下文的任何进程可读，这条判断直接决定封装要求。
- [只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md) —— 截图与索引的固定方式。

<a id="section-36"></a>

### 同层深入：同属「用户行为痕迹」的其它工件

Windows Timeline 与 Recall 的区分见本篇 2.6 的对照表：**前者是应用与文档的活动记录缓存，不含屏幕内容**。同组的其它工件如下。
- [取证实战流程](../computer-security/computer-security-security-investigation-workflow.md) —— 完整流程里工件提取的顺序与取舍。Recall 的特殊性在于它改变了排期：它有留存窗口，且一旦存在就要求最高封装等级。
- [用户行为痕迹](../computer-registry-log/computer-registry-log-user-activity-artifacts.md) —— UserAssist、TypedPaths。「打开过什么程序」是这一组工件的能力，Recall 的能力是「屏幕上出现过什么」——两者不能互相替代。
- [SRUM 数据库分析](computer-browser-behavior-srum.md) —— Recall 记内容、SRUM 记资源消耗与前台时长，两者叠起来能判断「用户看了多久、期间有没有输入」。
- [浏览器取证](computer-browser-behavior-browser-forensics.md) —— 访问记录。Recall 能证明「屏幕上出现过这个页面」，但访问了什么、能证明得更准确的是浏览器的数据库。

<a id="section-37"></a>

### 相邻议题：内存与网络侧能补的部分

- [Windows Profile 机制](../../memory/memory-acquire/memory-acquire-windows-profile.md) —— 内存镜像能确认 Recall 相关的进程与配置状态，是判定「该机是否启用过 Recall」的另一条独立线索。
- [网络流量与 PCAP 取证](../../memory/memory-network/memory-network-pcap.md) —— Recall 的语义搜索依赖本地处理，**但若配置了云端环节，流量侧会留下痕迹**。

<a id="section-38"></a>

### 工具与规范：处置纪律是本篇的重点

- [证据文件格式](../../fundamentals/fundamentals-chain/fundamentals-chain-dd-e01-aff4-evidence-formats.md) —— 截图与索引的归档封装。
- [证据保管链与委托证明](../../fundamentals/fundamentals-chain/fundamentals-chain-chain-of-custody-and-authorization.md) —— Recall 数据一旦存在即属最高敏感级别，移交与留痕必须按最严标准。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md) —— 屏幕内容可能包含与案件无关的第三方隐私，摘录必须与授权范围逐项对应。

<a id="section-39"></a>

### 判据与反例：哪些结论不能下

- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— **本篇 4.3 的结论边界来源**：无法确认构建号时必须写明检索范围与未覆盖形态，不得对单一版本下断言。
- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— Recall 的时间戳由系统生成，**它是屏幕侧最难被篡改的独立时钟**；若与其它来源矛盾，**矛盾本身是发现**。
<a id="section-40"></a>

## 七、命令速查

```bash
# 1) 确认系统版本（Recall 随 Windows 11 24H2 提供）
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v DisplayVersion
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuild

# 2) 检查 VBS 状态（ESS 前置条件）
powershell -c "Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select VirtualizationBasedSecurityStatus,SecurityServicesRunning | Format-List"

# 3) 检查 TPM
powershell -c "Get-Tpm | Select TpmPresent,TpmReady | Format-List"

# 4) 检查生物识别注册表键
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio"

# 5) 确认生物识别日志通道与 ESS 状态
powershell -c "Get-WinEvent -ListLog 'Microsoft-Windows-Biometrics/Operational' | Select LogName,IsEnabled,RecordCount | Format-List"
powershell -c "Get-WinEvent -Path 'Microsoft-Windows-Biometrics/Operational' -MaxEvents 50 | Select TimeCreated,Id | Format-Table -AutoSize"

# 6) 多候选路径定位 Recall 数据（不要只查单一路径）
fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -Ei '/Users/[^/]+/AppData/Local/(Microsoft/Recall|CoreAIPlatform[^/]*)' | grep -E '^r/r' | awk '{print $2}'

# 7) 提取后立即计算哈希并按最高敏感级封装
sha256sum /evidence/recall/*.bin | tee /evidence/recall/SHA256SUMS.txt

# 8) 确认 SQLite 库结构（先看列名再写查询）
sqlite3 "file:/evidence/recall/index.db?immutable=1" ".tables"
sqlite3 "file:/evidence/recall/index.db?immutable=1" "PRAGMA table_info(activations);"

# 9) 按时间排序导出（列名以实际检材为准）
sqlite3 "file:/evidence/recall/index.db?immutable=1" \
  "SELECT timestamp, app_name, window_title FROM activations ORDER BY timestamp;"

# 10) 交叉验证：确认登录主体与时间区间
Get-WinEvent -Path "C:\evidence\Logs\Security.evtx" \
  -FilterHashtable @{LogName='Security'; Id=4624,4634} |
  Select-Object TimeCreated,Id,@{n='User';e={$_.Properties[5].Value}},@{n='Type';e={$_.Properties[8].Value}} |
  Sort-Object TimeCreated
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — Windows 11 与 Recall」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《Windows 11 与 Recall》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-mem.raw` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。

---
