---
title: "Web 攻击痕迹还原"
slug: "server-log-web-attack-trace-reconstruction"
canonical: "https://www.digiforensics.cn/wiki/server-log-web-attack-trace-reconstruction"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:50+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "server"
space: "服务器与云取证"
node_path: ["日志分析"]
---

# Web 攻击痕迹还原

<a id="section-1"></a>

## 一、概述

日志能告诉你"有人请求了什么"，但回答不了三个关键问题：他改了什么？他落地了什么？他删掉了什么？

这三个问题必须回到**配置与文件系统**层解决。

而这一层有个残酷的特点：**痕迹会自己消失。** 日志能被截断、文件能被删除、时间戳能被批量重置。等到你拿到镜像时，攻击者往往已经清过一遍现场。

但 NTFS 有一个决定性的优势：删除文件不会抹掉 MFT 条目。

把一个文件的 MFT 条目标记为"未使用"（flags 里的 `0x06`）只是修改了 `$MFT` 这个元数据文件自身的内容，没有产生第二个"删除 MFT 条目"的操作，因此 REDOP/UNDO 机制不会为这次删除生成一条可直接还原的撤销记录。

需要说清边界：`$LogFile` 记录的**不只是**非元数据文件的写事务，NTFS 的索引更新、元数据修改同样会以事务形式落进 `$LogFile`。区别在于这次删除没有留下可供 `fls`/`istat` 复原的独立事务线索——它表现为元数据文件内部的一处字节改写。

所以准确的说法是：文件名、父目录引用、四个时间戳在 `$MFT` 的已删除记录里完整可读，`$LogFile` 则是补充而非主要来源。

这构成本篇的方法论基础：攻击者能删文件，删不掉"文件曾经存在过"这个事实在 MFT 里的投影。

**在取证流程中的位置**：本篇属于**分析环的主机侧还原层**，与日志侧互为闭环——日志产出"哪些请求可疑"，本篇产出"主机上发生了什么"，**两边对上才构成一条可采信的证据链**。

上游依赖 [Web 访问日志深度分析](server-log-web-access-log-analysis.md) 的可疑请求集与 [IIS 配置与 W3C 日志](server-log-iis.md) 的站点映射；下游支撑归因结论与报告里的攻击链叙述。

**涉及的证据形态**（按攻击链六阶段组织，具体到文件）：

| 阶段 | 痕迹落点 | 取证价值 |
|---|---|---|
| **配置篡改** | `Web.config`（**含上传目录里的子目录配置**） | ★★★★★ 攻防焦点，**被改过 ≠ 被攻击者改的** |
| | `applicationHost.config` + `.bak` | ★★★★★ diff 即篡改证据 |
| **DoS / 藏身** | `App_Offline.htm` | ★★★★ 内容与业务无关就是线索 |
| **加载链落地** | `bin\*.dll`、`Global.asax`、`App_Code\` | ★★★★★ **无源码的 DLL 是首要嫌疑** |
| | 预编译 `App_Web_*.dll` | ★★★★ **原始文件被删也能反编译出 IL** |
| **密钥泄露** | `Web.config` 的 `<machineKey>`、`machine.config` 默认值 | ★★★★ **配置弱点 ≠ 已被利用** |
| **不常检查的面** | Windows 上的 PHP 站点 | ★★★ 团队惯性盲区 |
| **清理痕迹** | `$MFT` 的 `0x06` 条目、`$UsnJrnl` 删除记录 | ★★★★★ **删掉了什么，只有这里能答** |
| **反取证** | `Security` 1102（清日志）、4719（改审计策略） | ★★★★★ **最强单点证据** |
| **时间戳** | 正常文件**成簇**，落地文件**离群** | ★★★★★ 批量重置会破坏这个分布 |

> ★ **判读方法贯穿全篇**：正常项目的文件时间戳会**成簇**（一次部署一批文件），而**离群的单个文件**——尤其"只有一个文件的时间戳与所有其他文件都差很远"——是篡改或落地的首要嫌疑。**这个方法对整站目录都适用，不限于 `bin`。**

`Web.config` 相对基线改了什么、是谁改的；`bin` 目录里哪个 DLL 没有对应源码；`Global.asax` 是否被植入了 `Application_Start` 逻辑；哪些文件被删除了（哪怕已删）；时间戳是否被批量重置；**攻击者清理现场的动作顺序与时间**（4719 → 1102 → IIS 日志截断）。

**攻击者执行了什么命令**（文件层看不到执行过程，要看 4104 与事件日志）；ViewState 反序列化**是否真的发生过**（明文 `machineKey` 是配置弱点，攻击是另一件事）；**已删文件的完整内容**（MFT 给你元数据，不给数据流——内容要靠未分配空间与预编译 DLL）；配置被改的**具体操作者**（要靠事件日志的 4672/4688 配合审计策略）。

**内容边界（本篇的红线）**：本篇讲的是**如何识别配置篡改、加载链异常与清理痕迹**，以及如何把痕迹串成攻击链。不提供任何配置篡改方法、后门 DLL 的构造方式、ViewState 载荷的生成手法或清理现场的操作步骤。

提到"上传目录里的 `web.config`"时，**必须同时写出两种截然不同的来源**——见 [2.2 判读要点](#section-4)。

**读者前提**：需要 NTFS 元数据与 MFT 结构（见 [NTFS 结构与 MFT 解析](../../filesystem/filesystem-ntfs/filesystem-ntfs-ntfs-master-file-table.md)）、IIS 应用池与 ASP.NET 生命周期、反取证基本概念。

建议按 [3.6 拿到一个可疑 IIS 站点后的 Runbook](#section-17) 的顺序执行——本章的六个步骤有依赖关系，跳步会让"清理痕迹"那一步失去参照基线。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 攻击链六阶段与各自的痕迹落点

| 阶段 | 攻击者做什么 | 日志侧痕迹 | 文件/配置侧痕迹 | 注册表/事件日志侧痕迹 |
|---|---|---|---|---|
| **① 信息收集** | 扫端口、扫路径、扫备份文件 | 大量 404、`404/1`（虚拟主机扫描）、工具 UA | 无 | 4625（若扫到 RDP/SMB） |
| **② 漏洞利用** | 打 SQL 注入、文件上传、越权 | 注入载荷在 `cs-uri-query`、`500/0` 集中在某时段 | 无（或产生临时文件） | 应用日志的异常堆栈 |
| **③ 上传落地** | 传 webshell、后门 DLL | `PUT`/`201`、对上传路径的后续访问 | 上传目录新增 `.aspx`/`.config`/`.dll` | — |
| **④ 权限维持** | 改配置、建服务、建任务 | 站点行为突变 | `Web.config` 被改、`bin\` 新增 DLL、`Global.asax` 被改 | 7045 新服务、任务缓存新增 |
| **⑤ 横向移动** | 用同一凭据打内网其他主机 | — | 落地凭据类文件 | 4624 `LogonType=3`、4648 |
| **⑥ 痕迹清理** | 删文件、清日志、改时间戳 | **日志文件体积异常、日期缺失** | **时间戳批量同值、文件消失但 MFT 留痕** | **1102（清日志）、4719（改审计策略）** |

> **★ 关键认识**：③ 之后的所有痕迹，**取证价值高于 ①②**。① ② 只留下"网络行为"，③④ 留下"主机状态变更"——**状态变更比行为更难伪造**，因为它改变了系统本身。

<a id="section-4"></a>

### 2.2 ★★ `Web.config`：攻防焦点，且是双向的

`Web.config` 是 ASP.NET 应用的行为开关文件。它的特殊之处在于：它既是攻击者最常下手的目标，也是防守方最常加固的地方——因此"被改过"这个事实本身需要仔细分析是谁改的、改了什么。

取证时必须能回答"这个 `Web.config` 相对基线改了什么"。

判断基线有三个来源，按可靠性排序：

| 基线来源 | 可靠性 | 说明 |
|---|---|---|
| **同站点的历史副本**（版本管理、备份、`bin` 内的历史文件） | ★★★★★ | 唯一能确定"改了什么" |
| `applicationHost.config.bak` | ★★★★ | 只覆盖站点级配置（绑定、认证、日志目录），**不覆盖应用内 `Web.config`** |
| **同类站点的通用模式** | ★★ | 只能提示"这里有个不常见的元素" |

**必须重点检查的配置元素**：

| 元素 | 攻防含义 | 取证判读 |
|---|---|---|
| **上传目录里的 `web.config`** | 子目录配置可**关闭脚本执行**（移除 handler 映射），也可**改变该目录的解析行为** | ★★★★★ **上传目录出现它本身就是高危信号**——业务没理由在那里放配置 |
| `<httpHandlers>` / `<handlers>` | 扩展名重新映射到不同处理程序 | 正常文件突然被新 handler 接管 → 行为改变 |
| **`<authorization>` 段** | 某目录被设为允许匿名 | 原本需认证的管理路径变公开 |
| `<customErrors mode="Off">` | 关闭错误详情 | 异常页回显堆栈，**这是攻击者的侦察手段** |
| `<compilation debug="true">` | 生产开调试 | 严重降低防护 |
| **连接字符串** | `<connectionStrings>` 中的数据库账号 | 明文。**被改过可能意味着账号变更或数据外传** |

> **★ 判读要点**：上传目录里的 `web.config` 有两种截然不同的来源——防守方加的（关脚本执行）和攻击者加的（改解析行为）。**区别在内容，不在存在本身**。必须读出内容再判断，不能看到 `web.config` 就定性。

<a id="section-5"></a>

### 2.3 `App_Offline.htm`：DoS 与藏身的双用途文件

`App_Offline.htm` 是 ASP.NET 的**内置约定**：一旦应用根目录存在这个文件，ASP.NET 会**立即停用该应用**（所有请求返回该文件内容或 503），并在文件被删除后**自动重启应用**。

| 用途 | 表现 | 取证识别 |
|---|---|---|
| **正常停机维护** | 放置公告页，站点暂时下线 | 内容是 HTML 公告，时间戳对应维护窗口 |
| **★ 攻击者 DoS** | 短时间使站点完全不可用 | 内容**不是公告**，或时间戳落在攻击时段 |
| **★ 痕迹藏身** | 把敏感内容写进去——**访问者以为在取公告，实际取走了内容** | 内容与业务完全无关 |

**为什么它是理想的藏身处**：它在应用根目录，**本来就该有 HTML**，不违和；且**访问不需要认证**。

★ `LastAccessTimeUtc` 是这里的额外价值点：`App_Offline.htm` 被访问意味着有人取走了它的内容，而NTFS 默认启用 Last Access Time 更新（虽然很多系统实际关闭，需确认）。

若 `LastAccessTimeUtc` 显著晚于 `LastWriteTimeUtc`，说明文件写好后**被人取走过**。

<a id="section-6"></a>

### 2.4 `bin` 目录与 `Global.asax`：加载链上的两个位置

ASP.NET 应用启动时会**自动加载**特定位置的程序集与文件，这条"加载链"是后门 DLL 的天然落点。

| 位置 | 加载时机 | 攻击用途 | 取证判读 |
|---|---|---|---|
| `bin\*.dll` | 应用启动时全部加载 | 放后门 DLL，**随应用启动自动执行** | 目录里出现**无对应源码、无法归类、命名不符规范**的 DLL |
| `Global.asax` | 应用启动事件 | 在 `Application_Start` 里植入代码 | 文件 `LastWriteTime` 与其他源码文件**明显不同批** |
| `App_Code\` | 目录里的 `.cs` 运行时编译 | 放后门源码，**改完即时生效** | 正常项目极少用（除非明确开启 CodeDom） |
| `App_Data\` | 不编译，直接可下载 | 放配置文件、上传文件 | 存放了本该在配置文件里的敏感内容 |
| 预编译 `*.dll`（`Temporary ASP.NET Files`） | 运行时缓存 | — | `%windir%\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\` 下的编译产物**能反编译出源码** |

**★ 预编译 DLL 的取证价值**：`bin\` 里的 `App_Web_*.dll` 是预编译应用程序集。即使原始 `.aspx` 和 `.cs` 都被删了，预编译 DLL 仍保留着可反编译的 IL 代码——这让"已删除的落地文件"有了恢复途径。

> **★ 判读方法**：见 1 章"判读方法贯穿全篇"，判定落地与批量重置的具体操作步骤见 3.3。

<a id="section-7"></a>

### 2.5 ★ ViewState：加密了，但密钥在配置文件里

ASP.NET 的 ViewState（视图状态）是页面状态数据的序列化载体，默认**加密并带 MAC 校验**。

但它的加密密钥（`machineKey`）保存在 `Web.config` 的 `<machineKey>` 元素里，或在 `machine.config`（全局默认）里。换句话说，密钥和被保护的数据放在同一套配置体系内，取证时要把它们当成一个整体看。

**攻击链**：

```
从某个途径获得 machineKey  →  自行构造合法 ViewState 载荷
                            →  触发 ViewState 反序列化  →  远程代码执行
```

这里描述的是**链条的构成**，不是构造方法。取证要判断的是这条链走完了哪几步。

**取证要点**：

| 观察项 | 意义 |
|---|---|
| `Web.config` 中 `<machineKey>` 是**明文自定义值**而非 `AutoGenerate` | 说明密钥是硬编码的。**若该文件被攻击者读取过，密钥即泄露** |
| `machine.config`（`%windir%\Microsoft.NET\Framework64\v4.0.30319\config\machine.config`）中的默认值 | 全局默认密钥，**发布后从未修改**同样危险 |
| 请求中出现**异常长的 `__VIEWSTATE` 参数** | 载荷体积远超正常页面状态 |
| 请求中出现 `__VIEWSTATEARGUMENT` | 少见，**可能在探测不同 ViewState 处理路径** |
| 站点 `500/0` 集中爆发且响应体含序列化异常 | 反序列化失败的典型表现 |

> **★ 定性边界**：**不能**仅凭"`machineKey` 是明文"就断言"发生了反序列化攻击"——明文密钥是**配置弱点**，攻击是**另一件事**。报告必须分两栏写：前者是事实，后者需要 `__VIEWSTATE` 异常载荷或 500 异常佐证。

<a id="section-8"></a>

### 2.6 PHP on Windows：不常被检查的面

服务器上跑的不只有 ASP.NET。PHP 也很常见，尤其是 CMS 和运维工具。它的几个配置项在取证上有意义：
| 配置项 | 作用 | 取证意义 |
|---|---|---|
| `auto_prepend_file` | 每个 PHP 脚本**前**自动包含指定文件 | **被设置为非空且指向不明路径 → 高危**，等效于全局植入 |
| `auto_append_file` | 每个脚本**后**自动包含 | 同上 |
| `short_open_tag` | 允许 `<?` 短标签 | 开启会扩大代码注入面 |
| `disable_functions` | 禁用的 PHP 函数 | 被清空 → **攻击者已尝试提权** |
| `extension_dir` / 加载的扩展 | 扩展路径 | 指向非标准目录的 `.dll` 可能是恶意扩展 |

```powershell
# php.ini 的关键项（★ auto_prepend/append_file 非空且指向不明路径 = 高危）
Select-String -Path C:\php\php.ini,C:\inetpub\php\php.ini -Pattern 'auto_prepend_file|auto_append_file|short_open_tag|extension_dir'
# 全盘找可疑的 PHP 落地（★ 注意 web 根之外也可能被 include）
Get-ChildItem C:\ -Recurse -Include *.php -ErrorAction SilentlyContinue |
  Where-Object { $_.FullName -notmatch '\\inetpub\\wwwroot\\digiforensics-site\\' -and $_.LastWriteTimeUtc -gt (Get-Date).AddDays(-7) } |
  Select-Object FullName, Length, LastWriteTimeUtc | Select-Object -First 30
```

<a id="section-9"></a>

### 2.7 ★ 清理痕迹的识别：删除动作的四种残影

攻击者清理现场有四种常见手法，每种都留下不同的残影。

| 手法 | 残影 | 提取方式 |
|---|---|---|
| **① 删除文件** | **MFT 条目仍在**，flags 含 `0x06`（未使用），保留文件名与时间戳 | `fls -r -p` 列出已删除文件；`istat <inode>` 读元数据 |
| **② 批量重置时间戳** | **一批文件时间戳完全相同**（到秒） | 按时间戳分组，"只有 1 个分组的批"即异常 |
| **③ 清空后重建日志** | 事件日志 **`1102`**；文件创建时间晚于应有起始时间 | 查 1102；比对 `.evtx` 的 `CreationTime` 与最早记录 |
| **④ 改审计策略** | 事件日志 **`4719`** | 查 4719，通常紧邻 1102 |

**★ 关于 ① 的技术细节（这是本篇最重要的一段）**：

- NTFS 删除文件时，只是把该文件在 `$MFT` 中对应的**主记录**（$FILE）标记为"未使用"，具体是 **flags 字段置 `0x06`**（`0x02 | 0x04`，即"未分配 + 已删除"）。
- **关键点**：这次修改是对 `$MFT` 这个元数据文件自身内容的修改。删除一个 MFT 条目不会生成"删除 MFT 条目"这个独立操作，因此 `$LogFile` 里不会有一条可直接还原本次删除的撤销记录——它体现为元数据文件内部的一处字节改写。但不能说 `$LogFile` 完全不记录元数据变更：索引更新、元数据修改同样会落成事务，只是本次删除不留下可复原的独立线索。
- 取证含义：**MFT 是"已删除文件"的主要信息源**。文件名、创建/修改/访问时间、父目录引用（指向父目录 MFT 记录）都还在。只有**文件内容**（`$DATA` 属性的数据流）通常已被释放给其他文件复用，除非紧接着被恢复占用。
- 内容恢复路径见[文件雕刻与签名恢复](../../filesystem/filesystem-unix/filesystem-unix-file-carving-and-signature-recovery.md)——**用 `$DATA` 的未分配空间按签名雕刻**。
```bash
# ★ 列出站点目录下的已删除文件（flags 含 0x06 的会带 *deleted* 标记）
fls -o 2048 -r -p /work/DigiForensics.dd | grep -A2 -i 'wwwroot/digiforensics-site' | grep -i deleted

# 读某个已删除 MFT 条目的完整元数据（含时间戳、父目录）
istat -o 2048 /work/DigiForensics.dd <inode>

# 在全盘未分配空间里按内容签名雕刻（寻找已删除的 .aspx/.asax 内容）
blkls -o 2048 /work/DigiForensics.dd > /work/unalloc.raw
 foremost -i /work/unalloc.raw     # 或 testdisk / scalpel
```

> **★ 报告表述要点**：MFT 中存在已删除条目，**只能证明"该文件曾存在过"**，不能证明"它的内容是什么"。若要断言内容，必须有雕刻出的字节数据或 `$DATA` 未被复用。**两者是不同强度的结论，不能混用。**

<a id="section-10"></a>

### 2.8 ★ 清日志本身会留下 1102：反取证的最强单点证据

| 事件 | 通道 | 含义 | 为什么是铁证 |
|---|---|---|---|
| **1102** | `Security` | **Security 日志被清除** | 清理动作本身**被记录进了另一个日志**——清 `Security` 的人常忘了 `System` 里的这条 |
| **4719** | `Security` | 系统审计策略被修改 | 通常先禁用审计再清理，**4719 早于 1102** |
| **104** | `System` | 事件日志被清除（**非 Security 通道**） | 覆盖 Application/System 等其他通道 |
| **6008** | `System` | 异常关机 | 清理后可能直接断电，"没清干净"的痕迹 |

> **★★ 最有说服力的取证结论往往是反取证本身。** 攻击者花大力气隐藏入侵痕迹，却在清理动作上留下了新的痕迹——`4719 → 1102` 这对组合在时间上紧密相邻，正常运维不会成对触发这两条事件。报告里"存在刻意反取证"这一条的证据强度，通常高于"发现了某个可疑文件"。

---

<a id="section-11"></a>

## 三、操作步骤

<a id="section-12"></a>

### 3.1 第 1 步：固定证据并建立基线

```bash
# 站点目录、IIS 配置（含 .bak）、事件日志 —— 一次提取并哈希
fls -o 2048 -r -p /work/DigiForensics.dd > /work/filelist.txt
grep -iE 'wwwroot/digiforensics-site' /work/filelist.txt > /work/site.txt
grep -iE 'inetsrv/config/applicationHost\.config(\.bak)?$' /work/filelist.txt
grep -icE '\.evtx$' /work/filelist.txt

# 逐个 icat 导出（完整清单见第七章），导出后立刻计算哈希并记录 inode
icat -o 2048 /work/DigiForensics.dd <inode-siteconfig> > /evidence/01-Web.config
icat -o 2048 /work/DigiForensics.dd <inode-appconf>    > /evidence/02-applicationHost.config
icat -o 2048 /work/DigiForensics.dd <inode-appconfbak> > /evidence/03-applicationHost.config.bak
sha256sum /evidence/* | tee /evidence/SHA256SUMS.txt
```

**验证**：报告的每个提取物都要能指回镜像中的 **inode 与字节偏移**。`fls -r -p` 输出的第 4 列即为 inode。

<a id="section-13"></a>

### 3.2 第 2 步：配置层 diff——与 `.bak` 和历史版本对照

```bash
# ★ 站点级配置 diff（改绑、关认证、换应用池身份都会显形）
diff -u /evidence/03-applicationHost.config.bak /evidence/02-applicationHost.config

# ★ 应用配置：看结构变化（diff 全文太长时先看结构）
python3 - <<'PY'
import xml.etree.ElementTree as ET
def outline(p):
    root = ET.parse(p).getroot()
    out = []
    for e in root.iter():
        if len(e) == 0:                       # 只取叶子节点 = 实际生效的配置项
            txt = (e.text or "").strip()
            out.append(f"{e.tag}={txt[:60]}")
    return out
a, b = outline(r"C:\evidence\01-Web.config"), outline(r"C:\evidence\03-applicationHost.config.bak")
print("站点 Web.config 配置项数:", len(a))
for line in a:
    if line not in b:                         # ★ 只在新版里出现的项 = 重点怀疑对象
        print("  [新增/变更]", line)
PY
```

**验证**：若站点无历史 `Web.config` 备份，则**基线不存在**——此时报告必须写"无基线可比对，配置篡改无法从内容直接认定"，转而用**时间戳成簇性**（见 3.3）作为间接依据。

<a id="section-14"></a>

### 3.3 第 3 步：时间戳成簇性分析（识别落地与批量重置）

这是本篇**最通用**的技术：不需要基线，只需要"分布异常"。

```powershell
# 3.3.1 站点内所有文件按修改时间分组（★ 找出孤立成批的）
Get-ChildItem C:\inetpub\wwwroot\digiforensics-site -Recurse -File |
  Group-Object { $_.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss') } |
  Sort-Object Count | Select-Object -First 15 Count, Name
# ★ 正常：一个部署批次几百个文件同秒 → Count 很大
# ★ 异常：只有 1–3 个文件共享同一时间戳，且该时间戳与任何批次都不同

# 3.3.2 上传目录单独看（★ 业务上传的文件时间戳应分散在多个时段）
Get-ChildItem C:\inetpub\wwwroot\digiforensics-site\uploads -File |
  Group-Object { $_.LastWriteTimeUtc.ToString('yyyy-MM-dd') } | Sort Name | Select Count, Name
# 若某一天只有 1 个文件而其余天各有几百个 → 那天是重点排查日

# 3.3.3 精确到秒的碰撞检测（★ 批量重置时间戳的典型特征）
$all = Get-ChildItem C:\inetpub\wwwroot\digiforensics-site -Recurse -File
$all | Group-Object { $_.LastWriteTimeUtc.Ticks } |
  Where-Object { $_.Count -ge 5 -and $_.Name -match '^6[0-9]{17}$' } |
  Select-Object Count, @{n='Time';e={[DateTime]::new([long]$_.Name, [DateTimeKind]::Utc)}}
```

**★ 陷阱**：复制部署、备份还原、批量改权限都会刷新 `LastWriteTime`。必须结合 `CreationTimeUtc` 三者对照（见第四章陷阱表）。

<a id="section-15"></a>

### 3.4 第 4 步：加载链检查（`bin`、`Global.asax`、预编译产物）

执行第七章"加载链检查"的三组命令，判读要点：

| 检查对象 | 高危信号 |
|---|---|
| `bin\*.dll` | 命名不符规范、`VersionInfo.CompanyName` 与 `FileDescription` 均为空（正常厂商 DLL 都带版本资源） |
| `Global.asax` | `LastWriteTimeUtc` 与同目录源码**明显不同批**；`Application_Start` 内有非常规逻辑 |
| `Temporary ASP.NET Files` | 存在**站点目录里已找不到对应源文件**的编译产物 |

**验证**：`bin` 下的 `App_Web_*.dll` 是**预编译的应用程序集**，可用反编译工具导出 IL/伪源码。如果站点目录里找不到对应的 `.aspx` 源文件，但预编译 DLL 存在且含可疑代码——这说明攻击者删了源文件但没清预编译缓存。

<a id="section-16"></a>

### 3.5 第 5 步：删除痕迹与 `$UsnJrnl`

```bash
# 5.1 已删除文件（★ MFT 0x06 痕迹，见 2.7）
fls -o 2048 -r -p /work/DigiForensics.dd | grep -i 'deleted' | grep -iE 'wwwroot|inetpub' | head -30
istat -o 2048 /work/DigiForensics.dd <inode>       # 读已删除条目的时间戳与父目录

# 5.2 $UsnJrnl 记录的文件操作时间线（★ 谁改了什么、什么时候）
icat -o 2048 /work/DigiForensics.dd <inode-usnjrnl> > /evidence/UsnJrnl-$J.0
python3 - <<'PY'
import struct, sys
# ★ $UsnJrnl 解析必须用支持它的工具（链锯/UsnJrnl2csv 等），此处仅演示结构自检
data = open(r"C:\evidence\UsnJrnl-$J.0", "rb").read()
print("长度:", len(data), "字节")
print("USN_RECORDSIZE_V2 =", struct.calcsize("<QBBIBBHI") )   # 变长记录，V2 最小 60 字节
print("前 16 字节 USN:", struct.unpack("<Q", data[:8])[0])
PY

# 5.3 事件日志侧：反取证三件套（★ 与 [01](server-log-server-artifact-map.md) 相同，每次必查）
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102,4719} -MaxEvents 20 | Select TimeCreated, Id
Get-WinEvent -FilterHashtable @{LogName='System';   Id=104,6008} -MaxEvents 20 | Select TimeCreated, Id
```

**验证**：`$UsnJrnl` 是**变更日志**，循环写入、**早期条目已被覆盖**——必须先判断覆盖到多早（对比首条记录时间与文件最早业务时间）。解析需用支持 USN 的工具，**不要手工解析变长记录**。

<a id="section-17"></a>

### 3.6 ★★ 拿到一个可疑 IIS 站点后的 Runbook

以下清单可**直接打印勾选**，按顺序执行。**顺序不能颠倒**——先固定证据、再改状态、最后下结论。

```
□ 1. 固定证据
  □ 1.1 镜像已做 SHA-256 并记录来源、交接时间（见 fundamentals/04）
  □ 1.2 全部提取物已哈希，inode 与偏移已登记
  □ 1.3 确认现场是否关机；在线系统先做只读挂载（见 imaging/03）

□ 2. 确认覆盖范围（★ 先做这步，否则后面全是空中楼阁）
  □ 2.1 各日志通道 FileSize vs MaximumSizeInBytes → 判断是否已循环覆盖
  □ 2.2 W3SVC<n> 目录的日期跨度 → 判断 IIS 日志覆盖窗口
  □ 2.3 $UsnJrnl 最早记录时间 → 判断文件操作时间线覆盖窗口
  □ 2.4 ★ 把三个窗口的最小值写进报告"证据局限"

□ 3. 攻击链定位（按阶段推进，不跳步）
  □ 3.1 ①信息收集：日志侧 404 突增、404/1 虚拟主机扫描 → 确认外部探测
  □ 3.2 ②漏洞利用：注入载荷 + 500/0 时段集中 → 确认利用尝试
  □ 3.3 ③上传落地：PUT/201、上传目录新增文件、时间戳离群 → ★ 必须打开文件看内容
  □ 3.4 ④权限维持：Web.config 变更、bin 新 DLL、Global.asax 变更、7045、任务缓存
  □ 3.5 ⑤横向移动：4624 LogonType=3、4648、落地凭据文件
  □ 3.6 ⑥痕迹清理：1102/4719/104、日志体积异常、MFT 0x06、时间戳成簇

□ 4. 三源交叉验证（★ 每个结论至少两源支撑）
  □ 4.1 W3C 日志（网络行为）
  □ 4.2 事件日志（主机行为）
  □ 4.3 文件系统 / MFT / $UsnJrnl（状态变更）
  □ 4.4 注册表（服务、任务缓存、IIS 配置）

□ 5. 清理痕迹的专项确认
  □ 5.1 全盘 fls 找已删除文件，重点站点目录
  □ 5.2 已删除条目做 istat，取时间戳
  □ 5.3 按签名在未分配空间雕刻（可选，成本高）
  □ 5.4 日志文件体积逐日对比，找出异常小的日期

□ 6. 输出
  □ 6.1 行为链时间线（UTC 与本地时间双标注）
  □ 6.2 反取证链时间线（4719→1102 顺序）
  □ 6.3 结论表：每条结论标注支撑源与强度
  □ 6.4 证据局限章节（覆盖窗口、未部署的监控、无法恢复的内容）
```

---
<a id="section-18"></a>

## 四、常见陷阱

攻击痕迹还原最容易出的错，是把**存在性证据**当**内容证据**。

文件系统能证明「某个文件曾经存在」，但证明不了「那个文件里是什么」；配置里有某个设置，只能说明配置状态，不能说明是谁设的。

本章按**配置判读、时间判读、存在性与内容、采集姿势** 四组拆开。

<a id="section-19"></a>

### 4.1 配置判读

<a id="section-20"></a>

#### 陷阱 1：把配置文件存在当异常

**现象**

在站点目录发现某个配置文件，报告写「发现可疑配置文件」。

**原因**

**该配置文件是应用框架的正常组成部分。** 常规部署下由应用框架自行生成，而且**防守方自己也会创建和修改它**——最典型的是在里面关闭脚本执行权限。

也就是说，这个文件的存在是常态，内容被改动才是需要关注的点。

把正常的运维配置报成安全事件。

这类误报在报告里特别扎眼，因为对方一看就知道那是他自己配的。

**影响**

一句话就把对方自己的工作写成了安全事件。

**核查**

**必须读内容，判断改的是哪一类设置。** 判断方向：

- 关闭脚本执行、增强校验 → **这是加固行为**，是防守方的动作
- 放宽执行限制、改变内容解析行为、指定自动包含的文件 → **需要追查**

结论表述要区分：
`站点存在该配置文件，内容为加固配置（关闭脚本执行），未见异常改动`
vs
`该配置文件在 X 时间被修改，改动内容为 <具体项>，需追查修改来源`

**判定依据是内容，不是文件的存在性。**

<a id="section-21"></a>

#### 陷阱 2：以为配置备份副本能反映应用侧配置

**现象**

发现配置文件被改动，于是去找它的备份副本做对照，
但备份副本里看不出同样的东西，结论写「无法确认改动」。

**原因**

服务端站点的配置和备份副本，覆盖的是不同层级的配置：站点级的绑定、认证设置、日志目录等在站点配置里；而应用内部的配置在应用自己的配置文件里，两者互相独立。

配置文件的备份副本不包含应用侧配置。

所以拿备份副本去对照应用侧的改动，**方向就是错的**，当然对照不出结果。

结论写成「无法确认」，实际是「查错了对象」。

**影响**

报告里一句"无法确认"，实际是查错了对象。

**核查**

**分层取证，两类配置分开处理、分开取证。**

| 层级 | 位置 | 关注项 |
|---|---|---|
| 站点级 | 服务端站点配置 | 绑定、认证、日志目录、处理器映射、请求过滤 |
| 应用级 | 应用自己的配置文件 | 调试开关、内容解析、自动包含项、数据库连接 |

两层的改动要**分别追查来源**，它们的责任人也可能不同（站点级归运维，应用级归开发）。

报告里明确区分这两类证据，不要混在一起描述。

对站点级配置，备份副本确实是有效的对照物——但要记得陷阱 9：**它本身也可能被同步改过**。

<a id="section-22"></a>

#### 陷阱 3：把明文密钥当攻击证据

**现象**

在配置里发现一段明文形式的加密密钥，报告写「已遭攻击，密钥被读取」。

**原因**

**明文密钥本身是配置弱点，不是攻击证据。** 这两件事要分开：

- **配置弱点**：密钥以可读形式存储在配置里 —— 这是**部署时的问题**
- **攻击**：有外部主体获取了这个密钥，或者用这个密钥做了什么事 —— 这是**事件**

很多生产环境至今保留着这个历史设计。发现它应该写进「配置安全建议」，而不是「安全事件」。

把配置问题报成事件，性质定性错误。如果对方据此对外发布安全通告，后果更严重。

**影响**

性质定性错误，而且这个错误一旦公开就无法收回。

**核查**

**分两栏写。**

- **配置弱点栏**：明文密钥存在于配置文件的哪一行、影响的范围是什么、
  建议的处置方式（迁移到密钥管理机制）
- **事件栏**：要坐实攻击，需要**独立的攻击证据**。
  常见的佐证方向：页面的隐藏字段里出现了异常的载荷形态、
  该页面被异常的访问来源大量请求、认证日志里有对应的登录记录

**没有攻击证据时，就只写配置弱点。**
这不是弱化结论，而是让结论与证据匹配。

<a id="section-23"></a>

### 4.2 时间判读

<a id="section-24"></a>

#### 陷阱 4：只看一个时间字段判断篡改

**现象**

比对文件的修改时间与预期不符，判定配置被篡改。

**原因**

**单一时间字段会被大量正常行为刷新**：

- 从其他环境复制部署（开发 → 生产）
- 备份还原
- 批量调整权限时的连带写入
- 某些部署工具的规范化写入

而且文件时间是可以被修改的。所以「修改时间晚于部署时间」这件事本身**不能区分正常运维与蓄意改动**。

**影响**

把正常的部署操作报成篡改。而且这种误判一旦被反驳，会连带削弱报告里所有基于时间的结论。

**核查**

**三源对照，用差异定性。**

1. **创建时间** —— 反映文件最初落盘的时刻
2. **修改时间** —— 反映内容最后变化
3. **变更日志** —— 记录每一次变更的**实际操作**，
   包括时间与触发方

判断逻辑：

- 创建时间晚于部署时间 → 文件是部署后新增的，需要追查引入路径
- 修改时间远晚于创建时间 → 中间有过改动，但原因可能正常
- **变更日志有记录、文件系统时间对不上** → 有人在改时间，
  **这才是真正的篡改信号**

变更日志的判读有严格约束：它的记录是变长的，按固定偏移手工解析会得到乱序的错误数据。

必须用支持该格式的现成工具，输出结果才可作为依据。自己写的解析器只能用来做长度与首序号的粗校验。

<a id="section-25"></a>

#### 陷阱 5：看到时间与预期不符就定性

**现象**

发现某个文件的时间「应该是 2023 年的，怎么变成了 2024 年」，
据此判定篡改。

**原因**

**预期值本身是猜的。** 站点可能有多个部署批次、可能有跨环境同步、可能有历史目录整体刷新过。

在没有可靠基准的情况下，「不符合预期」只是「我不知道它的预期」。

而且文件系统时间有一个合法的变化模式：文件被移动或重命名时，其创建时间会更新为新位置的时刻。跨目录移动比单纯的内容修改更明显。

结论建立在一个自己假设的基准上，整个推理链条从第一步就是空的。

**影响**

这是全篇最隐蔽的一种：链条看起来完整，只是起点是空的。

**核查**

**基准必须来自外部可信来源，不能来自推测。** 优先级：

1. **系统启动时间**（不受文件操作影响）
2. **部署记录**（部署工具的日志、版本管理系统的记录）
3. **配置备份副本的时间**（它与主文件是同源的，可对照）
4. **应用日志**（如果应用记录了启动或加载配置的时刻）

**永远不要用站点目录内的另一个文件当基准**——它和被检对象一样，基准不可信。

另外要注意**跨目录移动**这个合法解释：如果文件从一个目录搬到另一个目录，创建时间会变，但内容可能完全没改。追查时要把这条路径也考虑进去。

<a id="section-26"></a>

#### 陷阱 6：忘了一次记录在另一个通道

**现象**

清点了各类事件记录，报告里没有提到某类关键记录，
后续又发现它其实存在。

**原因**

**不同的事件类型记录在不同的日志通道里**，而且「清空某个通道」
只影响那个通道。存在这样的形态：

- 常规运行记录在一个通道
- **日志服务自身的完整性事件记录在另一个通道**
- 配置变更记录又在一个通道

只查了前两类，结论里就完全不会出现第三类。

而在完整性事件被清空的情况下，**恰恰是这条记录最需要被看到**。

报告漏掉了一整类关键证据，而这类证据常常是定性的关键。

**影响**

漏掉的那一类，往往正是能定性的一类。

**核查**

**按通道列出完整的清点表，逐个确认。** 清点表要包含三列：
通道名 / 是否存在 / 已启用 / 覆盖时间范围。

然后交叉验证：**如果某个通道显示记录被清空，
就必须去对应的完整性通道找记录**。这个对应关系是固定的：
当主通道发生清空类操作时，完整性通道会有对应的事件，
带操作者、进程、次数等信息。

**排查时要养成一个习惯**：
每次发现某类记录缺失，先问「缺失本身有没有留下痕迹」。

<a id="section-27"></a>

### 4.3 存在性与内容的边界

<a id="section-28"></a>

#### 陷阱 7：把存在性当内容

**现象**

文件系统的记录显示某个文件曾经存在，
报告写「发现可疑脚本文件」。

**原因**

文件系统的元数据记录能证明「曾存在过」，但不能证明「内容是什么」。

这是两个不同层面的结论。元数据里只有名字、大小、时间、所属的记录位置——没有内容。

从「曾存在过」到「是恶意脚本」，中间缺的内容证据需要另找：文件被删除且未复用时，未分配空间里可能残留部分字节；但那块空间可能已经被新数据覆盖，也可能没有。

结论强度超出了证据强度。

「文件存在」和「文件是恶意代码」在报告里的分量完全不同，后者会直接导致定性结论。

**影响**

把"存在"当成"内容"，报告的分量会凭空上一个台阶。

**核查**

**报告分两栏表述，这是硬要求。**

- **存在性栏（强证据）**：文件系统记录了某个文件的存在，
  包含文件名、大小、时间戳、所属的元数据记录位置。
  结论写「该文件在系统中曾存在」
- **内容栏（需佐证）**：只有当有字节级证据时才能写。
  证据来源：未分配空间里的雕刻字节、
  应用缓存、备份副本、内存镜像、终端日志里的内容输出

**两栏必须都写。** 只写存在性会显得单薄，只写内容会失去证据支撑。

分栏写出来的结论既准确，又让读者能判断每一条的可靠程度。

<a id="section-29"></a>

#### 陷阱 8：看到某个模板文件就定性为拒绝服务

**现象**

站点目录里存在一个特定用途的模板文件，
报告写「存在拒绝服务相关的配置」。

**原因**

**这个文件是双向的。** 它的设计目的是在应用不可用时展示友好提示，而**正常的维护操作也会主动创建它**——维护期间显示自定义提示页，是标准的运维做法。

也就是说，这个文件的存在有两种同样合理的解释：应用异常时自动生成，或者维护时人工放置。

把一次常规维护报成一次服务异常事件。

**影响**

对方一旦拿出维护记录，这条发现就整条作废。

**核查**

**读内容 + 对照维护窗口。** 判断方法：

1. 文件内容是**框架生成的默认提示**，还是**人工编辑的自定义内容**
2. 文件的创建时间是否落在**已知的维护窗口**内
3. 同一时段**系统日志里有没有服务重启、部署、故障的记录**
4. **访问日志里有没有大量请求返回了特定状态码** ——
   这是最有力的旁证，因为拒绝服务的影响会体现在请求结果上

只有第 4 项有明确对应，才支持「发生了服务不可用」的结论。
仅有文件存在，结论最多到「存疑」，并且要写出待核查项。

<a id="section-30"></a>

#### 陷阱 9：把缓存产物当手工植入

**现象**

在站点目录里发现一批编译产物文件，判定为异常。

**原因**

**这类文件是应用框架的正常缓存产物**，每个正常的应用站点都会有。
它们的存在完全正常，命名也有规律。

需要关注的不是「有没有」，而是**内容与源码是否对应**。

如果缓存产物里的代码与当前源码的版本不匹配，那才说明**有人在绕过正常编译流程直接改了产物**——这是一种隐蔽的植入方式，因为框架会一直使用这份缓存。

把正常产物报成异常。或者反过来，把真正的问题当成正常产物放过。

**影响**

两个方向都危险：报成异常浪费信任，当成正常放过则丢掉真问题。

**核查**

**把产物与源码做版本对照**，而不是只看它在不在。**判据是「对应关系」，不是「存在性」。** 具体检查：

1. 缓存产物的生成时间 vs 源码的修改时间 —— 缓存应该**晚于**源码（由源码编译而来）
2. 缓存产物里内嵌的源码行号与信息，是否与实际源码文件对得上
3. 缓存产物的内容，与按当前源码重新编译的结果是否一致
4. 缓存产物的哈希，是否与官方发行包或备份里的同名文件一致

**前两项最快、成本最低，且能覆盖大部分情况。**

第 1 项出现「缓存早于源码」时，说明这份缓存不是由当前源码生成的，需要重点追查。

<a id="section-31"></a>

#### 陷阱 10：查站点目录就以为查全了

**现象**

在站点根目录及其子目录做了全量检索，未发现异常文件，
报告写「站点目录未见可疑文件」。

**原因**

**Web 应用的执行位置不只有站点目录。** 需要一并考虑：

- 框架的临时编译目录（`%windir%` 下的临时目录）
- 某类配置文件可以让**特定目录的请求自动包含另一个文件**，
  而那个文件可以在站点目录**之外**
- 站点根目录之外的某些全局配置（影响所有站点，包括这个）

也就是说，「站点目录内没有可疑文件」这件事本身，不保证这个站点没有被劫持。

覆盖面不足导致的漏检，而且是结构性漏检——不是「查得不够仔细」，是「查的位置不对」。

**影响**

这一类漏检最难自查：查过了、也写进报告了，但位置从一开始就错。

**核查**

把「行为由什么决定」作为排查的出发点，而不是「目录里有什么」。

对每个站点的执行链，逐一确认：

1. **自动包含机制**：站点内与全局配置里，是否指定了自动包含的文件？
   这些文件指向哪里？
2. **临时目录**：框架的临时编译目录里有没有异常产物？
3. **全局配置**：影响所有站点的配置项，是否被改动过？
4. **其他技术栈的痕迹**：如果站点混合了其他运行时的组件
   （这类场景在生产环境并不少见），那套组件的配置也要查
   ——它对网站也有等效的影响力

第 1 项的排查方法：全量查找这类配置文件（命名有规律，可以在全站范围内找），逐个读取并确认它指向的文件路径，把被指向的文件也纳入检查范围。

「被引用的文件」和「文件本身」同样重要，只检查引用者不检查被引用者，等于只查了一半。

<a id="section-32"></a>

### 4.4 采集姿势与报告纪律

<a id="section-33"></a>

#### 陷阱 11：在运行中的站点目录上直接操作

**现象**

为了分析可疑文件，直接在生产服务器的站点目录里打开、复制、执行某些操作。

**原因**

**访问文件会更新元数据里的最后访问时间。** 在取证语境下，这是一个改变检材状态的动作——而且是不可逆的：最后访问时间一旦被刷新，就无法还原成刷新前的值。

而最后访问时间在某些分析里是有意义的证据（比如用它判断某个文件近期是否被访问过）。

证据状态被自己改变，且无法解释。如果报告里用到最后访问时间，读者会问「这个值是你分析时改的还是原本的」。

**影响**

不可逆：被自己刷掉的那个时间点，谁也补不回来。

**核查**

**在线采集的三条原则**：

1. **只读方式访问** —— 用只读挂载，或先做只读复制
2. **先记录后操作** —— 需要写操作时，先在副本上做
3. **记录采集过程** —— 谁、何时、对什么、做了什么、前后哈希

如果确实需要在运行中的系统上取文件（比如内容正在被使用、复制会造成不一致），先记录该文件当前的元数据作为**采集时状态**，并在报告里明确标注「以下时间为采集时读取值，非历史值」。

**最根本的做法是：优先做离线分析。** 如果条件允许关机做镜像，那么运行中采集的所有问题都不存在。

<a id="section-34"></a>

#### 陷阱 12：把「存在缓存产物」与「存在植入」混为一谈

**现象**

查到了可疑文件，但不确定它是否被实际使用，
报告里写「疑似植入」。

**原因**

「文件在磁盘上」和「文件被使用」是两个问题。判定后者需要观察运行时的行为证据：应用日志里是否有该文件被加载的记录、访问日志里的响应特征是否与该文件的行为一致、进程层面的证据等。

结论强度模糊——「疑似」这个词既没有说明证据强度，也没有给读者判断的依据。

**影响**

「疑似」在报告里是最省事也最不负责的词：它把判断责任推回给读者。

**核查**

**按证据强度分档表述，不要用模糊词。**

- **已确认使用**：有运行时证据（加载记录、行为特征吻合）→ 可以进入发现清单
- **存在但未确认使用**：文件在磁盘上，无运行时证据 →
  列入「待核查」清单，写明需要什么条件才能进一步确认
- **存在但属正常产物**：有对应关系证明是正常生成的 → 列入排除清单并写理由

三档之间的区别不在「可能性」，而在**「有没有证据支撑」**。

报告里给出每一档的判定依据，读者才能自己判断结论的可靠程度。

<a id="section-35"></a>

#### 陷阱 13：结论没有「证据局限」章节

**现象**

报告写完发现清单就结束了。

**原因**

攻击痕迹还原的结论边界特别容易被忽略，而这些限制是客观的：

- **循环覆盖的日志**已把更早的记录覆盖掉
- **已清理的记录**只在完整性通道里留下痕迹，而完整性通道可能也被清空
- **未部署的审计组件**导致某类行为完全没有记录
- **重启导致的状态丢失**（内存态证据、部分缓存）
- **未分配空间被复用**导致内容无法恢复

一份没有说明这些的报告，读者只能按「报告说的都对」或
「报告说的都不对」来理解。

**影响**

结论被过度外推。**这是本篇所有陷阱的共同后果**——
前面每一条误判，最终都会在报告里表现为「结论超出了证据支持的范围」。

**核查**

**把「证据局限」写成与「发现清单」平级的独立章节**，逐项写清：

- **未部署的组件**：某类行为无独立记录
- **时间覆盖限制**：日志最早到某时刻、覆盖策略是什么
- **不可查区间**：哪些位置或时段无法检查，原因是什么
- **未做的检测**：内容层面的深度特征匹配未做，原因是什么
- **内容证据的缺失**：哪些文件只能证明存在、不能证明内容

阴性结论的写法（每个「未发现」都套这个结构）：

> **在 X 范围 Y 检查内未发现 Z。**
> 范围：站点根目录及全部子目录（路径写明）、N 个日志文件（覆盖时间）、
> M 份配置文件。
> 方法：内容特征检索、文件头类型一致性检查、配置引用关系梳理。
> 未覆盖：框架临时目录（无访问权限）、
> 全局配置（超出本次授权范围）、
> 内存中的运行状态（已关机，无内存证据）、
> 2024-01 之前的日志（已被轮转覆盖）。

<a id="section-36"></a>

## 五、案例示例

<a id="section-37"></a>

### 5.1 时间戳成簇到清理链闭合的完整入侵还原

**场景**

查获 Windows Server 2019（IIS 10，ASP.NET 站点 `digiforensics-site`，`C:\inetpub\wwwroot\digiforensics-site`），镜像 `DigiForensics.dd`（raw，1 TB，NTFS 起始扇区 2048），已关机。

委托方要求查明"站点被入侵到什么程度、攻击者做了什么、清理到什么程度"。已按 [03](server-log-web-access-log-analysis.md) 确认 11-14 凌晨存在 SQL 注入与 PUT 上传。

这条路径值得先走，是因为委托方的问题里"入侵到什么程度"是个**需要分层回答**的问题。

**入口、在场、加载、清理**是四件不同的事，任何一件缺失都会让结论高估或低估本案的实际损失。而"清理到什么程度"更特殊——它只能靠文件系统残留痕迹来回答，日志恰好是最不可靠的那一环。

**处置过程**

**第 1 步 · 覆盖范围（先做这步）**

```powershell
Get-WinEvent -ListLog Security,System,Application,'Microsoft-Windows-PowerShell/Operational' |
  Select LogName, RecordCount, FileSize, MaximumSizeInBytes
# Security   32710  20.00MB  20.00MB   ← 已循环覆盖
```

**发现 0**：`Security` 已写满 → **只能回溯约 11 天**。站点目录时间戳跨度为 2024-11-01 至 11-20。**11-03 之前的事件日志不可查，写入报告局限。**

**第 2 步 · 时间戳成簇分析**

```powershell
Get-ChildItem C:\inetpub\wwwroot\digiforensics-site -Recurse -File |
  Group-Object { $_.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss') } |
  Sort-Object Count | Select-Object -First 8 Count, Name
#  312 2024-11-01 03:12:44     ← 初始部署批次
#  308 2024-11-15 01:05:20     ← 常规更新批次
#    4 2024-11-14 03:09:41     ← ★ 4 个文件共享同一秒，且与任何批次都不同
```

**发现 1**：`2024-11-14 03:09:41` 有 **4 个文件时间戳完全相同到秒**，与两次正常部署批次毫无关联。**这 4 个文件就是重点。**

**第 3 步 · 逐个打开这 4 个文件**

```powershell
Get-ChildItem C:\inetpub\wwwroot\digiforensics-site -Recurse -File |
  Where-Object { $_.LastWriteTimeUtc -eq [datetime]'2024-11-14T03:09:41Z' } |
  Select-Object FullName, Length, CreationTimeUtc, LastWriteTimeUtc
# \uploads\report.docx    284512
# \uploads\web.config        186   ← ★ 上传目录出现配置文件
# \uploads\up.aspx           114
# \bin\App_Master.dll      24576   ← ★ bin 目录新增，命名伪装成官方程序集
```

**发现 2**：`uploads\web.config` **出现在一个业务上只存文档的上传目录里**——业务没有任何理由在这里放配置文件。读其内容后发现它**移除了该目录的脚本处理程序映射**（把 `aspx` 的 handler 指向静态文件），**使已落地的 `up.aspx` 无法被执行**。

> **★ 判读要害**：这是**双向含义**的。移除脚本执行是**防守动作**（有人发现后门后做了加固），也可能是**攻击者自己藏后门的手段**。区分依据是**时间先后**：`up.aspx` 的访问在日志中持续到 03:40，而 `web.config` 写入于 03:09:41——**配置早于后续使用**。结合 `bin\App_Master.dll` 同时出现，**倾向于这是攻击者的隐藏手法**：让 `up.aspx` 看起来"存在但不执行"，同时保留一条可通过修改配置恢复执行的通路。但这一判断需要 `App_Master.dll` 的内容分析佐证，不能仅凭时间戳下结论。

**第 4 步 · `bin` 目录与预编译产物**

```powershell
Get-ChildItem C:\inetpub\wwwroot\digiforensics-site\bin -File |
  Select-Object Name, Length, LastWriteTimeUtc,
    @{n='Company';e={$_.VersionInfo.CompanyName}}, @{n='Desc';e={$_.VersionInfo.FileDescription}}
# App_Master.dll  24576  2024-11-14 03:09:41  （空）  （空）   ← ★ 无版本资源
# digiforensics.Site.dll  180224  2024-11-01 03:12:44  DigiForensics Inc  Site Library
```

**发现 3**：`App_Master.dll` 的命名**刻意模仿**真实的预编译程序集命名法（`App_*` 是 ASP.NET 自动生成程序集的约定），但**没有公司名和描述**——正常编译产物都带版本资源。**这是伪装，不是巧合。**

**第 5 步 · 清理痕迹**

```bash
# 5.1 已删除文件
fls -o 2048 -r -p /work/DigiForensics.dd | grep -i deleted | grep -iE 'wwwroot/digiforensics-site'
# r/r 4484-128-4:            $FILE  2024-11-14 03:44:58  $FILE_NAME  "report.aspx"  (deleted)
# r/r 4484-128-5:            $FILE  2024-11-14 03:44:58  $FILE_NAME  "uploads\	est.aspx"   (deleted)

# 5.2 读元数据
istat -o 2048 /work/DigiForensics.dd 4484-128-4
# Created: 2024-11-14 03:20:11   Modified: 2024-11-14 03:41:02   Accessed: 2024-11-14 03:44:50
```

```powershell
# 5.3 事件日志侧
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102,4719} -MaxEvents 20 |
  Select TimeCreated, Id, @{n='Msg';e={$_.Message.Substring(0,60)}}
# 2024-11-14 03:02:11  4719  系统审核策略已修改
# 2024-11-14 03:44:58  1102  Security 日志已被清除
```

**发现 4**：**清理链完整闭合**——`4719`（03:02，先关审计）→ 两个文件在 03:44:58 被删 → **`1102` 同一秒 03:44:58**。删除文件与清日志发生在同一秒，间隔明显低于本机正常人工操作间隔，符合自动化脚本完成"清理—停机"两步的形态。两个已删除文件的 MFT 条目**仍然存在**，`report.aspx` 的 `Accessed=03:44:50`（删除前 8 秒还在被访问）。

**结论**

| 结论 | 支撑 | 强度 |
|---|---|---|
| 存在有目标的 Web 入侵 | 注入 + PUT 落地（[03](server-log-web-access-log-analysis.md)）+ 4 个同秒时间戳文件 | **强** |
| 落地文件包含后门脚本 | `uploads\up.aspx` 存在于该秒批次，日志中 03:12–03:40 被反复调用 | **强**（需内容分析最终定性） |
| `bin\App_Master.dll` 为伪装的后门程序集 | 命名模仿 `App_*` 约定 + **无版本资源** + 与落地文件同秒写入 | **强**（需反编译内容佐证定性） |
| 存在刻意反取证 | 4719 → 删除文件 → 1102 **同一秒** | **强**（反取证铁证） |
| 至少 2 个落地文件已被删除 | MFT 中 `4484-128-4/5` 仍保留条目与时间戳 | **强（仅证"曾存在"）** |
| 已删除文件的内容 | `$DATA` 未分配空间**可能已被复用** | **弱**：需雕刻字节佐证，否则不予断言 |
| 11-03 之前的事件日志行为 | `Security` 已循环覆盖 | **不可查（已列为局限）** |

**本节能证明**：入口到场、加载到站、清理到点三条行为链，以及清理动作的自动化特征。
**本节不能证明**：已删除文件的实际内容、`web.config` 的真实意图、`App_Master.dll` 的功能。**阴性面**：事件日志仅覆盖 11-03 之后，11-03 之前的登录、提权、命令执行行为均不可查。

**误判对照**

1. **把"存在过文件"写成"内容是恶意脚本"**。判据是**两类证据的强度差**：MFT 条目 `4484-128-4/5` 与 `Created=03:20:11 / Accessed=03:44:50` **只能证明该文件存在过并被访问过**；内容是否恶意需要从 `$DATA` 未分配空间**雕刻出字节**并确认其为可执行脚本。"存在过"是 MFT 元数据的强结论，"内容是什么"是数据恢复的弱结论，两者不可互换。 **代价**：报告里写"发现恶意脚本文件"，而复核时对方发现内容无法恢复，会把整份报告的可信度一起扣掉——**这是取证报告最常见也最容易被抓住的越界表述**。
2. 把 `web.config` 的存在直接当成"攻击者做的加固"或"攻击者做的隐藏"。判据是**时间先后与加载链的联合**：`web.config` 写入 03:09:41，而 `report.aspx` 的访问持续到 03:40——**配置先行、后续仍在使用**，这不支持"防守加固"的解释；配合 `bin\App_Master.dll` 同秒出现才形成"隐藏 + 可恢复"的推断。单看"移除了脚本执行"这一个动作，两种解释都说得通。 **代价**：定性反了会让委托方去追一个不存在的"内部运维"，或者反过来放过一个还在潜伏的通道——**两种错都发生在同一个动作的两种解读上**。
3. **把"没找到更多痕迹"写成"没有更多动作"**。判据是**载体本身是否记录该行为**：`Security` 已循环覆盖（32710 条 / 20 MB），11-03 之前的行为没有被写下来，而不是没有被执行。**阴性结论必须以载体能力为前提**——本案能说的是"在 11-03 至 11-20 的 Security 覆盖范围内未见更多提权行为"，**不能是"攻击者没有做过其他动作"**。**代价**：漏判前的潜伏期行为，会让委托方误以为入侵只发生在 3 分钟内，从而放弃扩大排查范围——而这正是潜伏型攻击的典型藏身处。

**按错误判据走的代价**：第 1 条踩中，报告会在最关键的"损失认定"上被推翻；第 3 条踩中会让整个入侵窗口被压缩成 03:09–03:45 这 36 分钟，委托方据此认为入侵范围可控，从而不通知上游与合规方，一旦后续发现更早的横向移动，责任会落到取证方身上。

<a id="section-38"></a>

### 5.2 反例 Sysmon 未部署时的阴性结论边界

**场景**

同一台机器上的一类"查不到就放心"的问题。委托方在上文结论基础上继续问："有没有人在这台机上做过命令行操作、做过注册表持久化？"

将此情形单列的原因是 Windows 主机侧的命令行与进程创建问题**主要靠 Sysmon 回答**，而 Sysmon **是可选组件**。

**先确认它有没有被部署，比先去找日志要重要得多**——否则会在一个本就不存在的载体上耗掉几小时，最后写出一份"未发现"的报告。

**处置过程**

**第 1 步 · 先确认 Sysmon 是否存在**

```powershell
Get-WinEvent -ListLog '*Sysmon*' -ErrorAction SilentlyContinue |
  Select LogName, RecordCount, FileSize, MaximumSizeInBytes
# （无输出）

Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
# Get-Service : 找不到名称为 "Sysmon64" 的服务

Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' |
  Where-Object { $_.DisplayName -like '*Sysmon*' } | Select DisplayName, DisplayVersion
# （无输出）
```

**发现 1**：没有 Sysmon 日志通道、没有服务、没有卸载项记录——三者互相印证，**Sysmon 从未被部署到这台机器上**，而不是"部署了但被卸载了"（卸载会留下卸载项或事件记录）。

第 2 步 · 退回到原生通道，列出它们各自记录什么

```powershell
Get-WinEvent -ListLog Security,System,Application,'Microsoft-Windows-PowerShell/Operational' |
  Select LogName, RecordCount, LastWriteTime
# Security      32710  2024-11-20
# System        18432  2024-11-20
# Application   12045  2024-11-20
# PowerShell/Operational  2088  2024-11-19
```

**发现 2**：**原生通道里能回答的问题被逐条收窄**——`Security` 能回答登录与提权（4624/4672/4719），**但完全不记录进程创建、不记录命令行内容**；`PowerShell/Operational` 能回答脚本块内容，但**只覆盖 PowerShell 会话**；`System`/`Application` 只能提供间接的环境变更痕迹。"没有 Sysmon"意味着"进程命令行在主机上从未被记录过"。

**第 3 步 · 用现存通道把可回答的部分答完**

```powershell
# 3.1 登录与新建会话（Security 内）
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 2000 |
  Group-Object { $_.Properties[18].Value } |
  Sort-Object Count | Select-Object Count, Name
# 1181  -
#    9  DIGIFORENSICS\webadmin
#    3  DIGIFORENSICS\backupsvc

# 3.2 交互式登录的类型（4624 的 LogonType）
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 2000 |
  Group-Object { $_.Properties[8].Value } |
  Sort-Object Count | Select-Object Count, Name
#  995 2    ← 交互
#  921 3    ← 网络
#   58 5    ← 服务
#   40 10   ← RemoteInteractive（远程桌面）
```

**发现 3**：**可确认的账户维度**只有 9 次 `webadmin` 与 3 次 `backupsvc` 的登录，其中 40 次 LogonType=10 表明存在远程桌面交互，这与站点被上传文件的时间跨度一致。但这些都是"谁登录过"，不是"登录后执行了什么"。

**第 4 步 · 明确说出查不到的东西**

```bash
# PowerShell 脚本块日志：仅覆盖 11-19 之后，且只含 2088 条
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} |
  Measure-Object | Select Count
# Count : 87

# 87 条脚本块日志，全部落在 11-19 至 11-20（清理后一天）
```

**发现 4**：**87 条脚本块记录全部晚于清理时间（11-14）**——清理动作本身如果走的是 PowerShell，**它的脚本块内容已不可查**，因为 `1102` 只清 `Security`，但 `PowerShell/Operational` 独立轮转且覆盖期更短。

**结论**

| 结论 | 支撑 | 强度 |
|---|---|---|
| Sysmon **从未部署**到该机 | 无日志通道 + 无服务 + 无卸载项，三源互证 | 强 |
| **进程创建与命令行内容在主机侧从未被记录** | Sysmon 缺失这一事实本身 | 强（**能力缺失，非行为缺失**） |
| 11-03 至 11-20 期间登录账户仅 `webadmin`(9)、`backupsvc`(3) | `Security` 4624 聚合 | 中（**受 11-03 下界限制**） |
| 存在 40 次远程桌面交互 | 4624 的 LogonType=10 | 中（**未关联到具体操作**） |
| 清理动作是否经 PowerShell 执行 | `4104` 最早记录为 11-19 | **不可判** |
| 是否存在未被任何通道记录的进程执行 | 无 Sysmon、无 EDR | **不可查（已列为局限）** |

**限定范围**：「`Security`、`System`、`Application`、`PowerShell/Operational` 四个通道、11-03 至 11-20 这一时间窗」。

**未覆盖**：**进程创建与命令行**（Sysmon 未部署）；**网络连接**（无 Sysmon 事件 3/事件 22）；**文件哈希**（无 Sysmon 事件 7/11）；**注册表键值级变更**（`Security` 只记录 4657 的键名级别，且本例未查）；`Security` 循环覆盖前的 11-03 之前；**其他站点目录**的痕迹。

**误判对照**

1. **把"没查到命令行记录"写成"没有执行过命令"**。判据是**载体能力**：Sysmon 未部署 = 事件 1（进程创建）与命令行内容**在本机上从未被采集**，**这是采集能力缺失，不是行为缺失**。**阴性结论的成立前提是"该载体本应记录此行为"**——本案这个前提不成立。**代价**：一份"未发现命令执行痕迹"的报告会被当成安全证明使用，而实际上**这一维度根本没有被观测过**；一旦后续通过其他途径发现命令执行，**取证方要为"未发现"这个表述负责**。
2. 看到 `PowerShell/Operational` 有记录，就认为命令行维度已被覆盖。判据是**记录条数与时间分布**：本案 87 条 `4104` 全部晚于清理时间，说明**这条通道的轮转周期短于日志保留需求**，清理动作本身没有被留下。**"有日志"不等于"日志覆盖了你要的时间段"。** **代价**：委托方看到"PowerShell 日志存在"就会以为这段维度已查完，实际上一旦涉及清理动作本身，唯一的脚本块证据已经轮转掉了。
3. **把缺少 Sysmon 的原因默认为"没人管"**。判据是**三源互证的方向**：`Sysmon/Operational` 日志通道、服务项、卸载项**三者全无**——这指向"从未安装"；若是"安装后被卸载"，**至少会留下卸载项或安装时间的痕迹**。**区分"从未部署"与"部署后移除"是有意义的**：前者说明是**基线缺失**，整改方式是部署；后者说明**有人刻意移除监控**，性质完全不同。**代价**：把"基线缺失"写成结论却不说清，会让委托方误以为监控曾经存在过，**从而跳过"谁在什么时候移除了它"这条真正的调查线**。

**按错误判据走的代价**：本条最实际的代价是报告里的"未发现"如果没有限定范围，会成为后续所有排除性推理的地基。一旦这份报告被用于免责或对外说明，第 1 条与第 2 条中任一处成立，整个"未发现"表述都不成立——**而这类问题通常在交付几个月后才由另一份材料暴露**，那时补救成本远高于现在补一句限定。

<a id="section-39"></a>

## 六、扩展阅读方向

本篇的方法论建立在 NTFS 元数据不会消失这一点上。 下面先把这块地基补齐——不读这几篇，"删掉了什么"这个问题的答案就拿不到。

<a id="section-40"></a>

### 文件系统层：痕迹的真正来源

- [NTFS 结构与 MFT 解析](../../filesystem/filesystem-ntfs/filesystem-ntfs-ntfs-master-file-table.md) —— **本篇最重要的前置**。`$MFT` 条目结构、flags `0x06` 的含义、MFT 记录的 LSN，以及本篇反复用到的结论"删除动作不产生第二个 MFT 条目"在这里有完整推导。
- [Steady-State 与 LogFile 还原](../../filesystem/filesystem-ntfs/filesystem-ntfs-steady-state-logfile.md) —— **为什么 `$LogFile` 里读不到删除记录**，以及配置被改但没有 `.bak` 时，从日志区回放变更的思路。
- [UsnJrnl 与文件操作时间线](../../computer/computer-execution/computer-execution-usn-journal-timeline.md) —— `$UsnJrnl` 的记录结构、覆盖窗口判断与工具化解析。本篇的"删除痕迹"与"批量重置"判定都依赖它。
- [NTFS 数据流与隐藏数据](../../filesystem/filesystem-ntfs/filesystem-ntfs-ntfs-alternate-data-streams.md) —— 备用数据流与 ADS：站点目录里的文件可能不止一个流。
- [文件雕刻与签名恢复](../../filesystem/filesystem-unix/filesystem-unix-file-carving-and-signature-recovery.md) —— 元数据告诉你"有过这个文件"，**签名才能告诉你"它是什么"**。

<a id="section-41"></a>

### 日志侧：与本篇互为闭环

- [Web 访问日志深度分析](server-log-web-access-log-analysis.md) —— 本篇产出"主机上发生了什么"，那篇产出"哪些请求可疑"，两边对上才算闭环。`time-taken` 离群值、`404/7` 这类三元组判据是时序对齐的锚点。
- [IIS 配置与 W3C 日志](server-log-iis.md) —— `applicationHost.config` 的 `.bak` 对照、站点 ID 与物理路径映射，本篇的配置层分析依赖它。
- [Web 服务器取证工件地图](server-log-server-artifact-map.md) —— 7045 新服务、任务缓存、PowerShell 4104、Sysmon 这些主机侧行为证据在哪、覆盖到哪。
- [事件日志深度分析](../../computer/computer-registry-log/computer-registry-log-windows-event-log-analysis.md) —— 1102、4719、4672/4688 的完整语义。本篇的"最强单点证据"要从这里取。

<a id="section-42"></a>

### 跨平台对照：同一问题的不同落点

- [网站目录与 WebShell 检测](../server-web/server-web-webshell-detection.md) —— Linux 侧的对应议题。`Web.config` 与 `.user.ini` 是同一类东西：都是"目录级配置劫持"，都让站点目录里一个可疑文件都没有也能被接管。理解了这个共性，两边的排查清单就能互相迁移。
- [WebShell 工具流量特征](../server-web/server-web-webshell-traffic-patterns.md) —— 从流量侧补齐主机层缺失的证据，用于确认"落地之后发生了什么交互"。

<a id="section-43"></a>

### 工具与判据：结论强度的上限

- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— **判断"清理痕迹"与"时间戳被重置"需要它的方法**。它的分层定级思路可以直接套到清理动作的强度判定上。
- [哈希与完整性校验](../../fundamentals/fundamentals-concepts/fundamentals-concepts-hashes-and-integrity-verification.md) —— 配置文件基线比对、预编译 DLL 与源码的一致性验证。
- [取证概念与分类](../../fundamentals/fundamentals-concepts/fundamentals-concepts-digital-forensics-concepts.md) —— 证据的关联性、解释力、可采性三维度，用来给"存在持久化"这类判断定强度。
- [Exchange 与邮件数据恢复](server-log-exchange.md) —— 攻击链涉及邮件投递时，邮件侧 ESE 数据库能补上哪些主机层看不到的路径。
<a id="section-44"></a>

## 七、命令速查

```bash
# ===== 证据固定 =====
fls -o 2048 -r -p /work/DigiForensics.dd > /work/filelist.txt
grep -iE 'wwwroot/digiforensics-site' /work/filelist.txt > /work/site.txt
grep -iE 'inetsrv/config/applicationHost\.config(\.bak)?$' /work/filelist.txt
icat -o 2048 /work/DigiForensics.dd <inode> > /evidence/01-Web.config
sha256sum /evidence/* | tee /evidence/SHA256SUMS.txt    # inode 与偏移必须登记

# ===== 配置 diff（★ .bak 只含站点级配置，不含应用内 Web.config）=====
diff -u /evidence/03-applicationHost.config.bak /evidence/02-applicationHost.config

# ===== ★ 删除痕迹：MFT 0x06 = 曾存在过（不证明内容）=====
fls -o 2048 -r -p /work/DigiForensics.dd | grep -i deleted | grep -iE 'wwwroot|inetpub'
istat -o 2048 /work/DigiForensics.dd 4484-128-4     # 读已删除条目的时间戳与父目录
blkls -o 2048 /work/DigiForensics.dd > /work/unalloc.raw
foremost -i /work/unalloc.raw                       # 按签名雕刻已删除内容（成本高）

# ===== $UsnJrnl（★ 变长记录，必须用支持 USN 的工具解析）=====
icat -o 2048 /work/DigiForensics.dd <inode-usnjrnl> > /evidence/UsnJrnl-\$J.0
```

```powershell
# ===== 覆盖范围（★ 每次先做这步）=====
Get-WinEvent -ListLog Security,System,Application,'Microsoft-Windows-PowerShell/Operational' |
  Select-Object LogName, RecordCount, FileSize, MaximumSizeInBytes, LogMode
# FileSize ≈ MaximumSizeInBytes → 已循环覆盖，写入报告局限

# ===== ★ 反取证三件套（每次必查）=====
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102,4719} -MaxEvents 20 | Select TimeCreated, Id
Get-WinEvent -FilterHashtable @{LogName='System';   Id=104,6008} -MaxEvents 20 | Select TimeCreated, Id
Get-WinEvent -FilterHashtable @{LogName='System';   Id=7045} -MaxEvents 20 | Select TimeCreated, Id
# 4719 → 1102 紧密相邻 = 先关审计再清日志，几乎不可能是正常运维

# ===== ★ 时间戳成簇分析（识别落地与批量重置，不需基线）=====
Get-ChildItem C:\inetpub\wwwroot\digiforensics-site -Recurse -File |
  Group-Object { $_.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss') } |
  Sort-Object Count | Select-Object -First 15 Count, Name
Get-ChildItem C:\inetpub\wwwroot\digiforensics-site\uploads -File |
  Group-Object { $_.LastWriteTimeUtc.ToString('yyyy-MM-dd') } | Sort-Object Name | Select-Object Count, Name

# ===== 加载链检查 =====
Get-ChildItem C:\inetpub\wwwroot\digiforensics-site\bin -File |
  Where-Object { $_.Name -notmatch '^(App_Web_|digiforensics\.)' -and $_.Extension -eq '.dll' } |
  Select-Object Name, Length, LastWriteTimeUtc,
    @{n='Company';e={$_.VersionInfo.CompanyName}}, @{n='Desc';e={$_.VersionInfo.FileDescription}}
# ★ 无 CompanyName / FileDescription 的 DLL 高度可疑（厂商 DLL 都带版本资源）
Get-Item C:\inetpub\wwwroot\digiforensics-site\Global.asax -ErrorAction SilentlyContinue |
  Select-Object Length, CreationTimeUtc, LastWriteTimeUtc
Get-ChildItem 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files' -Recurse -File `
  -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTimeUtc -gt (Get-Date).AddDays(-30) } |
  Select-Object -First 20 FullName, Length, LastWriteTimeUtc

# ===== App_Offline.htm（★ 双向：维护 or DoS，读内容再判）=====
Get-Item C:\inetpub\wwwroot\digiforensics-site\App_Offline.htm -ErrorAction SilentlyContinue |
  Select-Object Length, CreationTimeUtc, LastWriteTimeUtc, LastAccessTimeUtc
# LastAccessTimeUtc 显著晚于 LastWriteTimeUtc → 文件写好后被人取走过

# ===== 上传目录里的 Web.config（★ 业务上不该存在，必须读内容）=====
Get-ChildItem C:\inetpub\wwwroot\digiforensics-site -Recurse -Filter '*.config' -File |
  Select-Object FullName, Length, CreationTimeUtc, LastWriteTimeUtc
Select-String -Path C:\inetpub\wwwroot\digiforensics-site\uploads\web.config `
  -Pattern 'httpHandlers|handlers|buildManager|compilation' -Context 0,3

# ===== machineKey（★ 明文 = 配置弱点，不等于已遭攻击）=====
Select-String -Path C:\inetpub\wwwroot\digiforensics-site\Web.config -Pattern 'machineKey' -Context 0,3
Select-String -Path C:\Windows\Microsoft.NET\Framework64\v4.0.30319\config\machine.config `
             -Pattern 'machineKey' -Context 0,3
# 两处相同 → 全站共用同一密钥

# ===== PHP on Windows =====
Select-String -Path C:\php\php.ini,C:\inetpub\php\php.ini `
  -Pattern 'auto_prepend_file|auto_append_file|short_open_tag|extension_dir'
# auto_prepend/append_file 指向不明路径 = 等效于全局植入
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — Windows 服务器取证 — Web 攻击痕迹还原」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《Web 攻击痕迹还原》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.vc` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
