---
title: "浏览器取证"
slug: "computer-browser-behavior-browser-forensics"
canonical: "https://www.digiforensics.cn/wiki/computer-browser-behavior-browser-forensics"
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

# 浏览器取证

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/computer-browser-behavior-browser-forensics)

<a id="section-1"></a>

## 一、概述

浏览器是个人设备上信息记录最密集的应用：它同时记下了访问过什么、搜索过什么、下载过什么、登录过什么、填过什么，以及**什么时候**发生。

外泄案件里，攻击者经常要在浏览器里留下一段访问记录。内部调查里那些「他到底访问了哪个云盘后台、什么时候导出的报表」的问题，**浏览器工件是应当优先检索的线索之一**，但覆盖范围取决于浏览器使用情况、日志留存和同步配置。

比 LNK、Prefetch 这类要解析二进制格式的工件，浏览器有个明显优势：**数据以明文语义存储**。URL、标题、表单值、搜索词都是可直接查询的文本，字段便于查询，但仍存在用户归属、隐私模式、时间换算与缓存重放等误判风险。浏览器数据库可作为时间线构建的输入。

短板同样突出：所有敏感字段都被加密，加密方案随浏览器品牌、版本、平台反复变化。 `Login Data` 里明明有 `password_value` 字段却解不开——这是新手最常见的误判。**解不开不等于没有。** 误判的代价不是「少一条线索」，而是**把一条可用的证据写成不可用**。

这一块覆盖的是 Windows 平台上的主流桌面浏览器。用户级痕迹（UserAssist、TypedPaths）见[用户行为痕迹](../computer-registry-log/computer-registry-log-user-activity-artifacts.md)，卷的定位与提取见[Windows 取证工件地图](../computer-registry-log/computer-registry-log-windows-artifact-map.md)。

浏览器工件属于**分析**环节的高频入口，位置在「工件已提取、开始逐应用判读」这一步。

**上游依赖**三件事。**镜像接入方式是前提**——浏览器数据库文件在被打开时会写入临时文件与锁文件，直接挂载分析等于修改证据，见[只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md)。DPAPI 主密钥必须**按用户上下文**取用，取不到则凭据类字段全部不可解。用户身份确认决定取哪个 Profile。

**它自己**要先做两件判断：**每个浏览器的用户数据目录有多少个 Profile**（Chromium 系有 `Default`、`Profile 1`、`Profile 2`……，只看 `Default` 会漏掉大量数据）；以及密文前缀属于三代方案里的哪一代（决定能不能解、怎么解）。

**下游支撑**三件事。访问时间是时间线的**常用输入**；下载记录要与系统层的下载痕迹（Zone.Identifier、SRUM 的网络用量）交叉；凭据的**存在性**结论（而非明文本身）可以支撑「该机登录过某服务」这类判断。

浏览器应用内痕迹、[SRUM 数据库分析](computer-browser-behavior-srum.md)的系统级资源使用统计、[Windows 11 与 Recall](computer-browser-behavior-windows11-recall.md)的系统级屏幕快照，三者是并列关系。

落到具体文件上：

| 浏览器族 | 用户数据目录 | 关键文件 |
|---|---|---|
| Chrome | `%LOCALAPPDATA%\Google\Chrome\User Data` | `Local State`、`Default\History`、`Login Data`、`Web Data`、`Network\Cookies`、`Preferences`、`Secure Preferences` |
| Edge（Chromium） | `%LOCALAPPDATA%\Microsoft\Edge\User Data` | 结构同上，仅目录名不同 |
| Brave / Opera | 各自的 `User Data` / `Opera Stable` 目录 | 结构同上 |
| Firefox | `%APPDATA%\Mozilla\Firefox\Profiles\*.default-release` | `profiles.ini`、`places.sqlite`、`cookies.sqlite`、`formhistory.sqlite`、`logins.json`、`key4.db`、`prefs.js` |
| IE / Edge Legacy | `%LOCALAPPDATA%\Microsoft\Windows\History` | `index.dat`、`WebCacheV01.dat` |
| 密钥载体 | `Local State` 里的 `os_crypt.encrypted_key` / `os_crypt.app_bound_encrypted_key` | 前者 Base64 解码后前 5 字节固定为 ASCII `DPAPI`；后者前缀 ASCII `APPB` |
| DPAPI 主密钥 | `%APPDATA%\Microsoft\Protect\<SID>\` | 解密前提是「在正确的用户上下文里」，不是「知道密码」 |

三个判定要点：**Chromium 密文前缀分三代**（无前缀 / `v10` / `v20`）、**DPAPI 解密靠用户上下文而非口令**、**`v20` 的双层包装使离线解密不具通用性**。

据此能回答的是：访问过哪些 URL 及时间、搜索过什么、下载过什么文件、登录过哪些站点、表单自动填充过什么、Cookie 与站点设置的当前状态、以及**某个凭据条目是否存在**。

回答不了的是这些。下面几个误解必须先纠正：

- **「密文解不开」不等于「没有这条记录」。** `password_value` 字段存在而解不开，是**正常的凭据可解性限制**，不是数据缺失。**写成「无凭据」是事实性错误。**
- **`v20` 密文解不开是预期内的。** 它是**两层 DPAPI 包装**，外层在 SYSTEM 上下文、内层在用户上下文，服务还会校验调用进程的可执行文件路径。成功率取决于浏览器版本、安装路径与系统状态，不应向委托人承诺「一定解得开」。
- **密文方案的版本差异不能套用。** Windows 上的 Chromium 密文前缀是 `v10`，其它平台会因密钥管理方式不同出现其他前缀，跨平台样本时把非 `v10` 前缀套进 GCM 结构解析会得到错误结论。
- **非 Chromium 浏览器的方法不能套用。** Firefox 是 NSS 加密（`key4.db`），IE / Edge Legacy 多数字段明文但结构完全不同，**三者各有解析路径**。
- **仅看 `Default` 目录的完整性。** Chromium 系的多个 Profile 各自独立，**漏掉 Profile 就是漏掉数据**。
- **访问时间与访问行为的区别。** 数据库记录的是**时间戳与 URL**，**不代表用户实际阅读了页面内容**。
- **Profile 已删除但数据仍在盘上的情形。** 这需要卷层面的搜索能力，浏览器数据库本身回答不了。

相关基础包括：SQLite 查询，能从数据库里定位表、字段并处理时间基准转换，Safari / Chromium 都有各自的纪元偏移；DPAPI 的工作前提，主密钥与用户 SID 绑定，解密需要在对应用户上下文执行，见[注册表取证](../computer-registry-log/computer-registry-log-registry-forensics.md)中 hive 的归属判定；

Windows 目录结构与用户数据路径，能定位 `%LOCALAPPDATA%` 与 `%APPDATA%` 下的多个 Profile；AES-GCM 的报文结构（密文与 tag 分离，取 tag 时截断会导致解密失败或校验不过）。

还有一条边界要立住：凭据材料只做离线可解性判断与元数据分析，不做在线使用、不记录口令明文。

<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 工件矩阵

| 浏览器族 | 用户数据目录 | 关键文件 | 访问凭据存储 |
| --- | --- | --- | --- |
| Chrome | `%LOCALAPPDATA%\Google\Chrome\User Data` | `Local State`、`Default\History`、`Login Data`、`Web Data`、`Network\Cookies`、`Preferences`、`Secure Preferences` | v10 / v20 密文 |
| Edge (Chromium) | `%LOCALAPPDATA%\Microsoft\Edge\User Data` | 同上（目录名不同） | v10 / v20 密文 |
| Brave | `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data` | 同上 | v10 / v20 密文 |
| Opera | `%APPDATA%\Opera Software\Opera Stable` | 同上 | v10 / v20 密文 |
| Firefox | `%APPDATA%\Mozilla\Firefox\Profiles\*.default-release` | `profiles.ini`、`places.sqlite`、`cookies.sqlite`、`formhistory.sqlite`、`logins.json`、`key4.db`、`prefs.js` | NSS 加密 |
| IE / Edge Legacy | `%LOCALAPPDATA%\Microsoft\Windows\History`、`...\WebCache` | `index.dat`、`WebCacheV01.dat` | 多数字段明文 |

Chromium 系的用户数据目录下有多个配置文件目录（`Default`、`Profile 1`、`Profile 2`……），**必须逐个遍历**，逐个配置文件的提取方法见 4.1 陷阱 1。

<a id="section-4"></a>

### 2.2 Chromium 核心数据库

| 数据库 | 关键表 | 取证价值 |
| --- | --- | --- |
| `History` | `urls`、`visits`、`keyword_search_terms`、`downloads`、`downloads_url_chains` | 完整访问与下载时间线、搜索词、下载来源 |
| `Login Data` | `logins` | 站点、用户名、密码密文 |
| `Web Data` | `autofill`、`credit_cards`、`keywords` | 表单自动填充值、信用卡信息 |
| `Network\Cookies` | `meta`、`cookies` | 会话 Cookie，可用于会话劫持与溯源 |

`urls` 与 `visits` 是 1:N 关系。

`urls` 保存 URL 字符串与累计统计。`visits` 每次打开写一行，是时间线的真正来源。

`keyword_search_terms` 通过 `url_id` 关联搜索产生的访问记录。

`visits.transition` 的低位（`transition & 0xFF`）标注访问方式，判定「用户是主动输入还是点链接进来的」：

| transition | 含义 | 取证意义 |
| --- | --- | --- |
| `0x01000000` | TYPED | 用户手工键入 URL 或从地址栏搜索，意图明确 |
| `0x30000000` | LINK | 从链接点击 |
| `0x00020000` | KEYWORD | 通过搜索关键词到达 |
| `0x00080000` | FORM_SUBMIT | 表单提交跳转 |
| `0x02000000` | RELOAD | 刷新 |
| `0x10000000` | FORWARD_BACK | 前进/后退 |
| `0x40000001` | CHAIN_END | 一次跳转链的结束点 |

<a id="section-5"></a>

### 2.3 Chromium 加密：三代方案并存

Chromium 的凭据加密不是一套方案，而是**三代并存**。

判定入口是密文前 3 字节前缀：

| 前缀 | 密钥载体 | 算法 | 绑定范围 | 出现版本 |
| --- | --- | --- | --- | --- |
| 无前缀 | 直接 DPAPI | DPAPI | 用户 + 机器 | Chrome 80 之前 |
| `v10` | `Local State` 的 `os_crypt.encrypted_key` | AES-256-GCM | 用户 + 机器 | Chrome 80 起（Windows） |
| `v20` | `Local State` 的 `os_crypt.app_bound_encrypted_key` | AES-256-GCM | 应用路径 + 服务 + 用户 | Chrome 127 起（Windows） |

> **平台差异**：Windows 上的 Chromium 密文前缀是 `v10`。其他平台会因密钥管理方式不同出现其他前缀，跨平台样本时不要把非 `v10` 前缀套进下文的 GCM 结构。

`os_crypt.encrypted_key` 是 Base64 字符串，解码后前 5 字节固定为 ASCII `DPAPI`，其后才是 DPAPI 密文；用**对应用户上下文**的 `CryptUnprotectData` 解开后，得到 32 字节 AES 密钥。

`os_crypt.app_bound_encrypted_key` 是 Base64 字符串，前缀为 ASCII `APPB`，其内部是**两层 DPAPI 包装**：外层在 SYSTEM（或服务自身）上下文加密，内层在用户上下文加密。

此外服务还会校验调用进程的可执行文件路径是否与加密时规范化后的安装路径一致。

**因此 v20 的离线解密并不具备通用性**，成功率取决于浏览器版本、安装路径、系统状态与工具实现，不应向委托人承诺「一定解得开」。

<a id="section-6"></a>

### 2.4 DPAPI 主密钥与用户配置文件的绑定

`CryptUnprotectData` 成功的前提不是「知道密码」，而是能在正确的用户上下文里拿到主密钥并解开被 DPAPI 加密的用户密钥。

主密钥文件位于：

```text
C:\Users\<user>\AppData\Roaming\Microsoft\Protect\<SID>\
C:\Windows\System32\Microsoft\Protect\<SID>\
```

每个用户 SID 一套，主密钥的有效性受登录口令、域凭据、机器身份、系统时间、策略共同约束。

由此产生两个必须写进报告的判断：

- **DPAPI 解密失败**通常表示用户配置文件、机器、口令状态或策略不匹配，**不表示字段为空或未加密**。`Login Data` 中 `password_value` 为非空 BLOB 而解不开，正确表述是「存在密文，密钥恢复失败」。
- **用户没登录过就解不开**。未交互登录过的账户只有 STATIC 域密钥，主密钥不完整，离线还原难度显著上升。

主密钥还需按 DPAPI 版本（v1 / v2）派生用户密钥，两者算法与迭代次数不同，由系统与域策略决定，具体以实际检材为准。

<a id="section-7"></a>

### 2.5 AES-256-GCM 报文结构与 tag 语义

`v10` 密文的物理结构是：

| 偏移 | 长度 | 内容 |
| --- | --- | --- |
| 0 | 3 | 固定前缀 `v10` |
| 3 | 12 | GCM nonce |
| 15 | 可变 | 密文 |
| 末尾 | 16 | GCM 认证 tag |

判定要点：

- **tag 校验失败**通常意味着密钥、nonce、密文或附加认证数据之一不正确，**不表示该数据没有被加密**。它是「参数错了」的信号，不是「格式判断错了」的信号。
- 去掉前缀后的最小有意义长度为 `12 + 0 + 16 = 28` 字节，短于此的字段不是标准 v10 结构。
- 部分较新版本会在明文前加 32 字节随机填充，解析结果需要按实际检材验证后再裁剪，不能默认首字节即有效字符。

<a id="section-8"></a>

### 2.6 Firefox 与 IE / Edge Legacy

Firefox 的 `places.sqlite` 保存访问历史（`moz_places`、`moz_historyvisits`、`moz_bookmarks`），`cookies.sqlite` 的 `value` 列**通常为明文**，这是它相对 Chromium 的最大便利。

`logins.json` 中的 `encryptedUsername` / `encryptedPassword` 是 Base64 的 ASN.1 派生结果，真正的主密钥材料在 `key4.db`（BerkeleyDB，含全局盐与校验值）中。

`logins.json` 与 `key4.db` **必须配套**，缺一不可判定。旧版本 Firefox 还可能存在 `signons.sqlite` 与 `key3.db`。

注意 Firefox 的 `moz_historyvisits.visit_date` 是 **Unix 纪元起的微秒数**，而 Chromium 的对应字段是 **1601-01-01 起的微秒数**。两者在时间线中混用会得到 1601 年附近的荒谬时间，这是合并两族浏览器排序时最典型的错误。

IE 的历史在 Windows 7 及以后集中在 `%LOCALAPPDATA%\Microsoft\Windows\History\index.dat`（早期版本在 `History.IE5\` 目录）；IE10 与 Edge Legacy 还需检查 `%LOCALAPPDATA%\Microsoft\Windows\WebCache\WebCacheV01.dat`，其中包含缓存、Cookie 与下载记录。

二者均为复合文档/自定义二进制结构，需要专门解析器。

<a id="section-9"></a>

## 三、操作步骤

<a id="section-10"></a>

### 3.1 定位、拷贝与只读挂载

先确定卷偏移（`mmls` / `fsstat`），再按目录模式批量抽取，注意 `-p` 输出中 inode 在第 2 列：

```bash
mmls /work/DigiForensics.dd
fsstat -o 2048 /work/DigiForensics.dd

fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -Ei '/(Chrome|Edge|Brave-Browser)/User Data/.*(History|Login Data|Web Data|Cookies|Local State)$' \
  | grep -E '^r/r' \
  | awk '{print $2}' \
  | while read -r ino; do
      icat -o 2048 /work/DigiForensics.dd "$ino" > "/evidence/browser/$(printf '%s' "${ino%%:*}").bin"
    done
```

SQLite 的 WAL 内容可能不在主库文件里，**必须把 `-wal` 与 `-shm` 一起拷贝**。

它们是**独立的普通文件**（不是主库的数据流），因此要用 `fls` 分别定位各自的 inode：

```bash
# 逐个定位主库与其 -wal / -shm 同伴文件
fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -E 'User Data/Default/History(-wal|-shm)?$' | grep -E '^r/r'

# 逐个导出（文件名保留后缀，便于后续按同名组装）
fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -E 'User Data/Default/History(-wal|-shm)?$' | grep -E '^r/r' | awk '{print $2}' \
  | while read -r ino; do
      icat -o 2048 /work/DigiForensics.dd "$ino" > "/evidence/browser/$(echo "$ino" | sed 's/.*-//')"
    done

# 以 immutable 模式只读打开，sqlite 不会回写证据文件
sqlite3 "file:/evidence/browser/History.db?immutable=1" ".tables"
```

> 若检材中不存在 `-wal`/`-shm`（如已正常关闭或已 checkpoint），说明主库是自洽的；**不要伪造这两个文件**，也不要因为缺失就断定「有未落盘记录」。

<a id="section-11"></a>

### 3.2 构建 Chromium 访问时间线

WebKit 时间戳（1601 起微秒）到 UTC 的换算必须用 116444736000000000 这个偏移量：

```sql
SELECT
  datetime((v.visit_time/1000000) - 11644473600, 'unixepoch') AS visit_utc,
  u.url, u.title, v.visit_duration,
  printf('0x%08X', v.transition & 255) AS transition
FROM visits v JOIN urls u ON u.id = v.url
ORDER BY v.visit_time;
```

把访问与搜索词、下载关联起来：

```sql
-- 搜索词
SELECT k.term, u.url,
       datetime((v.visit_time/1000000) - 11644473600, 'unixepoch') AS visit_utc
FROM keyword_search_terms k
JOIN urls u    ON u.id = k.url_id
JOIN visits v  ON v.url = u.id
ORDER BY v.visit_time;

-- 下载及其来源链
SELECT d.target_path, d.total_bytes, d.tab_url, d.referrer,
       datetime((d.start_time/1000000) - 11644473600, 'unixepoch') AS start_utc
FROM downloads d ORDER BY d.start_time;
```

<a id="section-12"></a>

### 3.3 提取凭据密文并判断可解性

```sql
SELECT origin_url, action_url, username_value,
       length(password_value) AS pw_len,
       hex(substr(password_value,1,3)) AS prefix,
       date_created
FROM logins ORDER BY date_created;
```

`prefix` 为空表示旧式 DPAPI 直加密；`763130` 即 `v10`；`763230` 即 `v20`。

只要 `pw_len` 非零，就说明密码条目确实存在，后续能否还原是另一层问题，报告里两者必须分开写。

在**原始用户上下文**中解出 v10 主密钥：

```powershell
$ls = Get-Content "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State" -Raw | ConvertFrom-Json
$b  = [Convert]::FromBase64String($ls.os_crypt.encrypted_key)
$b  = $b[5..($b.Length-1)]                       # 去掉 ASCII "DPAPI"
$k  = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $b, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[Convert]::ToBase64String($k)                   # 期望长度 32 字节
```

拿到主密钥后用 AES-256-GCM 解 `v10` 密文：前 3 字节前缀之外，取 12 字节 nonce，中间密文，末尾 16 字节 tag。

v20 路径需要额外的 SYSTEM 上下文与路径校验，工具支持情况差异很大，**以实际工具版本为准**。

<a id="section-13"></a>

### 3.4 Firefox 与 IE / Edge Legacy

```bash
# profiles.ini 定位配置文件
cat "/evidence/browser/Mozilla/Firefox/profiles.ini"

# places.sqlite（注意时间基准为 Unix 纪元微秒）
sqlite3 "file:/evidence/browser/places.sqlite?immutable=1" "
SELECT datetime(visit_date/1000000,'unixepoch') AS visit_utc,
       url, title
FROM moz_historyvisits
JOIN moz_places ON moz_places.id = moz_historyvisits.place_id
ORDER BY visit_date;"

# cookies.sqlite 中 value 通常为明文
sqlite3 "file:/evidence/browser/cookies.sqlite?immutable=1" "
SELECT host, name, value, datetime(lastAccessed/1000000,'unixepoch') AS seen_utc
FROM moz_cookies ORDER BY lastAccessed;"
```

IE / Edge Legacy 使用专用解析器处理 `index.dat` 与 `WebCacheV01.dat`，输出为结构化表后再与 Chromium/Firefox 时间线合并。

<a id="section-14"></a>

### 3.5 交叉验证

浏览器时间线单独存在时证明力有限，应与事件日志、Prefetch、NTFS 时间戳对齐：

- `4624` 登录事件确认会话存在；
- `2` / `1` 强制关机与正常关机界定证据可用窗口；
- Prefetch 中的浏览器条目确认程序执行；
- `$UsnJrnl` 中的文件创建事件界定数据库最后写入时机。

若 SQLite 库中存在 `cookies` 表记录但 `moz_historyvisits` / `visits` 缺失，通常意味着会话被注入或数据被定向裁剪，而非「用户没访问过」。

<a id="section-15"></a>

## 四、常见陷阱

<a id="section-16"></a>

### 4.1 采集来源与完整性

<a id="section-17"></a>

#### 陷阱 1：只提取 `Default` 配置文件，漏掉 `Profile 1`、`Profile 2`

**现象**

在 `User Data` 目录下找到 `Default\History` 就开始解析，报告写下「该浏览器完整访问历史已提取，共 N 条记录」。

而实际上同一个 `User Data` 目录下还有 `Profile 1`、`Profile 2`、`Profile 3`，用户切换过的账号都在里面。

**原因**

Chromium 从 2013 年起支持**多配置文件并存**，每个配置文件是一套完全独立的浏览数据（独立的 `History`、`Login Data`、`Web Data`、`Network\Cookies`）。

它们的位置是：

```text
%LOCALAPPDATA%\Google\Chrome\User Data\
├── Local State              ← 共享：加密密钥、配置文件名册
├── Default\                 ← 第一个配置文件
├── Profile 1\               ← 用户后来创建的账号
├── Profile 2\
└── Guest Profile\
```

`Default` 只是**首次运行时自动创建的那一个**，与"用户实际在用的账号"没有对应关系。

用户工作账号用 `Default`、私人账号用 `Profile 1` 是常见布局。

漏掉配置文件的后果尤其隐蔽：`Local State` 里的 `profile.info_cache` 会列出每个配置文件的**显示名与最后使用时间**，一对照就能发现某个配置文件最近活跃，而它的 `History` 从没被解析过。

**影响**

- 报告写"完整历史"，实际只覆盖了部分账号——委托方据此认为"没有相关记录"时会得出完全错误的结论
- 私人配置文件中的访问记录一旦缺失，"该员工是否用私人账号访问"这个关键问题无法回答
- 提取范围不完整也影响证据完整性声明，质证时难以自证

**核查**

先读 `Local State` 拿全量配置文件清单，再逐个提取：

```bash
UD="$EVIDENCE/Edge/User Data"
# 配置文件名册：显示名、路径、最后使用时间
python3 -c "
import json
d=json.load(open('$UD/Local State',encoding='utf-8'))
for k,v in d.get('profile',{}).get('info_cache',{}).items():
    print(f\"{k}\	{v.get('name','?')}\	{v.get('last_active_time','?')}\")
"
# 输出示例：Default  工作  1.7e12   ← last_active_time 是 WebKit 微秒，需换算

# 逐个配置文件提取
for p in "$UD"/*/; do
  n=$(basename "$p")
  for f in History "Login Data" "Web Data" Network/Cookies; do
    [ -f "$p$f" ] && cp -v "$p$f" "/evidence/browser/${n}__$(basename $f)"
    for x in wal shm; do
      [ -f "$p$f-$x" ] && cp -v "$p$f-$x" "/evidence/browser/${n}__$(basename $f)-$x"
    done
  done
done
```

`info_cache` 的 `last_active_time` 是 **1601 起微秒**，换算方式与 `visits.visit_time` 一致。

配置文件的最后活跃时间晚于目标时间段的，必须优先解析。

<a id="section-18"></a>

#### 陷阱 2：只拷主库，丢掉 `-wal` 与 `-shm`

**现象**

用通配 `History` 拷出单个文件，`sqlite3` 打开正常、表结构完整、查询也能返回数据，报告写「访问历史已完整提取」。

随后与其他工件对照时，案发前几天的记录"莫名其妙缺了一段"，却找不到原因。

**原因**

SQLite 的 WAL（Write-Ahead Logging）模式下，最新的事务先写入 `History-wal`，**不立即回写主库**，只有在 checkpoint 或正常关闭时才合并。

于是出现一个很有欺骗性的现象：只拷主库时 SQLite 完全正常，条数看起来不少，但最近一段时间的访问记录整体缺失，且没有任何报错。

缺失量取决于上次 checkpoint 距今多久。

`-wal` / `-shm` 是**独立的普通文件**（不是主库的数据流），所以必须用 `fls` 分别定位 inode，不能指望随主库一起出来。

**影响**

- 「近期访问凭空消失」——最需要证明的时段恰恰是丢失的部分
- 缺失很容易被误读为"用户没有访问"，这是最严重的方向性错误
- 完整性声明不成立，报告里"完整提取"的表述无法支撑

**核查**

在镜像里用 `fls` 定位并导出三件套，用 `immutable=1` 只读打开：

```bash
fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -E 'User Data/.*/History(-wal|-shm)?$' | grep -E '^r/r' | awk '{print $2}' \
  | while read -r ino; do
      # 保留后缀便于按同名组装；-wal / -shm 是独立文件，需逐个导出
      icat -o 2048 /work/DigiForensics.dd "$ino" \
        > "/evidence/browser/$(echo "$ino" | sed 's/.*-//')"
    done

# immutable=1 让 sqlite 只读打开，不回写证据文件
sqlite3 "file:/evidence/browser/History.db?immutable=1" ".tables"
```

**注意区分两种情况**：

| 情形 | 判断 | 报告表述 |
|---|---|---|
| `-wal` 存在且 `mtime` 晚于主库 | 有未回写事务 | 「存在未 checkpoint 事务，完整边界需以 `-wal` 内容为准」 |
| `-wal` / `-shm` 不存在 | 已正常关闭或已 checkpoint | 「主库自洽，无未落盘记录」 |

`fls` 结果里没有 `-wal` 行，就是真的没有，不要伪造这两个文件，也不要因为缺失就断定"有未落盘记录"。

<a id="section-19"></a>

#### 陷阱 3：把 `Local State` 和数据库拷到分析机上再解 DPAPI

**现象**

把 `Local State`、`Login Data` 拷到自己的分析机，用常用的密码提取工具跑一遍，全部失败。

工具报「DPAPI 解密失败」，于是报告里写「凭据已加密，无法获取」。

**原因**

**DPAPI 的加密是三重绑定的**：

| 绑定对象 | 机制 | 后果 |
|---|---|---|
| **用户配置文件** | 主密钥文件在 `C:\Users\<user>\AppData\Roaming\Microsoft\Protect\<SID>\` | 换用户 = 换主密钥 |
| **机器身份** | 机器特定密钥参与派生 | 换机器 = 派生结果不同 |
| **登录凭据状态** | 密码、域凭据、策略、系统时间 | 密码变更后部分主密钥需要重新派生 |

所以在分析机上解，**必然失败**——失败原因是上下文不匹配，而不是"数据有问题"或"没有口令"。

主密钥文件按 SID 分目录存放，`CryptUnprotectData` 需要在对应 SID 的上下文中取到主密钥，再解开被 DPAPI 包装的用户密钥。

还有一个容易忽略的前置条件：用户从未交互登录过时，账户只有 STATIC 域密钥，主密钥不完整，离线还原难度显著上升。

**影响**

- 把"上下文不匹配"报成"凭据无法获取"，掩盖了**真实的取证能力边界**
- 委托方据此认为这条线索断了，可能不再追查
- 工具的失败信息容易被误读为"数据已被清除"

**核查**

两条路径：原机提取，或完整获取 SID 主密钥后离线还原：

```powershell
# 路径一：在原机器上以对应用户上下文提取
$ls = Get-Content "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State" -Raw | ConvertFrom-Json
$b  = [Convert]::FromBase64String($ls.os_crypt.encrypted_key)
$b  = $b[5..($b.Length-1)]        # 去掉 ASCII "DPAPI" 前缀
$k  = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $b, $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[Convert]::ToBase64String($k)      # 期望 32 字节 AES 密钥
```

```bash
# 路径二：离线还原需要该 SID 的完整主密钥目录
# C:\Users\<user>\AppData\Roaming\Microsoft\Protect\<SID>\
# C:\Windows\System32\Microsoft\Protect\<SID>\
```

报告的表述必须区分两层：

> `Login Data` 中 `origin_url=webmail.corp.example.com`、`username_value=j.liang@corp.example.com`、`password_value` 长度为 231 字节且前缀为 `v10`，**证明该条目确实存在**。本次因用户 DPAPI 主密钥恢复失败，未能还原明文。失败原因为上下文不匹配，不代表字段为空，也不代表凭据不存在。

<a id="section-20"></a>

#### 陷阱 4：把 AES-GCM tag 校验失败当成"格式判断错了"

**现象**

解 `v10` 密文时抛出 tag 校验失败，于是判断"这个字段不是 v10 结构"、"是旧式 DPAPI 直加密"，转而用完全不同的算法反复尝试。
**原因**

`v10` 密文的物理结构是确定的：

| 偏移 | 长度 | 内容 |
| --- | --- | --- |
| 0 | 3 | 固定前缀 `v10` |
| 3 | 12 | GCM nonce |
| 15 | 可变 | 密文 |
| 末尾 | 16 | GCM 认证 tag |

tag 校验失败是「参数错了」的信号，不是「格式判断错了」的信号。 tag 同时覆盖密钥、nonce、密文与附加认证数据，任意一项不对都会报同样的错：

- nonce 长度取错（比如把 12 字节当成 16 字节）
- 起始偏移差 1 字节（多算或少算了 `v10` 前缀）
- 密文末尾切分位置算错，tag 被多切或少切字节
- 用错密钥（`Local State` 里有多把不同用途的密钥）
- 附加认证数据构造错误

一个有用的自检：去掉前缀后的最小有意义长度是 `12 + 0 + 16 = 28` 字节，短于此的一定不是标准 `v10` 结构。

长度够但 tag 失败，就是参数问题。

**影响**

- 在错误的算法路径上反复尝试，浪费大量时间且最终仍失败
- 可能因为"试不出来"而写出"密文不可解"的错误结论，而实际只是切分偏移错了

**核查**

**先做长度与偏移自检，再逐项排查参数**：

```python
# 结构自检：先确认它确实是 v10，再谈解密
raw = bytes.fromhex(hex_blob)
assert raw[:3] == b'v10', '不是 v10 前缀'
body = raw[3:]
print('body 长度', len(body), '最小应为 28')
if len(body) < 28:
    raise ValueError('短于 v10 最小结构，不是标准 v10')
nonce, ct_and_tag = body[:12], body[12:]
ciphertext, tag = ct_and_tag[:-16], ct_and_tag[-16:]
# 分别打印各段长度，确认切分点与预期一致
print('nonce', len(nonce), 'ciphertext', len(ciphertext), 'tag', len(tag))
```

另外要注意：**较新版本会在明文前加一段随机填充**，解析结果需要按实际检材验证后再裁剪，不能默认首字节就是有效字符。

tag 通过但明文看着是乱码时，先怀疑填充，而不是怀疑加密。

<a id="section-21"></a>

### 4.2 解析与时间基准

<a id="section-22"></a>

#### 陷阱 5：把 Firefox 的时间戳按 1601 基准换算

**现象**

把 Firefox `places.sqlite` 的 `moz_historyvisits.visit_date` 和 Chromium 的 `visits.visit_time` 放进同一张表排序，发现 Firefox 那部分记录全部落在 1601 年 1 月，Chromium 那部分落在未来几万年。

于是得出「Firefox 记录时间异常，不可用」的结论，把 Firefox 侧证据整体丢弃。

**原因**

**两族浏览器的纪元起点完全不同**：

| 来源 | 字段 | 单位 | 纪元起点 | 换算 |
| --- | --- | --- | --- | --- |
| Chromium 系 | `visits.visit_time` | **微秒** | **1601-01-01** | `/1000000 - 11644473600` |
| Firefox | `moz_historyvisits.visit_date` | **微秒** | **1970-01-01** | `/1000000` |
| Firefox | `moz_places.last_visit_date` | **微秒** | **1970-01-01** | `/1000000` |
| Firefox | `moz_cookies.lastAccessed` | **微秒** | **1970-01-01** | `/1000000` |
| Chromium 系 | `downloads.start_time` | **微秒** | **1601-01-01** | `/1000000 - 11644473600` |

两者的单位相同（都是微秒），但纪元差 11644473600 秒（约 369 年）。

混用基准时，Firefox 记录会落到 1601 年，Chromium 记录会落到 5 万多年后。

**影响**

- 一整族浏览器的证据被当成"时间异常"丢弃，而它可能正是独立交叉验证的关键
- 更隐蔽的情形是：某个值被"修正"过了头（比如对 Firefox 值也减了 11644473600），结果落在合理年份附近但整体偏移，时间线悄悄错位
- 涉及"非工作时间访问"这类需要时区与时段判断的结论，一旦基准错误会同时错两个维度

**核查**

**换算写进查询，并且逐源自查落在合理区间**：

```sql
-- Chromium：1601 纪元
SELECT datetime((v.visit_time/1000000) - 11644473600, 'unixepoch') AS visit_utc,
       u.url, printf('0x%08X', v.transition & 255) AS transition
FROM visits v JOIN urls u ON u.id = v.url
ORDER BY v.visit_time;

-- Firefox：Unix 纪元，不要减 11644473600
SELECT datetime(visit_date/1000000,'unixepoch') AS visit_utc, url
FROM moz_historyvisits
JOIN moz_places ON moz_places.id = moz_historyvisits.place_id
ORDER BY visit_date;
```

合并前的强制自检：

```sql
SELECT datetime(max(visit_time)/1000000 - 11644473600,'unixepoch') FROM visits;   -- 应在 2015 年之后
SELECT datetime(max(visit_date)/1000000,'unixepoch') FROM moz_historyvisits;       -- 应在 2015 年之后
```

任一结果落在 1601 年或 5 万年之后，说明基准用错了，**此时不要解读任何一行**。

<a id="section-23"></a>

#### 陷阱 6：把工具默认输出的时间列直接当成已换算

**现象**

用一个现成的浏览器取证工具导出全部记录，工具输出里有一列叫 `time`，看着正常就直接写进报告。

稍后有人手工复算部分记录，发现有一批时间差了 369 年。

**原因**

很多工具把**不同表、不同纪元的时间混在同一列输出**：

- `urls.last_visit_time`（1601 微秒）—— URL 维度的最后访问
- `visits.visit_time`（1601 微秒）—— 每次访问
- `downloads.start_time`（1601 微秒）
- Firefox 的 `visit_date`（Unix 微秒）
- `logins.date_created`（1601 微秒）
- `cookies.lastAccessed`（Firefox 侧 Unix 微秒 / Chromium 侧 1601 微秒）

只要工具把两个族的值塞进同一列，**混排的那部分就是错的**，而且格式上看不出来 —— 都是漂亮的日期字符串，只有量级暴露问题。

**影响**

- 时间线整体错位，尤其是"非工作时间""凌晨"这类时段判断全部失效
- 一旦这类时间点进入报告结论，质证时很难解释
- 复核人可能用另一个工具复算出不同结果，损害报告可信度

**核查**

**逐列核对单位与纪元，不信任工具的时间列命名**：

```bash
# 工具输出后，先看数值量级：10 位=秒，13 位=毫秒，16 位=微秒
# 16 位且大于 1e16 的，多半是 1601 纪元；1e15~1e16 的是 Unix 纪元微秒
head -20 /evidence/browser-export.csv
```

正确做法是**只用原始数据库、自己在 SQL 里换算**，或至少对工具输出的每个时间列逐一验证量级与首末值范围：
```sql
-- 对每张表先看 max，再看 min，确认量级
SELECT 'visits' AS src, min(visit_time), max(visit_time) FROM visits
UNION ALL SELECT 'downloads', min(start_time), max(start_time) FROM downloads
UNION ALL SELECT 'logins',   min(date_created), max(date_created) FROM logins;
```

<a id="section-24"></a>

#### 陷阱 7：只检查 Chromium 系，把 Firefox、IE/Edge Legacy 当成"无数据"

**现象**

在 `User Data` 下做完分析，报告写下「该工作站浏览器痕迹已完整排查，未发现相关站点访问记录」，完全没查 Firefox 的 `places.sqlite` 和 IE 的 `index.dat`。
**原因**

同一台机器上并存多套独立浏览数据，**存储位置、格式、可读性完全不同**：

| 浏览器 | 数据位置 | 关键文件 | 可读性 |
| --- | --- | --- | --- |
| Chromium 系（Chrome/Edge/Brave/Opera） | `%LOCALAPPDATA%\<Vendor>\User Data` | `History`、`Login Data`、`Web Data`、`Network\Cookies` | 明文 SQLite，**只需时间基准换算** |
| Firefox | `%APPDATA%\Mozilla\Firefox\Profiles\*.default-release` | `places.sqlite`、`cookies.sqlite`、`formhistory.sqlite`、`logins.json`、`key4.db` | SQLite 明文；Cookie 的 `value` **通常明文** |
| IE（Win7+） | `%LOCALAPPDATA%\Microsoft\Windows\History` | `index.dat` | 复合文档结构，需专用解析器 |
| IE10 / Edge Legacy | `%LOCALAPPDATA%\Microsoft\Windows\WebCache` | `WebCacheV01.dat` | 自定义二进制结构，需专用解析器 |

Chromium 系分析便利会形成"做熟了这一套就以为做完了"的错觉。

Firefox 的 Cookie 值通常是明文，这往往是比 Chromium 更有价值的证据 —— 会话令牌不需要解密就能看到。

**影响**

- 漏掉独立证据源，无法做"同一行为在两套浏览器中的交叉印证"，单源证据证明力弱得多
- Firefox 的 `formhistory.sqlite` 记录**表单输入历史**，常含搜索词与填写过的文本，是 Chromium 系完全没有的信息
- 「未发现相关访问」变成一个不可靠的结论

**核查**

**逐族、逐路径确认，把每一项的结论状态写清**：

```bash
EV="D:/Users/jliang"
# Chromium 系
ls -d "$EV/AppData/Local/Google/Chrome/User Data" \
      "$EV/AppData/Local/Microsoft/Edge/User Data" \
      "$EV/AppData/Local/BraveSoftware/Brave-Browser/User Data" \
      "$EV/AppData/Opera Software/Opera Stable" 2>/dev/null
# Firefox：先读 profiles.ini 拿真实配置名
cat "$EV/AppData/Roaming/Mozilla/Firefox/profiles.ini"
# IE / Edge Legacy
ls -la "$EV/AppData/Local/Microsoft/Windows/History" 2>/dev/null
ls -la "$EV/AppData/Local/Microsoft/Windows/WebCache" 2>/dev/null
```

Firefox 侧的 `formhistory.sqlite` 不要漏 —— 它是 Chromium 系没有的独立信息：
```sql
SELECT fieldname, value FROM moz_formhistory ORDER BY timesused DESC;
```

<a id="section-25"></a>

### 4.3 凭据可解性与结论表述

<a id="section-26"></a>

#### 陷阱 8：把 `password_value` 为空或解不开写成"没有密码"

**现象**

`Login Data` 里 `webmail.corp.example.com` 条目 `username_value` 有值，但 `password_value` 取出来是空的或解不开，报告写「该站点无保存密码」。

**原因**

必须先看**长度**再下结论。

`password_value` 字段的内容分三类：

| 情况 | 判别 | 含义 |
| --- | --- | --- |
| `length = 0` 且 `blacklisted_by_user = 0` | 真的空字段 | 可能是用户保存后清空，或程序化写入 |
| `length > 0`，`prefix = 763130`（`763130` hex = `v10`） | 存在 `v10` 密文 | **条目存在，密钥恢复失败** |
| `length > 0`，`prefix = 763230`（`v20`） | 存在 `v20` 密文 | 条目存在，App-Bound 路径校验未通过 |
| `length > 0`，`prefix` 为空 | 旧式 DPAPI 直加密（Chrome 80 前） | 条目存在，需对应用户上下文 |

**`length > 0` 就证明条目存在**，这与能否还原明文是两个独立层次的问题。

`v20` 尤其容易造成误判：它用 `os_crypt.app_bound_encrypted_key`，Base64 解码后前缀是 ASCII `APPB`，内部是**两层 DPAPI 包装**（外层 SYSTEM 或服务自身上下文，内层用户上下文），并且服务会校验调用进程的可执行文件路径是否与加密时规范化的安装路径一致。

这意味着离线解密**不具备通用性**，成功率取决于浏览器版本、安装路径、系统状态与工具实现。

**影响**

- 「无保存密码」是**事实性错误**，一旦后续通过原机环境取到，报告可信度受损
- 把"解不开"归为"没有"，掩盖了真实的取证能力边界
- 委托方可能据此判断用户"没有泄露凭据"，方向完全错

**核查**

**先用长度和前缀做分类，再谈可解性**：

```sql
SELECT origin_url, username_value,
       length(password_value)  AS pw_len,
       hex(substr(password_value,1,3)) AS prefix,
       blacklisted_by_user,
       date_created
FROM logins ORDER BY date_created;
```

报告按前缀分别表述：

> `webmail.corp.example.com`：`password_value` 长度 231 字节，前缀 `v10`，**存在加密凭据条目**。在原机 `jliang` 用户上下文中恢复出 32 字节主密钥，成功还原。
>
> `file.example-cloud.net`：`password_value` 非空，前缀 `v20`。**存在加密凭据条目。** App-Bound Encryption 的路径校验在本次离线环境中未通过，**未能还原明文。**

**对 v20 不向委托人承诺「一定解得开」。** 尝试失败时如实写明失败原因与已尝试的方法。

<a id="section-27"></a>

#### 陷阱 9：把 `visits` 记录等同于"用户主动访问"

**现象**

查到 `visits` 表有指向某站点的记录，就在报告里写「用户于 X 日访问了该站点」。

`transition` 字段明明是 `LINK`（链接跳转）或 `RELOAD`（刷新），却没有体现。

**原因**

`visits.transition` 的低位（`transition & 0xFF`）标注访问方式，这是判断意图的关键：

| transition | 含义 | 取证意义 |
| --- | --- | --- |
| `0x01000000` | TYPED | **手工键入 URL 或地址栏搜索，意图明确** |
| `0x30000000` | LINK | 从页面内链接触发，**不代表用户想看这个站点** |
| `0x00020000` | KEYWORD | 通过搜索关键词到达 |
| `0x00080000` | FORM_SUBMIT | 表单提交跳转 |
| `0x02000000` | RELOAD | 刷新当前页 |
| `0x10000000` | FORWARD_BACK | 前进/后退 |
| `0x40000001` | CHAIN_END | 一次跳转链的结束点 |

更重要的是 `urls` 与 `visits` 是 1:N 关系：`urls` 表保存 URL 字符串与**累计统计**（`visit_count`、`last_visit_time`），`visits` 表**每次打开写一行**。

很多分析只查 `urls` 表，看到 `visit_count = 3` 就写"访问了 3 次"—— 这是累计计数，不等于时间线上有 3 条独立记录。

同时 `visits` 里的记录可能来自**页面自动加载资源**（如 `<img>` 引用的第三方统计像素），这时甚至没有对应的用户可见导航。

**影响**

- 把"页面内被动加载"写成"主动访问"，意图判断错误
- 用 `urls.visit_count` 冒充时间线条数，记录数与实际不符
- `LINK` 型与 `TYPED` 型访问在案件中的意义差别极大，混同会影响行为链的可信度

**核查**

始终从 `visits` 表取时间线，并把 `transition` 一起输出：

```sql
SELECT
  datetime((v.visit_time/1000000) - 11644473600, 'unixepoch') AS visit_utc,
  u.url, u.title, v.visit_duration,
  printf('0x%08X', v.transition & 255) AS transition
FROM visits v JOIN urls u ON u.id = v.url
ORDER BY v.visit_time;
```

结论表述按意图分档：

> 目标时段内存在 1 条指向 `drive.example-cloud.net` 的访问记录，`transition` 为 `0x30000000`（LINK），即**由页面内链接触发**，非用户手工输入。同一 URL 在 `urls` 表中 `visit_count` 累计为 3，**其中 2 次发生在其他时段**。

<a id="section-28"></a>

#### 陷阱 10：把"数据库里没有"写成"用户没有做过"

**现象**

在 `History` 中检索不到目标站点，报告写下「该员工未访问过该站点」「未通过浏览器访问外部服务」，并把它作为否定性结论的重点。

**原因**

"数据库里没有"至少有七种成因，每种对应完全不同的结论强度：
| 成因 | 正确表述 |
| --- | --- |
| 只看了 `Default` 一个配置文件 | 「该配置文件内未发现，其他配置文件未检查」 |
| 丢了 `-wal` / `-shm` | 「主库内未发现，最近事务未验证」 |
| 只查了 Chromium 系 | 「Chromium 系未发现，Firefox 与 IE 系未检查」 |
| 记录被定向裁剪 | 「未见该记录，**存在清理可能**」 |
| 隐私模式/无痕窗口 | 「无痕会话不落盘，此类访问本就不会留痕」 |
| 记录在另一台设备上 | 「本机未发现，不排除其他终端」 |
| 时间基准或表关联用错导致查询漏行 | 「查询条件已复核，但需人工确认覆盖度」 |
| **确实不存在** | 「在 X 范围内确认无 Y 行为」 |

还有一个很有价值的反常信号需要单独查：如果 SQLite 库里存在 `cookies` 表记录但 `visits` / `moz_historyvisits` 缺失（对应用户侧为 `moz_historyvisits`），这通常意味着**会话被注入或数据被定向裁剪**，而不是"用户没访问过"。
**影响**

- 「未访问过」是**最强的一种结论**，一旦被推翻，整份报告的严谨性受质疑
- 委托方可能据此做出错误的人事或法律决策
- 忽略"cookies 有而 visits 无"这个信号，会错过定向清理这一重要发现

**核查**

**阴性结论必须带范围、条件、覆盖度三重限定**：

```text
未发现项清单（DWS-0427，卷偏移 2048）

| 项 | 结论 | 范围 | 限制 |
|---|---|---|---|
| 目标站点访问 | 未发现 | Edge/Chrome/Brave/Opera 的 Default 配置文件 History 表 | 未检查 Profile 1/2/3；Firefox 与 IE 系未检查 |
| 表单填写内容 | 未发现 | Default\Web Data 的 autofill 表 | Firefox formhistory.sqlite 未检查 |
| 会话 Cookie | 已确认存在 | Network\Cookies | — |
```

**表间反常必须单独核查**：

```sql
-- cookies 有记录但 visits 为空 → 提示定向裁剪或会话注入
SELECT (SELECT count(*) FROM visits)      AS visits_rows,
       (SELECT count(*) FROM urls)        AS urls_rows,
       (SELECT count(*) FROM cookies)     AS cookies_rows;
```

最后统一一句原则：用「未发现 / 未能验证 / 已确认无」三档替代笼统的「没有」。

<a id="section-29"></a>

## 五、案例示例

<a id="section-30"></a>

### 5.1 双浏览器与下载链还原出一条外泄准备行为链

**场景**

某公司财务部员工工作站 `DWS-0427` 发生数据外泄，调查方向为「是否通过个人云盘将客户清单上传至外部服务」。

检材为该工作站磁盘镜像，卷偏移经 `mmls` 确认为 2048，目标用户目录为 `D:\Users\jliang`。

**处置过程**

第一步，锁定并提取两套浏览器的工件，SQLite 主库与 `-wal`/`-shm` 一并提取：

```bash
# Chromium 侧
mkdir -p /evidence/edge
cp -r "/mnt/dws0427/Users/jliang/AppData/Local/Microsoft/Edge/User Data/Local State" \
      "/evidence/edge/"
cp "/mnt/dws0427/Users/jliang/AppData/Local/Microsoft/Edge/User Data/Default/History" \
   "/evidence/edge/History"
cp "/mnt/dws0427/Users/jliang/AppData/Local/Microsoft/Edge/User Data/Default/History-wal" \
   "/evidence/edge/" 2>/dev/null
cp "/mnt/dws0427/Users/jliang/AppData/Local/Microsoft/Edge/User Data/Default/Web Data" \
   "/evidence/edge/"
cp "/mnt/dws0427/Users/jliang/AppData/Local/Microsoft/Edge/User Data/Default/Network/Cookies" \
   "/evidence/edge/"

# Gecko 侧
mkdir -p /evidence/ff
cp "/mnt/dws0427/Users/jliang/AppData/Roaming/Mozilla/Firefox/Profiles/y7x2p.default-release/places.sqlite" \
   "/evidence/ff/"
cp "/mnt/dws0427/Users/jliang/AppData/Roaming/Mozilla/Firefox/Profiles/y7x2p.default-release/cookies.sqlite" \
   "/evidence/ff/"
cp "/mnt/dws0427/Users/jliang/AppData/Roaming/Mozilla/Firefox/Profiles/y7x2p.default-release/logins.json" \
   "/evidence/ff/"
```

第二步，以 `immutable=1` 只读方式查询 Edge 访问记录（`immutable=1` 保证不生成 WAL、不改原始库）：

```bash
sqlite3 "file:/evidence/edge/History?immutable=1" \
 "SELECT datetime((visits.visit_time/1000000)-11644473600,'unixepoch','localtime') AS t,
         urls.url, visits.transition
  FROM visits JOIN urls ON visits.url = urls.id
  WHERE urls.url LIKE '%example-cloud.net%'
  ORDER BY visits.visit_time;"
```

```text
2024-03-15 23:47:12  https://drive.example-cloud.net/            1
2024-03-16 00:12:03  https://drive.example-cloud.net/upload       1
2024-03-16 00:31:55  https://drive.example-cloud.net/folder/9f2a  1
```

第三步，读取 `transition` 位定义并核对 `urls` 表的累计字段：

```bash
sqlite3 "file:/evidence/edge/History?immutable=1" \
 "SELECT url, visit_count, typed_count, last_visit_time FROM urls
  WHERE url LIKE '%example-cloud.net%';"
```

```text
https://drive.example-cloud.net/   visit_count=3  typed_count=0
```

第四步，关联 `downloads` 与 `downloads_url_chains` 表还原下载链：

```bash
sqlite3 "file:/evidence/edge/History?immutable=1" \
 "SELECT datetime((start_time/1000000)-11644473600,'unixepoch','localtime'),
         tab_url, target_path, total_bytes
  FROM downloads;"
```

```text
2024-03-16 00:05:41  https://portal.corp.example.com/reports/list
                     C:\Users\jliang\Downloads\客户清单_20240315.xlsx   184320
```

```bash
sqlite3 "file:/evidence/edge/History?immutable=1" \
 "SELECT d.target_path, c.url, c.chain_index
  FROM downloads d JOIN downloads_url_chains c ON d.id = c.id ORDER BY c.chain_index;"
```

```text
客户清单_20240315.xlsx  https://portal.corp.example.com/reports/download?id=8821   0
客户清单_20240315.xlsx  https://share.example-cloud.net/d/9f2a?token=…             1
```

第五步，检查 `Web Data` 的 `autofill` 表中的人工录入项：

```bash
sqlite3 "file:/evidence/edge/Web Data?immutable=1" \
 "SELECT name, value, date_created FROM autofill;"
```

```text
CloudDrive_Account   liwei@163.com
ShareLink           https://share.example-cloud.net/d/9f2a
```

第六步，系统侧交叉印证会话归属与文件再次写入：

```bash
python3 - <<'PY'
# Security 日志 4624：LogonType 3 = 网络登录，2 = 交互式
print("4624 j.liang@corp.example.com LogonType=3 → 事发时段存在会话")
# $UsnJrnl：解析 Client 日志
#   FILE_NAME=客户清单_20240315.xlsx  Reason=0x00000102  Timestamp=2024-03-16 00:38:12
print("UsnJrnl: 目标文件在下载后 00:38:12 被再次写入，落在非工作时间")
PY
```

**结论**

Edge 侧存在一条可完整解释的行为链。

2024-03-15 23:47:12 起三次访问云盘域名且 `transition=1`（LINK，页面内链接触发而非地址栏手工输入）、`typed_count=0`（从未手工输入过该地址）。

下载表显示 2024-03-16 00:05:41 从公司门户 `portal.corp.example.com` 下载 `客户清单_20240315.xlsx`（184320 字节）到本地。

`downloads_url_chains` 显示其重定向链第 0 跳为公司门户、第 1 跳为云盘直链接口 `share.example-cloud.net/d/9f2a?token=…`。

`autofill` 表中存在人工录入的 `CloudDrive_Account` 与 `ShareLink` 两项，正常工作中从不需要手工填写，指向人为构造上传流程。

`$UsnJrnl` 显示该文件在下载后 32 分钟被再次写入且落在非工作时间。

Firefox 侧同期存在对同一域名的访问与 `share_token` 会话 Cookie，系统日志 `4624`（LogonType 3）排除了他人冒用账户的可能。

结论表述为「存在将客户清单从公司门户导出、准备上传至外部云服务的完整行为链」。

**上传完成状态未确证**，因 Edge 侧仅有访问与下载记录，直接证明上传动作需网关或云服务侧日志补齐。

**误判对照**

最典型的错误结论是把 `transition=1` 当成「手工输入地址访问」，从而推断用户主动搜索过云盘服务。

正确判据是：`visits.transition` 是位域，`0x00000001` 为 LINK（页面内跳转）、`0x00000002` 为 TYPED（地址栏输入并提交）、`0x00000004` 为 AUTO_BOOKMARK、`0x00000008` 为 AUTO_SUBFRAME 等；本案 `transition=1` 且 `urls.typed_count=0` 两个字段共同证明**从未手工输入**该地址，访问完全由页面内链接驱动。

按错误判据写「用户主动搜索并访问云盘」，会把一次被动跳转升级为主动意图，量刑差别极大；`typed_count=0` 这个直接反证一旦被辩护方引用，整条行为链的解读都会被推翻。

第二处易错点是把 `downloads_url_chains` 的 `chain_index=0` 当作下载来源 URL。正确判据是重定向链中 `chain_index=0` 是**最初发起**的 URL、`chain_index` 越大越靠近最终落地地址；本案 `chain_index=0` 是 `portal.corp.example.com`，说明下载动作从公司门户发起，之后才被 302 跳转到云盘直链。

按错误判据写成「从云盘下载客户清单」，会把从内部系统导出数据这一关键性质完全颠倒——本案真正的可疑点是数据流向外部，而这需要看链尾（`chain_index=1`）是否落在外部域名。

第三处易错点是拿 `downloads.total_bytes` 直接写成外泄数据量。正确判据是该字段是本次下载写入本地的字节数（184320），与外发量是两个不同的量；且下载文件与云盘上的分享对象是否同一份内容，需要 `total_bytes` 与上传侧记录比对才能确认。

按错误判据把 184320 写成「外发 184 KB 客户清单」，在数据已被压缩或分批上传的场景里会严重偏离实际；在数据被另存为其它格式的场景里则完全错误。

<a id="section-31"></a>

### 5.2 v10 与 v20 凭据前缀的差异化处置与如实记录

**场景**

`Login Data` 中出现两类密码条目：`webmail.corp.example.com` 与 `file.example-cloud.net`。

委托方要求给出登录凭据的使用情况，需要判断哪些能还原、哪些不能，以及不能还原时报告该怎么写。

**处置过程**

第一步，只读提取 `password_value` 的前缀与长度，不做任何解密尝试：

```bash
sqlite3 "file:/evidence/edge/Login Data?immutable=1" \
 "SELECT origin_url, username_value, length(password_value),
         hex(substr(password_value,1,3)), datetime((date_created/1000000)-11644473600,'unixepoch','localtime')
  FROM logins;"
```

```text
https://webmail.corp.example.com/   j.liang@corp.example.com   231   763130   2023-11-02 09:14:22
https://file.example-cloud.net/     j.liang@corp.example.com   299   763230   2024-02-28 20:41:07
```

第二步，把前缀翻译为算法标识：

```bash
python3 - <<'PY'
for name, hx in (("webmail.corp.example.com", "763130"), ("file.example-cloud.net", "763230")):
    v10 = bytes.fromhex(hx)[:3] == b"v10"
    v20 = bytes.fromhex(hx)[:3] == b"v20"
    print(f"{name:32s} {'v10 = DPAPI + AES-GCM' if v10 else 'v20 = App-Bound Encryption'}")
PY
```

第三步，在原机器上以 `jliang` 用户上下文取 `os_crypt.encrypted_key` 并解出主密钥：

```bash
# ★ 必须在目标机器上、以目标用户上下文执行；离线不行
# 导出 DPAPI 主密钥（Base64）
certutil -user -encode "%LOCALAPPDATA%\Microsoft\Edge\User Data\Local State" "%TEMP%\ls.txt"
python3 -c "import re;print(re.search(r'\"encrypted_key\":\"(.*?)\"',open(r'%TEMP%\ls.txt').read()).group(1))" > /tmp/key.b64
```

```bash
# 已知主密钥后离线解 v10 条目
python3 - <<'PY'
import base64, json, struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = base64.b64decode(open("/tmp/master.bin","rb").read().strip().split(b"DPAPI")[0])
blob = base64.b64decode("763130" + "<ciphertext-base64>")
nonce, ct = blob[3:15], blob[15:]
print(AESGCM(key).decrypt(nonce, ct, None).decode("utf-16-le"))
PY
```

第四步，对 v20 条目按其校验路径要求准备条件后重试：

```bash
# v20（App-Bound Encryption）需要满足：
#   1) 同版本 Edge 的注入进程
#   2) 目标机器的 IElevation 提升令牌
#   3) 校验目标应用的签名与安装路径
# ★ 单纯复制 Local State 的 encrypted_key 无法通过路径校验
echo "v20 路径校验未通过 → 记录为未能还原"
```

第五步，把两条结论分别入表：

```bash
python3 - <<'PY'
rows = [
    ("webmail.corp.example.com", "v10", "已还原", "DPAPI 主密钥于原机 jliang 上下文取得，路径校验通过"),
    ("file.example-cloud.net",   "v20", "未能还原", "App-Bound Encryption 路径校验未通过，保留密文"),
]
for r in rows:
    print(" | ".join(r))
PY
```

**结论**

`webmail.corp.example.com` 条目 `password_value` 长度 231、前缀 `763130`（即 `v10`，DPAPI + AES-GCM），`username_value` 为 `j.liang@corp.example.com`。

在原机器上以 `jliang` 用户上下文取得 `os_crypt.encrypted_key` 对应的 32 字节主密钥后成功还原明文，且取证动作完成后当场清除临时文件与导出痕迹。

`file.example-cloud.net` 条目前缀 `763230`（`v20`，App-Bound Encryption），其校验绑定目标应用的签名与安装路径，单纯持有 `Local State` 中的密钥无法通过，尝试离线还原失败，报告中如实记录为「存在密文，App-Bound Encryption 路径校验未通过，未能还原」，**不写成「无密码」**。

报告中不出现任何密码明文，仅记录条目存在性、账号、时间与算法标识。

**误判对照**

最容易出现的错误结论是「`v20` 条目解密失败 = 该站点没有保存密码」。

正确判据是：`password_value` 长度为 299 且前缀为 `v20`，这本身就是一条**已保存凭据**的记录，密文存在即证明用户在 2024-02-28 20:41:07 在该站点输入并提交过密码；解密失败只反映取证手段受限，不反映凭据不存在。

按错误判据写「无密码」，会直接抹掉本案最有价值的一条线索——该用户在事发前两个月刚用过外部云盘站点的凭据，而这恰恰与 5.1 的外泄行为链直接相关。

第二处易错点是把 `v10` 与 `v20` 混用同一套还原流程，得出「都能解开」或「都解不开」的笼统结论。

正确判据是：`v10` 的加密密钥由 DPAPI 派生，`Local State` 中的 `encrypted_key` 加上用户凭据即可解密；`v20`（App-Bound Encryption）在 2023 年后引入，除密钥外还校验调用进程的签名、路径与提升令牌，离线几乎不可解。

两种算法在同一 `Login Data` 里并存是常态，把结论写成「Edge 密码可解密」会让委托方以为拿到全部凭据，后续发现缺失时反而质疑报告的严谨性。

第三处易错点是在非目标机器或非目标用户上下文下尝试解 `v10`。

正确判据是：DPAPI 主密钥由用户登录凭据派生，`SYSTEM` 账户、另一用户、甚至同一用户的另一台机器都可能得到不同主密钥，解出的结果必须是不可读的乱码而非报错，极易被误判为「密文损坏」。

本案选择在原机 `jliang` 上下文执行正是为了避免这一点；报告中若写「DPAPI 解密失败」，复核人只要在正确上下文重试成功，整份报告的可信度都会受损。

<a id="section-32"></a>

### 5.3 Gecko 纪元换算错误导致整条证据被错误排除

**场景**

Firefox 侧检出对同一云盘域名的访问记录与 `share_token` 会话 Cookie。

首次分析时该记录被认为「时间不合理、应予排除」，但委托方对排除结论提出质疑，要求复核。

**处置过程**

第一步，读取 `places.sqlite` 的访问表，原始值不做换算先看清量级：

```bash
sqlite3 "file:/evidence/ff/places.sqlite?immutable=1" \
 "SELECT moz_historyvisits.visit_date, moz_places.url
  FROM moz_historyvisits JOIN moz_places ON moz_historyvisits.place_id = moz_places.id
  WHERE moz_places.url LIKE '%example-cloud.net%' ORDER BY 1 LIMIT 8;"
```

```text
13088404428000000   https://drive.example-cloud.net/
13088407012000000   https://drive.example-cloud.net/upload
```

第二步，识别纪元基准——Gecko 使用 **Unix 纪元微秒**（值约 1.3e16），而不是 Chromium 的 WebKit/Windows 纪元（值约 1.3e17）：
```bash
python3 - <<'PY'
import datetime
WEBKIT_EPOCH_DELTA = 11644473600     # 1601-01-01 → 1970-01-01，单位秒
for raw in (13088404428000000, 13088407012000000):
    # 正确：Unix 微秒
    t_ok = datetime.datetime.utcfromtimestamp(raw / 1e6)
    # 错误：套用 Windows/WebKit 纪元再除以 1e7
    t_bad = datetime.datetime.utcfromtimestamp(raw / 1e7 - WEBKIT_EPOCH_DELTA)
    print(f"raw={raw}  正确(Unix µs)={t_ok}   错误(WebKit)={t_bad}")
PY
```

```text
raw=13088404428000000  正确(Unix µs)=2024-03-16 00:34:02   错误(WebKit)=1601-04-25 …
raw=13088407012000000  正确(Unix µs)=2024-03-16 00:50:01   错误(WebKit)=1601-04-25 …
```

第三步，取会话 Cookie 印证：

```bash
sqlite3 "file:/evidence/ff/cookies.sqlite?immutable=1" \
 "SELECT host, name, datetime((lastAccessed/1000000)-11644473600,'unixepoch','localtime')
  FROM moz_cookies WHERE host LIKE '%example-cloud.net%';"
```

```text
.example-cloud.net  share_token  2024-03-16 00:50:03
```

第四步，与 Edge 侧时间线合并比对：

```bash
python3 - <<'PY'
edge = [("2024-03-16 00:05:41", "下载客户清单"),
        ("2024-03-16 00:12:03", "访问云盘 upload 页"),
        ("2024-03-16 00:38:12", "UsnJrnl: 文件被再次写入")]
ff   = [("2024-03-16 00:34:02", "Firefox 访问云盘首页"),
        ("2024-03-16 00:50:01", "Firefox 访问 upload 页"),
        ("2024-03-16 00:50:03", "share_token Cookie 末次访问")]
for t, d in sorted(edge + ff):
    print(t, "|", d)
PY
```

**结论**

`moz_historyvisits.visit_date` 为 13088404428000000，量级为 1.3e16，确定 Gecko 使用 Unix 纪元微秒；除以 1e6 得 2024-03-16 00:34:02，与 Edge 侧下载（00:05:41）和再次写入（00:38:12）处于同一夜间时段。

`moz_cookies` 中 `host = .example-cloud.net` 的 `share_token` 会话 Cookie `lastAccessed` 为 2024-03-16 00:50:03，与 Firefox 对 `upload` 页的访问 00:50:01 相隔 2 秒。

两套浏览器在完全独立的数据结构与存储路径下记录了同一夜间时段对同一云盘服务的使用，可认定该用户在两套浏览器中均实际使用了该云盘服务。

此前「时间不合理应予排除」的结论系纪元换算错误所致，已在报告中更正并保留更正记录。

**误判对照**

本案例的核心误判是把 Gecko 的 Unix 纪元微秒套用 Chromium 的 WebKit 纪元公式（`raw/1e7 - 11644473600`），得到 1601 年 4 月的荒谬时间，进而认为「Firefox 记录不可信」而整条排除。

正确判据是换算前先看数值量级：1.3e16 对应 Unix 微秒，1.3e17 对应 WebKit/Windows 纪元微秒，两者在数量级上就差 10 倍；更稳妥的验证是双向验算——换算结果必须落在镜像时间范围内且与其它工件同处合理时段。

按错误判据处置的代价是全案丢失「两套浏览器均使用该云盘服务」这一强证据，报告从「多浏览器印证」降级为「仅 Edge 单侧」，辩护方只需指出 Firefox 数据被无理由排除，即可质疑分析完整性。

第二处易错点是发现时间落在 1601 年后，反过来把 Firefox 记录「修正」成 Edge 侧的时间（如按行序对齐到 00:05:41），以使两条时间线看起来连续。

正确判据是：两个系统的时钟与时间戳来源完全独立，没有任何依据可以相互赋值；Gecko 侧换算出的 00:34:02 与 00:50:01 是各自独立的观测值，它们与 Edge 时间线「同一时段」的证据是时段重合，而不是时刻相同。

按错误判据强行对齐，会凭空造出 Firefox 侧不存在的行为时刻，一旦对方提供 Firefox 自身的同步日志即可发现矛盾。

第三处易错点是 `lastAccessed` 字段名与 Chromium 侧 Cookies 的 `last_access_utc` 语义搞混——两者都是「最后访问」但更新时机不同：Gecko 的 `lastAccessed` 随每次 Cookie 回传更新，即便页面内容未变也会刷新。

按错误判据把 `share_token` 的 `lastAccessed = 00:50:03` 解释为「用户在 00:50:03 进行了上传操作」，就把一个会话维持时间点当成传输时间点；本案正确的读法是它只能证明「00:50:03 时该会话 Cookie 仍在被使用」，与 00:50:01 的 `upload` 页访问互相印证会话活跃，不能单独支撑传输动作。

---
<a id="section-33"></a>

## 六、扩展阅读方向

<a id="section-34"></a>

### 前置基础：解密与定位的前提

- [只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md) —— 浏览器数据库被打开时会写临时文件与锁文件，直接挂载分析等于修改证据。
- [Windows 取证工件地图](../computer-registry-log/computer-registry-log-windows-artifact-map.md) —— 用户数据目录的定位与卷准备。用户身份的确认在这一篇，它决定了取哪个 Profile 与哪个主密钥。
- [注册表取证](../computer-registry-log/computer-registry-log-registry-forensics.md) —— DPAPI 主密钥的 SID 归属与 hive 提取方法，凭据可解性判断的前提。

<a id="section-35"></a>

### 同层深入：凭据加密的其它层

- [浏览器密码库与 Token 解密](../../crypto/crypto-app/crypto-app-browser-passwords-and-tokens.md) —— 凭据解密的完整方法论。本篇只判定「能不能解」，那一篇讲「怎么解」以及各浏览器的差异。
- [数据库与配置文件加密](../../crypto/crypto-app/crypto-app-database-configuration-decryption.md) —— 应用层数据库加密的一般形态，SQLite 加密的实现差异。
- [Keychain 与 Safari 痕迹](../computer-security/computer-security-keychain-safari.md) —— macOS 侧的凭据模型。Keychain 是系统中枢、DPAPI 绑用户、浏览器自管，三种模型对照看能看清设计取舍。

<a id="section-36"></a>

### 相邻议题：系统级与用户级的其它痕迹

- [SRUM 数据库分析](computer-browser-behavior-srum.md) —— 系统级的资源使用统计，能给出「哪个应用在前台用过多久」，与浏览器的访问记录互为印证。
- [Windows 11 与 Recall](computer-browser-behavior-windows11-recall.md) —— 系统级屏幕快照。Recall 记录「屏幕上出现过什么」，比浏览历史更宽，两者的证据性质与敏感性都不同。
- [用户行为痕迹](../computer-registry-log/computer-registry-log-user-activity-artifacts.md) —— UserAssist 与 TypedPaths。「打开过某个程序」与「访问过某个 URL」是同一类问题的两种答案。
- [内存中的凭据与密钥](../../memory/memory-artifact/memory-artifact-memory-credentials-and-keys.md) —— 磁盘上的密文解不开时，内存里可能有明文，**但只做离线分析与最小化提取**。

<a id="section-37"></a>

### 工具与规范：操作边界与报告纪律

- [证据文件格式](../../fundamentals/fundamentals-chain/fundamentals-chain-dd-e01-aff4-evidence-formats.md) —— 浏览器 Profile 的归档容器选择。Profile 目录必须整体固定，单独拷一个数据库文件会丢失与之关联的密钥载体。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md) —— 浏览记录属高敏感个人数据，**摘录必须与授权范围一致并做脱敏。**
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 阴性结论的表述纪律，「未取得可解密钥」与「无凭据」必须写成两句不同的结论。

<a id="section-38"></a>

### 判据与反例：哪些解释不能成立

- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— 浏览历史被清理后，SQLite 里残留的空闲页与 WAL 文件都可能留有可恢复记录，该篇给的是这类痕迹的识别判据。
- [SQLite-WAL 取证](../../mobile/mobile-database/mobile-database-sqlite-wal.md) —— **WAL 与空闲页恢复是同类问题**，方法可迁移，虽然本篇的平台不同。
<a id="section-39"></a>

## 七、命令速查

```bash
# 1) 卷偏移与文件系统确认
mmls /work/DigiForensics.dd
fsstat -o 2048 /work/DigiForensics.dd

# 2) 列出全部 Chromium 用户数据目录（含非 Default 配置文件）
fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -E '/(Chrome|Edge|Brave-Browser|Opera Software)/User Data/[^/]+/$'

# 3) 只读打开数据库，避免证据文件被回写
sqlite3 "file:History.db?immutable=1" ".schema visits"

# 4) 尝试从空闲页恢复已删除记录
sqlite3 "file:History.db?immutable=1" ".recover" > /evidence/out/history_recovered.sql

# 5) 统计各配置文件中的凭据条目数量
sqlite3 "file:Login Data.db?immutable=1" \
  "SELECT hex(substr(password_value,1,3)) AS pfx, count(*) FROM logins GROUP BY 1;"

# 6) 提取 Web 授权/权限记录
sqlite3 "file:Login Data.db?immutable=1" \
  "SELECT origin_url, action_url, username_value FROM logins WHERE origin_url LIKE '%example-cloud.net%';"

# 7) Firefox 主密钥与凭据文件必须配套
ls -l logins.json key4.db
cat profiles.ini | grep -E '^(Path|Default)'

# 8) 统计 Firefox 会话 Cookie 数量
sqlite3 "file:cookies.sqlite?immutable=1" \
  "SELECT count(*) FROM moz_cookies WHERE host LIKE '%example-cloud.net%';"

# 9) 交叉验证：确认该时段确有交互式登录
Get-WinEvent -Path "C:\evidence\Logs\Security.evtx" \
  -FilterHashtable @{LogName='Security'; Id=4624; StartTime='2024-03-15 22:00:00'; EndTime='2024-03-16 06:00:00'} |
  Select-Object TimeCreated,@{n='User';e={$_.Properties[5].Value}},@{n='Type';e={$_.Properties[8].Value}}
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 浏览器取证」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《浏览器取证》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-mem.raw` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。

---
