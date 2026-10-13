---
title: "浏览器密码库与 Token 提取"
slug: "crypto-app-browser-passwords-and-tokens"
canonical: "https://www.digiforensics.cn/wiki/crypto-app-browser-passwords-and-tokens"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:50+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "crypto"
space: "加密与密码取证"
node_path: ["应用与数据库加密"]
---

# 浏览器密码库与 Token 提取

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/crypto-app-browser-passwords-and-tokens)

<a id="section-1"></a>

## 一、概述

浏览器是**单设备上凭据密度最高的取证目标**。一个普通用户的 Chrome 里可能有上百个站点的账号密码、信用卡信息、Cookie 会话和长期有效的 API Token。在磁盘上能拿到的凭据里，它常常是最集中的一份。

没有这套方法，案件里最常见的一类问题就悬在半空：**"这个人掌握了哪些系统的访问权"**。

凭据清单能给出站点的完整覆盖面。而覆盖面在内部调查、账号泄露追源、数据外泄路径分析里，都是决定性事实。

浏览器凭据相比其它类型的加密存储，有三个特点让它在案件里格外重要。

1. **多站点覆盖**。一次提取往往就回答了"这个人掌握哪些系统的访问权"，不需要逐个系统单独取证。
2. **Token 常常绕过口令**。`Local Storage` 与扩展存储里的 token **很多是明文**，拿到就能直接访问账号，**不需要任何解密**——把这类明文目标当成"解不开的密文"而放弃，是最常见的一类漏判。

3. **防护机制正在变紧**。Chrome 127 引入的 App-Bound Encryption（ABE）已经让大量流传的 DPAPI 解密教程失效——这是本篇必须写清的第一个重点，也是本章最容易被旧资料误导的地方。

> **本篇要写清的最重要一句**：如果你在网上找到的教程只做了"读 `Local State` → `CryptUnprotectData` → AES-GCM 解 `v10`"，它在 2024 年 7 月之后的 Chrome 上对部分数据（Cookies）会失败。**这不是工具的 bug，是防护边界的设计变更。** 原因见 2.5。

**本篇处理的证据形态**：

| 浏览器 | 关键文件 | 加密层 | 判据 |
|---|---|---|---|
| Chrome / Edge / Brave（Chromium 系） | `Login Data`、`Cookies`、`Web Data`（SQLite），`Local State`（JSON），`Local Storage/leveldb/` | AES-GCM，密文前缀 `v10` / `v11` / `v20` | **`v20` = ABE 保护**，传统 DPAPI 流程必然解不开 |
| Firefox | `logins.json`、`key4.db`、`cookies.sqlite` | **NSS 体系**，不是 DPAPI | `key4.db` 里 NSS 私钥项的加密方式 |
| Safari（macOS） | `Keychains` 文件 | **Keychain 钥匙串**，受系统钥匙串 ACL 保护 | 与前两者机制完全不同 |

记住 Chromium 系和 Firefox 是两套完全独立的体系——加密层、密钥存放、破解前提都不通用。把 Chrome 的方法套到 Firefox 上（或者反过来）会一路碰壁。

而且**前缀不是浏览器主版本的映射**——这是最常见的误读。Chromium 源码 `os_crypt_linux.cc` 把它们定义为**密钥来源枚举**：`V10` = 使用硬编码口令派生（Linux 上即经典问题来源），`V11` = 密钥存放在 OS 级库中（kwallet / gnome-libsecret，取不到时回退 V10）。**所以同一次 Chrome 发布里，`v10` 与 `v11` 会同时出现**，与"某个版本改过前缀"的时间叙事无关。`v20` 则是 Windows 上的 ABE 保护前缀。

**密文前缀本身就是判据。** 读任何一条记录之前先看前缀，再决定走哪条解密链。

**本篇的操作主链**是五步，每一步都有明确的产出与停手条件：

| 步骤 | 动作 | 产出 | 什么时候就该停 |
|---|---|---|---|
| 1 | 定位所有浏览器与所有 Profile | 浏览器清单 + Profile 路径清单 | 只找到一个 Profile 就动手 → 会漏读 |
| 2 | 读 `Local State`，拿主密钥并判 ABE 状态 | 是否有 `app_bound_encrypted_key`（解码后以 `APPB` 开头） | 出现 `v20` 前缀且无内存镜像 → 转"本阶段不可解" |
| 3 | 解密 `Login Data` 并导出 | 域名 / 用户名 / 口令（脱敏） | 遇到 `v20` 不换工具硬试 |
| 4 | 顺带取更高价值的目标 | Cookies、支付数据、`Local Storage` 里的 token | token 若是明文就到此为止 |
| 5 | 记录与脱敏 | 结构化记录 + 脱敏说明 | 完整明文不进报告正文 |

**第 4 步的性价比最高。** 很多人把全部精力耗在 `Login Data` 上，而 `Local Storage` 与扩展存储里的 token 大量是明文的——它们不需要任何解密就能读出来，却往往比口令更直接地指向访问权。

反过来，第 3 步的失败也不该被当成失败：`v20` 在关机镜像上解不开是**符合预期的正确结果**。写成"该数据受 App-Bound Encryption 保护，在现有检材范围内不可解"就是完整结论。

**在取证流程中的位置**：本篇属于**分析**环节，紧跟在采集之后。

**上游依赖**是[镜像制作](../../imaging/imaging-acquire/imaging-acquire-disk-imaging-and-evidence-preservation.md)——浏览器 profile 分散在用户目录下，必须从镜像里取，不能在目标机现场翻；[只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md)提供只读访问；[SQLite 基础与结构](../../mobile/mobile-database/mobile-database-sqlite.md)是解 `Login Data` 与 `Cookies` 的前置。

**DPAPI 机制的完整背景**见[EFS 文件系统加密取证](../crypto-volume/crypto-volume-efs.md)。浏览器密码库用的就是同一套 DPAPI 主密钥，主密码一旦解开，EFS 与浏览器两条线同时打开。

**下游支撑**的是[浏览器取证](../../computer/computer-browser-behavior/computer-browser-behavior-browser-forensics.md)里的历史、下载与扩展痕迹，与本篇的凭据侧互为印证。涉及"这个人访问过什么"的问题，则延伸到[时间线重建](../../computer/computer-log/computer-log-linux-timeline-reconstruction.md)。

这台机器上装过哪些浏览器、有几个用户 Profile、每个 Profile 的凭据覆盖面（域名 + 用户名）、哪些字段是可读的明文、哪些受 ABE 或系统钥匙串保护、Cookie 会话与本地存储里有哪些 token、以及它们的可用期限。

`v20` 加密的数据在**不改变检材状态**的前提下解不开——这是 ABE 的设计目标，不是能力不足。Firefox 在不知道主密码且无内存镜像时同样受阻。

更不能回答的是**"这个人有没有实际使用过某个账号"**。凭据存在与使用是两条独立的证据链，后者要走[浏览器取证](../../computer/computer-browser-behavior/computer-browser-behavior-browser-forensics.md)的历史与下载记录。

本篇也明确不涉及任何在线验证行为。

**读者前提**：你需要先掌握 SQLite 的基本读写（[SQLite 基础与结构](../../mobile/mobile-database/mobile-database-sqlite.md)）、DPAPI 的工作方式与主密钥存放（[EFS 文件系统加密取证](../crypto-volume/crypto-volume-efs.md)）、以及 AES-GCM 的密文结构（前缀 + 12 字节 IV + 密文 + 16 字节 tag）。

合规前提同样要先对齐：提取出的凭据默认**只做固定与上报、不做使用**，相关要求见[合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md)。

如果你的检材只有一台已关机设备、没有内存镜像，遇到 `v20` 密文就应当把结论写成"在现有检材范围内不可解"并列出未覆盖范围，而不是换工具继续试。

**最后提醒一个范围问题**：一个 Profile 里的凭据清单，**只覆盖这台机器上这个浏览器**。同一个人可能有第二个浏览器、另一台设备、手机端的 App 登录态。

**报告里写"发现 N 组凭据"时必须同时写明范围**，否则"未发现的凭据"这个推论会在质证时被推翻——尤其当案件本身涉及多设备时。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 Chromium 系的文件布局

Chromium 系浏览器的目录结构高度相似，主要差别在路径——理解一次即可通用于多数：

| 浏览器 | User Data 根目录（`%LOCALAPPDATA%` 下，Opera 例外） |
|---|---|
| Chrome | `Google\Chrome\User Data` |
| Edge | `Microsoft\Edge\User Data` |
| Brave | `BraveSoftware\Brave-Browser\User Data` |
| Vivaldi | `Vivaldi\User Data` |
| Opera | `%APPDATA%\Opera Software\Opera Stable` |
| 360 等国产套壳 | `\360Chrome\Chrome\User Data`（结构同 Chrome） |

根目录下：

| 文件/目录 | 内容 | 取证价值 |
|---|---|---|
| `Local State` | JSON，**存放主密钥** | **解密链的起点** |
| `<Profile>\Login Data` | SQLite，口令与自动填充用户名 | **最高** |
| `<Profile>\Web Data` | SQLite，自动填充、信用卡 | 高（含卡号） |
| `<Profile>\Cookies` | SQLite，会话 Cookie | **高（token 常在此）** |
| `<Profile>\History` | SQLite，访问历史 | 高 |
| `<Profile>\Local Storage\leveldb\` | LevelDB，**token 常明文** | **最高之一** |
| `<Profile>\Session Storage` | LevelDB，会话态 | 中 |
| `<Profile>\Local Extension Settings\<id>` | 扩展数据 LevelDB | 中（可含扩展保存的凭据） |
| `<Profile>\Preferences` | JSON，搜索词、主页、扩展列表 | 中（**搜索历史是主观意图的直接证据**） |

> Profile 目录名不是 `Default` 就找不着。 实际是 `Default`、`Profile 1`、`Profile 2`……数量与用户数对应。**必须遍历所有 Profile**，只读 `Default` 会漏掉其他账号体系。

<a id="section-4"></a>

### 2.2 v10/v11 的解密链（Chromium 传统 DPAPI 路径）

```
Local State
  └─ os_crypt.encrypted_key  (Base64 字符串)
       │  Base64 解码
       ├─ [0:5]  = b"DPAPI"      ← ASCII 前缀，不是密文，剥掉
       └─ [5:]   = DPAPI 密文    ← CryptUnprotectData  → 32 字节 AES 主密钥
                                              │
Login Data 的 logins.password_value (BLOB)   │
  └─ [0:3]  = b"v10" 或 b"v11"               │
  └─ [3:15] = 12 字节 GCM nonce               │
  └─ [15:-16] = 密文                          ├── AES-256-GCM 解密
  └─ [-16:]  = 16 字节 GCM tag               ┘
```

**需要纠正的常见说法**：

- 主密钥是 32 字节，`v10` 和 `v11` 都走 AES-256-GCM。 说"`v10` 是 AES-128、`v11` 才是 AES-256"是错的——密钥长度由 `Local State` 决定，与前缀无关。`v11` 与 `v10` 的差异在 Chromium 内部实现，**解密方式与前缀无关**。
- **前缀不是加密算法标识。** 只需要判断"是 v10/v11 走 GCM"还是"无前缀走旧版 DPAPI"。

**判定分支**，实际写脚本时按这个顺序：

```text
len(blob) >= 3 且 blob[0:3] in (b"v10", b"v11")  → 取主密钥走 AES-256-GCM
blob[0:3] == b"v20"                                → ABE 保护的 Cookie，见 2.5
blob[0:8] == 01 00 00 00 D0 8C 9D D0              → 未经过 os_crypt 封装的原始 DPAPI blob
```

<a id="section-5"></a>

### 2.3 Linux / macOS 上的 Chromium

同一份 `Login Data`，密钥来源不同：

| 平台 | 密钥来源 | 取证难度 |
|---|---|---|
| **Windows** | DPAPI（用户凭据绑定） | 中，**受 2.5 的 ABE 影响** |
| **macOS** | Keychain，需该用户的 keychain 密码 | 高（**详见 [07 之外**：Keychain 解锁是独立课题） |
| **Linux** | 固定口令 `peanuts`（明文硬编码在源码里） | **极低**——主密钥可直接算出 |

> Linux 上的 `peanuts` 值得单独记住：Chromium 在 Linux 上用一个硬编码的固定口令加密主密钥。这在设计上是"依赖 kwallet/gnome-libsecret"的兜底路径，但**只要文件可读，密钥就可复现**。这是跨平台对比中差异最大的一项。

<a id="section-6"></a>

### 2.4 Firefox：用另一套体系（NSS）

Firefox 完全不走 DPAPI/AES-GCM，而是 Mozilla 的 NSS（Network Security Services）：

| 文件 | 内容 |
|---|---|
| `%APPDATA%\Mozilla\Firefox\Profiles\<随机名>.default-release\logins.json` | 凭据清单，**字段名是明文**，密码是 NSS 加密串 |
| 同目录 `key4.db` | SQLite，存放 NSS 主密钥（PKCS#11 格式） |
| `cert9.db`（老版本 `cert8.db`） | 证书库 |
| `global-magento-db.json` | 老版本（<58）的密码库，已被 logins.json 取代 |

**解密依赖关系**：`logins.json` 里的 `encryptedUsername`/`encryptedPassword` 需要 `key4.db` 中的密钥，**两者同目录**。

若用户设置了 **Primary Password**（主密码），则还需该密码参与解锁，**无密码时不可解**。

> **取证顺序**：先看 `logins.json` 里的 `hostname` 字段——**这已经是明文的高价值证据**（"这台机器访问过哪些站点"），**密码本身往往不是必需的**。

<a id="section-7"></a>

### 2.5 ⚠️ App-Bound Encryption：为什么老教程失效了

这是本篇的技术核心，Chrome 127（2024 年 7 月）开始引入。

**旧模型的弱点**：DPAPI 只能证明"这个数据属于这个 Windows 用户"。

**任何以该用户身份运行的程序**——包括信息窃取木马——都能调用 `CryptUnprotectData` 把它解开。

防护边界在**用户**，不在**程序**。

**ABE 把边界从用户移到了程序**：

```
① Chrome 生成随机 32 字节 app_bound_key
② 把它交给一个以 SYSTEM 权限运行的 COM 服务（Elevation Service）
③ 该服务做信封加密：
   - 把调用者进程的可执行文件路径作为身份数据编入（规范化后比对）
   - 用硬编码在服务内的密钥加密 app_bound_key
   - 内层 CryptProtectData（用户上下文）
   - 外层 CryptProtectData（SYSTEM 上下文）  ← 双层 DPAPI 包装
④ 结果写入 Local State 的 os_crypt.app_bound_encrypted_key
   （Base64，解码后以 ASCII "APPB" 开头）
```

**解密时**：Chrome 通过 COM 接口（`IElevator::DecryptData`）把 `APPB` 块交给 Elevation Service，服务验证调用者确实是那个签名的 chrome.exe，才返回 32 字节密钥。

**别的程序来问，一律被拒。**

**在 Local State 里怎么认出来**：看是否存在 `app_bound_encrypted_key` 字段（值解码后以 ASCII `APPB` 开头），命令见第七节 2。

**受影响范围**——要精确，不要过度宣称：

| 数据 | Chrome 127+ 状态 |
|---|---|
| **Cookies** | **首批迁移到 ABE**，密文前缀为 `v20` |
| `Login Data` 口令 | **127 初始批次尚未全部迁移**，多数仍为 `v10`/`v11` + 传统 DPAPI 主密钥 |
| 支付数据等 | 设计上计划后续迁移 |

> **准确的表述是"部分失效"而非"全部失效"**：ABE 首发覆盖 Cookies，`Login Data` 的迁移在后续版本逐步推进。判据是数据本身的前缀——`v20` 就是 ABE 保护，传统 DPAPI 流程必然解不开。

**三条应对路径**，都要写进报告的方法论，说明各自代价：

| 路径 | 做法 | 代价与限制 |
|---|---|---|
| **运行中提取** | 在目标机器上让浏览器处于运行态，从其进程内存中取得已解密的密钥材料 | **改变了检材状态**，需授权；破坏了"关机镜像"这一取证前提 |
| **受控启动参数** | 以 `--disable-features=AppBoundEncryption` 启动浏览器 | **需要用户侧配合或可控账户**；改变了配置与可能的运行痕迹，**必须记录** |
| **维持静态分析** | 关机镜像上只解 `v10`/`v11` 数据，对 `v20` 数据**如实记录为"受 ABE 保护，本阶段未解出"** | **最保守、零污染**，v20 密文本身的存在即是证据 |

> **取证原则**：**"没解出来"是一个合法且应当如实写进报告的结论。** 不要为了"拿到明文"而越过授权去改检材状态。密文存在、格式可辨、机制可述——这本身就是充分的证据描述。

**一条有用的旁证**：Chrome 在 ABE 校验失败时会在 Application 日志的 `Chrome` 源写 Event ID 257。

日志里出现这条事件，说明**当时有程序试图解密该数据但被拒**——这本身就是一条独立的攻击痕迹证据。

<a id="section-8"></a>

### 2.6 Safari 与 Edge Legacy

| 目标 | 位置与机制 | 要点 |
|---|---|---|
| **Safari** | `~/Library/Keychains/login.keychain-db`、`~/Library/Safari/History.db` | 凭据在 **Keychain**，需该用户 keychain 密码解锁；**iOS 备份另有一套 schema** |
| **Edge Legacy** | `%LOCALAPPDATA%\Microsoft\Windows\WebCache\WebCacheV01.dat` | **ESE 数据库格式**，非 SQLite，**必须用专用解析工具**，直接读取只会得到乱码 |

> 不要把 Edge Legacy 和 Chromium 版 Edge 搞混：新版 Edge 是 Chromium，路径与 Chrome 一致；`WebCacheV01.dat` 属于 IE 时代的遗留组件，两者机制完全不同。

<a id="section-9"></a>

### 2.7 合规边界

| 允许 | 禁止 |
|---|---|
| 提取并**脱敏记录**"该设备曾登录过某站点" | **用提取的凭据登录任何网站** |
| 记录 Cookie/token 的**存在**、**有效期**、**归属站点** | **使用 token 访问对方账号**（包括"只看一下有没有"） |
| 用 token 的**格式与签发时间**做时间线分析 | 把完整凭据写进报告正文 |
| 将凭据**固定为证据**并移交委托方 | 私存一份"以备后用" |

> **报告中的正确表述**："在 Chrome Profile 1 的 `Local Storage/leveldb/` 中发现某站点会话 token（JWT 格式，签发时间 2024-03-11，有效期 7 天），表明**该设备在该时段持有该站点的有效会话**。**本次分析未使用该 token 访问任何服务。**"
>
> **错误表述**："恢复出该站点账号密码，可登录查看内容。"——这既超出了委托范围，也可能构成非法访问。

---
<a id="section-10"></a>

## 三、操作步骤

<a id="section-11"></a>

### 步骤 1：定位所有浏览器与所有 Profile

```bash
# 以 Windows 检材为例（只读挂载后）
ls -d /mnt/image/Users/*/AppData/Local/{Google/Chrome,Microsoft/Edge,BraveSoftware,Vivaldi}*/User\\ Data 2>/dev/null
# 逐个列出 Profile 目录名——Default 只是其中之一
for d in /mnt/image/Users/*/AppData/Local/Google/Chrome/User\ Data/*/; do
  [ -f "$d/Login Data" ] && echo "PROFILE: $d"
done
```

**先做这一步再做任何解密**。Profile 数量、浏览器种类决定了后面所有工作的规模。

<a id="section-12"></a>

### 步骤 2：读 `Local State`，拿主密钥并判断 ABE 状态

命令见第七节 2。要点：读 `os_crypt.encrypted_key`（Base64 解码后**前 5 字节必须是 `DPAPI`**，剥掉后做 DPAPI 解密得 32 字节主密钥），并检查是否存在 `app_bound_encrypted_key`。

**这一步的输出就是报告里"解密可行性"的依据**：有没有 ABE 键，决定了哪些数据能解、哪些不能。

**它必须发生在跑提取脚本之前。**

<a id="section-13"></a>

### 步骤 3：解密 `Login Data` 并导出

**Windows 环境可直接运行**（只用标准库，无需 pip 安装）：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""chrome_creds.py — 提取 Chromium 系浏览器保存的口令（Windows）
依赖：仅标准库（ctypes 调用 crypt32/bcrypt）。DPAPI 与 AES-GCM 均需在
      **原机器、原用户上下文**中执行——复制到别的机器上 DPAPI 会失败。
用法（Windows 管理员或目标用户身份）：python chrome_creds.py "C:\\Users\\zhang\\AppData\\Local\\Google\\Chrome\\User Data"
"""
import os, sys, json, base64, sqlite3, shutil, tempfile, ctypes
from ctypes import wintypes

# ---------- DPAPI ----------
def dpapi_unprotect(blob: bytes) -> bytes:
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
    def to_blob(b: bytes) -> DATA_BLOB:
        buf = ctypes.create_string_buffer(b, len(b))
        return DATA_BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    src, out = to_blob(blob), DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(src), None, None, None, None, 0, ctypes.byref(out)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)

# ---------- AES-256-GCM（bcrypt.dll）----------
def aes_gcm_decrypt(key: bytes, nonce: bytes, ct: bytes, tag: bytes) -> bytes:
    """AES-256-GCM 解密。BCryptImportKey 的 hSecret 传 None（无需导入密钥包）。"""
    bcrypt = ctypes.windll.bcrypt
    alg = ctypes.c_void_p()
    if bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(alg), b"AES", None, 0) != 0:
        raise OSError("BCryptOpenAlgorithmProvider failed")
    hkey = ctypes.c_void_p()
    try:
        if bcrypt.BCryptSetProperty(alg, b"ChainingMode",
                ctypes.c_wchar_p("ChainingModeGCM"), (len("ChainingModeGCM") + 1) * 2, 0) != 0:
            raise OSError("set ChainingMode failed")
        if bcrypt.BCryptImportKey(alg, None, b"AES",
                ctypes.byref(hkey), ctypes.create_string_buffer(key, len(key)),
                len(key), 0) != 0:
            raise OSError("BCryptImportKey failed")
        # GCM 上下文：nonce 与 16 字节 auth tag 都通过 AUTHENTICATED_CIPHER_MODE_INFO 传入
        class AUTH_INFO(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.DWORD), ("pbNonce", ctypes.c_void_p),
                        ("cbNonce", wintypes.DWORD), ("pbAuthData", ctypes.c_void_p),
                        ("cbAuthData", wintypes.DWORD), ("pbTag", ctypes.c_void_p),
                        ("cbTag", wintypes.DWORD), ("pbMac", ctypes.c_void_p),
                        ("cbMac", wintypes.DWORD), ("cbAAD", wintypes.DWORD),
                        ("cbData", wintypes.DWORD), ("cbTagOffset", wintypes.DWORD)]
        nbuf = ctypes.create_string_buffer(nonce, len(nonce))
        tbuf = ctypes.create_string_buffer(tag, len(tag))
        info = AUTH_INFO(ctypes.sizeof(AUTH_INFO), ctypes.cast(nbuf, ctypes.c_void_p), len(nonce),
                         None, 0, ctypes.cast(tbuf, ctypes.c_void_p), len(tag),
                         None, 0, 0, len(ct), 0)
        out = ctypes.create_string_buffer(len(ct) + 32)
        got = ctypes.c_ulong(0)
        st = bcrypt.BCryptDecrypt(hkey, ctypes.create_string_buffer(ct, len(ct)), len(ct),
                                  ctypes.byref(info), None, 0,
                                  out, len(out), ctypes.byref(got), 0)
        if st != 0:
            raise OSError(f"BCryptDecrypt failed: 0x{st:08X}（tag 不匹配 = 密钥错误）")
        return out.raw[:got.value]
    finally:
        bcrypt.BCryptDestroyKey(hkey); bcrypt.BCryptCloseAlgorithmProvider(alg, 0)

# ---------- 主逻辑 ----------
def get_master_key(user_data: str):
    st = json.load(open(os.path.join(user_data, "Local State"), encoding="utf-8"))["os_crypt"]
    raw = base64.b64decode(st["encrypted_key"])
    if raw[:5] != b"DPAPI":
        raise ValueError("encrypted_key 前缀异常，可能不是传统 DPAPI 键")
    return dpapi_unprotect(raw[5:]), ("app_bound_encrypted_key" in st)

def decrypt_value(blob: bytes, key: bytes):
    if blob[:3] in (b"v10", b"v11"):
        return aes_gcm_decrypt(key, blob[3:15], blob[15:-16], blob[-16:])
    if blob[:3] == b"v20":
        return b"[ABE 保护，未解密]"
    if blob[:8] == bytes.fromhex("01000000D08C9DD0"):
        return dpapi_unprotect(blob[8:])
    return b"[未知前缀，未处理]"

def dump_profile(profile: str, key: bytes):
    # 检材中的 DB 可能处于 WAL 状态且被浏览器占用 → 连 -wal/-shm 一起复制到临时目录
    tmpdir = tempfile.mkdtemp()
    tmp = os.path.join(tmpdir, "Login Data")
    shutil.copy2(os.path.join(profile, "Login Data"), tmp)   # 只读取，不动原文件
    for ext in ("-wal", "-shm"):
        side = os.path.join(profile, "Login Data" + ext)
        if os.path.exists(side):
            shutil.copy2(side, tmp + ext)
    con = sqlite3.connect(tmp)
    try:
        rows = con.execute(
            "SELECT origin_url, username_value, password_value, date_created "
            "FROM logins ORDER BY origin_url").fetchall()
    finally:
        con.close(); shutil.rmtree(tmpdir, ignore_errors=True)
    for url, user, pwd, created in rows:
        if not pwd:
            continue
        try:
            plain = decrypt_value(bytes(pwd), key).decode("utf-8", "replace")
        except Exception as e:
            plain = f"[解密失败: {e}]"
        print(f"{url}\	{user}\	{plain}\	{created}")

if __name__ == "__main__":
    if os.name != "nt":
        sys.exit("本脚本依赖 DPAPI，仅能在 Windows 上运行；Linux 侧见 2.3。")
    ud = sys.argv[1]
    key, has_abe = get_master_key(ud)
    print(f"# 主密钥 {len(key)} 字节；ABE 启用: {has_abe}")
    if has_abe:
        print("# 注意：Cookies 等 v20 数据受 ABE 保护，本脚本不解（见 2.5）")
    for d in sorted(os.listdir(ud)):
        p = os.path.join(ud, d)
        if os.path.isfile(os.path.join(p, "Login Data")):
            print(f"\
## Profile: {d}"); dump_profile(p, key)
```

**运行（必须在原机器、原用户上下文）**：

```powershell
cd D:\evidence
python chrome_creds.py "C:\Users\zhang\AppData\Local\Google\Chrome\User Data"
# 输出为 TSV → 转入 CSV 归档；**完整口令不进报告正文**
```

> 为什么用 ctypes 而不是 `pywin32`/`pycryptodome`：不引入第三方依赖，可在**纯净的取证环境**直接运行，减少"工具本身的风险"这一层质疑。`crypt32.dll`（DPAPI）与 `bcrypt.dll`（AES-GCM）都是 Windows 自带组件。

<a id="section-14"></a>

### 步骤 4：别忘了比口令更高价值的目标

```bash
# Local Storage：token 常直接明文，不需要任何解密
strings -n 20 "DigiForensics.dd" | grep -iE "eyJ[A-Za-z0-9_-]{20,}" | head -20
# ↑ JWT：header.payload.signature，payload 直接 base64url 解码即明文

# Firefox 凭据清单：字段名就是明文
cat "/mnt/image/Users/zhang/AppData/Roaming/Mozilla/Firefox/Profiles/xxxx.default-release/logins.json"
```

**只看密文前缀**即可判断加密世代（命令见第七节 4）：`hex(substr(encrypted_value,1,3))` 输出 `763130` = `v10`（AES-GCM，走传统 DPAPI 主密钥）、`763230` = `v20`（ABE，需 2.5 的路径）。**这是不接触密文内容就能描述机制的最小充分证据**。

<a id="section-15"></a>

### 步骤 5：记录与脱敏

每条凭据最少记录：站点/主机名、用户名（可保留）、是否成功解密、解密方式、数据库/文件路径、时间戳、Profile 名。

密码与 token 原文单独归档、受控调阅，报告中只写"已解密/未解密"。

---
<a id="section-16"></a>

## 四、常见陷阱

本章按「定位与范围 → 前缀与机制判读 → 解密执行与验证 → 结论表述与合规边界」归组，每条给出：现象、为什么会误判、误判代价、正确做法。
★ 标记表示该操作会导致原始检材永久灭失或不可逆改变，执行前必须停下来确认。

<a id="section-17"></a>

### 4.1 定位与范围：漏读 Profile 与目标

<a id="section-18"></a>

#### 陷阱 1：只处理 `Default` Profile

**现象**：脚本写死 `Chrome/User Data/Default/Login Data`，导出一批口令后报告"该机浏览器凭据已完整提取"。

**原因**：Profile 目录名不是 `Default` 就找不着（2.1）。

实际结构是 `Default`、`Profile 1`、`Profile 2`……，数量与用户在该浏览器里的账号体系对应。每个 Profile 是一套完全独立的登录态、Cookie 集合、扩展数据。

只读 `Default` 在物理上就访问不到其他 Profile 的数据——不是解析失败，是根本没去读。

**影响**："完整提取"是一个**完整性承诺**，委托方会据此认为证据已经取全，从而不再安排补充取证。

等到需要其他账号信息时，发现**原始检材的获取途径已经关闭**（设备已归还、委托关系结束），**这个损失事后无法弥补**。

而且漏读的往往正是案情关键的那个——员工常用账号在 `Profile 1`，私人账号在 `Default`，两者在时间线上互为佐证。

**核查**：**先枚举、后解密**，这一步必须在跑任何提取脚本之前完成：

```bash
# 遍历所有浏览器、列出全部 Profile
for d in /mnt/image/Users/*/AppData/Local/Google/Chrome/User\ Data/*/; do
  [ -f "$d/Login Data" ] && echo "PROFILE: $d"
done
# 注意路径：Opera 在 %APPDATA%，不在 %LOCALAPPDATA%
```

**报告写法**："共发现 N 个用户目录、M 种浏览器、K 个 Profile，均已逐一下载"——**K 这个数字必须是枚举出来的，不能是估计的**。

<a id="section-19"></a>

#### 陷阱 2：只查浏览器本体，漏掉 LevelDB 与扩展数据

**现象**：四个目标文件（`Login Data`、`Web Data`、`Cookies`、`History`）都提取完了，报告写"浏览器数据提取完毕"。

**原因**：**现代站点很少把凭据放在密码库里**。

单点登录普及之后，令牌更多落在 `Local Storage/leveldb/` 里，而且是**明文**——不做任何加密。

2.1 已经把这一项标注为"最高之一"，但它不是 SQLite 文件、不在常规工具的默认扫描列表里，**工具"没找到"很容易被当成"不存在"**。

同样被漏掉的还有 `Local Extension Settings\<id>`——扩展自建的凭据存在这里。

**影响**：漏掉的往往是**当前有效的凭据**。而这会让分析员对案情产生一个方向性误判：以为"这台机器上没有可用会话，只能看历史访问记录"，实际令牌就在 leveldb 里明文躺着——能力边界一旦被低估，报告的结论随之保守化。

**核查**：把提取目标从"四个 SQLite 文件"扩展成一份**显式清单**，逐项记录存在性与提取状态：

```bash
# LevelDB 中的 JWT：payload 直接 base64url 解码即明文
strings -n 20 DigiForensics.dd | grep -iE "eyJ[A-Za-z0-9_-]{20,}" | head -20
# 扩展数据
ls /mnt/image/Users/*/AppData/Local/Google/Chrome/User\ Data/*/Local\ Extension\ Settings/
```

报告里按清单逐项写"存在/不存在/已提取/提取失败"，而不是写一句"数据提取完毕"。

<a id="section-20"></a>

#### 陷阱 3：把 `WebCacheV01.dat` 当 SQLite 打开

**现象**：Edge Legacy 的 `WebCacheV01.dat` 用 SQLite 读出来是一堆乱码，分析员判为"文件已加密"。

**原因**：它是 ESE 数据库（Extensible Storage Engine），不是 SQLite（2.6）。

两者是完全不同的存储引擎，页结构、记录格式、命名空间概念都不同。

用 SQLite 读它，得到的不是"部分可读"而是彻底的乱码——而"乱码"与"密文"在现象上无法区分。缺的是**格式识别**这一步。

**影响**：误判成"已加密"会把后续工作导向不可解的方向（寻找密钥、尝试暴力破解），而正确路径只是换一个解析器——一个本可读的数据被写成了"不可读"，这是纯粹的自伤。

**核查**：**先判定容器格式，再选解析器**：

```bash
# ESE 数据库的 magic 是 0xE11AB1A1E011CFD0（小端呈现）
xxd -l 8 "/mnt/image/Users/zhang/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat"
# 头部形如 00 d0 c1 01 e0 11 1a e1 → ESE
```

**另一个混淆源**：新版 Edge 是 Chromium 内核、路径与 Chrome 一致，`WebCacheV01.dat` 属于 IE 时代遗留组件。报告里两者必须分开表述，不要混为"Edge 浏览器"。

<a id="section-21"></a>

### 4.2 前缀与机制判读

<a id="section-22"></a>

#### 陷阱 4：以为 `v10` 是 AES-128、`v11` 是 AES-256

**现象**：按前缀分流逻辑，只对 `v11` 的数据走 AES-256，`v10` 的数据判为"旧版弱加密"另作处理，脚本因此漏掉了一批条目。

**原因**：主密钥恒为 32 字节，`v10` 与 `v11` 都走 AES-256-GCM（2.2 的明确纠正）。

前缀不是算法标识，它只区分"有没有 DPAPI 那一层"。

**"前缀 = 算法"是一个非常自然但完全错误的类比**——它来自对早期版本差异的碎片记忆，而非对机制的准确理解。两者的差异在 Chromium 内部实现，**解密方式与前缀无关**。

**影响**：漏解一批条目，或者对同一批数据做出"用两种不同算法解密"的错误尝试。

更实质的问题是**它会污染报告的定性**——写"`v10` 数据使用较弱的加密方式"是一个没有依据的技术断言，专业读者会据此质疑整份分析。

**核查**：**前缀只用于分支，不用于判定算法**：

```text
len(blob) >= 3 且 blob[0:3] in (b"v10", b"v11")  → 取 32 字节主密钥，走 AES-256-GCM
blob[0:3] == b"v20"                                → ABE 保护，见 2.5
blob[0:8] == 01 00 00 00 D0 8C 9D D0              → 未经过 os_crypt 封装的原始 DPAPI blob
```

**只读前缀就能描述机制**，这是不接触密文内容的最小充分证据（步骤 4）：

```bash
python3 -c "
b=open('DigiForensics-login.data','rb').read()
print(hex(b[:3]))"   # 763130=v10 / 763230=v20
```

<a id="section-23"></a>

#### 陷阱 5：把 ABE 说成"全部数据都解不出来"

**现象**：在 `Local State` 里发现 `app_bound_encrypted_key`，报告写"该机采用 App-Bound Encryption，浏览器凭据无法解密"。

**原因**：ABE 首批覆盖的是 Cookies（密文前缀 `v20`），`Login Data` 的迁移在后续版本逐步推进（2.5）。

也就是说同一台机器上会同时存在 `v10`/`v11` 与 `v20` 两类数据，前者仍走传统 DPAPI 路径、可解。

**"部分失效"是准确表述，"全部失效"不是。** 把两者混为一谈，源于"启用了一个新机制 ⇒ 旧机制整体停止工作"这个直觉，而密码系统是逐数据项迁移的，不是一刀切。

**影响**：这是**方向性的能力误判**。

它会让分析员宣布"该路径已死"并转向昂贵手段（内存取证、要求用户配合），而实际上大部分口令就在手边的 `Login Data` 里躺着。

同时报告里那句"无法解密"是**不成立的否定性结论**，委托方会据此认为这条线索彻底断掉。

**核查**：**判据永远落在具体数据项的前缀上，而不是全局机制上**：

```bash
# 先看状态
python3 -c "
import json
d=json.load(open('Local State'))['os_crypt']
print('encrypted_key:', 'encrypted_key' in d)
print('app_bound:', 'app_bound_encrypted_key' in d)"
# 再逐条看前缀
python3 -c "
import sqlite3
for (u,p,e) in sqlite3.connect('DigiForensics-login.data').execute(
  'select username_value,hex(substr(password_value,1,3)),password_value from logins'):
  print(e[:3].decode('latin1') if e else 'NO-PREFIX', u)"
```

**报告写法**："该机启用了 ABE（`Local State` 含 `app_bound_encrypted_key`）。逐条判读前缀后：K 条口令为 `v10`/`v11`，已解密；M 条 Cookies 为 `v20`，受 ABE 保护，本阶段未解出。"

<a id="section-24"></a>

#### 陷阱 6：DPAPI 换台机器解

**现象**：把 `Local State` 和 `Login Data` 复制到取证工作站的 Windows 上调用 DPAPI 解密，全部失败，判为"密钥已损坏"或"版本不兼容"。

**原因**：**DPAPI 的保护边界是「用户 + 机器」**——它把用户的登录凭据与本机特定数据绑在一起。换了机器或换了用户上下文，`CryptUnprotectData` 就会失败。 这是设计目标，不是缺陷。而这个失败现象与"密钥损坏""版本不兼容"在报错上很像，**三种成因无法在异地区分**。

**影响**：把环境问题误判为数据问题，会导向"数据不可用"的结论。

更进一步的做法是有人会去尝试离线破解 DPAPI 备份——那已经进入攻击范畴，且对现代 DPAPI 基本无效，纯粹浪费算力。

**核查**：**DPAPI 必须在原机器、原用户上下文中解**，具体三条路径：

```powershell
# 路径 A（最规范）：在原机以原用户交互会话中执行
# 路径 B：提取 DPAPI 凭据材料后，在原机的受控环境用
#        CryptUnprotectData 复现原用户上下文
# 路径 C：内存取证——从已运行的浏览器进程内存直接取已解密材料
#        （改变了检材状态，需授权；见 2.5 的三条路径对比）
```

**报告里必须写明执行位置**——"在原机原用户上下文下完成解密"和"在取证机上完成解密"是两条能力不同的证据，可信度也不同。

<a id="section-25"></a>

#### 陷阱 7：在 Linux 上套 Windows 的 DPAPI 流程

**现象**：在 Linux 分析机上直接按 `Local State` → `encrypted_key` → DPAPI 解密的流程跑，全部失败，判为"该机数据不可恢复"。

**原因**：**DPAPI 是 Windows 专有的实现**，在 Linux 上没有对应物，走这条路在原理上就不可能成功。

而同一份 `Login Data` 在 Linux 上的密钥来源完全不同——Chromium 在 Linux 上用一个硬编码的固定口令加密主密钥（2.3），主密钥**可以直接算出，不需要任何 DPAPI**。

用 Windows 流程处理 Linux 检材，是把一个"极低难度"的任务当成了"不可完成"。

**影响**：**把可解的数据写成不可解**，而且方向完全错了——真正该用的路径简单到不需要任何特权。

同类混淆还有平台判断：macOS 的密钥在 **Keychain**，需要该用户的 keychain 密码，是**三个平台里最难的一个**。判据不是"非 Windows 即易解"。

**核查**：**先判平台，再选路径**：

| 平台 | 密钥来源 | 难度 |
|---|---|---|
| Windows | DPAPI（受 ABE 影响，见 2.5） | 中 |
| macOS | Keychain，需该用户 keychain 密码 | 高 |
| **Linux** | **硬编码固定口令，主密钥可直接算出** | **极低** |

**报告的方法论部分要写明平台与所走路径**，否则读者无法判断"不可解"是真的不可解还是走错了路。

<a id="section-26"></a>

### 4.3 解密执行与验证

<a id="section-27"></a>

#### 陷阱 8：★ 直接对检材里的 SQLite 写 SQL，忽略 WAL 与文件锁

**现象**：对镜像里挂载出来的 `Login Data` 直接执行 `SELECT ... FROM logins`，只查出一部分记录，甚至报 `database is locked`。

**原因**：**SQLite 有 WAL（预写日志）机制**——已提交的数据可能还在 `-wal` 文件里而未合并回主库。

**只读主库文件会看到一份"过去某一时刻的快照"**，记录数偏少且不自洽。

而 `-shm` 共享内存文件缺失时，SQLite 无法判断 WAL 状态，可能直接拒绝打开。

**影响**：一是**记录数偏少会被读成"这台机器只登录过这几个站点"**——这是一个关于事实的错误结论，且无声无息。

二是若为图省事在挂载点直接复制数据库文件，可能触发 SQLite 的自动恢复，从而在检材上写入并改动原始文件。

**核查**：**三个文件一起复制到工作区再查，检材上不做任何写入**：

```bash
# 必须 -wal 与 -shm 一起复制，缺一不可
cp --preserve=timestamps "/mnt/image/.../Login Data"            ./DigiForensics-login.data
cp --preserve=timestamps "/mnt/image/.../Login Data-wal"        ./DigiForensics-login.data-wal 2>/dev/null
cp --preserve=timestamps "/mnt/image/.../Login Data-shm"        ./DigiForensics-login.data-shm 2>/dev/null
# 在副本上查，并核对总记录数是否合理
sqlite3 ./DigiForensics-login.data "SELECT count(*) FROM logins;"
```

**核对方法**：若 `count(*)` 明显少于预期，先确认 `-wal` 是否遗漏；若 sqlite 报告页面计数与主库头部不符，说明 WAL 未被读取，**此时的数据是残缺的，不得作为完整性依据**。

<a id="section-28"></a>

### 4.4 结论表述与合规边界

<a id="section-29"></a>

#### 陷阱 9：★ 为拿明文而修改检材状态（受控启动参数 / 进程注入 / 内存提取）

**现象**：为解开 `v20` 数据，以 `--disable-features=AppBoundEncryption` 启动目标机上的浏览器，或向浏览器进程注入代码提取密钥。

**原因**：这些手段在技术上都可能奏效，而**"拿到明文"看起来是分析员的正当目标**。但它们**改变了检材的状态**：启动浏览器会改写 `Preferences`、可能刷新缓存、重建 Profile 状态；注入会改变进程内存。

这些痕迹**会留在镜像里并被后续分析看到**，形成一个自相矛盾的证据——"取证人员动过这台机器"。

**影响**：这正是 2.5 说的"破坏了关机镜像这一取证前提"。

后果不只是痕迹污染：一旦对方主张检材被污染，你**无法证明取出的数据是原始状态下的数据**。"未解出"是一个合法结论；"污染了检材换来的明文"可能让整份报告在质证环节失去可信度。

**核查**：**维持静态分析，把 `v20` 如实记为未解出**（2.5 的第三条路径，零污染）：

```bash
# 只读前缀，不接触密文内容——这是最小充分的机制描述
python3 -c "
import sqlite3
c=sqlite3.connect('./DigiForensics-cookies')
for (h,prefix) in c.execute('select host_key, hex(substr(encrypted_value,1,3)) from cookies limit 20'):
  print(prefix, h)"
# v20(763230) = ABE 保护 → 报告写"受 ABE 保护，本阶段未解出"
```

若确需尝试其他路径，必须先取得委托方书面授权，并在报告中记录：授权文件编号、执行时间、操作内容、对检材的影响范围。 另外 2.5 提到的那条旁证很有用：Chrome 在 ABE 校验失败时会向 Application 日志的 `Chrome` 源写 Event ID 257——日志里出现这条事件，说明当时确实有程序尝试解密而被拒，这本身就是独立的攻击痕迹证据。

<a id="section-30"></a>

#### 陷阱 10：拿到 token 或口令就去访问

**现象**：从 `Local Storage/leveldb/` 提取到某站点的会话 token 或从 `Login Data` 解出账号口令，为了"验证凭据有效性"或"看看被访问了什么内容"，实际登录了该站点。

**原因**：这类验证在技术上是可行的，逻辑上也似乎合理——"确认凭据真实"。

但它**完全改变了行为的法律性质**（2.7）：委托方授权检验的是**这台设备上的数据**，**不是**那个第三方账号。

访问第三方服务器既超出授权范围，也可能构成非法访问，且不同司法辖区的判定标准并不一致。

**影响**：与远控凭据那一类（见 [02 远程工具凭据解密](crypto-app-remote-tool-credential-preservation.md) 的同名红线）性质相同——连接行为会在服务端留下访问记录，对方可以查到你的 IP 与时间；被控账户的所有权人可能据此主张权利；而分析员个人承担相应的法律风险。

此外这会**污染时间线**——你在对方服务器上产生的新活动，可能与案发现场的时间线混在一起。

**核查**：**只记录，不使用**。凭据固定后报告这样写：

> "在 Chrome Profile 1 的 `Local Storage/leveldb/` 中发现某站点会话 token（JWT 格式，签发时间 2024-03-11，有效期 7 天），表明**该设备在该时段持有该站点的有效会话**。**本次分析未使用该 token 访问任何服务。**"

**对照的错误表述**："恢复出该站点账号密码，可登录查看内容。"——这既超出了委托范围，也可能构成非法访问。同理，**不得私存一份凭据"以备后用"**。

<a id="section-31"></a>

#### 陷阱 11：在报告正文里写完整凭据

**现象**：报告附件里贴出完整口令、完整 token、完整 Cookie 串，注明"便于复核"。

**原因**：复核确实需要知道"拿到的是什么"，于是自然地把值本身写进去。

但**报告的传播范围远大于分析环境**——交给委托方、可能进卷宗、可能在质证中公开。

凭据是二次泄露的源头，而报告恰恰是最容易被广泛传阅的那份文件。

**影响**：泄露后**责任在报告作者而不在原始设备持有者**。

更现实的风险是：一个 token 可能仍处于有效期内，**报告公开的当天凭据就是活的**。

**核查**：报告只写"已解密/未解密"这一状态，以及站点、归属、时间；口令与 token 原文单独归档、受控调阅（步骤 5 的记录清单七项）。需要复核时用"字段 + 掩码前后若干位 + 校验方式"替代完整值。

<a id="section-32"></a>

#### 陷阱 12：忽视 `Preferences` 里的搜索历史

**现象**：提取完所有数据库文件后认为"浏览器侧工作已完成"，把 `Preferences`（JSON，非数据库）跳过。

**原因**：**搜索词是主观意图的直接证据**（2.1 对它的定性），而它既不在任何 `.db` 文件里，也不在常规工具的默认目标列表中——它是一个 JSON 文件，工具往往只在"找口令"时才会去读它。

在口令已解出、任务看似完成的情况下，它最容易被当成边角料。

而"用户主动搜索了什么"在证明意图时的效力，往往**高于他登录过哪些网站**。

**影响**：丢掉的是**证明力最强的一类证据**。

访问历史说明"这台设备去过某个站点"，可以被解释为误入、广告跳转；而**主动输入的搜索词说明用户知道要找什么**——这在主观故意的认定上完全是另一种证明强度。

**核查**：把 `Preferences` 列入必取清单，与数据库文件同级处理：

```bash
# 搜索历史、主页、扩展列表都在这里
python3 -c "
import json
d=json.load(open('/mnt/image/.../Preferences'))
print(json.dumps(d.get('keyword_search_terms',''), ensure_ascii=False))
print('首页:', d.get('homepage'))"
```

**报告里把它单列为一项发现**（"浏览器搜索历史（时间范围），其中若干条与本案争议事实直接相关"），而不是混在"其他信息"里一笔带过。
<a id="section-33"></a>

## 五、案例示例

<a id="section-34"></a>

### 5.1 Chrome 双 Profile + JWT 载荷：明文证据已足以定案

**场景**

查获一台 Windows 11 笔记本（`DigiForensics.dd`）。委托方需证明「该设备持有某电商平台的登录凭据，并在 2024-06 前后访问过该平台」。**委托方明确要求不得访问该平台。**

这条路径值得先走，是因为**本案的关键结论完全由明文构成**：`date_created` 是明文、JWT 的 payload 是明文、访问历史是明文。先把这些用足，再考虑解密。

**处置过程**

第 1 步，定位所有 Profile——只看 `Default` 会直接漏掉目标：

```bash
fls -o 2048 -r /evidence/DigiForensics.dd | grep -iE '(Chrome|Edge)/User Data/(Default|Profile [0-9]+)'
# C:\Users\zhang\AppData\Local\Google\Chrome\User Data\Default
# C:\Users\zhang\AppData\Local\Google\Chrome\User Data\Profile 1
# C:\Users\zhang\AppData\Local\Microsoft\Edge\User Data\Default
# 共 3 个 Profile
```

第 2 步，读 `Local State` 确认 ABE 状态——**这一步决定后续可行性**：

```bash
icat -o 2048 /evidence/DigiForensics.dd <inode> > /evidence/LocalState.json
python3 -c "import json;d=json.load(open('/evidence/LocalState.json'))['os_crypt'];\
print('encrypted_key present:', 'encrypted_key' in d);\
print('ABE present:', 'app_bound_encrypted_key' in d)"
# encrypted_key present: True
# ABE present: False        ← 该构建未启用 ABE，Login Data 可正常解密
# Edge 需单独确认其状态，不要沿用 Chrome 的结论
```

第 3 步，解 `Login Data`（**每个 Profile 都要单独跑**）：

```bash
icat -o 2048 /evidence/DigiForensics.dd <inode> > /evidence/LoginData.db
python3 -c "
import pysqlite3 as s
for r in s.connect('/evidence/LoginData.db').execute(
  'select origin_url,username_value,hex_value,date_created from logins'):
    print(r)"
# ('https://target-shop.example','zhangsan@example.com',<密文>,17173728000000000)  ← Profile 1
# Profile 1 中目标站点 1 条，另有 87 条其他站点
```

若此步失败，正确结论是「密钥不匹配，DPAPI 需原机原用户上下文」，而不是反复重试。

第 4 步，时间线固化：

```bash
# logins.date_created 是 Chrome 的 WebKit 微秒时间戳
python3 -c "import datetime;print(datetime.datetime.utcfromtimestamp(17173728000000000/1e6))"
# 2024-06-03

# 与 History 的访问记录对齐
python3 -c "
import pysqlite3 as s,datetime
for u,t in s.connect('/evidence/History.db').execute(
  'select url,last_visit_time from urls where url like \"%target-shop%\" order by 2'):
    print(datetime.datetime.utcfromtimestamp(t/1e6), u)"
# 2024-06-03 ~ 2024-06-09 期间 11 次访问，与委托方时间窗一致
```

第 5 步，发现更高价值目标——**JWT 载荷本身就是明文**：

```bash
icat -o 2048 /evidence/DigiForensics.dd <inode> > /evidence/leveldb
strings -a /evidence/leveldb | grep -aoE 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
# 解码 payload（仅解码，不使用）
python3 -c "
import base64,json
p='<payload段>'
print(json.loads(base64.urlsafe_b64decode(p+'='*(-len(p)%4))))"
# {'sub':'<已脱敏>','iat':1717372800,'exp':1718001600}   ← 签发 2024-06-04，有效期 7 天
```

第 6 步，**确认 ABE 边界并把它变成正面证据**：

```bash
icat -o 2048 /evidence/DigiForensics.dd <inode> > /evidence/Cookies.db
python3 -c "
import pysqlite3 as s
for h,u in s.connect('/evidence/Cookies.db').execute('select hex(encrypted_value),host_key from cookies limit 5'):
    print(h[:2],u)"
# v20 ...               ← 前缀 v20 = 受 ABE 保护，本阶段未解密

# Chrome Application 日志中的对应痕迹
grep -aE 'Event ID 257|Decryption failed' /evidence/ChromeDebug.log
# Event ID 257 → 当时确有程序尝试解密受 ABE 保护的数据但被拒
```

第 7 步，合规处置：

```bash
# 未启动浏览器、未改配置、未注入进程、未使用口令或 token 访问该平台
# 全部结论仅基于本地文件的结构、时间戳与密文格式
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 该设备 Chrome `Profile 1` 保存有目标平台账号凭据 | `logins` 表命中 1 条 + 密文可解 | 强 |
| 该凭据创建于 2024-06-03 | `date_created` 转 WebKit 时间戳 | 强 |
| 该设备在 06-03 至 06-09 访问过该平台 | `History` 11 次访问记录 | 强 |
| 该设备持有签发于 06-04、有效期 7 天的会话 | JWT payload 的 `iat`/`exp` | 强（明文，不需解密） |

**不能证明的**：**「持有凭据」不等于「由本机实际操作人使用」**——Profile 可能被多人共用，也可能凭据是从别处导入的。

JWT payload 可读不代表会话在检材形成时仍然有效（本案签发后 7 天过期，是否被使用需服务端日志佐证）。

「v20 未解密」是明确边界，必须写进报告，不能藏。

**误判对照**

本案最容易犯的错误是因为 Cookies 里有 `v20` 前缀没解开，就在报告里写「浏览器凭据部分未能解密，数据获取不完整」。

**为什么这个表述是错的**：**未解密的部分和已解开的部分根本不是同一类数据**。

`Login Data` 是保存的口令（可解，且已解出目标站点），`Cookies` 里 `v20` 前缀的是受 ABE 保护的会话数据。

**前者直接支撑了委托方的核心诉求**，后者只是附加信息。

用一个附加项的失败去概括整体成果，等于用最小的那个短板否定了已经坐实的结论。

**正确判据有三条**：

1. `v20` 未解开的正确表述是「受 ABE 保护，本阶段未解密」，不是「数据获取失败」。必须同时写明依据（`Local State` 无 `app_bound_encrypted_key`，说明该部分数据由其他机制或更高版本写入）。
2. 必须逐 Profile、逐浏览器统计，不要合并报数。本案 3 个 Profile 里目标账号只在 `Profile 1`，**只查 `Default` 会直接漏掉核心证据**；反过来，若把三个 Profile 的 88 条记录混成一条，也会让委托方无法判断命中范围。
3. **Event ID 257 是独立痕迹证据**。它说明「当时确有程序尝试解密但被拒」，把一条边界说明转化为正面证据——**日志层面的痕迹比格式推断更硬。**

**按错误判据走的代价**：委托方看到「未能完整解密」，会怀疑已经给出的结论是否可靠，甚至要求重新送检。

而实际上核心结论——**持有凭据 + 特定时段持有会话**——证据链已经完整。

为了一条不影响结论的附加信息，否定了已经站得住的证据，这是取证写作里性价比最差的错误。

<a id="section-35"></a>

### 5.2 DPAPI 密钥不匹配时的正确停手方式

**场景**

另一宗委托，同类 Windows 11 设备，但 `Login Data` 解密返回 `CryptUnprotectData` 失败。若在此处反复重试或换工具空转，很容易写出方向完全相反的结论。

**处置过程**

按三步定位失败原因，**任一步失败即应停手并定性**：

```bash
# 第 1 步：确认 DPAPI 前缀是否正常（正常为 DPAPI + 0x01 0x00 0x00 0x00）
xxd -l 16 /evidence/LocalState.json_encrypted_key
# 44 50 41 50 49 01 00 00 00 ...   ← 前缀正常

# 第 2 步：确认 SYSTEM/SOFTWARE 是否取自同一镜像同一偏移
icat -o 2048 /evidence/DigiForensics.dd <sys-inode>  > /evidence/SYSTEM
icat -o 2048 /evidence/DigiForensics.dd <soft-inode> > /evidence/SOFTWARE
ls -l /evidence/SYSTEM /evidence/SOFTWARE
# 两者必须来自同一次挂载，偏移不同会导致主密钥解不开

# 第 3 步：确认 DPAPI 主密钥归属的 SID 与 Profile 用户是否一致
python3 -c "
import json;print(json.load(open('/evidence/LocalState.json'))['os_crypt'].get('encrypted_key','')[:20])"
# 解出的 SHA1 应与 <user SID>\AppData\...\Protect\<SID>\ 下主密钥匹配
```

```bash
# 归属检查：本机 profile 路径
fls -o 2048 -r /evidence/DigiForensics.dd | grep -i 'Protect/.*/[0-9a-f-]\{36\}$'
# S-1-5-21-*-1001/...   ← 只有 1001 的主密钥，没有目标用户的
```

**结论**

- 本次**未能解开 DPAPI 保护的凭据**，正确原因为：检材中的 DPAPI 主密钥与目标 Profile 的用户 SID 不匹配。这属于**上下文缺失**，不是算法问题。
- **阴性发现必须限定范围**：「在本案检材范围内（该机器的 `Protect\<SID>` 目录中）**未发现**与目标 Profile 用户 SID 匹配的主密钥」。**未覆盖范围**包括：该用户的漫游配置备份、其他曾登录该账号的设备、系统卷影副本中的旧版本 `SOFTWARE`。
- 报告必须写明停手理由与依据，**不得写成「解密失败，因技术原因无法处理」**——两者对委托方的后续动作指导完全不同。

**误判对照**

错误结论是「**浏览器凭据加密强度较高，本次分析无法突破**」。

**为什么它错**：DPAPI 的设计目标是**绑定到用户上下文**，而不是提供高强度抗分析。

它的实际含义是「**你手上没有这台机器上这个用户的完整环境，就解不开**」。

把它描述成「加密强度高」，会误导委托方把问题理解成技术对抗，而不是检材范围问题——进而可能要求升级投入或者转向其他方向。

**正确判据有三条**：

1. **必须区分「上下文缺失」与「强度不足」**。判据是 SID 与主密钥归属是否匹配：**不匹配 → 上下文缺失**（换个检材可能就能解）；**匹配但算不动 → 强度问题**。**两者的后续路径完全相反。**
2. **必须报告停手条件，而不是报告失败**。写「所需条件：目标 SID 对应的 DPAPI 主密钥或该用户的登录口令」，委托方就知道下一步该提供什么。**只写「失败」等于把问题原样退回。**
3. **不要反复重试同一路径**。DPAPI 主密钥匹配与否是个二值判定，**换工具、换参数不会改变结果**。反复重试只是把时间耗在确定性失败的路径上。

**按错误判据走的代价**：委托方收到「无法突破」的结论后，会认为需要引入更昂贵的手段或直接放弃这条证据线。

而真实情况可能只是检材只覆盖了这台机器，而目标用户的 profile 在另一台设备上——多一个检材就能解决。

把范围问题误判成技术问题，**会让调查在错误的维度上消耗资源**。

<a id="section-36"></a>

### 5.3 反例：历史搜索记录作为独立发现单列

**场景**

在 5.1 的同一台设备上，`History` 库的 `keyword_search_terms` 中存在若干条与本案争议事实直接相关的搜索记录——但委托方要证明的是「持有凭据 + 访问过该平台」，**搜索记录不在委托范围内**。

**处置过程**

按范围外发现的处理方式单列登记：

```bash
python3 -c "
import pysqlite3 as s,datetime
for t,u in s.connect('/evidence/History.db').execute(
  'select term,url from keyword_search_terms'):
    print(u, t)"
# https://www.baidu.com/  <争议事实相关检索词，已脱敏>
# https://www.bing.com/    <争议事实相关检索词，已脱敏>
```

**结论**

- 报告里**单列为一项独立发现**（「浏览器搜索历史（时间范围），其中若干条与本案争议事实直接相关」），**而不是混在「其他信息」里一笔带过**。
- 搜索词内容在报告中**做脱敏处理**，按需在受控附件中提供完整值。
- **不能证明的**：搜索记录**只能证明「该 Profile 发起过该检索」**，不能证明「检索人就是委托方认定的操作人」，也不能证明「检索动机与争议事实相关」——检索词的相关性是分析判断，需在报告中如实标注为判断而非事实。
- **未覆盖范围**：未做该 Profile 是否被多人共用的排查（本次未取得用户登录与远程会话记录）。

**误判对照**

两种错误方向：一是**把搜索记录当作「用户主观故意」的证据**写进结论，二是**因为不在委托范围内就完全不记录**。

**为什么两者都站不住**：第一种把「检索行为」等同于「主观故意」——但搜索行为有大量中性解释（替他人查资料、误触推荐、他人共用电脑）。

第二种则造成漏报：一旦后续争议点转移到「该设备是否知情」，**这条线索的缺失会让整个调查失去方向**。

**正确判据有三条**：

1. 搜索记录只能支撑「行为发生」，不能支撑「主观状态」。报告里写「该 Profile 于 X 时间发起过与争议事实相关的检索」是事实陈述；写「用户明知并主动检索」是主观推断——**后者必须有其他证据支撑才能成立**。
2. **范围外发现必须单列，不能一笔带过**。混进「其他信息」的发现，在后续争议中很难被援引——**报告结构本身就是证据强度的一部分**。
3. **检索词必须脱敏**。检索内容往往涉及个人隐私，报告正文写「与争议事实相关的检索若干条」，完整词条入受控附件，遵循与凭据同级的最小化原则。

**按错误判据走的代价**：把搜索记录写成主观故意的证据，一旦被对方质疑「这台电脑是共用」，报告就会在这处失守，并连带削弱其余部分的可信度。

而完全不记录，则在争议点转移时无据可依——**漏报在诉讼阶段暴露的代价比误报更难补救**。

<a id="section-37"></a>

## 六、扩展阅读方向

下面四组方向按"你在这条路上会撞到什么"组织。


**第一组：前置基础——机制侧的三块拼图**

本篇是应用层取证，往下追会撞到三个独立的机制层。

跳过它们，遇到异常就只能靠试。

- [EFS 文件系统加密取证](../crypto-volume/crypto-volume-efs.md) —— 浏览器密码库保护的底层就是 DPAPI，而 DPAPI 主密钥的解法（用户 profile 里的 `Protect\<SID>\<GUID>\`、密码派生、离线爆破）在 EFS 那篇讲得更完整。**两篇合起来才是一条完整的解密链**：DPAPI 断了，浏览器的 `v10`/`v11` 与 EFS 的 `$EFS` 流会同时打不开。
- [SQLite 基础与结构](../../mobile/mobile-database/mobile-database-sqlite.md) 与 [SQLite WAL 取证](../../mobile/mobile-database/mobile-database-sqlite-wal.md) —— `Login Data`、`Cookies`、`Web Data` 都是 SQLite 库。只读拷贝时漏掉 `-wal` 与 `-shm` 会让你看到"少了最近的数据"，而这在浏览器场景里常常正是最关键的部分。
- [Windows 注册表取证](../../computer/computer-registry-log/computer-registry-log-registry-forensics.md) —— Profile 路径、浏览器安装记录、ABE 策略项 `ApplicationBoundEncryptionEnabled`、以及企业漫游配置都落在注册表里。ABE 是否被策略关闭，直接决定你面对的是 `v10` 还是 `v20`。

**第二组：同层深入——其它形态的凭据与其它证据层**

- [远程工具凭据解密](crypto-app-remote-tool-credential-preservation.md) —— 本篇讲"浏览器里存了什么"，那篇讲"业务客户端与远控软件里存了什么"。两者的字段分级方法论完全一致：明文 / 可逆编码 / 加密 / 单向哈希四类，**遇到哈希就该停手**。合起来才是 Windows 单机的凭据地图。
- [浏览器取证](../../computer/computer-browser-behavior/computer-browser-behavior-browser-forensics.md) —— **凭据存在与凭据被使用是两条独立的证据链。** 本篇给出"这个人掌握哪些账号"，那篇给出"这个人实际访问过什么"。只有把覆盖面（有哪些账号）与使用记录（访问了哪些）分开表述，报告才不会把两件事混为一谈。
- [Keychain 与 Safari 痕迹](../../computer/computer-security/computer-security-keychain-safari.md) —— macOS 侧的对位文章。Safari 凭据走的是钥匙串而非 DPAPI，机制完全不同，本篇的 Chromium 路径在 macOS 上不适用。
- [Windows 11 与 Recall](../../computer/computer-browser-behavior/computer-browser-behavior-windows11-recall.md) —— 新机制会改变"浏览器是唯一凭据集中地"这个前提。做时间线推断时需要知道系统侧还有哪些工件在同期记录访问行为。

**第三组：判据与反例——判断"解不开"和"用过了"**

本篇最容易出错的两个结论，都出在这一组。

- [内存取证总览](../../memory/memory-acquire/memory-acquire-memory-forensics-overview.md) 与 [内存中的凭据与密钥](../../memory/memory-artifact/memory-artifact-memory-credentials-and-keys.md) —— 面对 `v20` 数据，"在目标机器上让它保持运行态从内存取密钥"是三条应对路径之一。但那改变了检材状态、破坏了"关机镜像"这个取证前提，代价必须写进报告。方法论见[内存证据的可采性与报告](../../memory/memory-artifact/memory-artifact-memory-evidence-and-reporting.md)：**内存结论的强度天然弱于磁盘结论，表述方式也不同。**
- [通用密码恢复](crypto-app-passware-and-password-recovery.md) —— Firefox 的 `key4.db` 主密码未知时，本篇能给出的答案是"本阶段不可解"；那篇给出**授权范围内的离线恢复方法论**与"为什么暴力破解必须是最后手段"的优先级。**它的三条合规红线对本篇同样适用。**
- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— 本篇依赖浏览器的文件时间与数据库写入顺序来判断"最后一次使用"。**当对方有技术能力时，这些前提本身需要独立检验**：同一事实能否从历史记录、下载目录这类另一类痕迹侧印证。

**第四组：结论表述——把发现写成能进报告的句子**

- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 本篇的处置纪律（先定位所有 Profile 再动手、提取范围一次定全、提取物单独归档不上网）的上游依据。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md) —— **"证明使用痕迹"与"使用凭据"的分界**。本篇全部产出物默认按前者处置：固定、记录、脱敏、上报。一旦进入后者（用提取出的 token 访问系统验证），性质就变了。
- [时间线重建](../../computer/computer-log/computer-log-linux-timeline-reconstruction.md) —— 凭据的覆盖面 + 使用记录 + 文件时间三者合并后如何排序、如何标注置信度、冲突如何处理。**本篇的产出是这条时间线的输入，不是它的替代品。**

**一句话总结这四组**：机制侧的三块拼图决定你能不能解开（DPAPI、SQLite WAL、注册表策略项）；同层深入那组决定你会不会漏（第二个浏览器、macOS 钥匙串、凭据 vs 使用）；判据与反例那组决定你会不会写下"无法解密"这种含糊话——正确写法是"受 ABE 保护，在现有检材范围内不可解"并列出未覆盖范围；最后一组决定你交出去的东西能不能被复核。

四组缺任何一组，本篇的产出都只是"技术上提取到了东西"，而不是"一份能进报告的结论"。
<a id="section-38"></a>

## 七、命令速查

```powershell
# ===== 1. 定位（逐个浏览器列出所有 Profile，不要只取 Default）=====
Get-ChildItem "C:\Users\*\AppData\Local" -Directory |
  Where-Object { $_.Name -match 'Google|Microsoft|BraveSoftware|Vivaldi' }
Get-ChildItem "C:\Users\zhang\AppData\Local\Google\Chrome\User Data" -Directory |
  Where-Object { Test-Path "$($_.FullName)\Login Data" } | Select-Object -Expand Name

# ===== 2. 判断 ABE 是否启用（决定哪些数据能解）=====
python -c "
import json, base64, os
p = os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\User Data\Local State')
s = json.load(open(p, encoding='utf-8'))['os_crypt']
print('传统键前缀:', base64.b64decode(s['encrypted_key'])[:5])   # 应为 b'DPAPI'
print('ABE 已启用:', 'app_bound_encrypted_key' in s)
if 'app_bound_encrypted_key' in s:
    print('ABE blob 前缀:', base64.b64decode(s['app_bound_encrypted_key'])[:4])  # b'APPB'"

# ===== 3. 提取（仅标准库；必须在原机原用户上下文运行）=====
python chrome_creds.py "C:\Users\zhang\AppData\Local\Google\Chrome\User Data"
# Linux Chromium：主密钥源自硬编码 peanuts，路径 ~/.../User Data/Local State
# Firefox：logins.json + key4.db（NSS），有 Primary Password 则不可解

# ===== 4. 只看密文前缀（不接触内容即可判断加密世代）=====
sqlite3 "Cookies" "SELECT host_key, hex(substr(encrypted_value,1,3)) FROM cookies LIMIT 20;"
# 763130 = v10 → AES-256-GCM，走传统 DPAPI 主密钥
# 763230 = v20 → ABE 保护，需 2.5 的路径；传统流程必然失败

# ===== 5. 明文类高价值目标 =====
Get-ChildItem "…\Profile 1\Local Storage\leveldb" | Select-Object -First 5
Select-String -Path "D:\evidence\DigiForensics-mem.raw" -Pattern "eyJ[A-Za-z0-9_-]{20,}" -AllMatches |
  Select-Object -First 20   # JWT：payload 直接 base64url 解码

# ===== 6. 旁证 =====
Get-EventLog -LogName Application -Source Chrome | Where-Object { $_.EventID -eq 257 }
# Event ID 257 = ABE 校验失败，说明当时有程序尝试解密受保护数据

# 🚫 全流程硬性禁止：用提取的凭据或 token 登录/访问任何站点
# ✅ 正确做法：离线提取 → 脱敏记录 → 封存移交 → 仅用于证明"使用痕迹"
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 加密取证 — 浏览器密码库与 Token 提取」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《浏览器密码库与 Token 提取》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-mem.raw` 均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
