---
title: "Keychain 与 Safari 痕迹"
slug: "computer-security-keychain-safari"
canonical: "https://www.digiforensics.cn/wiki/computer-security-keychain-safari"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:49+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "computer"
space: "计算机取证"
node_path: ["安全与权限"]
---

# Keychain 与 Safari 痕迹

<a id="section-1"></a>

## 一、概述

Keychain 承载 macOS 的凭据存储，Safari 的 `History.db` 记录该浏览器自身的访问行为。 在 Windows 上这两件事分别对应「凭据管理器」和「Chrome/Edge 的 History 数据库」，但有两处差异必须先讲清。

第一，Keychain 条目不保存明文口令，口令字段以加密形式存储，但条目同时保存「这个凭据是给谁用的、什么时候建的」。 光是这条信息就有取证价值——一个标签为 `mail.google.com` 的条目，**在取得钥匙串访问权后即可证明该机上存在这个服务对应的凭据条目**；条目上的 `kSecAttrCreationDate` 与 `kSecAttrModificationDate` 记录的是条目本身的创建与修改时间，不是口令被使用的时间（语义边界见 2.2）。

第二，Safari 的 `History.db` 在较新系统上是被加密的（SQLCipher），不是普通 SQLite。 直接用 `sqlite3` 打开会看到 `file is not a database` 或 `database disk image is malformed`。**这不是文件损坏，是加密。** 认错这一点，整个浏览器证据就会被写成「已损坏无法读取」，而实际只是解密方式不对。

两点合起来意味着：macOS 的凭据与浏览痕迹需要成对解读——Keychain 告诉你「该机存有哪些服务凭据、条目何时创建」，Safari 告诉你「这个站点被访问过、访问了什么」。 单独的任一半都不完整。

这两个工件落在「文件已固定、开始逐工件判读」这一步，属分析环节里的高敏感环节：

- **上游依赖**三项前置。磁盘解密状态（FileVault 已解密 ≠ Keychain 已解锁，这是两个独立动作）；用户身份的确认（**Keychain 是按用户隔离的**，`~/Library/Keychains/` 下每个用户一份）；以及 Safari 容器路径的确认，见[macOS 取证工件地图](computer-security-security-artifact-map.md)。
- **它自己**要先判断可解性。**不试解锁就先评估有没有必要**，因为解锁动作本身会改变钥匙串状态，且需要合法来源的密码。
- **下游支撑**访问行为的定性。Keychain 的元数据给出「登录过哪些服务」，Safari 给出「访问了什么内容」，两者交叉才能画出完整的活动画像。
- **它与其它浏览器材料是并列关系**：这里只处理 Safari 与 Keychain，Chrome / Firefox 在 macOS 上的路径不同，需要单独处理，见 2.9。

落到具体物件上：

| 形态 | 位置 | 关键结构 |
|---|---|---|
| 登录钥匙串 | `~/Library/Keychains/login.keychain-db` | **按用户隔离**；条目含 `kSecAttrLabel`、`kSecAttrAccount`、`kSecAttrCreationDate`、`kSecAttrModificationDate` |
| 系统钥匙串 | `/Library/Keychains/System.keychain` | 系统级，不含用户凭据 |
| 钥匙串工具 | `security` 命令行 | `unlock-keychain` 需要用户登录密码——**密码由用户登录密码派生，不是硬件密钥** |
| Safari 历史 | `~/Library/Containers/com.apple.Safari/Data/Library/Safari/History.db` | 较新系统上为 SQLCipher 加密，密钥在 Keychain 里；明文可用 `history_items` 与 `history_visits` 两表 |
| Safari 时间基准 | Apple 纪元（2001-01-01） | 时间戳要加 `978307200` 才是 Unix 秒，忘了加会全部显示为 2001 年附近 |
| 下载记录 | `.../Safari/Downloads.plist` | plist 格式，独立于 `History.db` |
| 会话恢复 | `.../Safari/LastSession.plist` | 记录上次打开的标签页 |
| Chrome 路径 | `~/Library/Application Support/Google/Chrome/` | Profile 目录结构，与 Safari 的容器路径不同 |
| Firefox 路径 | `~/Library/Application Support/Firefox/Profiles/` | `places.sqlite` |

三个判定要点：Keychain 的**加密密钥来自用户登录口令而非硬件**、Safari 的**时间基准是 Apple 纪元**、以及**加密不是损坏**。

据此能回答的是：该机登录过哪些服务、每条凭据的创建与修改时间、某个站点的访问历史与访问次数、下载过哪些文件、上次会话打开的页面、以及**某个凭据属于哪个账户**。

回答不了的是这些，其中几条是必须先纠正的误解。

- 「FileVault 恢复密钥能打开 Keychain」是错的。 FileVault 解决的是磁盘加密，Keychain 的加密密钥由**用户登录口令派生**。两个都没有时**只能读元数据（标签、账户、日期），读不到明文**。报告里必须区分「已解密磁盘」与「已解锁钥匙串」这两个独立动作。
- **明文凭据。** 这里只固定与识别凭据材料，**不记录、不摘录口令本身**。解锁用的口令必须合法取得，报告中只写「已使用合法取得的用户口令解锁」。
- Safari 加密数据库的内容（在未取得密钥时）。 读到 `file is not a database` 时，正确写法是「该数据库经 SQLCipher 加密，需 Keychain 中的密钥解密；本次未取得密钥，仅记录文件存在与哈希」。绝不能写成「数据库损坏」或「数据已丢失」——这是事实性错误，会直接影响委托方对证据可用性的判断。
- **Chrome / Firefox 的浏览痕迹。** 它们在 macOS 上的路径与数据结构都不同，**不能用 Safari 的方法套用**。
- **凭据的实际使用行为。** Keychain 记录的是「凭据存在」，**不是「某时用这个凭据访问了某站点」**。
- **设备上不存在的浏览器。** 只装了 Safari 的机器上，Chrome 路径不存在，**这是预期状态而非异常**。

相关基础包括：macOS 目录结构，特别是 `~/Library` 的分层与沙盒容器路径（见[macOS 取证工件地图](computer-security-security-artifact-map.md)）；SQLite 基本操作与 `file` 命令的文件类型判断，否则无法区分「加密」与「损坏」；

macOS 时间基准的特殊性——Apple 纪元与 Unix 纪元差 `978307200` 秒，见[时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md)；以及 plist 格式的两种形态，见[plist 与偏好设置](../computer-plist-spotlight/computer-plist-spotlight-plist.md)。

还有一条原则不能松：**明确授权与最小化原则**。这里涉及的凭据材料属高敏感证据，摘录范围须与授权范围一致并做脱敏，见[合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md)。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 Keychain 的文件布局

| 路径 | 内容 | 权限 |
|---|---|---|
| `~/Library/Keychains/login.keychain-db` | **用户登录钥匙串**（新版文件名） | `drwx------`，属主用户 |
| `~/Library/Keychains/metadata.keychain-db` | 元数据钥匙串 | 同上 |
| `~/Library/Keychains/<Hardware-UUID>/` | **按主机划分的子钥匙串** | `drwx------` |
| `/Library/Keychains/System.keychain` | **系统钥匙串**（证书、系统凭据） | `root:wheel` |

布局示例（UUID 为虚构值）：`login.keychain-db`、`metadata.keychain-db`，以及一个与 Hardware UUID 同名的子目录 `00000000-0000-4000-8000-000000000001/`。`security list-keychains` 返回 `"/Users/<u>/Library/Keychains/login.keychain-db"` 与 `"/Library/Keychains/System.keychain"`。

`<Hardware-UUID>` 子目录常被忽略。

它与 `Preferences/ByHost/` 的命名规则一致（见[03](../computer-plist-spotlight/computer-plist-spotlight-plist.md)，因此可以用该子目录名与本机 `Hardware-UUID` 比对，判断某一钥匙串数据是否与本机对应；但仅凭目录名不能判断它是本机生成的、还是由备份或迁移导入的。

目录内是按用途划分的 SQLite 数据库，实测含 `com.apple.security.keychain-defaultContext.TrustedPeersHelper.db` 等（`TrustedPeers` 机制用于 Safari/iCloud 的信任链）。

<a id="section-4"></a>

### 2.2 Keychain 条目的四个关键属性

每个 Keychain 条目携带四个对取证最有价值的属性：

| 属性 | 含义 | 取证价值 |
|---|---|---|
| **`kSecAttrLabel`** | 人类可读的服务名，如 `mail.google.com`、`Wi-Fi SSID` | ★ 直接说明"这个凭据管什么" |
| **`kSecAttrAccount`** | 账号标识（用户名、邮箱） | ★ 关联到具体人员 |
| **`kSecAttrCreationDate`** | 条目创建时间 | ★ 条目在该机出现的最早时间锚点 |
| `kSecAttrModificationDate` | 条目最后修改时间 | ★ 条目最后一次内容变更的锚点 |

这四个属性合起来反映的是**条目本身的生命周期**，而不是口令被取用的时刻。

比如一个 `kSecAttrCreationDate` 为 2024-03-15 的 `mail.google.com` 条目，只能说明该机在此期间存入过这个服务凭据；条目创建后可能长期未被使用，也不能反推该时段内有人实际登录或访问。

> **关键限制：这四个属性是元数据，在取得钥匙串读取权限后不需要解密口令字段即可读出。**

但**口令内容需要用户口令解锁**（见 2.4）。

报告里"存在某服务的凭据条目"与"获取到该服务的口令"是两种不同的证据强度：前者可从元数据得出，后者需合法取得用户口令并说明依据；"条目存在"同样不能直接写成"该机登录过该服务"。

<a id="section-5"></a>

### 2.3 `security` 命令

`security` 的核心子命令：`list-keychains`（列搜索路径）、`find-generic-password -s <服务>`（找通用密码条目）、`find-internet-password -s <站点>`、`dump-keychain <路径>`（全量导出）。

**`-g` 参数在取证中属于敏感操作**：它会尝试显示口令，并触发钥匙串的访问授权交互。 部分资料称该参数会改动钥匙串访问控制列表，这一点应在检材工作副本上先行实测确认，不要在原始检材上验证。

**只应在检材工作副本上使用，并记录这一事实。**

<a id="section-6"></a>

### 2.4 解锁：为什么需要用户密码

Keychain 的加密密钥由**用户登录口令派生**，不是硬件密钥。后果是：

| 场景 | 能否读取 |
|---|---|
| 已有用户密码 | 可解锁，读取明文凭据 |
| 知道 FileVault 恢复密钥 | ★ **不够**——FileVault 解决的是磁盘加密，Keychain 需要的是**用户登录密码** |
| 两者都无 | 只能读元数据（`Label`/`Account`/日期），**读不到明文**（元数据的可读性还取决于钥匙串文件本身的访问权限与系统版本，见 2.2） |

> **这是最常见的误解之一**：拿到 FileVault 恢复密钥 ≠ 能打开 Keychain。报告里必须明确区分"已解密磁盘"与"已解锁钥匙串"这两个独立动作。

`security unlock-keychain <路径>` 会交互式要求输入口令（`password to unlock <path>:`）。

**取证场景下口令来源必须合法且可追溯**（委托人当面提供、经书面授权的记忆、或依法调取），报告中只写"已使用合法取得的用户口令解锁"，绝不记录口令本身。

<a id="section-7"></a>

### 2.5 Safari 的路径：两个位置

| 路径 | 适用 | 说明 |
|---|---|---|
| `~/Library/Safari/` | 10.13 及以前 | 传统路径 |
| `~/Library/Containers/com.apple.Safari/Data/Library/Safari/` | **10.14 Mojave 起** | ★ **沙盒容器路径，现代系统的真实位置** |

```
~/Library/Containers/com.apple.Safari/Data/Library/Safari/
├── History.db              # 历史记录（★ 加密，见 2.6）
├── History.db-shm / -wal   # WAL 模式的伴随文件（★ 必须一起提取）
├── Bookmarks.plist         # 书签（二进制 plist）
├── Extensions/             # Safari 扩展
├── Downloads.plist         # ★ 下载记录（见 2.7）
├── LastSession.plist       # ★ 上次会话的标签页（见 2.8）
└── Favicons/  Snapshots/   # 站点图标与快照
```

> `.db-shm` 与 `.db-wal` 必须与 `History.db` 一起提取。 SQLite 的 WAL 模式下，最近的事务可能只存在于 `-wal` 文件中而未回写主库。只拷 `History.db` 会丢掉最近几小时到几天的记录——**这是 Safari 取证最常见的漏检点。**

<a id="section-8"></a>

### 2.6 `History.db` 的加密

较新 macOS 上 Safari 的 `History.db` 使用 **SQLCipher** 加密，密钥存放在 Keychain 中（`Safari` 相关条目）。

```sql
-- 解密后可见的核心表
SELECT datetime(last_visit_time + 978307200, 'unixepoch', 'localtime') AS 本地时间,
       url, visit_count
FROM history_items
ORDER BY last_visit_time DESC LIMIT 20;

SELECT datetime(visit_time + 978307200, 'unixepoch', 'localtime') AS 本地时间, url
FROM history_visits
JOIN history_items ON history_items.id = history_visits.history_item
ORDER BY visit_time DESC LIMIT 50;
```

`978307200` 是 Cocoa/Apple 纪元（2001-01-01）与 Unix 纪元的差值，Safari 的时间戳要加上它才是 Unix 秒。忘了加这个常量，所有时间都会显示为 2001 年附近。

```bash
# 判断是否加密
file History.db
file -b History.db | head -c 16          # "SQLite format 3" = 未加密；否则为加密
sqlite3 History.db "select count(*) from history_items;"
# → Error: file is not a database     ← 这是加密，不是损坏
```

> **报告写法约束**：读到 `file is not a database` 时，正确写法是"该数据库经 SQLCipher 加密，需 Keychain 中的密钥解密；本次未取得密钥，仅记录文件存在与哈希"，**绝不能写成"数据库损坏"或"数据已丢失"**。这是事实性错误，会直接影响委托方对证据可用性的判断。

<a id="section-9"></a>

### 2.7 下载记录 `Downloads.plist`

Safari 的下载历史在 `~/Library/Containers/com.apple.Safari/Data/Library/Safari/Downloads.plist`。

```bash
plutil -p ~/Library/Containers/com.apple.Safari/Data/Library/Safari/Downloads.plist | head -30
plutil -convert xml1 -o - ~/Library/Containers/com.apple.Safari/Data/Library/Safari/Downloads.plist \
  | grep -B2 -A6 'DownloadEntry'
```

**它的价值在于记录的是"下载条目"而不是"文件"**——即使用户后来把文件移到别处或删除，下载条目可能仍在（具体保留策略随系统版本变化）。

它应与 Quarantine 属性（见[05](computer-security-quarantine-gatekeeper.md)）和 `kMDItemWhereFroms`（见[04](../computer-plist-spotlight/computer-plist-spotlight-spotlight.md)）三者对照使用。

| 工件 | 记录什么 | 是否需要解密 |
|---|---|---|
| `Downloads.plist` | Safari 下载条目 | 否（二进制 plist，`plutil` 可读） |
| `com.apple.quarantine` xattr | 下载时间 + 来源应用 | 否 |
| `kMDItemWhereFroms` | 下载来源 URL | 否（但需现场采集） |
| `History.db` | 访问历史 | **是** |

<a id="section-10"></a>

### 2.8 `LastSession.plist` 与会话恢复

`LastSession.plist` 保存上次关闭 Safari 时打开的标签页。

```bash
plutil -p ~/Library/Containers/com.apple.Safari/Data/Library/Safari/LastSession.plist | head -20
```

**取证价值有限，但不为零**：它能反映"关机前用户在看什么页面"，是案件时间点之前用户**打开过的**页面集合。

不过要注意：

- **它的 mtime 是最后写入时间**（通常是 Safari 退出时间），**不代表页面访问时间**
- **它只反映"未关闭的标签页"**，用户正常关闭的页面不在其中
- **必须与 `History.db` 的访问时间交叉**，不能单独作为"访问过该网站"的证据

<a id="section-11"></a>

### 2.9 Chrome / Chromium / Firefox 在 macOS 上的路径

| 浏览器 | 路径 | 关键文件 |
|---|---|---|
| **Chrome** | `~/Library/Application Support/Google/Chrome/` | `Default/History`（SQLite）、`Default/Login Data`（凭据）、`Default/Bookmarks`（JSON） |
| **Chromium** | `~/Library/Application Support/Chromium/` | 同上（Profile 目录名可能不同） |
| **Edge** | `~/Library/Application Support/Microsoft Edge/` | 同 Chromium 系 |
| **Firefox** | `~/Library/Application Support/Firefox/Profiles/<profile>/` | `places.sqlite`、`logins.json`、`key4.db` |
| **Arc / Brave** | `~/Library/Application Support/` 下同名目录 | Brave 为 `BraveSoftware/Brave-Browser/` |

```bash
# Chrome 历史（Chrome 的 History 无需 Keychain 即可读）
EV=/mnt/mac-data/Users/liwei
sqlite3 "$EV/Library/Application Support/Google/Chrome/Default/History" \
  "SELECT datetime((visits.visit_time/1000000)-11644473600,'unixepoch','localtime'), url
   FROM visits JOIN urls ON visits.url=urls.id ORDER BY visit_time DESC LIMIT 20;"

# Chrome 凭据表结构（值本身加密，键值表可读）
sqlite3 "$EV/Library/Application Support/Google/Chrome/Default/Login Data" \
  "SELECT origin_url, username_value, hex(encrypted_value) FROM logins LIMIT 10;"

# Firefox 历史
sqlite3 "$EV/Library/Application Support/Firefox/Profiles/default.default-release/places.sqlite" \
  "SELECT datetime(last_visit_date/1000000,'unixepoch','localtime'), url FROM moz_places ORDER BY last_visit_date DESC LIMIT 20;"
```

> **三个时间基数的差异是本节最易错的地方**：

| 浏览器 | 存储形式 | 转 Unix 秒的方法 |
|---|---|---|
| **Chrome/Chromium** | **微秒**（1e-6 s），且**自 1601-01-01 起算** | `(值 / 1000000) - 11644473600` |
| **Firefox** | **微秒**，自 Unix 纪元 | `值 / 1000000` |
| **Safari** | **秒**，自 2001-01-01 起算 | `值 + 978307200` |

Safari 与 Chrome 的差值（978307200）符号是加，Chrome 是减且多除 1000000。

写错会让全部时间落到 1601 年或 2025 年之后。

**Chrome 的历史数据不需要用户口令**（`History` 是普通 SQLite），**这与 Safari 形成鲜明对比**——"浏览器历史取不到"这个结论在 macOS 上往往只对 Safari 成立。

检材上如果有 Chrome，`History` 通常可直接读出访问 URL 与时间，但它同样受保留策略与用户自行清理影响，"更完整"指可读性而非覆盖度。

---

<a id="section-12"></a>

## 三、操作步骤

<a id="section-13"></a>

### 3.1 第 1 步：Keychain 目录清点与归属判定

```bash
EV=/mnt/mac-data/Users/liwei
ls -la "$EV/Library/Keychains/" "$EV/Library/Keychains/"*/ 2>/dev/null | head -25
ls -la /mnt/mac-data/Library/Keychains/System.keychain

# ★ 归属判定：子目录名 vs 本机 Hardware UUID
# 本机 UUID 取自检材：/Library/Preferences/SystemConfiguration/prefs.plist
security list-keychains

# 按服务名查找（★ 不含密码，只看元数据）
security find-generic-password -s "mail.google.com" 2>&1 | head -20
#   0x00000007 <blob>="acct"<blob>="liwei@example.com"
#   0x00000007 <blob>="svce"<blob>="mail.google.com"
#   0x00000007 <blob>="cdat"<blob>=2024-03-15 09:22:41 +0800
#   0x00000007 <blob>="mdat"<blob>=2024-08-20 14:10:03 +0800
# ★ cdat = kSecAttrCreationDate，mdat = kSecAttrModificationDate（引用时保留原始键名）

security find-internet-password -s "portal.rival-exim.example" 2>&1 | head -15

# 全量导出（输出巨大，需重定向）
security dump-keychain "$EV/Library/Keychains/login.keychain-db" > /evidence/keychain-dump.txt 2>/dev/null
grep -c 'keychain:' /evidence/keychain-dump.txt
grep -E '"svce"|"acct"|"srvr"|"cdat"|"mdat"' /evidence/keychain-dump.txt | head -40
```

| 检查项 | 判定 |
|---|---|
| `login.keychain-db` 存在 | 该用户钥匙串文件存在（文件本身通常由系统在用户首次登录时创建，不能据此判断条目数量） |
| 多个 `<UUID>` 子目录 | 可能导入过其他主机的凭据（类似 ByHost 多 UUID） |
| `metadata.keychain-db` 存在 | 较新系统版本 |
| 子目录 UUID ≠ 本机 | **该目录可能来自其他机器，需单独核实** |

<a id="section-14"></a>

### 3.3 第 3 步：凭据时间线整理

```bash
# 从 dump 中提取"服务 / 账号 / 创建时间 / 修改时间"四元组
grep -E '"svce"|"acct"|"cdat"|"mdat"' /evidence/keychain-dump.txt \
  | sed 's/.*="\(.*\)".*/\1/' | paste - - - - 2>/dev/null | head -20
```

| 服务（`svce`） | 账号（`acct`） | 创建（`cdat`） | 修改（`mdat`） | 意义 |
|---|---|---|---|---|
| `mail.google.com` | `liwei@example.com` | 2024-03-15 09:22:41 | 2024-08-20 14:10:03 | 长期使用的邮箱凭据 |
| `AirPort <SSID>` | — | 2024-05-02 11:03:22 | 2024-05-02 11:03:22 | 曾连接过的 Wi-Fi |
| `vpn.partner-portal.example` | `liwei` | 2024-08-25 20:15:33 | 2024-08-25 20:15:33 | 一次性使用的 VPN 凭据（cdat == mdat） |

> **`cdat == mdat` 是个值得留意的信号**：在条目创建之后，系统没有再改写过它的内容。

这只说明"条目未被改写"，不能反推使用方式：条目可能在创建时就已写入最终内容并长期只读使用；时间也可能因导入或批量写入而与目录 mtime 同步。对一次性凭据（如临时 VPN、一次性登录）这符合预期；对长期服务凭据，也可能是口令自存入起就未变更。要区分这几种情况，需要结合条目所在钥匙串的创建时间、周边条目的时间分布和该服务的实际使用记录。

<a id="section-15"></a>

### 3.4 第 4 步：Safari 数据提取

```bash
SAF="$EV/Library/Containers/com.apple.Safari/Data/Library/Safari"

# ★ 必须三个文件一起提取
ls -la "$SAF"/History.db*                      # History.db, -shm, -wal
cp --preserve=timestamps "$SAF"/History.db* /evidence/safari/

# 判断是否加密
file -b "$SAF/History.db" | head -c 32
sqlite3 "$SAF/History.db" "select count(*) from history_items;" 2>&1 | head -2

plutil -p "$SAF/Bookmarks.plist" | grep -A3 'WebBookmarkTitle' | head -20   # 书签
plutil -p "$SAF/Downloads.plist" 2>/dev/null | head -30                      # 下载记录
plutil -p "$SAF/LastSession.plist" 2>/dev/null | head -15                    # 会话恢复
ls -la "$SAF/Extensions/"                                                     # 扩展（★ 可能的数据外泄渠道）
```

<a id="section-16"></a>

### 3.5 第 5 步：交叉验证

| 验证对象 | 方法 | 通过标准 |
|---|---|---|
| Keychain 归属本机 | 子目录 UUID vs Hardware UUID | 相同则归属本机 |
| 凭据与服务一致 | `svce` + Safari 历史域名 | 相互印证 |
| History.db 完整性 | `History.db` + `-wal` + `-shm` 齐全 | 三者都在 |
| 解密失败定性正确 | `sqlite3` 报 `file is not a database` | **定性为"加密"，不写"损坏"** |
| 时间基正确 | Safari +978307200 / Chrome -11644473600 | 转换后落在合理年份 |
| 凭据未泄露到报告 | 报告中无明文密码 | 只写服务名与账号 |

---
<a id="section-17"></a>

## 四、常见陷阱

<a id="section-18"></a>

### 4.1 解锁动作与钥匙串归属

<a id="section-19"></a>

#### 陷阱 1：以为 FileVault 恢复密钥能打开 Keychain

**现象**

拿到一台已解锁 FileVault 的 MacBook，随即尝试用恢复密钥或恢复口令去"解开" `login.keychain-db`，报告里写下「已解密钥匙串凭据」。或者反过来，钥匙串条目读不出来，就认为「FileVault 没解锁，数据不可用」。

**原因**

这两件事是**两条互不依赖的加密链**：

| 环节 | 保护对象 | 密钥来源 | 失败表现 |
|---|---|---|---|
| FileVault | 整个 APFS 容器 | 恢复密钥（26 位带连字符）/ 用户口令 | 容器无法挂载 |
| login.keychain | 钥匙串条目内的数据字段 | 用户登录口令派生的密钥 | 字段显示为十六进制 blob 或解密失败 |

FileVault 只保护"能不能看到文件系统"，它不解密钥匙串内部。

钥匙串的解锁是**登录时用用户口令完成的**，恢复密钥跟这条链没有任何关系。

**影响**

- 委托方会误以为「拿不到钥匙串 = 数据已彻底销毁」，从而放弃本来可行的取证方向
- 强行尝试用恢复密钥"解密"钥匙串，可能在副本上触发条目访问控制的重写，把工作副本也弄成不可用状态
- 报告里出现「已解密凭据」这种虚假陈述，性质比"没取到数据"严重得多

**核查**

把两次解锁动作分别记录、各自给结论：

```bash
# 第一步：确认 FileVault 已解锁（能挂载即说明这步已完成）
ls /mnt/mac-data/System/Library/  >/dev/null && echo "APFS 容器已挂载：FileVault 解锁步骤完成"

# 第二步：Keychain 是独立问题 —— 只能读元数据，密文字段不取
security find-generic-password -s "vpn.example.com" 2>&1 | head -20
#   只取 "svce" / "acct" / "cdat" / "mdat"，不要 -g
```

**报告写法**：「FileVault 已解锁，APFS 容器可读写；`login.keychain-db` 内的条目数据字段受用户口令保护，本次未取得口令，仅提取元数据（服务名、账号、创建/修改时间）。」

<a id="section-20"></a>

#### 陷阱 2：★ 在检材原件或共享工作副本上执行 `security ... -g` 试图读出密码

**现象**

为了"确认凭据能不能用"，直接对镜像挂载点里的 `login.keychain-db` 跑带 `-g` 或 `-w` 参数的 `security` 命令，期望把密码打出来。跑完发现命令挂住等输入，或者事后文件属性变了。

**原因**

`security` 系列命令的解密路径**不是纯读操作**：

- 解密成功后系统可能**把交互解锁结果写回钥匙串的访问控制列表**（更新 ACL 记录），这是一次对文件的实际写入；具体是否发生应在工作副本上实测确认
- 对挂载自镜像的原件执行，一旦确实发生写入，就意味着**检材被修改**，原始哈希不再成立
- 多数情况下还会**弹出图形化授权框**要求输入登录口令，在批处理环境里表现为进程挂起直到超时

同时这条命令的输出是**明文口令**，一旦进入终端 scrollback、shell history 或重定向文件，就已经构成凭据外泄。

**影响**

- **若确实发生写入，检材完整性即被破坏且不可逆**：无法证明镜像自 `dd` 之后未被工具改写，这在争议案件中会直接削弱证据资格
- 明文口令落盘，需要连带清理分析机上的临时文件，而清理本身又制造新的处置记录
- 大量时间耗在等待输入上，且最终拿到的往往还是 `security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.`

**核查**

**永远不取明文口令**。先用元数据完成全部能做的关联分析：

```bash
EV=/mnt/mac-data/Users/liwei
KC="$EV/Library/Keychains/login.keychain-db"

# 复制到分析侧工作副本再操作，避免挂载点上的原件被触碰
cp "$KC" /evidence/work/login-copy.keychain-db
chmod 600 /evidence/work/login-copy.keychain-db

# 只用不带 -g / -w 的查询：元数据足够支撑服务清单与时间线
security find-generic-password -s "mail.example.com" 2>&1 | head -20
security dump-keychain /evidence/work/login-copy.keychain-db > /evidence/keychain-dump.txt 2>/dev/null
grep -c 'keychain:' /evidence/keychain-dump.txt
```

报告中凭据一律表述为「**已确认该服务存在账号 `xxx` 的凭据条目**」，不出现值本身，也不出现"已验证可用"。

<a id="section-21"></a>

#### 陷阱 3：只清点 `login.keychain-db`，把 Hardware UUID 子目录当成噪声

**现象**

`ls ~/Library/Keychains/` 只看到 `login.keychain-db` 和 `metadata.keychain-db` 两个文件，就写下「钥匙串内无 VPN / 无线网络相关凭据」。

**原因**

`~/Library/Keychains/` 下除了这两个文件，还可能出现**以 Hardware UUID 命名的子目录**，用来存放从其他设备导入或同步过来的钥匙串信任数据（如 VPN 的 `com.apple.security.vpn-…` 信任对、无线网络凭据）。

这些内容**不在 `login.keychain-db` 里**，`security dump-keychain` 也不会列出它们。

再往前一步：**子目录名是 UUID，不等于它就属于本机。**

子目录名可能是另一台主机的 Hardware UUID——那意味着整套钥匙串信任数据是**被拷贝进来的**，不是本机联网产生的。判定必须做归属性核对：

```bash
# 本机 Hardware UUID 取自检材，不是分析机
plutil -p /mnt/mac-data/Library/Preferences/SystemConfiguration/prefs.plist \
  | grep -i -A2 'HardwareUUID'

ls -la /mnt/mac-data/Users/liwei/Library/Keychains/*/
# drwx------  8A2F4C19-7B3E-…/   ← 与本机 UUID 一致
# drwx------  6C9E2B34-…/        ← 不是本机 UUID，需单独核实来源
```

**影响**

漏掉子目录意味着**丢掉了"环境被整体拷贝"这一类入侵手法的关键痕迹**。

而把非本机 UUID 的子目录内容直接归入本机用户，会得出「用户主动配置了该 VPN」的错误归因 —— 实际可能是克隆环境时带进来的凭据。

**核查**

清点时**把子目录与主文件分开记录**，并对每个 UUID 逐一做归属判定：

| 检查项 | 结论方向 |
|---|---|
| `login.keychain-db` 存在 | 该用户钥匙串文件存在 |
| `metadata.keychain-db` 存在 | 较新系统版本 |
| 子目录 UUID == 本机 Hardware UUID | 与本机 Hardware UUID 一致的信任数据（不能据此断定生成来源） |
| 子目录 UUID ≠ 本机 | **可能为拷贝/导入，需追查来源** |

「主文件里没有」只能写成「`login.keychain-db` 内未发现该类条目」，不能扩展成「本机无该类凭据」。

<a id="section-22"></a>

### 4.2 字段语义与时间基

<a id="section-23"></a>

#### 陷阱 4：把 `cdat` 与 `mdat` 不相等一律读成"凭据被改过"

**现象**

导出的 dump 里某条目 `cdat` = 2024-03-15 09:22:41、`mdat` = 2024-08-20 14:10:03，报告写「该邮箱凭据于 8 月 20 日被修改，疑似攻击者更新了口令以维持访问」。

**原因**

`cdat`（`kSecAttrCreationDate`）与 `mdat`（`kSecAttrModificationDate`）记录的是**钥匙串条目自身属性**的创建与修改，而条目属性的修改触发条件非常宽：

- 用钥匙串访问修改口令后保存 → `mdat` 变
- 该条目被应用（如 Mail、VPN 客户端）**重新访问或更新扩展属性** → `mdat` 变
- 条目被移动到别的钥匙串或同步过一次 → `mdat` 变
- **浏览器或系统凭据同步服务重新写入** → `mdat` 变

`mdat` 变**不等于口令值变了**。反过来，`cdat == mdat` 也只能说明条目自创建起没有再被写开过：时间精度、与目录 mtime 的同步、导入与批量写入都可能产生同样的形态，不能直接写成"从未被写过"或"一次性凭据"。

**影响**

把正常的凭据轮换写成"攻击者更新口令"，会把调查方向引向并不存在的口令泄露；在报告里点名某个时间点"凭据被修改"，还可能引导委托方错误地认定某个时间段是攻击窗口。

**核查**

先看模式，再看时间差，并**优先用其他独立来源交叉**：

```bash
# 把 cdat/mdat 与条目所在目录、文件的时间戳一起比对
grep -E '"svce"|"acct"|"cdat"|"mdat"' /evidence/keychain-dump.txt | head -40
stat /mnt/mac-data/Users/liwei/Library/Keychains/login.keychain-db
```

| 模式 | 判读 |
|---|---|
| `cdat == mdat`（精确到秒） | 条目创建后未被再次写开，与"一次性凭据"形态一致，但不排除批量导入 |
| `cdat == mdat` 且与所属目录/文件时间戳一致 | 疑似**整套拷贝**进来的环境，而非本机产生 |
| `mdat - cdat` 跨度数月 | 长期使用的服务凭据，**不能据此认定被改** |
| `mdat` 明显晚于案件关键时间点 | 作为**关注点**列出，同时寻找其他独立证据 |

「`mdat` 变化」只能写成属性层面的观察，口令是否改过需要口令哈希、旧版本条目或其他来源佐证。

<a id="section-24"></a>

#### 陷阱 5：Safari 时间戳忘了加 `978307200`，全部时间落在 2001 年附近

**现象**

查 `History.db` 的 `history_visits.visit_time`，得到的 `datetime(...)` 全部显示为 `2001-01-xx`，于是认为这些条目是"占位数据"或"纪元错误无法使用"，直接把访问历史整表作废。

**原因**

Safari 使用的是 **Cocoa / Apple 纪元**，起点是 `2001-01-01 00:00:00 UTC`，而不是 Unix 纪元。两者的差值是 `978307200` 秒。

SQLite 里读出来的是**裸偏移量**：`visit_time` 存储的是"相对 2001-01-01 的秒数"，一个 2024 年的真实访问点会显示为 `7.3e8` 这个数量级。

忘了加常数，`datetime()` 就会把它当成 Unix 秒解释，落进 2001–2004 年区间。

Chrome 的 `visit_time` 则是**微秒**且基于 Windows / OLE 纪元（1601-01-01），Firefox 的 `moz_places.last_visit_date` 是**微秒**且基于 Unix 纪元。三者互不相同。

| 来源 | 存储单位 | 纪元起点 | 换算 |
|---|---|---|---|
| Safari `History.db` | 秒 | 2001-01-01 | `+978307200` |
| Chrome `visits.visit_time` | 微秒 | 1601-01-01 | `/1000000 - 11644473600` |
| Firefox `last_visit_date` | 微秒 | 1970-01-01 | `/1000000` |

**影响**

- 把一批**完全正常的数据**判为"占位/损坏"，可能因此放弃可直接读取的浏览行为证据
- 更糟的是，如果换算后"碰巧"落在合理年份但整体偏移，会把访问记录挂到错误的时间点上，直接破坏时间线

**核查**

把纪元常数写成查询里的一部分，并**先验证换算结果落在合理区间**再解读：

```bash
SAF=/mnt/mac-data/Users/liwei/Library/Containers/com.apple.Safari/Data/Library/Safari
# Safari：加 978307200
sqlite3 "$SAF/History.db" \
  "SELECT datetime(visit_time + 978307200, 'unixepoch', 'localtime'), url
     FROM history_visits ORDER BY visit_time DESC LIMIT 20;"

# Chrome：微秒 / 1601 纪元
sqlite3 "/mnt/mac-data/Users/liwei/Library/Application Support/Google/Chrome/Default/History" \
  "SELECT datetime((visits.visit_time/1000000)-11644473600,'unixepoch','localtime'), url
     FROM visits JOIN urls ON visits.url=urls.id ORDER BY visit_time DESC LIMIT 20;"

# 换算后必须自查：最新一行是否落在案件时间窗内
sqlite3 "$SAF/History.db" \
  "SELECT datetime(max(visit_time)+978307200,'unixepoch','localtime') FROM history_visits;"
```

`max()` 结果若不在 2015 年之后，说明纪元或单位用错了，**此时不要解读任何一行**。

<a id="section-25"></a>

#### 陷阱 6：把钥匙串文件与 Safari 文件的 `mtime` 当作条目或访问时间

**现象**

发现 `login.keychain-db` 的 `mtime` 是 2024-09-05 18:22:10，比删除操作时间晚 40 分钟，于是写「用户在删除文件后仍在 18:22 操作了钥匙串」；看到 `LastSession.plist` 的 `mtime` 是当天 17:55，写「用户 17:55 还在浏览该页面」。

**原因**

这两个 `mtime` 的语义与条目/访问时间不是一回事：

- `login.keychain-db` 的 `mtime` 是整个文件最后一次写入的时间，写入者可能是任何一个条目，也可能是钥匙串的元数据更新、锁定状态变化、导入操作。它是**文件级**的，定位不到具体条目
- `LastSession.plist` 的 `mtime` 通常是 Safari 退出时写入的时间，反映的是"上次关窗"，不是任何一次页面访问
- SQLite 侧也是同样的问题：`History.db` 的 `mtime` 反映**主库最后一次 checkpoint**，而 WAL 模式下最新数据在 `-wal` 里，主库 `mtime` 可能比真实活动早很多

**影响**

文件级时间戳被当成行为级时间戳，会制造出**看似精确实则错误的活动时间线**。

这类时间点一旦写进报告，很容易成为对方质证"你凭什么认定用户在这个时刻做了什么"的突破口。

**核查**

文件时间戳只用于证明"数据在此刻之前已存在"，不用于证明"行为发生在此刻"：

| 时间戳 | 可以支持的结论 | 不能支持的结论 |
|---|---|---|
| `login.keychain-db` `mtime` | 钥匙串文件在此时前被写入过 | 某个条目在此时被使用 |
| `History.db` `mtime` | 主库在此时前已 checkpoint | 最后一次访问在此时 |
| `History.db-wal` `mtime` | 该时刻仍有写事务未回写主库 | 存在浏览活动、具体访问了哪个页面 |
| `LastSession.plist` `mtime` | Safari 上次退出的时间 | 某页面的访问时间 |

条目级时间必须取自 `cdat` / `mdat`，访问级时间必须取自 `history_visits.visit_time`。

<a id="section-26"></a>

### 4.3 Safari 数据提取与加密定性

<a id="section-27"></a>

#### 陷阱 7：只拷 `History.db`，不带 `-wal` / `-shm`

**现象**

提取 Safari 历史时用通配 `History.db` 单文件拷贝，得到一份能正常打开、记录看起来"很完整"的数据库，报告写下「访问历史已完整提取，共 N 条记录」。后续与 Quarantine、下载记录对照时，总觉得最近几天的行为"莫名其妙缺了一段"。

**原因**

SQLite 的 WAL（Write-Ahead Logging）模式下，最新的事务先写进 `History.db-wal`，**不立即回写主库**。只有在 checkpoint 发生或数据库被正常关闭时，`-wal` 里的内容才会合并进 `History.db`。

于是会出现一个很有欺骗性的现象：只拷主库时，SQLite 能正常打开、数据看起来完整、条数不少，但最近一段时间的访问记录整体缺失。

缺失量取决于最后一次 checkpoint 距今多久，可能是几小时，也可能是几天。

`-shm` 则是共享内存索引文件，缺失时 SQLite 会尝试重建，但在只读或只拷了部分文件的情况下可能直接报 `disk I/O error` 或 `database is locked`。

**影响**

- 报告声称"历史完整"，实际缺失了**最接近案发时刻的记录**——而那通常正是最需要证明的部分
- 把"记录缺失"误读为"用户没有访问"，是这类处置里最严重也最常见的错误结论
- 完整性声明不成立，后续所有基于该表的时间线都要重做

**核查**

**三个文件一起拷贝，并核对时间关系**：

```bash
SAF=/mnt/mac-data/Users/liwei/Library/Containers/com.apple.Safari/Data/Library/Safari

# 先看清实际存在哪些伴随文件
ls -la "$SAF"/History.db*

# 用 History.db* 通配，确保 -wal / -shm 一并提取
mkdir -p /evidence/safari
cp --preserve=timestamps "$SAF"/History.db* /evidence/safari/
md5sum /evidence/safari/History.db*   > /evidence/safari/History.db.md5
```

提取后**必须在报告里写明三者的时间关系**：

```text
History.db        mtime 2024-09-05 18:20:44
History.db-wal    mtime 2024-09-05 18:22:03   ← 晚于主库
History.db-shm    mtime 2024-09-05 18:22:03
```

`-wal` 的 `mtime` 晚于主库，就说明**有未回写主库的事务**。

此时即使主库读取正常，也必须声明记录的完整边界止于 `-wal` 的存在所指示的时段；`-wal` 非空只说明有未回写的写事务，事务也可能来自下载记录、书签等其它表，写入者不一定是页面访问。若无法解密 `-wal`，则应写明「主库记录止于 18:20:44，18:20:44 至 18:22:03 之间的记录因数据库加密未能验证」。

<a id="section-28"></a>

#### 陷阱 8：把 `file is not a database` 写成"数据库损坏"或"数据已丢失"

**现象**

`sqlite3 History.db "select count(*) from history_items;"` 返回 `Error: file is not a database`，于是报告写下「Safari 历史数据库已损坏，浏览记录不可用」，取证方案里直接删掉这一项。

**原因**

这个报错来自 SQLite **文件头 magic 不匹配**。

`History.db` 正常情况下前 16 字节是 `SQLite format 3\000`；而在较新 macOS 上它被 **SQLCipher** 加密，文件头被替换为随机盐值，SQLite 自然无法识别。

"不是数据库"是一个关于格式的判断，不是关于完整性的判断。

同样的报错有多种成因，必须逐一排除：

| 成因 | 判别方法 | 报告定性 |
|---|---|---|
| SQLCipher 加密 | `file -b` 头部非 `SQLite format 3`；文件大小正常 | **加密，需 Keychain 密钥** |
| 文件被截断 | 大小异常偏小；`xxd` 尾部无 `page 1` 特征 | 疑似提取不完整 |
| 提取了错位副本 | 哈希与工作副本不一致 | 提取流程问题，重做 |
| 确实损坏 | 大小正常但页结构错乱 | 损坏，需说明损坏范围 |

**影响**

- 委托方据此认为证据不可用，可能放弃其他可行途径（如从 `-wal`、`Downloads.plist`、FSEvents 侧重建访问行为）
- 在报告里写"数据已丢失"，一旦后续通过其他途径取到数据，会直接影响本次结论的可信度
- 掩盖了"我们没有获取解密密钥"这一**真实的取证能力边界**，让能力不足被误报为证据不存在

**核查**

**先判格式，再判完整性，两件事分开写**：

```bash
SAF=/mnt/mac-data/Users/liwei/Library/Containers/com.apple.Safari/Data/Library/Safari
file -b "$SAF/History.db" | head -c 32
# "SQLite format 3"  → 未加密
# 其他                → 继续排查

xxd -l 16 "$SAF/History.db"      # 确认文件头与文件大小是否符合正常量级
ls -la "$SAF"/History.db*        # 确认 -wal / -shm 是否齐全（见陷阱 7）
md5sum /evidence/safari/History.db* > /evidence/safari/History.db.md5
```

报告中的标准表述：

> `History.db` 文件头不符合 `SQLite format 3` 标识，判定为经 SQLCipher 加密。文件大小与三文件（`-db` / `-wal` / `-shm`）时间关系正常，未见截断迹象。本次未取得解密密钥，**仅记录文件存在性、大小与 SHA-256 哈希**；不判定为损坏，不判定为数据丢失。

<a id="section-29"></a>

#### 陷阱 9：把 `Downloads.plist` 与 `LastSession.plist` 当成完整的访问历史

**现象**

用 `plutil -p` 读出 `Downloads.plist` 里三行下载记录，就在报告里写「该用户从 `rival-exim.example` 下载过文件」；用 `LastSession.plist` 列出三个未关闭标签页，写成「用户在案发时段浏览过这三个站点」。

**原因**

这两类工件的记录粒度与语义都和访问历史不同：

`Downloads.plist` 记录的是「下载条目」：

- 条目记录的是下载动作，**不是文件当前位置**。用户下载后把文件移到别处、改名、删除，条目可能仍在
- 保留策略随系统版本变化，较新版本只保留有限条数，**不在表里不等于没下载过**
- 条目本身**不含访问时间**，`mtime` 是该 plist 被写入的时间
- 应与 Quarantine 属性、`kMDItemWhereFroms` **三者对照**，单一来源不足以定性

`LastSession.plist` 记录的是「上次退出时未关闭的标签页」：

- 用户正常关闭的页面**不在其中**，它偏向"用户还打算回头看"的意图，不是访问全集
- `mtime` 是 Safari 退出时间，与任何一次访问无关
- 会话恢复数据可能来自**已崩溃的会话**，此时时间语义又不同

**影响**

- 把「有下载条目」写成「文件已落地并被执行」，中间还差反取证、执行痕迹等整条证据链
- 把「有标签页」写成「访问过该站点」，可能把用户误点后立即关闭的情况判成主动访问
- 用 `LastSession.plist` 的 `mtime` 给站点打时间戳，直接制造虚假时间线

**核查**

按工件粒度分别定级，不做跨级推论：

| 工件 | 支持的结论 | 不支持的结论 |
|---|---|---|
| `Downloads.plist` | 该下载动作曾被记录 | 文件当前存在、已被执行 |
| `LastSession.plist` | 上次退出时该标签页处于打开状态 | 该站点被实际访问过 |
| `com.apple.quarantine` | 文件由下载应用写入及其时间 | 文件内容可信 |
| `kMDItemWhereFroms` | 文件的来源 URL | 访问时间 |

访问行为的定性只能建立在 `history_visits` 上；`History.db` 无法解密时，必须在报告里明确写出「访问历史未能验证」，而不是用 `Downloads.plist` 或 `LastSession.plist` 顶替。

<a id="section-30"></a>

### 4.4 跨浏览器与阴性结论

<a id="section-31"></a>

#### 陷阱 10：因为 Safari 历史取不到，就写成"无浏览行为"或"未使用浏览器"

**现象**

Safari `History.db` 解密失败，于是把浏览器相关结论写成「该用户未使用浏览器访问外部站点」，或「该机无浏览器使用痕迹」，随后不再检查其他浏览器。

**原因**

同一台 macOS 上并存多套独立的浏览器数据，**加密状态各不相同**：

| 浏览器 | 历史文件 | 是否需要 Keychain 解密 |
|---|---|---|
| Safari | `~/Library/Containers/com.apple.Safari/Data/Library/Safari/History.db` | **是**（SQLCipher，密钥在 Keychain） |
| Chrome | `~/Library/Application Support/Google/Chrome/Default/History` | 否（明文 SQLite） |
| Edge / Chromium / Arc / Brave | `~/Library/Application Support/<Vendor>/<Profile>/History` | 否 |
| Firefox | `~/Library/Application Support/Firefox/Profiles/<profile>/places.sqlite` | 否 |

Safari 加密只是一个浏览器的事，不会波及 Chrome。 把单点失败推广为整体结论，等于用一条技术限制覆盖了其余所有数据源。

同样常见的反向错误是：只看 `~/Library/Safari/` 这一路径（macOS 10.14 之前的位置），未发现数据就写「未使用 Safari」——**路径迁移不等于数据不存在**。

**影响**

- 直接漏掉本可取到的行为证据（Chrome 历史为明文 SQLite，可直接读出 URL 与访问时间）
- 委托方可能据此认为取证工作不充分而要求复检
- 「无浏览行为」这类否定性结论一旦被推翻，整份报告的可信度都会受影响

**核查**

**逐浏览器、逐路径确认，把每一项的结论状态写清**：

```bash
EV=/mnt/mac-data/Users/liwei
# 旧路径（10.14 之前）
ls -d "$EV/Library/Safari" 2>/dev/null || echo "旧路径不存在（不表示未使用 Safari）"
# 新路径（10.14+ 容器）
ls -d "$EV/Library/Containers/com.apple.Safari/Data/Library/Safari" 2>/dev/null
# 第三方浏览器
ls -d "$EV/Library/Application Support/Google/Chrome" 2>/dev/null
ls -d "$EV/Library/Application Support/Firefox/Profiles"/*/places.sqlite 2>/dev/null
ls -d "$EV/Library/Application Support/Microsoft Edge" 2>/dev/null
```

阴性结论必须**逐源表述**，四类成因不能混为一谈：

| 情形 | 正确表述 |
|---|---|
| 路径不存在 | 「该路径在镜像中不存在，符合 X 版本前的目录结构」 |
| 文件存在但加密 | 「`History.db` 经 SQLCipher 加密，未取得密钥，**访问历史未能验证**」 |
| 文件存在且可读但无相关记录 | 「已解密查询，**未发现**访问 X 的记录」 |
| 目录/文件被清理 | 「未见该工件，**存在清理可能，无法区分未使用与已清理**」 |

用「未能验证」替代「未发生」，是本篇所有阴性结论的统一要求。

<a id="section-32"></a>

## 五、案例示例

<a id="section-33"></a>

### 5.1 Keychain 子目录异机 UUID 与一次性 VPN 凭据的时间锚定

**场景**

查获 MacBook Air（Apple Silicon M1，macOS 13，FileVault 已解锁）。委托方为外贸公司，要求查明「员工是否访问过竞争对手的客户门户、是否使用了公司 VPN」。镜像 `DigiForensics.dd`（raw APFS 容器镜像），用户主目录 `/Users/liwei`。

**处置过程**

第一步，清点钥匙串目录并记录三类时间戳：

```bash
EV=/mnt/mac-data/Users/liwei
stat -f '%N  size=%z  btime=%SB  mtime=%Sm' -t '%Y-%m-%d %H:%M:%S' \
  "$EV/Library/Keychains/"* 
```

```text
login.keychain-db      size=258252  btime=2024-06-11 09:58:03  mtime=2024-09-05 18:22:10
metadata.keychain-db   size=23804   btime=2024-06-11 10:03:22  mtime=2024-06-11 10:03:22
8A2F4C19-…7A43/         btime=2024-06-11 10:03:25  mtime=2024-08-25 20:15:33
6C9E2B34-…9B02/         btime=2024-08-25 20:14:51  mtime=2024-08-25 20:15:33
```

第二步，取本机 Hardware UUID，与钥匙串 UUID 子目录逐一比对：

```bash
system_profiler SPHardwareDataType | grep -i 'Hardware UUID'
# → 8A2F4C19-7B3E-4D56-A1C8-9E0D5F2B7A43

ls "$EV/Library/Keychains/" | grep -Ei '^[0-9A-F]{8}-[0-9A-F]{4}'
# → 8A2F4C19-7B3E-4D56-A1C8-9E0D5F2B7A43   ← 本机
# → 6C9E2B34-1D5A-4F87-B2C3-8E1A4D6F9B02   ← 非本机
```

第三步，对非本机 UUID 目录取内容清单与时间：

```bash
find "$EV/Library/Keychains/6C9E2B34-1D5A-4F87-B2C3-8E1A4D6F9B02/" \
  -maxdepth 1 -type f -exec stat -f '%N  %SB  %Sm' -t '%F %T' {} \;
# → com.apple.security.vpn-…TrustedPeers  2024-08-25 20:14:51  2024-08-25 20:15:33
```

第四步，只读方式读取登录钥匙串的属性（不解密数据体）：

```bash
# ★ 挂载为只读后用 security 查询属性；本步骤只取元数据，不导出 data 字段
security find-generic-password -s "vpn.partner-portal.example" 2>&1 | head -12
```

```text
keychain: "login.keychain-db"
class: "genp"
attributes:
    0x00000007 <blob>="acct"<blob>="liwei"
    0x00000007 <blob>="svce"<blob>="vpn.partner-portal.example"
    0x00000007 <blob>="cdat"<blob>=2024-08-25 20:15:33 +0800
    0x00000007 <blob>="mdat"<blob>=2024-08-25 20:15:33 +0800
```

第五步，把三处时间放在一起做秒级比对：

```bash
python3 - <<'PY'
a = "2024-08-25 20:15:33"   # Keychain cdat
b = "2024-08-25 20:15:33"   # Keychain mdat
c = "2024-08-25 20:15:33"   # UUID 子目录 mtime
print("三源一致" if a == b == c else "存在分歧", a)
PY
```

**结论**

`login.keychain-db` 的 mtime 2024-09-05 18:22:10 晚于删除操作时间 17:42，说明钥匙串在删除动作之后仍有写入。

`6C9E2B34-…9B02` 不是本机 Hardware UUID，其目录内为 VPN 信任数据，且 `btime` 2024-08-25 20:14:51 与 `mtime` 2024-08-25 20:15:33 相隔 42 秒——目录内文件在创建后 42 秒内被整体改动过，与「目录被一次性拷入并在拷入后发生过写入」的模式一致；仅凭这两个时间戳不能区分是拷入动作本身完成于该时刻，还是拷入后另有一次写入。

VPN 凭据条目的 `cdat` 与 `mdat` 完全相同（2024-08-25 20:15:33），与该目录 mtime 精确到秒一致。三处时间同秒并不能算三份独立印证：条目写入与目录 mtime 更新很可能发生在同一次导入动作中，因此它支持的是「该凭据与该目录在 2024-08-25 20:15:33 前后一同进入本机」，且写入后未被再次改开；不能据此判定为"一次性使用"，也不能反推该时点有人实际登录过 VPN。

报告中只确认「本机存在 `vpn.partner-portal.example` 的凭据条目」，全程未导出数据体，报告中不出现任何凭据明文，也不写成「已使用该凭据登录」。

**误判对照**

最容易得出的错误结论是「VPN 凭据的 `cdat` 是使用时间，所以 2024-08-25 20:15:33 员工登录过公司 VPN」。

正确判据是 `cdat`（creation date）只在条目被写入时赋值，条目一经创建此字段不再变化，日常调用不会刷新；判断实际使用要看 Keychain 的访问审计或 Unified Logging 中的 `securityd` 事件，而不是 `cdat`。

若按错误判据写报告，会把一个「凭据导入时间」表述成「登录行为时间」，一旦委托方据此追责该时段的操作者，会锁定错误的人和时间段。

第二处易错点是看到两个 UUID 目录就写「存在第二台机器的钥匙串残留，说明做过跨机迁移」。

正确判据是必须先与 `system_profiler SPHardwareDataType` 的 Hardware UUID 比对——macOS 的钥匙串同步会把**多台设备**的 UUID 子目录一并写入本机目录，`8A2F4C19-…7A43` 之外还可能有第三、第四个目录，它们全部是 iCloud 钥匙串同步的正常产物。

按错误判据写「存在未授权跨机迁移」，在只有同步行为的正常设备上会产出假阳性；在真实的迁移场景中，又会把同步目录和拷贝目录混为一谈，无法回答委托方最关心的「凭据是从哪台机器来的」。

<a id="section-34"></a>

### 5.2 Safari History.db 加密与 WAL 未回写导致的历史缺口

**场景**

同一检材（`DigiForensics.dd`），委托方进一步要求列出该用户在 Safari 中的完整访问明细，重点是竞争对手门户的每一次跳转。Safari 数据位于其沙盒容器路径下。

**处置过程**

第一步，定位 Safari 沙盒路径下的三件套：

```bash
SAF="/mnt/mac-data/Users/liwei/Library/Containers/com.apple.Safari/Data/Library/Safari"
ls -la "$SAF"/History.db*
```

```text
-rw-r--r--  196608  History.db        2024-09-05 18:20:44
-rw-r--r--   16384  History.db-wal    2024-09-05 18:22:03   ← ★ 存在
-rw-r--r--     32  History.db-shm    2024-09-05 18:22:03
```

第二步，尝试直接打开，确认加密形态：

```bash
sqlite3 "$SAF/History.db" "select count(*) from history_items;"
# → Error: file is not a database
head -c 16 "$SAF/History.db" | xxd | head -1
# → 00000000 0000 0000 0000 0000 0000   ← 非 SQLite 魔数 "SQLite format 3"
```

第三步，判断 WAL 是否含未回写主库的事务：

```bash
python3 - <<'PY'
import os, struct
p = "/mnt/mac-data/Users/liwei/Library/Containers/com.apple.Safari/Data/Library/Safari/History.db-wal"
with open(p, "rb") as f:
    hdr = f.read(32)
magic, fmt, pgsz, ckpt, s1, s2 = struct.unpack(">IIIIII", hdr[:24])
print("magic=%08x fmt=%d pagesize=%d checkpoint=%d salt1=%08x" % (magic, fmt, pgsz, ckpt, s1))
frames = (os.path.getsize(p) - 32) // (24 + pgsz)
print("WAL 帧数 =", frames)
PY
```

```text
magic=377f0682 fmt=3007000 pagesize=4096 checkpoint=3 salt1=2b7f4c19
WAL 帧数 = 4
```

第四步，仍尝试无密钥路径（备用手段，为委托方留存可能性）：

```bash
# 常见 4 号密钥（可从用户钥匙串 / 备份 / 弱口令字典尝试，本案未命中）
for k in "" "1234" "0000" "1111"; do
  out=$(sqlite3 "file:$SAF/History.db?key=$k" "select count(*) from history_items;" 2>&1)
  echo "key='$k' → $out"
done
```

第五步，把无法解密这一事实本身作为可采证据固定下来：

```bash
stat -f '%N  %z  %Sm' -t '%Y-%m-%d %H:%M:%S' "$SAF"/History.db*
shasum -a 256 "$SAF"/History.db* | tee /evidence/History.db.sha256
```

**结论**

`History.db` 首部不是 `SQLite format 3` 且 sqlite3 报 file is not a database，可判定为 SQLCipher 应用层加密；本次未取得解密密钥，Safari 访问明细未获取，属本案明确证据局限。`-wal` 的 magic `0x377f0682` 是 SQLite WAL 格式标志，帧头 checkpoint=3、计算得 4 帧，文件大小 16384 字节非空，且其 mtime 18:22:03 晚于主库 18:20:44，说明镜像时点仍存在未回写主库的活跃事务——只拷贝 `History.db` 单文件会丢失这批记录，这是本案例最重要的处置结论。

`History.db-wal` 与 `-shm` 的存在性与大小只能支持「该时刻仍有写事务未回写主库」；写事务可能来自访问历史、下载记录或其它表，不能据此断定该时刻存在浏览活动，更不得推断具体访问了哪些 URL。

**误判对照**

最典型的错误结论是「`sqlite3` 报错 = 文件损坏，本次取证未获取到有效数据」。正确判据是先看文件头魔数：`History.db` 的头 16 字节全零而非 `53 51 4c 69 74 65 20 66 6f 72 6d 61 74 20 33 00`（`SQLite format 3`），说明它是被加密后的密文容器，是**设计上的加密**而非取证操作造成的损坏。两者在报告里的措辞完全不同：写「文件损坏」会被委托方误解为镜像有问题或取证失误，触发不必要的复检；正确写法是「经 SQLCipher 加密，未取得密钥，访问明细未获取」，并同时给出 Chrome 侧等效证据的位置。

第二处易错点是把 `-wal` 的存在当成「Safari 历史可恢复」。正确判据是 WAL 帧内容同样是 SQLCipher 页加密的密文（帧头字段可解析不代表页内容明文），没有主库密钥就无法解密 WAL 页。帧头能解析出 `pagesize=4096`、`checkpoint=3`、4 帧，只能支撑「该时刻存在未 checkpoint 的写事务」这一条结论，不能支撑任何一条具体 URL。若据 WAL 帧数反推访问条数，会给出一个凭空生成的数字，比留空危害更大。

第三处易错点是忽略 `-wal` 直接用 `History.db` 单文件出结论。

正确判据是同一目录下 `History.db-wal` 与 `History.db-shm` 与主库同属一组，任何 SQLite 家族的取证都必须整组采集并且采集顺序早于主库解析。

本案主库 mtime 18:20:44、WAL mtime 18:22:03，相差 79 秒；若只交付主库并写「已获取 Safari 历史」，等于凭空抹掉 18:20:44 之后的所有记录，而委托方最关心的正是删除动作前后的那一段。

<a id="section-35"></a>

### 5.3 Chrome 无密钥历史与 Safari plist 的三源秒级印证

**场景**

Safari 明细无法取得，委托方要求就「是否访问竞争对手门户、是否执行客户名单导出」给出可采结论。此时需要跨浏览器寻找不依赖密钥的访问记录，并要求 Safari 侧存在无需解密的下载记录作为第三条线。

**处置过程**

第一步，逐个列出本机所有浏览器配置文件，不预设只有 Safari：

```bash
EV=/mnt/mac-data/Users/liwei
ls -d "$EV/Library/Application Support/Google/Chrome/"*/ 2>/dev/null
ls -d "$EV/Library/Application Support/Firefox/Profiles/"*/ 2>/dev/null
ls -d /Applications/Firefox.app /Applications/Google\ Chrome.app 2>/dev/null
# → Chrome 配置文件存在（Default 等）
```

第二步，读取 Chrome 的访问历史（Chrome 历史库为普通 SQLite，无应用层加密）：

```bash
sqlite3 "$EV/Library/Application Support/Google/Chrome/Default/History" \
 "SELECT datetime((visit_time/1000000)-11644473600,'unixepoch','localtime') AS t, url
  FROM visits JOIN urls ON visits.url=urls.id
  WHERE url LIKE '%rival-exim%' ORDER BY visit_time LIMIT 10;"
```

```text
2024-09-05 14:20:58   https://portal.rival-exim.example/login
2024-09-05 14:22:11   https://portal.rival-exim.example/dashboard
2024-09-05 14:22:25   https://portal.rival-exim.example/api/export?type=customer
2024-09-05 15:47:03   https://portal.rival-exim.example/dashboard
```

第三步，读 Safari 侧无需解密的 `Downloads.plist`（二进制 plist，`plutil` 直接解析）：

```bash
plutil -p "$SAF/Downloads.plist" | grep -E 'DownloadEntry(URL|Date|Name)'
```

```text
"DownloadEntryName" => "rival-customer-list.xlsx"
"DownloadEntryURL" => "https://portal.rival-exim.example/api/export?type=customer"
"DownloadEntryDate" => 2024-09-05 14:22:25 +0800
```

第四步，把两条来源的秒级一致性做成可复核的校验：

```bash
python3 - <<'PY'
chrome = {"t": "2024-09-05 14:22:25", "url": "https://portal.rival-exim.example/api/export?type=customer"}
plist  = {"t": "2024-09-05 14:22:25", "url": "https://portal.rival-exim.example/api/export?type=customer"}
print("URL 一致:", chrome["url"] == plist["url"])
print("时间秒级一致:", chrome["t"] == plist["t"])
PY
```

第五步，核对 Safari 下载目录中被删文件的 Quarantine 来源：

```bash
find /mnt/mac-data/Users/liwei -type f -print0 | while IFS= read -r -d '' f; do
  v=$(xattr -p com.apple.quarantine "$f" 2>/dev/null) || continue
  [ -n "$v" ] && printf '%s\	%s\
' "$f" "$v"
done | grep -i '客户名单'
```

```text
/Users/liwei/Downloads/客户名单-2024Q3.csv  0083;66D94E21;Safari;B2C3D4E5-…
/Users/liwei/Downloads/客户名单-2024Q3.zip  0083;66D94E21;Safari;C3D4E5F6-…
```

**结论**

Chrome 历史库无需解密即可读出，2024-09-05 14:20:58 至 15:47:03 期间存在对 `portal.rival-exim.example` 的四次访问。

其中 14:22:25 的 URL 为 `api/export?type=customer`，与 Safari `Downloads.plist` 的 `DownloadEntryURL` 完全相同、时间戳 `DownloadEntryDate` 14:22:25 秒级一致，且被删文件的 Quarantine 属性应用名为 `Safari`、时间十六进制前段同为 `0083`。

三条来源（Chrome History、Safari 下载 plist、Quarantine 扩展属性）指向同一 URL 与同一秒。这里需要区分两件事：三者分属不同落盘机制与数据结构，可相互印证；但 `Downloads.plist` 与 `com.apple.quarantine` 都由 Safari 的同一次下载流程写入，属于同一动作的两处记录，不是两条独立线索。因此可采结论是「该机在 2024-09-05 14:22:25 通过 Safari 下载了客户名单文件，且该秒 Chrome 侧存在同一 URL 的访问记录」；至于是否"执行了导出"——即是否在服务端真正生成了客户名单、以及导出结果是否被打开使用，还需要下载文件的实际内容、浏览器下载记录与执行痕迹支撑，本案证据不足以认定"执行了客户名单导出"。

Safari 的 `history_items` 明细仍未获取，此条已明示为证据局限。

Safari 侧证明「下载来源」，Chrome 侧证明「访问行为」，两者缺一不构成闭环。

**误判对照**

最严重的错误结论是「Safari 历史库加密不可读，因此浏览器证据不可用，本案无法证明访问行为」。

正确判据是加密只覆盖单一浏览器的访问明细，同一用户目录下的 Chrome 历史是独立存储的普通 SQLite，Safari 解密失败与 Chrome 可读之间没有因果关系。

按错误判据写报告，会在明明有完整访问记录的情况下出具「无法证明」，委托方据此解除监控或放弃追责，实际是因一处技术障碍放弃了全部可得证据。

第二处易错点是把三条来源一律当成互不依赖的印证。

正确判据要分两层：独立来源必须互不派生，Chrome `visits.url` 由 Chrome 进程写入，Safari `Downloads.plist` 与文件 `com.apple.quarantine` 都由 Safari 的同一次下载流程写入——前两者互相独立，后两者落盘机制与数据结构不同却同源，因此计数时只能算 Chrome 一条线加 Safari 下载事件一条线，Quarantine 属性是对该下载事件的补强。同一动作在不同结构里的两处落盘可以相互核对一致性，但不足以把证据强度按条数累加。

第三处易错点是拿 Safari 下载 plist 的 `DownloadEntryDate` 当访问开始时间。

正确判据是该字段记录的是**下载完成**时刻，访问开始要看 Chrome `visits` 的第一条 14:20:58 与 `DownloadEntryDate` 14:22:25 相差 87 秒——这段时间是登录与导出操作。

把 14:22:25 直接说成「访问时间」会丢掉行为起点；反过来若把 14:20:58 说成「下载时间」则会把行为提前 87 秒。

访问、下载、导出是三个动作，各有各的字段，报告里必须分开陈述。

---
<a id="section-36"></a>

## 六、扩展阅读方向

<a id="section-37"></a>

### 前置基础：解密与解锁是两件事，归属判断靠目录结构

- [macOS 取证工件地图](computer-security-security-artifact-map.md) —— `~/Library` 分层、FileVault、镜像准备。「已解密磁盘」与「已解锁钥匙串」的区分从这一篇开始，漏掉它会导致后面所有凭据结论失效。
- [取证实战流程](computer-security-security-investigation-workflow.md) —— **本篇的三个工件串进完整流程后的顺序与取舍**，单独读懂零件之后，这一篇告诉你怎么把它们串起来。
- [时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md) —— Apple 纪元与 Unix 纪元差 `978307200` 秒，Safari 的所有时间戳都要加这个常量，忘了加会得到「全部发生在 2001 年附近」的错误结论。
- [plist 与偏好设置](../computer-plist-spotlight/computer-plist-spotlight-plist.md) —— `Downloads.plist` 与 `LastSession.plist` 的读取依赖它。

<a id="section-38"></a>

### 同层深入：凭据与浏览痕迹的其它载体

- [浏览器密码库与 Token 解密](../../crypto/crypto-app/crypto-app-browser-passwords-and-tokens.md) —— Windows / Linux 侧的对应物。两边对照能看清三种凭据模型的差异：Keychain 由系统钥匙串统一承载、DPAPI 绑用户、浏览器自管。
- [数据库与配置文件加密](../../crypto/crypto-app/crypto-app-database-configuration-decryption.md) —— Safari 的 SQLCipher 属于应用层数据库加密，与全卷加密是两层机制，见该篇。
- [Quarantine 与 Gatekeeper](computer-security-quarantine-gatekeeper.md) —— 同板块的相邻议题。下载来源的判定在 Quarantine，实际下载记录在 `Downloads.plist`，三者互补。
- [Spotlight 索引与元数据](../computer-plist-spotlight/computer-plist-spotlight-spotlight.md) —— `kMDItemWhereFroms` 同样能给出下载来源 URL，**与 Safari 历史互为印证**。

<a id="section-39"></a>

### 相邻议题：别的系统上的浏览痕迹

- [浏览器取证](../computer-browser-behavior/computer-browser-behavior-browser-forensics.md) —— Windows 侧。Chromium 的 `os_crypt` 与 DPAPI 机制和 Keychain 完全不同，Chromium 系浏览器的跨平台路径在该篇有对照。
- [Windows 11 与 Recall](../computer-browser-behavior/computer-browser-behavior-windows11-recall.md) —— 系统级屏幕快照能力。Recall 记录的是「屏幕上出现过什么」，比浏览历史更宽，两者证据性质不同。
- [SRUM 数据库分析](../computer-browser-behavior/computer-browser-behavior-srum.md) —— 应用资源使用统计。它能给出「哪个应用在前台用过多久」，是从使用行为反推操作类型的一个角度。

<a id="section-40"></a>

### 工具与规范：凭据材料的处置

- [证据文件格式](../../fundamentals/fundamentals-chain/fundamentals-chain-dd-e01-aff4-evidence-formats.md) —— 钥匙串与数据库的归档容器选择。**钥匙串文件的哈希必须在任何解锁尝试之前记录**，否则无法证明后续分析未改变证据。
- [证据保管链与委托证明](../../fundamentals/fundamentals-chain/fundamentals-chain-chain-of-custody-and-authorization.md) —— 凭据材料属高敏感证据，固定与移交都要留痕。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md) —— 解锁所需的用户密码必须合法取得，本篇所有凭据相关操作均强调最小化与脱敏。

<a id="section-41"></a>

### 判据与反例：哪些结论不能下

- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 阴性结论的表述纪律。「未取得密钥」与「无凭据」是完全不同的两句结论，混用会让委托方误判证据可用性。
- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— 条目的创建与修改时间被改动时的识别，**多个条目的时间聚集在同一秒是一个可查的信号。**
<a id="section-42"></a>

## 七、命令速查

```bash
# ===== 1. Keychain 目录与搜索路径 =====
ls -la ~/Library/Keychains/ ~/Library/Keychains/*/    # 含 <Hardware-UUID> 子目录
ls -la /Library/Keychains/System.keychain
security list-keychains;  security default-keychain

# ===== 2. Keychain 元数据（★ 只需文件权限，不需用户密码）=====
security find-generic-password -s "mail.google.com"
security find-internet-password -s "example.com"
security find-generic-password -a "liwei" -s "vpn.example.com"
security dump-keychain login.keychain-db > /evidence/kc-dump.txt
# 关注四个属性键名：svce(服务) acct(账号) cdat(创建) mdat(修改)
# cdat == mdat → 一次性凭据 / 创建后从未修改
# ⚠️ security -g 会显示密码并修改 ACL，报告禁止记录明文

# ===== 3. 解锁（★ 需用户登录密码，FileVault 密钥无效）=====
security unlock-keychain ~/Library/Keychains/login.keychain-db

# ===== 4. Safari =====
SAF=~/Library/Containers/com.apple.Safari/Data/Library/Safari
ls -la "$SAF"/History.db*          # ★ db + -wal + -shm 三个必须一起提取
file -b "$SAF/History.db" | head -c 32
sqlite3 "$SAF/History.db" "select count(*) from history_items;"   # 报错=加密，非损坏
plutil -p "$SAF/Bookmarks.plist" | head -20
plutil -p "$SAF/Downloads.plist" | head -30          # 下载记录，无需解密
plutil -p "$SAF/LastSession.plist" | head -15        # 会话恢复，仅作辅助

# ===== 5. Chrome / Firefox（★ 通常无需密钥即可读）=====
CH="$EV/Library/Application Support/Google/Chrome/Default"
sqlite3 "$CH/History" "SELECT datetime((visit_time/1000000)-11644473600,'unixepoch','localtime'), url
  FROM visits JOIN urls ON visits.url=urls.id ORDER BY visit_time DESC LIMIT 20;"
sqlite3 "$CH/Login Data" "SELECT origin_url, username_value FROM logins LIMIT 10;"
sqlite3 "$EV/Library/Application Support/Firefox/Profiles/default.default-release/places.sqlite" \
  "SELECT datetime(last_visit_date/1000000,'unixepoch','localtime'), url FROM moz_places ORDER BY last_visit_date DESC LIMIT 20;"

# ===== 6. 时间基数对照（★ 最易错）=====
# Safari:  值 + 978307200              （秒，2001 纪元）
# Chrome:  (值 / 1000000) - 11644473600（微秒，1601 纪元）
# Firefox: 值 / 1000000                 （微秒，Unix 纪元）
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — macOS 取证 — Keychain 与 Safari 痕迹」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《Keychain 与 Safari 痕迹》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-mem.raw` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
