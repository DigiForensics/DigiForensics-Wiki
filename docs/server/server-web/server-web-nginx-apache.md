---
title: "Nginx 与 Apache 配置取证"
slug: "server-web-nginx-apache"
canonical: "https://www.digiforensics.cn/wiki/server-web-nginx-apache"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:48+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "server"
space: "服务器与云取证"
node_path: ["Web 与应用"]
---

# Nginx 与 Apache 配置取证

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/server-web-nginx-apache)

<a id="section-1"></a>

## 一、概述

没有 Web 服务器配置，手里的日志和文件就是一堆没有坐标的碎片。

站点目录在哪、日志写到哪、请求转到哪、某个 location 是不是压根不记日志——四个问题只在配置文件里有答案。

跳过这一层直接分析 access.log，你连自己在读哪台机器的哪一段时间都说不清，更解释不了为什么关键时段「什么都没有」。

要做的是一张「路由图」：把散落的工件归位到具体的站点、路径和日志文件上，顺带把配置本身当证据读。

**在取证流程中的位置**：这一层自己几乎不产出结论，却决定后面所有分析是否成立。站点映射错了，第 02 篇的日志分析跟着全错；`access_log` 路径找错了，「无访问记录」就是个伪结论。上游依赖 [取证工件地图（Linux 侧）](../../computer/computer-persistence/computer-persistence-persistence-artifact-map.md) 的目录清单与 [系统日志深度分析](../../computer/computer-log/computer-log-system-log-analysis.md) 的轮转认知；下游支撑网站目录取证（[第 2 步](#section-9)）、访问日志分析（[第 4 步](#section-11)）和报告里的归因表述。

**涉及的证据形态**——具体到文件，不是「配置文件」这种大类：

| 形态 | 位置 | 取证价值 |
|---|---|---|
| Nginx 主配置 | `/etc/nginx/nginx.conf`、`/www/server/nginx/conf/nginx.conf`（宝塔） | ★★★★★ 生效配置的入口 |
| 站点配置 | `conf.d/*.conf`、`conf/vhost/nginx/*.conf`、`sites-available/` + `sites-enabled/` **软链** | ★★★★★ 站点与日志映射 |
| Apache 主配置 | `/etc/apache2/apache2.conf`、`/etc/httpd/conf/httpd.conf` | ★★★★ |
| `log_format` 定义 | 主配置内，可多个 | ★★★★★ **决定字段顺序** |
| `.htaccess` | 站点目录**逐级向上**查找 | ★★★★ 隐藏重写规则 |
| `mods-enabled/` | Apache 模块加载状态 | ★★★ 决定 `.htaccess` 是否生效 |
| 访问/错误日志 | `/var/log/nginx/`、**`/www/wwwlogs/`**（面板环境） | ★★★★★ |
| 在线状态页 | `/server-status?auto`、`/server-info` | ★★★★★ 活证据（需授权窗口） |

> ⚠️ 本篇最容易被忽略的一点：面板环境的路径与源包完全不同。 源包装在 `/etc/nginx`、日志在 `/var/log/nginx`，宝塔装在 `/www/server/nginx/conf`、日志在 `/www/wwwlogs`。「在 `/var/log/nginx/` 没找到日志」和「这个站点没有日志」是两件完全不同的事，见 [4.2 字段与路径判读](#section-17)。

哪个配置文件真正生效；每个站点的 `root` / `DocumentRoot` 实际指向哪里；哪个 location 的日志被关掉了、日志文件在哪；`proxy_pass` 背后的内部拓扑，以及真实客户端 IP 能不能采信；`alias` 错配、`auto_prepend_file`、`.htaccess` 构成的配置层攻击面；某时段日志缺失是轮转、删除还是压根没记。

**注意配置层与 PHP 层的分界**：篡改机制的核心可能就写在 `.user.ini` 里，而它不是 Nginx 配置——只读 `nginx.conf` 会把最关键的证据整个漏掉。

请求体内容、文件上传内容、命令执行结果，配置层看不到这些。攻击者实际改了哪个文件，要靠文件时间戳与内容去比。`.htaccess` 里写了什么不等于生效的行为，它受 `AllowOverride` 和模块加载约束。至于在生产中的被入侵主机上执行 `nginx -T` 拿全量配置——它会实际加载配置，见 [4.1 定位与生效](#section-13)。

**读者前提**：HTTP 请求/响应结构、Linux 目录树与权限模型、进程与端口的基本认知，以及 [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) 里的哈希固定与只读挂载要求。Windows 侧的等价工件（W3C 字段顺序、IIS 站点配置）见 [IIS 配置与日志](../server-log/server-log-iis.md)，两边的字段顺序可以对照着记。

<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 配置文件的组织方式

Nginx 的配置是**层级化**的：`main` → `http` → `server` → `location`。取证时必须理解「上下文」，同一个指令在不同层级含义完全不同。

| 发行版/安装方式 | 主配置 | 站点配置目录 | 站点根目录 | 日志目录 |
|---|---|---|---|---|
| **apt / yum 安装** | `/etc/nginx/nginx.conf` | `conf.d/*.conf` | `/usr/share/nginx/html` 或自建 | `/var/log/nginx/` |
| **源码编译（官方 tar 包）** | `/usr/local/nginx/conf/nginx.conf` | `conf/extra/`、`conf/` 下直接写 | 编译时指定 | 同上 |
| **宝塔生成** | `/www/server/nginx/conf/nginx.conf` | `conf/vhost/*.conf` | `/www/wwwroot/<site>/` | **`/www/wwwlogs/`** |
| **宝麒麟等面板** | 路径随版本 | `conf/vhost/` | `/www/wwwroot/` | `/www/wwwlogs/` |
| **Debian 惯例** | `/etc/nginx/nginx.conf` | `sites-available/` + `sites-enabled/` 软链 | `/var/www/html` | `/var/log/nginx/` |
| **Apache (Debian)** | `/etc/apache2/apache2.conf` | `sites-available/` + `sites-enabled/` | `/var/www/html` | `/var/log/apache2/` |
| **Apache (RHEL/CentOS)** | `/etc/httpd/conf/httpd.conf` | `conf.d/*.conf` | `/usr/share/httpd/html` | `/var/log/httpd/` |

> ⚠️ `sites-enabled/` 只是软链接目录。 取证时要看**软链接指向谁**，而不是只看 `sites-enabled/` 里有什么——攻击者或运维可能直接改了 `sites-available/` 下的原文件，也可能有孤儿配置（available 里有、enabled 里没链，属未生效）。

**最关键的一步：拿到真正生效的完整配置。**

```bash
# 方式一：从镜像里静态找（不执行任何东西，最安全）
find /mnt/df -maxdepth 5 -name 'nginx.conf' -o -name 'httpd.conf' \
     -o -name 'apache2.conf' 2>/dev/null

# 方式二：确认主配置里 include 了什么（读文件，不执行）
grep -nE '^\s*include' /mnt/df/etc/nginx/nginx.conf

# 方式三：在目标副本上执行，输出全量生效配置（生产主机上禁止）
nginx -T 2>&1 | head -100
apachectl -S 2>&1 | head -40      # 列出 vhost 与 DocumentRoot 对应关系
```

<a id="section-4"></a>

### 2.2 `log_format` 字段详解

**这是本篇最容易被搞错、也最影响后续分析的部分。** Nginx 的 `combined` 格式定义如下：

```
log_format combined '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" "$http_user_agent"';
```

逐字段拆解（注意 `$remote_addr` 之后是 `-`，再之后是 `$time_local`，`$remote_user` 在方括号内）：

| 序 | 字段 | 含义 | 取证用途 |
|---|---|---|---|
| 1 | `$remote_addr` | 客户端 IP（TCP 对端）。**若前置了反向代理，这里是代理 IP** | ★★★★★ 定位攻击源 |
| 2 | `-` | **字面连字符，不是字段** | 固定占位 |
| 3 | `$remote_user` | HTTP Basic/Digest 认证用户名，未认证时为 `-` | 区分认证访问 |
| 4 | `$time_local` | 本地时区时间，格式 `[18/Mar/2024:02:14:33 +0800]` | ★★★★★ 时间线基准 |
| 5 | `$request` | 完整请求行：`"GET /a.php?x=1 HTTP/1.1"` | ★★★★★ 还原行为 |
| 6 | `$status` | 响应状态码 | 200 成功、403 禁目录、404 不存在、500 脚本错误 |
| 7 | `$body_bytes_sent` | 响应体字节数（**不含响应头**） | 估算上传/下载量 |
| 8 | `$http_referer` | Referer 头，无则 `-` | 判断是否同源；**WebShell 请求常无 Referer** |
| 9 | `$http_user_agent` | UA，无则 `-` | 工具指纹 |

> 🔴 **高频错误提醒**：`$remote_addr` 之后是字面 `-`，再之后是 `$time_local`。很多解析脚本错写成「IP → 时间 → 用户名」的顺序，或者把方括号里的时间当成第 3 字段。解析 combined 日志必须按上面的完整结构来做，第 7 篇和本节的脚本都严格遵守此顺序。

**其他需要认识的格式：**

| 格式名 | 字段 | 特点 |
|---|---|---|
| `main` | `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent` | 无 referer/UA |
| `combined` | 上表 9 项 | **默认，最常用** |
| 自定义 `dlog` | 常见加 `$request_time`、`$upstream_response_time`、`$server_protocol` | 自定义格式可能没有 UA/referer，也可能含 cookie——务必逐台核对 |

> ⚠️ 取证时必须核对 `log_format` 的实际定义，不能假设一定是 `combined`。一台机器可能有多个 `log_format` 定义，多个 `access_log` 引用不同格式。用 `grep -n 'log_format' nginx.conf` 逐一列出。

<a id="section-5"></a>

### 2.3 关键指令的取证意义

`root` vs `alias`（最危险的一类配置错误）

两者的路径拼接规则不同，这是很多「任意文件读取」漏洞的根因：

```nginx
location /static/ { alias /data/files/; }
# 请求 /static/../etc/passwd → /data/files/../etc/passwd → /data/etc/passwd
# 若写成 root /data/files;（无尾斜杠），/static/x → /data/files/static/x，语义完全不同
```

| 指令 | 语义 | 取证关注点 |
|---|---|---|
| `root` | 替换 location 前缀 | 拼错会导致**访问到计划外目录** |
| `alias` | **整段替换** location 前缀 | **少写尾斜杠或写错路径极易造成目录穿越**，务必逐个核对 |
| `try_files` | 依次尝试文件/目录 | `$uri$uri/` 落到目录可能触发索引列表泄露 |

`access_log off` —— 痕迹消失开关

`access_log off` 本身**不是恶意证据**（很多站点用它降压），但它的取证意义是：该 location 下的行为没有 Nginx 侧记录。此时必须转向 PHP 层（`/www/wwwlogs/` 面板日志、PHP-FPM 日志）或数据库审计。

**`proxy_pass` —— 看清真实拓扑**

```nginx
location /api/ { proxy_pass http://127.0.0.1:8080/; }     # 末尾有斜杠：会剥掉 /api/ 前缀
location /api/ { proxy_pass http://127.0.0.1:8080;  }     # 末尾无斜杠：路径传递方式不同！
```

| 观察 | 意义 |
|---|---|
| `proxy_pass` 指向 `127.0.0.1:某端口` | 有内部服务，可查该端口的进程与日志 |
| 指向内网 IP | 存在跨主机调用，内网主机可能也在检材范围内 |
| 上游转发明文 `Authorization` 或 `Cookie` | 凭据可能被写入下游日志 |
| `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for` | 后端日志里的是真实 IP，**取证时可直接采信** |
| **未设置该头** | 后端日志里全是代理 IP，**不能直接当作客户端 IP** |

`sub_filter` / `add_header` —— 内容与响应头被程序改写

```nginx
sub_filter_types text/html;
sub_filter 'https://cdn.old.com' 'https://cdn.new.com';   # 内容替换
add_header 'X-Powered-By' 'PHP/5.6.40';                    # 伪造版本号，干扰技术栈判断
```

`add_header` 伪造版本号在真实入侵中出现过——它让**基于响应头的技术栈判断失效**，取证时要意识到这一点。

Apache 侧：`mod_rewrite` 与 `.htaccess`

```apache
# 全局重写规则
RewriteRule ^/old/(.*)$ /$1 [R=301,L]

# .htaccess 隐藏规则（放在任意目录，逐级向上查找）
RewriteEngine On
RewriteRule ^\.(git|svn|env) - [F]        # 禁访问版本库
RedirectMatch 404 ^/backups?/            # 隐藏备份目录
```

1. `[R=301,L]` 通常是**管理员主动做的跳转**；`[R=302]` 出现在备份路径上，可能是后门在给自己打掩护。
2. `.htaccess` 是**逐级向上查找**的：请求 `/a/b/c.php` 时 Nginx 不读 `.htaccess`，但 Apache 会依次检查 `/a/b/`、`/a/`、`/`。**必须逐层找，不能只查站点根目录。**
3. `mod_rewrite` 生效需要 `AllowOverride All`；若为 `None`，站点目录里的 `.htaccess` **完全无效**——此时「配置看起来在禁某目录」实际是失效的假象。

<a id="section-6"></a>

### 2.4 Apache 特有工件的取证价值

| 文件/接口 | 内容 | 价值 |
|---|---|---|
| `/var/log/apache2/access.log` | 访问日志（格式同 Nginx） | ★★★★★ |
| `/var/log/apache2/error.log` | 错误日志，含 PHP 警告与栈 | ★★★★ |
| `/var/log/apache2/other_vhosts_access.log` | **多 vhost 时自动追加**，容易被忽略 | ★★★★ |
| `/var/log/apache2/access.log.*.gz` | 轮转历史 | ★★★★ |
| `server-status`（`/server-status?auto`） | **活动连接、正在处理的请求、子进程 PID** | ★★★★★ 在线时价值极高 |
| `server-info` | 模块列表与完整配置 | ★★★★ |
| `/etc/apache2/mods-enabled/` | 启用了哪些模块 | 判断 `mod_rewrite`/`mod_php` 是否真能用 |
| `/etc/apache2/sites-enabled/` | **软链接**，要 `ls -l` 看指向 | ★★★★★ |

> `server-status` 在取证中的特殊价值：它实时列出当前正在处理的请求 URL、来源 IP、子进程 PID。若取证窗口内还能访问，可以直接抓到攻击者正在进行的操作——这是任何离线日志都给不了的活证据。但**这必须在委托方明确授权的在线取证窗口内进行**，且要立即截图固定。

Windows 侧的同类配置（站点配置、日志目录、W3C 字段顺序）见[第 02 篇](../server-log/server-log-iis.md)，字段语义可以对照着看。

---

<a id="section-7"></a>

## 三、操作步骤

<a id="section-8"></a>

### 3.1 第 1 步：定位并固定配置

```bash
# 1) 找到所有候选主配置
find /mnt/df -maxdepth 5 \( -name nginx.conf -o -name httpd.conf \
     -o -name apache2.conf \) 2>/dev/null | tee /evidence/ws-conf-list.txt

# 2) 完整复制并固定哈希（先复制，再分析）
mkdir -p /evidence/nginx-conf /evidence/apache-conf
cp -rp /mnt/df/etc/nginx /evidence/nginx-conf/ 2>/dev/null
cp -rp /mnt/df/etc/apache2 /evidence/apache-conf/ 2>/dev/null
cp -rp /mnt/df/etc/httpd  /evidence/apache-conf/ 2>/dev/null
find /evidence/nginx-conf /evidence/apache-conf -type f \
     -exec sha256sum {} + > /evidence/ws-conf-hashes.txt

# 3) 看主配置的 include 关系
grep -nE '^\s*include' /evidence/nginx-conf/etc/nginx/nginx.conf 2>/dev/null

# 4) 配置文件的修改时间（判断是否被改过的关键）
find /evidence/nginx-conf /evidence/apache-conf -type f \
     -printf '%T+ %p\
' 2>/dev/null | sort | tail -20
# 或： find ... -name '*.conf' -newermt '2024-03-01' -ls
```

<a id="section-9"></a>

### 3.2 第 2 步：提取站点与日志映射

```bash
# 所有 server 块、root、access_log、error_log 一次看全
grep -rnE 'server_name|root |alias |access_log|error_log|proxy_pass' \
     /evidence/nginx-conf/etc/nginx/ 2>/dev/null

# Apache 侧
grep -rnE 'ServerName|ServerAlias|DocumentRoot|ErrorLog|CustomLog' \
     /evidence/apache-conf/ 2>/dev/null
ls -l /evidence/apache-conf/etc/apache2/sites-enabled/ 2>/dev/null   # 看软链接指向
```

把结果整理成映射表，这是后续所有分析的基准：

| 域名 | root 实际路径 | access_log 路径 | 是否 off | 备注 |
|---|---|---|---|---|
| `digiforensics-site` | `/www/wwwroot/digiforensics-site/` | `/www/wwwlogs/digiforensics-site.log` | 否 | 主站 |
| `cdn.digiforensics` | `/data/cdn/` | `off` | **是** | ★ 无访问记录 |

<a id="section-10"></a>

### 3.3 第 3 步：查隐藏规则、危险配置与站外目录

```bash
# .htaccess 逐级找（Apache 才会生效）
find /mnt/df/www/wwwroot /mnt/df/var/www -name '.htaccess' 2>/dev/null
find /mnt/df/www/wwwroot -name '.htaccess' -exec grep -HnE 'Rewrite|Redirect|php_value|auto_prepend' {} + 2>/dev/null
grep -rn 'AllowOverride' /evidence/apache-conf/ 2>/dev/null     # 决定 .htaccess 是否真生效

# Nginx 侧的隐藏规则
grep -rnE 'Redirect|return 40[13]|deny' /evidence/nginx-conf/ 2>/dev/null | head -30

# .user.ini（PHP 层面劫持，详见第 06 篇）
find /mnt/df/www/wwwroot -name '.user.ini' -exec grep -Hn . {} + 2>/dev/null

# 站外目录：面板装的站点有时把路径指到 /www/wwwroot 之外，
# 这类"计划外目录"是篡改网站改 JS 的常见落点
grep -rnE '^\s*(root|alias) ' /evidence/nginx-conf/etc/nginx/ 2>/dev/null \
  | grep -v '/www/wwwroot' | grep -v '/usr/share/nginx'
ls -la /mnt/df/data/ 2>/dev/null      # 结果需逐个核实：是否该存在？内容是否像正常业务？
```

<a id="section-11"></a>

### 3.4 第 4 步：解析访问日志与核查轮转

`awk -F'"'` 是 combined 日志的实用技巧：把行按双引号切成 3 段，`$1` 是「IP - user [time]」，`$2` 是请求行，`$3` 是 referer + UA。**不需要写正则就能可靠地拿到请求行。**

```bash
Z=/mnt/df/www/wwwlogs/digiforensics-site.log
awk -F'"' '{split($1,a," "); print a[1], $2}' "$Z" | sort | uniq -c | sort -rn | head -20
# 关键：按 IP + 路径组合看，能发现"只对某个 URL 反复访问"的扫描/后门行为
```

**服务还在跑的话，日志随时会被轮转覆盖**——这是[第 01 篇](../server-panel/server-panel-linux-server-artifact-map.md)强调的抢时间理由，在 Web 取证里要具体到文件层面：

```bash
ls -l /mnt/df/www/wwwlogs/ /mnt/df/var/log/nginx/ 2>/dev/null
# digiforensics-site.log              当前
# digiforensics-site.log.1            昨天
# digiforensics-site.log-20240317.gz  已压缩

cat /mnt/df/etc/logrotate.d/nginx 2>/dev/null    # daily / rotate 7 / compress
ls -1 /mnt/df/var/log/nginx/ | sort
# 若存在 access.log 但缺少 access.log-20240310.gz，说明那天被手工删过
zcat /mnt/df/var/log/nginx/access.log-2024031*.gz 2>/dev/null | grep '198.51.100.24'
```

**`nginx -s reopen` 会触发轮转。**如果某个时间段的日志缺失且无法用 `logrotate` 解释，要在报告里写明「**该时段记录缺失，疑似被人为删除**」，不要写成「该时段无访问」。
<a id="section-12"></a>

## 四、常见陷阱

Web 服务器配置取证的陷阱，可以归为一句话：**「看起来生效了」和「实际生效了」之间有距离**。找错配置文件、格式假设错、代理 IP 当真实 IP、失效的配置当有效——每一处都会让结论偏离。本章按「定位与生效 → 字段与路径判读 → 归因与结论 → 工具行为与环境前提」四段归组。

<a id="section-13"></a>

### 4.1 定位与生效

<a id="section-14"></a>

#### 陷阱 1：★ 在生产中的被入侵主机上跑 `nginx -T`

**现象**：为了拿到「全量生效配置」，直接在还在运行、且已确认被入侵的服务器上执行 `nginx -T`。

**原因**：`nginx -T` **不是只读命令**——它会实际加载并解析所有配置文件。加载过程会触发一系列实际行为：读取并解析证书、解析上游主机名、可能对后端发起连接、加载模块。**在生产主机上执行这些动作，状态可能因此改变。**

**影响**：**在证据现场制造了新的不确定性。** 加载配置可能刷新状态、可能让某个异常配置在日志或运行时留下痕迹——**这改变了现场，而这台机器恰恰是要作为检材的**。更重要的是：如果因此触发了某种行为（连接后端、加载证书失败导致重载异常），会干扰正在进行的调查。

**核查**：只对副本执行 `nginx -T`，生产主机上只读文件。 具体做法：① 现场先 `cp -rp` 完整配置目录到证据目录；② 离线分析时若需要合并视图，对**副本**执行 `nginx -T`，且执行环境要保证引用路径能解析（必要时保持目录结构一致）；③ 实在必须在主机上执行的，先记录执行前的连接表与进程快照，执行后再取一次做对比，并把这次操作写进证据说明。**Apache 侧同理**——`apachectl -S` 会解析配置，也放到副本上。

<a id="section-15"></a>

#### 陷阱 2：找到的 `nginx.conf` 根本没被加载

**现象**：`find` 找到一个 `nginx.conf`，按它去定位日志目录，结果「日志不存在」。

**原因**：**一台机器上可能有多套 Nginx 配置同时存在**，只有一套真正生效。案例里配置在 `/www/server/nginx/conf/nginx.conf`（宝塔自编译），而运维一直在 `/etc/nginx` 找——**找到的路径存在，但那是没被加载的那套**（或者根本不存在）。反向情况同样存在：Docker/K8s 环境下容器内还有另一套配置。

**影响**：**「日志不存在」这个结论的方向性错误**——它会把整个访问日志分析线废掉。案例中委托方「服务器日志里什么都没有」的说法正是这么来的。

**核查**：**先读 `include` 关系，再确认哪套在跑。** ① `grep -nE '^\s*include' nginx.conf` 看它引入了哪些文件；② 对副本执行 `nginx -T` 得到全量生效配置（首选）；③ **离线镜像上还可以用「运行痕迹」交叉验证**：哪个目录下的日志文件 mtime 是最新的、哪个配置目录里有 `*.pid` 或运行用户的痕迹，哪个就是实际在用的。判定依据不是「路径看起来标准」，而是「证据显示它被使用」。

<a id="section-16"></a>

#### 陷阱 3：假设日志格式是 `combined`，并凭直觉取字段

**现象**：写脚本按 `combined` 格式解析日志，抽出「IP、时间、URL、UA」，结果时间字段取到了用户名，UA 字段为空。

**原因**：**两个问题叠在一起。** ① **格式可以自定义**：一台机器上可以有多个 `log_format` 定义、多个 `access_log` 引用不同格式。默认是 `combined` 不等于实际是 `combined`——自定义格式可能没有 UA/referer，也可能**包含 cookie 或请求头**（这时日志文件本身就是凭据载体）。② **combined 的字段顺序不直观**：结构是 `$remote_addr` **空格 `-` 空格** `$remote_user` **空格** `[$time_local]`——IP 之后先是字面连字符，再是用户名，最后才是方括号里的时间。凭直觉写成「IP、时间、用户」必然错位。

**影响**：**字段错位导致整个分析失真**，而且是静默失真——脚本「解析成功」但**取到的是别的字段**（比如把响应体大小当成了状态码）。在按时间切片的分析里，一个字段错位会让整个时间窗全错。

**核查**：先 `grep -n 'log_format'` 列出所有格式定义，再逐个 `access_log` 确认引用的是哪一个。 拿到实际格式后**用 `awk -F'"'` 切引号**——`$1` 是 `IP - user [time]`，`$2` 是完整请求行，`$3` 是 referer + UA；IP 取 `split($1,a," ")` 的 `a[1]`，**时间从方括号里正则提取**（`[$time_local]` 内部含空格：`[18/Mar/2024:02:14:33 +0800]`）。永远用 2–3 行真实日志人工核对解析结果再跑全量——这是最便宜也最有效的防错手段。不同 location 引用不同格式时要分别解析，不能一套规则打天下。

<a id="section-17"></a>

### 4.2 字段与路径判读

<a id="section-18"></a>

#### 陷阱 5：只看 `/var/log/nginx/`，漏了宝塔的 `/www/wwwlogs/`

**现象**：在 `/var/log/nginx/` 找不到站点访问日志，报告写「该站点无访问日志」。

**原因**：**日志路径由配置决定，而面板环境的路径与源包不同。** 案例里 `access_log /www/wwwlogs/digiforensics-site.log;`——`/var/log/nginx` 里当然什么都没有。这与「日志不存在」是完全不同的两件事。

**影响**：**把「路径找错」写成「数据不存在」**，委托方会据此认为无法还原攻击时间线。而实际上访问日志完好无损。

**核查**：**日志路径必须从配置文件里读出来，不能猜。** 流程是：① 定位生效配置；② `grep -rnE 'access_log' ` 拿到全部日志路径；③ 按这些路径去取。配置里写 `off` 的 location 要单独记下来——那不是「日志在别处」，而是「这里没有日志」，两者在报告里必须区分表述（陷阱 6）。

<a id="section-19"></a>

#### 陷阱 6：★ 看到 `access_log off` 就判定「攻击者删的」

**现象**：某个站点或 location 的访问日志关闭，报告写「攻击者关闭了日志以隐藏痕迹」。

**原因**：`access_log off` 是一个常见的正常配置——用于高频的静态资源目录、API 接口、健康检查端点、后台管理路径，降压是真实存在的运维动机。而且**很多面板在删除站点或调整配置时会留下这个状态**。光凭 `off` 无法区分「预先关闭」与「案发后关闭」。

**影响**：**过度归因**。案例里 `old.digiforensics` 的 `access_log off` 确实与篡改有关，但**配置 mtime 早于入侵时间**——也就是说这一行很可能**本来就是那样配的**，攻击者只是恰好利用了它。把「恰好利用」说成「刻意关闭」，就是一次无依据的指控。

**核查**：要判断是否案发后被改，看配置文件的 mtime 与 ctime，并与其他证据做时间对照。 判据：① `access_log` 所在 `.conf` 文件的 `mtime` 与 `ctime`（`ctime` 不可回溯伪造，是更可靠的锚点）；② 是否晚于已知入侵时间窗；③ 该文件**其他部分**是否同期被改（如果只有这一行的时间指向可疑，证据更弱）；④ 面板侧的操作日志（`action.log`）里是否有改配置的记录。报告里写「该 location 配置为 `access_log off`，配置 mtime 为 `<时间>`，早于已知入侵时间，无法确认是否由攻击者添加」——把不确定性留给读者，而不是替它下结论。

<a id="section-20"></a>

#### 陷阱 7：只查站点根目录的 `.htaccess`

**现象**：在站点根目录找到 `.htaccess` 之后就认为查完了，报告里写「未发现隐藏重写规则」。

**原因**：Apache 的 `.htaccess` 是逐级向上查找的——请求 `/a/b/c.php` 时，Apache 会依次检查 `/a/b/.htaccess`、`/a/.htaccess`、`/.htaccess`，**任一层级的规则都会生效**。只查根目录意味着**子目录里的规则完全没被看到**，而子目录恰恰是攻击者放置东西的位置。

**影响**：**漏掉真正生效的隐藏规则。** 案例里攻击者把 `.user.ini` 放在 `old/` 子目录而不是站点根——如果只看根目录就下「未发现异常配置」的结论，整个篡改机制就漏了。

**核查**：`find /mnt/df/www/wwwroot -name '.htaccess'` 全盘找，逐个读内容。 读的时候注意三件事：① `RewriteRule` 的目标模式（禁访问的路径名是否可疑、是否在给某个后门路径放行）；② `RedirectMatch 404` 这类「隐藏目录」的规则是否覆盖了不该覆盖的路径；③ `php_value` / `auto_prepend_file` 这类**会改变 PHP 执行行为的指令**——它们是劫持机制而非单纯的访问控制。

<a id="section-21"></a>

#### 陷阱 8：★ 以为 `.htaccess` 一定生效

**现象**：站点里有 `.htaccess` 写着 `deny from all`，报告据此写「该目录已被禁止访问，攻击者无法通过它」。

**原因**：`.htaccess` 的生效前提是 `AllowOverride` 不是 `None`。 Debian/Ubuntu 的 Apache 默认 `AllowOverride None`，这意味着站点目录里的 `.htaccess` **完全不被读取**——你在里面写的任何规则都是死条文。另外 `mod_rewrite` 模块没启用、或 `RewriteEngine On` 没写，同样导致规则不生效。

**影响**：**把一个失效的配置当成有效的防护。** 报告里写「该目录已被 `.htaccess` 禁止访问」，而实际上它是敞开的——**这会给委托方一个虚假的安全结论**，而它可能正是攻击者利用的入口。

**核查**：先验证 `.htaccess` 是否有生效条件，再解读它的内容。 三个检查：① `grep -rn 'AllowOverride' /evidence/apache-conf/`——必须是 `All` 或至少包含 `FileInfo`/`Limit`；② `ls /etc/apache2/mods-enabled/` 确认 `mod_rewrite` 已启用（文件名是 `rewrite.load`）；③ `.htaccess` 里是否有 `RewriteEngine On`。报告里的表述要区分「配置了但未生效」与「配置且生效」——前者要写成一条配置缺陷（说明团队误以为加固了），后者才能作为防护证据。

<a id="section-22"></a>

#### 陷阱 9：把反向代理场景下的 `$remote_addr` 当真实客户端 IP

**现象**：日志里所有 IP 都是同一个（CDN 或 SLB 的 IP），分析员把这当作「所有访客都来自这个 IP」，或反过来据此认为「攻击者的真实 IP 被隐藏，无法归因」。

**原因**：当站点在反向代理后面时，`$remote_addr` 是代理的地址，不是客户端的。 关键在于后端有没有配置 `X-Forwarded-For`：① 配了 `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` → **后端应用日志里的 IP 可以采信**（且 Nginx 自己的 access.log 里也能用 `$http_x_forwarded_for` 取到）；② **没配** → 客户端 IP 根本没有被传递下来，Nginx 侧日志里就是代理 IP，信息已经永久丢失了。

**影响**：要么把 CDN IP 当成攻击者（最常见的错误之一），要么把「信息已丢失」当成「无法归因」而放弃。 案例里报告写「`198.51.100.24` 是操作者」但强度标为「中，需排除 `X-Forwarded-For` 缺失导致的误判」——**这个保留是必要的**，因为如果站点实际前面还有一层 CDN，那 6 条日志里的 IP 到底是不是真实来源，取决于有没有正确传递该头。

**核查**：先看 `proxy_set_header`，再决定日志里的 IP 是什么语义。 三种情况的正确表述：① 有该头且日志里能取到 → 「该 IP 为客户端来源，**前提是上游代理未被伪造该头**」；② 无该头 → 「Nginx 侧记录的为代理 IP，**客户端信息未在 Web 层留存**」，此时要转向上游（CDN 日志、SLB 访问日志）；③ 日志格式里根本没有这个字段（自定义 `log_format`）→ 同样属于「未留存」。**还要注意反向的伪造风险**：`X-Forwarded-For` 是可以被客户端随意设置的，只有当代理层做了覆盖/追加而非信任客户端传入值时它才可信——`$proxy_add_x_forwarded_for` 会把 `$http_x_forwarded_for` 追加进去，所以日志里的值是「客户端声称的 + 真实对端」拼接的结果，**第一个值不可信**。

<a id="section-23"></a>

#### 陷阱 10：把 `root` 与 `alias` 的语义差别当成配置细节忽略

**现象**：`location /static/ { alias /data/files/; }` 这种写法被归为「常规配置」，没被仔细核对。

**原因**：两者的路径拼接规则不同，而 `alias` 少写尾斜杠是历史上造成目录穿越问题的典型根因。 `root` 是「替换 location 前缀」，`alias` 是「整段替换」——请求路径里含 `..` 时，拼接结果可能落到预期目录之外。这属于「配置是否构成攻击面」的判断，不是格式问题。

**影响**：**漏掉一个既有的目录穿越入口。** 报告里没有这条风险项，委托方也不会去修——而攻击者可能正是通过它读到了 `/etc/passwd` 或站外配置。

**核查**：逐个核对 `root` / `alias` 指令，特别是 `alias` 的尾斜杠与目标路径。 同时找**「站外目录」**：`grep -rnE '^\s*(root|alias) ' | grep -v '/www/wwwroot'`，把所有指向预期路径之外的都列出来，逐个核实「是否该存在、内容是否正常」。配置里指向 `/data/`、`/tmp/`、`/opt/` 之类的站点根，都是需要解释的。这类配置的 `mtime` 也要记录——**它是「计划外目录何时出现」的锚点**。

<a id="section-24"></a>

### 4.3 归因与结论

<a id="section-25"></a>

#### 陷阱 11：把日志缺失写成「无访问」

**现象**：某个时间段的日志查不到，报告写「该时段无访问记录」。

**原因**：日志缺失至少有四种成因，且它们在报告里的价值完全不同：**轮转覆盖**（`rotate 7` 到期删除最老那份，压缩归档被删）；**人为删除**（`rm access.log-20240310.gz`）；**配置为 `off`**（根本没在记）；**时间格式跨越导致的文件切分**（跨零点、跨时区）。「无访问记录」把「记录不存在」和「记录里没有」混为一谈。

**影响**：**「记录不存在」被当成「没有发生」。**

案例里 `/old/` 下的行为因为 `access_log off` 完全没有 Nginx 侧记录。如果写成「该时段无访问」，等于把「有痕迹但没记」说成「没发生过」。

**核查**：**先解释缺失成因，再给结论。**

核对 `cat /etc/logrotate.d/nginx` 看 `rotate`/`daily`/`compress` 设置，**列出文件序列看是否连续**。案例的判据就是「若存在 `access.log` 但缺少 `access.log-20240310.gz`，说明那天被手工删过」。

表述模板：「`<时段>` 的访问日志**文件不存在**，经核对 `logrotate` 配置（`rotate 7`）与文件序列，判定为**该时段记录已被轮转删除**；**不能据此认为该时段无访问行为**。」

如果成因不明，写「记录缺失，成因待查」，不要往良性方向解释。

<a id="section-26"></a>

#### 陷阱 12：在取证时访问 `server-status` 却没留痕

**现象**：为了抓活证据访问了 Apache 的 `server-status?auto`，拿到数据后直接写进报告，没有记录这次访问本身。

**原因**：这是一次真实的 HTTP 请求，会在 `access.log` 里留下一条记录（如果该站点开了日志），也会出现在 `server-status` 自己的输出里。**取证动作本身改变了被检环境的状态**，而这个改变没有被记录。

**影响**：**污染了自己的证据**。后续分析时看到这条记录，会疑惑「取证人员是不是也访问了不该访问的路径」；更实际的问题是——如果委托方事后核对自己在正常时间没有访问过 `/server-status`，这条记录需要解释。

**核查**：**取证期间对目标发起的每一个请求都要留痕。** ① 记录访问的 URL、时刻、客户端 IP；② 立即截图或保存原始输出（`server-status?auto` 的内容本身就是证据——它会列出当前正在处理的请求 URL、来源 IP、子进程 PID）；③ 把它产生的 access.log 条目一并提取出来作为证据，同时在报告里注明「该条目为取证人员于 `<时间>` 访问所致，非攻击行为」；④ 只在委托方明确授权的在线取证窗口内进行，**不擅自访问**。这个接口的价值很高——它是任何离线日志都给不了的活证据，但前提是窗口期恰好覆盖了攻击者的活动。

<a id="section-27"></a>

#### 陷阱 13：把「未发现异常配置」写成无边界的否定结论

**现象**：报告写「Nginx 配置未见异常」，不写检查范围。

**原因**：配置层的阴性发现被多重因素限制：**只查了一套配置**（陷阱 2）；`access_log off` 的 location 里没有任何配置可查（行为不留痕）；**`.htaccess` 逐级查找，只查了根目录**（陷阱 7）；**PHP 层配置不在 Nginx 配置里**（`.user.ini`、`php.ini` 的 `disable_functions`、`.htaccess` 的 `php_value`）——案例里篡改机制的核心在 `.user.ini`，而 `.user.ini` 不是 Nginx 配置。

**影响**：**阴性发现被高估**，而这在「配置是否被篡改」这个问题上是严重的——委托方会认为「配置没被动过，问题在代码」，从而走错整改方向。

**核查**：**三段式。**

第一段写已查范围：「在 `<列出已查配置文件与目录>` 范围内，检索了 `<列出检索项：隐藏规则 / 危险 alias / 站外 root / 代理头配置>`，**未发现**异常配置项」。

第二段写未覆盖项：「`access_log off` 的 `<location>` 下无任何 Web 层记录、PHP 层配置（`.user.ini`、`php.ini`）不在本项检查范围、`sites-available/` 中未生效的孤儿配置、容器内配置」。

第三段给动作：把「被 `off` 关闭的 location」单独列成一节——**那是本案最需要解释的配置事实**。

<a id="section-28"></a>

### 4.4 工具行为与环境前提

这一组讲的是另一类失误：**解析规则写错时工具不会报错**，以及**结论依赖某个版本的默认行为**。这两类都不会留下错误提示。

<a id="section-29"></a>

#### 陷阱 14：`awk -F'"'` 切分日志时把 referer 当成 UA

**现象**：用 `awk -F'"' '{print $4}'` 提取 User-Agent，得到的是 Referer 值；或者从 `$NF` 取 UA，在请求行里含引号的畸形请求上取到空值。

**原因**：combined 日志被双引号切成三段，但「最后一段」不一定是 UA。 正常情况下 `$3` 是 `referer UA`，按空格切分的最后一个字段是 UA——**前提是 UA 里不含空格**。而 UA 字段本身允许含空格（`Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)` 这类字符串就带空格），所以「取最后一个空格后的 token」这种写法在**多数正常行上碰巧正确**，只在部分行上出错。更麻烦的是 Referer 为空时日志形如 `"-" "Mozilla/5.0..."`，UA 仍在 `$3` 的后半段——只要脚本写了 `print $3` 就拿到 `"-" "Mozilla/5.0..."` 整串。

**影响**：UA 是工具指纹的主要来源。取错字段会让你把 Referer 里的域名当成客户端工具，凭空造出一条「访问来源」的结论；或者 UA 全部为空，被读成「攻击者使用了自定义 UA、意图规避识别」——**而真相只是解析错了**。这类错误在报告里表现为一个具体的、有说服力的错误结论，比空值更危险。

**核查**：不要按位置猜，按 `log_format` 的定义逐段对应；UA 取第三段里最后一个引号对的内容：

```bash
# UA：第三段内最后一个引号对之间（Referer 在前、UA 在后）
awk -F'"' '{n=split($0,q,"\""); print q[n-1]}' /mnt/df/www/wwwlogs/digiforensics-site.log | head -5
# Referer：第三段内第一个引号对
awk -F'"' 'NF>=6 {print $5}' /mnt/df/www/wwwlogs/digiforensics-site.log | head -5
# 状态码与响应字节数在请求行之后
awk -F'"' '{split($2,a," "); print a[2], a[3]}' /mnt/df/www/wwwlogs/digiforensics-site.log | head -5
```

**自检判据**：跑完全量后 `sort -u | wc -l`，**取到的不同 UA 值数量应该远大于 1**。若结果只有 1–2 个值，先怀疑解析规则，再怀疑攻击者。另外用 `awk -F'"' 'NF!=6'` 单独挑出行数不等于 6 的行——这些是被引号或换行破坏的畸形请求，它们常常正是扫描器与注入尝试的产物，值得单独成节分析。

<a id="section-30"></a>

#### 陷阱 15：把请求量低谷当成攻击者的时间偏好

**现象**：按日期统计请求量，发现某日请求数只有相邻日的十分之一，报告写「攻击者刻意避开白天活动，多在夜间出现」。

**原因**：日志的切分单位是「文件」而不是「日」，只有无异常时两者才一致。 跨零点时当前文件同时含有前一天尾部与当天头部，此时单文件内的日期分布本就跨天；被 `truncate`、`sed -i` 或重写过的日志会在**同一文件内出现日期回退**（先 03-18 的行、后面又出现 03-17 的行）；`logrotate` 的 `dateext` 与纯数字后缀混用时，**文件名的时间序与文件内容的日期可能完全不对应**。按 `sort` 排序后取区间，会把这些乱序当成数据缺失。

**影响**：请求量低谷会被读成「攻击者的行为习惯」，而真相是文件被截断或轮转错位。**反向污染更麻烦**：你会把一个文件里的两段内容当成两天，在时间线上制造一个不存在的「活动间歇」，用它支撑「攻击者只在夜间活动」这类画像——而这个画像会反过来影响对入侵窗口的划定。

**核查**：**先确认每个文件的时间范围与单调性，再谈日分布**：

```bash
# 每个文件的首末时间，确认是否跨天
for f in /mnt/df/www/wwwlogs/*.log /mnt/df/var/log/nginx/*.log; do
  [ -f "$f" ] || continue
  echo "$f  首: $(head -1 "$f" | grep -oE '\[[^]]+\]')  末: $(tail -1 "$f" | grep -oE '\[[^]]+\]')"
done
# 检查文件内时间是否回退（回退说明被重写或拼接过）
python3 - <<'EOF'
import re, datetime
pat = re.compile(r'\[(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})\]')
prev = None
for n, line in enumerate(open('/mnt/df/www/wwwlogs/digiforensics-site.log', encoding='latin-1'), 1):
    m = pat.search(line)
    if not m: continue
    d = datetime.datetime.strptime(' '.join(m.groups()[:6]), '%d/%b/%Y:%H:%M:%S')
    if prev and d < prev: print(f'行 {n}: 时间回退 {prev} → {d}')
    prev = d
EOF
```

`awk` 的字符串比较对 `[18/Mar/2024:...]` 这种格式不可靠，时间回退检查必须解析成日期时间再比较。报告里描述请求量分布时，粒度以「文件」为准并注明跨零点情况，不要直接按日期字段下「某日偏低」的结论。

<a id="section-31"></a>

#### 陷阱 16：把 `logrotate` 的默认设置当作该机的实际设置

**现象**：报告写「按 `rotate 7` 配置，旧日志保留 7 天」，据此判定「7 天前的日志不可得属正常」，把对应的证据缺口一笔带过。

**原因**：`rotate 7` 是发行版默认模板里的值，不是该机的实际值。 `/etc/logrotate.d/nginx` 可能被改成 `rotate 30`、可能被整段注释、也可能被面板改写。更关键的是 **`rotate` 计数的是轮转份数而不是天数**：`daily` 才按天，`weekly` 按周，`size 100M` 则完全按容量切分、**与天数无关**——`size` 模式下 `rotate 7` 表示保留 7 个文件，而每个文件可能是一小时也可能是一个月。**把这三种触发条件混为一谈是本条的核心。**

**影响**：会用「日志过期删除」这个良性解释覆盖一个真实的证据缺口。若实际是 `weekly` 且 `rotate 4`，那么 3 周前的日志仍在磁盘上——报告却告诉委托方「已经不可得」，委托方会以这个结论为前提放弃追查；而那些文件一旦被正常轮转删掉，就再也找不回来。

**核查**：逐 site 读全 `logrotate` 片段的四个要素（触发条件、保留份数、是否压缩、是否延迟压缩），**不从发行版默认值推断**：

```bash
cat /mnt/df/etc/logrotate.d/nginx 2>/dev/null | grep -vE '^\s*(#|$)'
# 逐项确认：rotate <N> / daily|weekly|monthly|size <n> / compress / delaycompress
# 日志后缀形态也要看：.1 纯数字 = 非 dateext；-20240317 = dateext
ls -1 /mnt/df/www/wwwlogs/ | head -20
```

**表述模板**：「该站点日志按 `<触发条件>` 轮转、保留 `<N>` 份、`<是否压缩>`；据此 `<日期>` 起的记录应仍存在于 `<文件名模式>`，**当前该文件缺失**，成因待查。」——先按实际配置算出「应该存在哪些文件」，再看哪些真的不在，这是把「缺失」与「过期」区分开的唯一办法。

<a id="section-32"></a>

#### 陷阱 17：把 `try_files` 落到目录或 `autoindex on` 当成正常配置

**现象**：`location / { try_files $uri $uri/ /index.php?$args; }` 被记为「标准 PHP 站点配置」，`autoindex on` 被记为「调试遗留，无害」。

**原因**：这两条都是配置面攻击面，而判定依赖 Nginx 的匹配优先级与指令所在层级。 ① `try_files` 里的 `$uri/` 一旦命中目录，**Nginx 会尝试列目录**；只有当后面没有兜底指令接住时才返回索引列表。② `autoindex on` 的影响范围取决于它挂在哪一层——放在 `server` 层是整站生效，放在某个 `location` 里只影响该路径，而读报告的人极易忽略层级。③ **`internal;`** 会让 location 只被内部重定向访问、外部直连返回 404——这类「看起来像隐藏后门目录、实际是内部接口」的配置，不核对 `internal` 就会被误标为可疑入口。

**影响**：两个方向都出错。把 `internal` 的内部接口标为「隐藏后门」是误报；把 `$uri/` 落到目录当正常则会**漏掉一个真实的目录列表泄露入口**——目录列表往往直接暴露备份文件、上传目录与源码树结构，是后续入侵路径的起点。

**核查**：按「层级 + 指令组合」判定，而不是「看起来像不像」：

```bash
grep -rnE -A6 '^\s*(server|location)\s|^\s*(try_files|autoindex|internal|alias|root)\b' \
  /evidence/nginx-conf/etc/nginx/ 2>/dev/null | head -80
```

三条核对项：**① `autoindex` 在哪一层**（server = 整站，location = 该路径）；② `try_files` 的最后一个 fallback 是什么（`/index.php?$args` 属正常，无兜底或兜底是目录则需解释）；③ 疑似隐藏目录的 location 是否有 `internal;`——有 `internal` 是内部接口，无 `internal` 且能返回 200 才是可疑入口。 还要注意 location 匹配是有优先级的（精确 `=` > 正则 `~` > 前缀 `^~` > 普通前缀），一个正则 location 可能整段覆盖掉你刚读完的那个，核对时按匹配顺序通读一遍，不要孤立逐个看。

<a id="section-33"></a>

#### 陷阱 18：`proxy_pass` 的尾斜杠差异被当成无关格式

**现象**：两个 location 都是 `proxy_pass http://127.0.0.1:8080`，一个末尾带 `/`、一个不带，被当作写法不统一的普通差异记下。分析时按日志里的请求路径去推后端收到的路径，推算结果与后端应用日志对不上。

**原因**：**带尾斜杠与不带尾斜杠的路径传递规则不同。** `location /api/ { proxy_pass http://127.0.0.1:8080/; }`（**带**斜杠）会把 `/api/` 前缀**剥掉**再转发，`/api/x` 到后端变成 `/x`；而 `proxy_pass http://127.0.0.1:8080;`（**不带**斜杠）会**原样保留** `/api/`，`/api/x` 到后端仍是 `/api/x`。两者在访问日志里看起来毫无区别（日志记的是客户端请求的 URI，不是转发后的 URI），**只有拿到后端应用日志比对才能发现**，而这正是取证里最容易缺失的一环。

**影响**：你会用错误的路径映射去反查后端接口，把某个后端接口的调用记录关联到错误的公开路由上；或者反过来，用后端日志里的 `/api/...` 去匹配 Nginx 日志里的 `/...`，匹配不上就误判「有请求未出现在 Nginx 日志中」，进而怀疑 Nginx 日志被篡改——**用一个自己造出的映射错误去指控证据。**

**核查**：把每个 `proxy_pass` 的尾斜杠状态与路径传递规则逐条记录，并标出它影响的 location：

```bash
# 逐条打印 proxy_pass 及其所属 location（-B 给出上文）
grep -rnE -B4 '^[[:space:]]*proxy_pass' /evidence/nginx-conf/etc/nginx/ 2>/dev/null
# 记录表：location 前缀 | proxy_pass URL（有无尾斜杠）| 转发后路径规则
```

**表述模板**：「`location /api/` 的 `proxy_pass` 末尾**带** `/`，前缀 `/api/` 被剥除，后端实际收到 `<示例>`；该转发关系下 Nginx access.log 记录的仍是客户端原始 URI，两者不可直接对应。」拿到后端应用日志时按这条规则换算后再比对，**换算规则本身要写进报告**，否则读者无法复核。


## 五、案例示例

<a id="section-34"></a>

### 5.1 配置定位失败与 access_log off 造成的证据断层

**场景**

查获一台 Ubuntu 22.04 云主机（编号 `web01`，宝塔环境）。委托方报告：官网首页被改成跳转博彩站，但「服务器日志里什么都没有」。镜像 `DigiForensics.dd` 只读挂载到 `/mnt/df`。

这条路径值得先走，是因为「**日志里什么都没有**」这个前提**本身就是待验证的结论**。

这句话里包含两个独立命题——「日志在哪」和「日志记了什么」——**委托方只验证了第一个，而且很可能验证的位置是错的**。查清配置的层级，是打开后面所有取证动作的前提。

**处置过程**

**第 1 步 · 定位配置**

```bash
find /mnt/df -maxdepth 5 -name 'nginx.conf' 2>/dev/null
# /mnt/df/www/server/nginx/conf/nginx.conf       ← 宝塔的，不是 /etc/nginx
cp -rp /mnt/df/www/server/nginx/conf /evidence/nginx-conf-bt/
grep -nE '^\s*include' /evidence/nginx-conf-bt/nginx.conf
# include vhost/nginx/*.conf;
```

**这就是第一个转折点**：运维一直在 `/etc/nginx` 找日志，所以「什么都没有」。宝塔的日志在 `/www/wwwlogs/`。

**第 2 步 · 提取站点映射**

```bash
grep -rnE 'server_name|root |access_log|error_log' /evidence/nginx-conf-bt/vhost/nginx/ | head -40
# server_name digiforensics-site;
# root /www/wwwroot/digiforensics-site/;
# access_log /www/wwwlogs/digiforensics-site.log;
# access_log /www/wwwlogs/digiforensics-site.error.log;
```

| 域名 | root | access_log | 备注 |
|---|---|---|---|
| `digiforensics-site` | `/www/wwwroot/digiforensics-site/` | `/www/wwwlogs/digiforensics-site.log` | 主站 |
| `old.digiforensics` | `/www/wwwroot/digiforensics-site/old/` | `off` | ★ **无访问日志** |

**第二个转折点**：`old.digiforensics` 的 `access_log off`。篡改首页的访问行为**不会出现在任何 Nginx 日志里**。

委托方「日志里什么都没有」的说法，**只对了一半**——主站日志存在，但关键子域被刻意静音了。

**第 3 步 · 查隐藏配置**

```bash
find /mnt/df/www/wwwroot -name '.user.ini' -exec grep -Hn . {} + 2>/dev/null
# /www/wwwroot/digiforensics-site/old/.user.ini:2:auto_prepend_file=/www/wwwroot/digiforensics-site/old/helper.php

ls -la /mnt/df/www/wwwroot/digiforensics-site/old/
# -rw-r--r-- 1 www www  824 2024-03-17 22:38 helper.php     ← 篡改时刻
ls -l --time-style=long-iso /mnt/df/www/wwwroot/digiforensics-site/index.html
# -rw-r--r-- 1 www www 5120 2024-03-17 22:40 2024-03-17 22:40 index.html  ← 被改
```

`.user.ini` 的 `auto_prepend_file` 指向 `helper.php`——**每个请求都会先执行它**，这正是篡改首页而不改 `index.html` 内容的机制（详见[第 06 篇](server-web-webshell-detection.md)）。本案只确认该文件的配置指向与存在性，未执行、未还原其逻辑。

**第 4 步 · 主站日志仍有线索**

```bash
Z=/mnt/df/www/wwwlogs/digiforensics-site.log
awk '{print $1}' "$Z" | sort | uniq -c | sort -rn | head -5
# 84213 203.0.113.10        正常访客
#     6 198.51.100.24        ★ 陌生 IP，只有 6 次
awk -F'"' '{split($1,a," "); print a[1], $2}' "$Z" | grep '198.51.100.24'
# 198.51.100.24 GET /old/ HTTP/1.1
# 198.51.100.24 GET /old/helper.php HTTP/1.1     ← ★ 探测后门是否生效
# 198.51.100.24 POST /old/helper.php HTTP/1.1
```

6 次访问，间隔规律，最后访问 `helper.php`——这是典型的「写入后验证」模式。`POST` 请求说明攻击者不只是放置了文件，而是**通过它下发指令**（内容改写、投放新文件）。

第 5 步 · 对照 `.user.ini` 时间线

| 时间 | 事件 | 证据 |
|---|---|---|
| 22:38 | `helper.php` 写入 | 文件 mtime |
| 22:40 | `index.html` mtime 更新 | 文件 mtime |
| 22:41–22:44 | `198.51.100.24` 6 次访问 `/old/` 与 `helper.php` | access_log |
| 22:50 | 主页开始出现博彩跳转 | 委托方报告 |

`access_log off` 不是「没有攻击」，而是「攻击这段没被记录」。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 运维「查了 `/etc/nginx` 所以没日志」的说法不成立 | 实际配置在 `/www/server/nginx/conf/` | 强 |
| `old.digiforensics` 的访问日志被 `access_log off` 关闭 | vhost 配置原文 | 强 |
| 首页篡改通过 `.user.ini` 的 `auto_prepend_file` 实现 | `.user.ini` 原文 + `helper.php` mtime | 强（双源） |
| `198.51.100.24` 是操作者 | access_log 中 6 次访问 | 中（需排除 `X-Forwarded-For` 缺失导致的误判，见 2.3） |
| `helper.php` 接受了 POST 指令 | access_log 请求方法 | 中（未捕获请求体） |
| `/old/` 下的具体行为无 Nginx 记录 | `access_log off` | 强（**证据缺口**） |
| **`access_log off` 是攻击者所加** | 配置文件 mtime 早于入侵时间 | **不成立——见误判对照** |

**本节能证明**：配置的真实位置、哪个 vhost 缺日志、后门文件的落地时刻、攻击 IP 的存在与时间。
**本节不能证明**：`/old/` 下的具体行为、POST 的请求体与指令内容、`access_log off` 的添加者与添加时间。

**误判对照**

这个案例最容易出的错有三个，第三个最需要注意——**它涉及一个很自然但完全错误的归因冲动**。

1. **把「日志被配置关闭」与「日志不存在」混为一谈。**判别方法是**看 vhost 配置原文**：`access_log off` 是**人为配置**；`access_log` 指向一个不存在的路径是**另一种问题**（权限或路径错误）；配置文件里根本没有 `access_log` 指令，则说明**走了 Nginx 的默认路径**（默认在编译选项指定的前缀下）。三种情况在「查不到日志」这个现象上表现完全一样，但含义天差地别——第一种是主动隐藏，第二种是配置错误，第三种是找错位置。本案是第一种，且**它直接告诉了你攻击者知道哪个路径不受记录**。
2. **把「6 次访问」当成身份认定。**6 是个极小的样本量。判别力在于：这一条 IP 在 84,213 次正常访问中只出现 6 次，且全部指向 `/old/` 与 `helper.php`——**指向性远强于频次**。但仍要排除两种可能：(a) 该 IP 若是反向代理/CDN 节点，其 `$remote_addr` 会被大量正常流量共用；(b) 若站点在反代之后，真实客户端在 `X-Forwarded-For` 里而 `$remote_addr` 是代理 IP。**本案 2.3 已说明确认方法**，结论只能是「该 IP 与后门操作高度相关，**待结合反代配置确认**」。
3. 把 `access_log off` 归因于攻击者。这是最需要克制的一条。判别方法很简单：看配置文件与该指令所在 vhost 的 mtime。本案 `old.digiforensics` 的 vhost 文件 mtime **早于入侵时间数月**，说明**这个配置在攻击发生前就存在**。一个攻击者通常不会特意去改一个已存在的站点配置来隐藏自己——**他更可能直接用现有的静音路径**。正确表述是「`access_log off` 为站点既有配置，其存在客观上使 `/old/` 下的行为不被记录；配置非本次事件所加」。

**按错误判据走的代价**：第 3 条踩中的代价在责任认定上最重。

若报告写「攻击者关闭了该子域的日志以掩盖痕迹」，而配置文件证明这是站点上线时就这么配的，那么委托方会据此追问「日志关闭了多久、是不是内部有人配合」——一个技术问题被引向内部责任调查，而真相是运维疏忽。

反过来，若因为这条归因不成立就**不强调这个暴露面**，委托方也不会去修它——而 `access_log off` 至今仍然在那儿，任何下一次入侵都同样不会被记录。

正确的处理是**两条都写**：不归因，但要列为加固项。

<a id="section-35"></a>

### 5.2 主站与子域日志的缺口划分与反证清单

**场景**

承接 5.1。委托方在看完时间线后提出一个更实际的要求：「我们要出一份完整的损失评估。哪些请求发生了、哪些没发生，你们能不能给个清单？」

这个要求看似简单，实际上是这类案件里最难交付的东西——**因为答案不是「有」或「没有」，而是一张分层缺口表**。把缺口讲清楚，委托方才知道哪些损失可以评估、哪些只能承认无法评估。

**处置过程**

第 1 步 · 先把所有可能的记录层列出来，逐层标注可用性

以 `/old/` 路径下 22:38–23:00 的行为为待评估区间：

| 层 | 记录内容 | 本案可用性 | 覆盖情况 |
|---|---|---|---|
| Nginx access_log | 每个 HTTP 请求 | **不可用** | `access_log off` |
| Nginx error_log | 5xx / upstream 错误 | **不可用** | 同 vhost 亦为 `off` |
| PHP 错误日志 | PHP 报错 | **不可用** | `php.ini` 的 `error_log` 未配置，落 `/dev/null` |
| PHP-FPM access log | 每个 PHP 请求 | **不可用** | 未启用（`pm.status_path` 存在但无 access log） |
| 站点应用日志 | 业务侧记录 | **部分** | 应用自建 `storage/logs/`，但**仅记业务异常，不记所有请求** |
| 文件系统 mtime | 文件增删改时刻 | **可用** | 精度到秒 |
| 主机 `auth.log` | 登录 | **可用** | 但 Webmin/面板走自己的认证路径 |
| 面板日志 | 管理操作 | **不可用** | 本 vhost 不受面板管理 |

**这张表是本节的核心交付物。**它比「有没有日志」这个回答有用得多。

**第 2 步 · 从还能用的层里尽可能还原行为序列**

```bash
# 应用日志：注意它只记异常，所以「没记」不等于「没发生」
ls -l --time-style=long-iso /mnt/df/www/wwwroot/digiforensics-site/storage/logs/
# app-2024-03-17.log  2024-03-17  88214 bytes
grep -aE '22:3[0-9]|22:4[0-9]' /mnt/df/www/wwwroot/digiforensics-site/storage/logs/app-2024-03-17.log | head
# [2024-03-17 22:44:07] WARN  rewrite target outside root, rejected: /old/helper.php
# [2024-03-17 22:44:22] WARN  cache purge requested by /old/

# 文件系统时间线：这是本案最可靠的行为序列来源
find /mnt/df/www/wwwroot/digiforensics-site -newermt '2024-03-17 22:30' \
     -printf '%TY-%Tm-%Td %TH:%TM:%TS  %m %10s %p\
' | sort
# 2024-03-17 22:38:41  644      824  old/helper.php            ★ 后门文件
# 2024-03-17 22:38:44  644      196  old/.user.ini             ★ 挂载点
# 2024-03-17 22:40:07  644     5120  index.html                ← mtime 变了
# 2024-03-17 22:40:09  644     4180  old/.cache/rendered.html   ★ 篡改内容落这里
```

**关键发现**：`.user.ini` 写在 `22:38:44`，比 `helper.php`（22:38:41）**晚 3 秒**——这个顺序说明攻击者**先放载荷、再挂载**，符合「配置生效即可执行」的思路。这个顺序在 Nginx 日志缺失的情况下，只能靠 mtime 推出。

第 3 步 · 反证清单：哪些「没发生」是有证据支持的

| 待证命题 | 能否证伪 | 依据 |
|---|---|---|
| `/old/helper.php` 之外是否还有同类后门 | **部分能** | 全站 `.user.ini` 扫描仅命中 1 处；但**伪装文件扫描尚未做全站结构化覆盖** |
| 22:38 之前是否已有后门 | **不能** | `old/` 下无 access_log；文件系统 mtime 只能证明 22:38 这次 |
| 数据库是否被拖 | **不能** | 应用日志不记查询；`general_log` 状态未确认 |
| 22:44 之后攻击者是否停止 | **不能** | 22:44 之后无任何记录层可用，**「沉默」是记录缺失造成的，不是行为终止** |
| `198.51.100.24` 是否为真实来源 | **部分能** | 需确认站点是否在反代后（2.3 方法） |

**第 4 步 · 把缺口写进交付物的措辞**

```markdown
在 2024-03-17 22:38 至 23:00 区间，/old/ 路径的 HTTP 访问记录因该 vhost
配置 access_log off 而不存在。据此：

- 可认定：该路径下于 22:38 落地 helper.php 与 .user.ini 两个文件（文件系统 mtime）。
- 可认定：主站 access_log 记录到 198.51.100.24 于 22:41–22:44 的 6 次请求，
  指向 /old/ 与 helper.php。
- 不可认定：该路径下的具体请求数量、请求体内容、响应状态码。
- 不可认定：22:44 之后该路径的活动情况。

未覆盖范围：Nginx access_log 与 error_log（配置为 off）、PHP 错误日志
（未配置）、PHP-FPM access log（未启用）、面板操作日志（不适用）。
```

**结论**

| 结论 | 强度 |
|---|---|
| 22:38–23:00 区间 `/old/` 路径的 HTTP 记录**结构性缺失** | 强（配置原文 + 逐层排查） |
| 缺口是**配置导致**，非日志被删除 | 强（vhost mtime 早于入侵） |
| 攻击者先放 `helper.php`（22:38:41）后挂 `.user.ini`（22:38:44） | 强（mtime 顺序） |
| 篡改内容落在 `old/.cache/rendered.html` 而非 `index.html` 本体 | 中（需与站点代码逻辑核对） |
| 22:44 之后该路径无活动 | **不成立——记录缺失不等于行为终止** |

**误判对照**

这个案例最容易出的错是**把「记录缺失」当成「行为终止」**——它是 5.1 第 3 条误判的延伸，但在损失评估场景里后果被放大。

1. **「某时段无记录」与「某时段无活动」是两个命题。**要主张后者，需要**正向证据**——比如某个必然会产生记录的层在时段内确实没有记录。判别方法是**先确认该时段的记录层是否可用**（本节第 1 步那张表）。**记录层不可用时，「无活动」是不可判定的**，正确表述是「无法判断」。
2. **应用自建日志的覆盖是业务驱动的，不是全量的。**`storage/logs/` 里只有两条 WARN 记录，**这不能证明 22:44 之后没有请求**——应用只记它认为值得记的东西。**判别方法是看应用的日志调用点**：若它只在一类事件上写日志，那么「没记」对其他类型事件没有排除力。
3. 文件 mtime 的排序是可靠的行为序，但精度有限。ext4 的 mtime 精度到纳秒、`stat` 显示到秒，**同一秒内的多次写入顺序无法区分**。本案「22:38:41 先于 22:38:44」是**跨秒的，判别力可靠**；若两文件时间相同，**则不能断言先后**。**报告里不应把同秒事件排出确定顺序。**
4. **「配置为 off」与「日志被删」要区分。**前者 vhost mtime 早于入侵；后者则会有**文件被删除的痕迹**（`/www/wwwlogs/` 目录的 ctime 变化、inode 重用、gzip 轮转文件的序号断档）。

   本案 `/www/wwwlogs/` 轮转链连续（14 份，最早 03-05），**支持「配置为 off」而非「被删」**。

   **这个区分影响的不只是技术描述，还有责任归属**——「被删」意味着有人主动清理，与「配置错误」是完全不同的性质。

**按错误判据走的代价**：第 1 条踩中，损失评估会写成「攻击活动于 22:44 结束」。委托方据此认为事件已闭环、可以恢复业务——而攻击者可能仍在通过同一条 `helper.php` 通道活动。

由于 `/old/` 没有任何记录，**这个「结束」永远不会被数据推翻**，它会一直是个错误结论。

反过来，若报告写「22:44 之后无法判断」，委托方会问「那要怎么办」——**这时正确的答案是给出补强建议**（开启该 vhost 日志、部署主机侧 HIDS、在 `/old/` 加文件完整性监控），**把取证缺口转化为可执行的加固动作**。这才是交付一份缺口清单的意义。

<a id="section-36"></a>

## 六、扩展阅读方向

**先补「活证据」和易失工件的处理方法。**本篇的在线状态页取过一次证就少一次机会，连接表与内存更是稍纵即逝——这一组解决的是「还来得及的时候怎么取」。

- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md)：配置目录的哈希固定顺序、只读挂载要求，以及为什么「先复制、后分析」不能颠倒。
- [网络连接与流量痕迹](../../memory/memory-artifact/memory-artifact-memory-network-artifacts.md)：`proxy_pass` 指向的 `127.0.0.1:某端口` 该去哪个进程上找答案。
- [网络流量与 PCAP 取证](../../memory/memory-network/memory-network-pcap.md)：access.log 已被轮转清空时，从流量侧重建会话、SNI 与请求内容。
- [Linux 与 Android 内存取证](../../memory/memory-artifact/memory-artifact-linux-android.md)：从内存还原已关闭连接，以及 Apache 正在处理的子进程。

**再补时间线能力。**配置的 `mtime`/`ctime` 是判断「是否案发后被改」的核心锚点，但单看一个时间点不够用。

- [时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md)：日志里的 `[18/Mar/2024:02:14:33 +0800]` 与文件 `mtime` 统一到同一时区，否则时间线会整体错位。
- [时间线重建](../../computer/computer-log/computer-log-linux-timeline-reconstruction.md)：把配置改动、日志首行时间、文件时间戳统一到一条轴上，支撑「时间交叉」这一核心判据。
- [哈希与完整性校验](../../fundamentals/fundamentals-concepts/fundamentals-concepts-hashes-and-integrity-verification.md)：配置副本与基线镜像的比对方式，以及为什么 `ctime` 不可回溯伪造。

**然后是本层的直接延续与邻近议题。**配置层的发现必须落到文件与流量上才能定性。

- [网站目录与 WebShell 检测](server-web-webshell-detection.md)：`root` / `DocumentRoot` 映射出的站点目录怎么查，以及 `.user.ini` 的 `auto_prepend_file` 这类配置劫持如何落到具体文件。
- [WebShell 工具流量特征](server-web-webshell-traffic-patterns.md)：把 access.log 里的字段读成可疑度排序，识别「写入后验证」模式。
- [CDN 识别与源站挖掘](server-web-cdn.md)：`$remote_addr` 是代理 IP 时如何回溯真实客户端，以及源站暴露面。
- [IIS 配置与日志](../server-log/server-log-iis.md)：Windows 侧的等价工件，W3C 字段顺序与 Nginx `combined` 可以对照着看。
- [取证工件地图（Linux 侧）](../../computer/computer-persistence/computer-persistence-persistence-artifact-map.md)：站点目录、日志目录在整机证据体系中的位置。

**最后是判据与反例。**阴性发现最容易被高估，这一组专门讲「没查到」到底意味着什么。

- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md)：`access.log` 被截断、`.bash_history` 被清空时的**识别特征**，用来判断阴性发现的真实范围。
- [Web 攻击痕迹还原](../server-log/server-log-web-attack-trace-reconstruction.md)：漏洞利用请求与后落地时序对齐，解释后门是「上传即用」还是「提权后安装」。
- [计划任务与持久化痕迹](../../computer/computer-persistence/computer-persistence-scheduled-tasks-and-persistence.md)：配置层看不到的持久化落点——cron、rc.local、systemd unit。
- [近似匹配与模糊哈希](../../fundamentals/fundamentals-concepts/fundamentals-concepts-fuzzy-hashing.md)：判断被篡改的 `index.html` 是否源自公开模板，或是否与已知 WebShell 家族同源。
<a id="section-37"></a>

## 七、命令速查

```bash
# ===== 1. 定位并固定配置 =====
find /mnt/df -maxdepth 5 \( -name nginx.conf -o -name httpd.conf -o -name apache2.conf \) 2>/dev/null
cp -rp /mnt/df/etc/nginx /evidence/nginx-conf/ 2>/dev/null
cp -rp /mnt/df/etc/apache2 /evidence/apache-conf/ 2>/dev/null
cp -rp /mnt/df/www/server/nginx/conf /evidence/nginx-conf-bt/ 2>/dev/null
find /evidence/nginx-conf* -type f -exec sha256sum {} + > /evidence/ws-conf-hashes.txt
grep -nE '^\s*include' /evidence/nginx-conf/etc/nginx/nginx.conf
find /evidence/nginx-conf* -type f -name '*.conf' -newermt '2024-03-01' -ls   # 近期改动

# ===== 2. 站点与日志映射 =====
grep -rnE 'server_name|root |alias |access_log|error_log|proxy_pass' /evidence/nginx-conf/ 2>/dev/null
grep -rnE 'ServerName|DocumentRoot|ErrorLog|CustomLog' /evidence/apache-conf/ 2>/dev/null
ls -l /evidence/apache-conf/etc/apache2/sites-enabled/          # 软链接指向
apachectl -S 2>&1 | head -40                                  # 仅在目标副本上执行
grep -rn 'AllowOverride' /evidence/apache-conf/                # 决定 .htaccess 是否生效

# ===== 3. 隐藏规则与危险配置 =====
grep -n 'log_format' /evidence/nginx-conf/etc/nginx/nginx.conf  # 别假设是 combined
grep -rn 'proxy_set_header' /evidence/nginx-conf/                # 决定后端日志里 IP 的可信度

# ===== 4. 日志统计（combined：IP → - → user → [time]）=====
Z=/mnt/df/www/wwwlogs/digiforensics-site.log
awk '{print $1}' "$Z" | sort | uniq -c | sort -rn | head -20       # Top IP
awk '{print $9}' "$Z" | sort | uniq -c | sort -rn                 # 状态码分布
awk '{print $7}' "$Z" | sed 's/?.*//' | sort | uniq -c | sort -rn | head -30
awk -F'"' '{split($1,a," "); print a[1], $2}' "$Z" | sort | uniq -c | sort -rn | head -20

# ===== 5. 轮转与留存 =====
ls -l /mnt/df/www/wwwlogs/ /mnt/df/var/log/nginx/ 2>/dev/null
cat /mnt/df/etc/logrotate.d/nginx 2>/dev/null
zcat /mnt/df/var/log/nginx/access.log-2024031*.gz 2>/dev/null | grep '198.51.100.24'

# ===== 6. Apache 在线状态页（仅在授权的在线窗口内取证）=====
curl -s 'https://127.0.0.1/server-status?auto' 2>/dev/null | head -30
ls -l /mnt/df/var/log/apache2/other_vhosts_access.log 2>/dev/null
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 服务器与 Web 取证 — Nginx 与 Apache 配置取证」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《Nginx 与 Apache 配置取证》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.vc` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
