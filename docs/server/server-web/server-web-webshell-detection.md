---
title: "网站目录与 WebShell 检测"
slug: "server-web-webshell-detection"
canonical: "https://www.digiforensics.cn/wiki/server-web-webshell-detection"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:50+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "server"
space: "服务器与云取证"
node_path: ["Web 与应用"]
---

# 网站目录与 WebShell 检测

<a id="section-1"></a>

## 一、概述

站点目录是排查落地后门的常见入口，可与日志和内存工件交叉核对。

前面几篇从配置和日志追到"发生了什么"，这一篇回答的是另一件事——东西落在哪、长什么样。

具体是三类问题：哪些文件可能不是业务文件、哪些文件内容可疑但扩展名正常、哪些机制能让站点目录里一个可疑文件都没有也能被劫持。

分析时不要在检材或分析机上执行可疑文件。


理由很实在。执行会在检材上产生新的状态变化——进程、临时文件、连接、下游写操作，而且不可逆。WebShell 通常具备 `system`、`exec` 能力，在分析机上跑一遍，等于把攻击者的能力引进你的分析环境。

而取证要求"检材状态可复现"。执行过的东西，回不到未执行。

正确姿势只有一条：只读挂载 → 复制副本 → 哈希固定 → 用文本工具看内容。

**在取证流程中的位置**：本篇属于**分析环的落地层**，承接上一层的配置映射。

`root` / `DocumentRoot` 告诉你查哪个目录，本篇负责在这个目录里给文件定性。**上游依赖** [Nginx 与 Apache 配置取证](server-web-nginx-apache.md) 提供的站点映射。

**下游支撑**有三处：流量侧验证（[第 2 步](#section-11) 找到的文件需要用 access.log 确认是否真被访问过）、主机侧交叉（账户、计划任务、SSH 痕迹），以及最终报告里的证据台账。

**涉及的证据形态**（不是"网站文件"这种大类）：

| 形态 | 位置 / 特征 | 检测锚点 |
|---|---|---|
| **静态资源藏 PHP** | `upload/a.php.jpg`、`static/x.gif` —— `file` 判图片，内部含 `<?php` | **两者矛盾 = 高危** |
| **双扩展名** | `x.php.jpg`、`x.jpg.phtml`、`x.pht`、`x.phar` | 点号数量 + 中间段是否可执行扩展名 |
| **正常扩展名的后门** | `cache/1738.php` 放在 `cache/`、`vendor/` 里 | **内容里的 PHP 危险函数** |
| **`.user.ini` 劫持** | 站点任意层级的 `.user.ini` | `auto_prepend_file` / `auto_append_file` |
| **`.htaccess` 劫持** | 逐级向上查找，含 `php_value`、`RewriteRule` | Apache 侧，见 [3.4](#section-12) |
| **内存文件系统残留** | `/tmp`、`/dev/shm`、`/run`、`/var/tmp` | 关机即失，**关机镜像里反而还在** |
| **依赖目录篡改** | `vendor/x.inc`、`node_modules/` 内被改的文件 | **无新增文件也能劫持** |
| **元数据** | `mtime` / `ctime` / `btime` / 权限 / 属主 | `ctime` **无法用常规用户态命令改写**，是判断"是否被动过手脚"的关键 |

站点目录里哪些文件不符合"目录职责"预期；哪些 PHP 文件把用户输入直接当函数名；`.user.ini` 指向的载荷是否存在；哪些文件的时间戳被 `touch` 掩盖；`/tmp` 一类内存盘里有没有落地物；可疑文件的哈希与完整元数据。

**还要回答"这是一条完整的时间线"**：这些文件是什么时候被放进来的、站点是什么时候上线的、异常文件相对部署时间是否更新。

单看一个 `mtime` 说明不了任何事。

后门是否真的能执行、能干什么——静态分析只看代码语义，不做实测（要验证只能在隔离沙箱里用样本副本）。

这个文件是不是唯一入口？得查账户、计划任务、SSH 侧。被删除的文件内容？除非在内存镜像或备份里。

还有一条最容易被跳过的：**"未发现 WebShell"这个说法本身**。阴性发现必须写清范围、方法与未覆盖项，见 [4.5 时间判读与结论表述](#section-33)。

**内容边界（本篇的红线）**：本文只讲**如何发现、如何识别、如何排除误报**，不提供任何载荷构造、免杀或持久化实现。

判断"这不是业务代码"靠内容特征 + 时间关系 + 目录上下文三者结合，**不靠文件名**——理由与可信度排序见 [陷阱 6](#section-24)。

命中危险函数只是线索。框架代码里 `preg_replace`、`base64_decode` 极其常见，报告的写法要求见 [2.3 取证立场](#23-php-危险函数内容检测的核心)。

**读者前提**：需要 Linux 文件权限与时间戳语义（尤其 `mtime` 与 `ctime` 的区别）、PHP 基本概念与函数执行模型，以及 Web 服务器配置基础（[第 1 篇](server-web-nginx-apache.md)）。

执行前请先确认 [3.1 第 0 步](#section-9) 的挂载参数真的生效了。`ro`、`noload`、`noatime` 缺一个，后面所有分析都建立在不稳固的基线上。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 网站目录的典型结构

先建立"正常长什么样"的基线，才能判断"不正常"。典型结构：

```
/www/wwwroot/digiforensics-site/
├── index.php            入口
├── upload/  uploads/    ★ 用户上传目录——最高危落点
├── static/  img/  css/  js/             静态资源
├── storage/  runtime/  cache/  log/     可写但不该有代码
├── vendor/  thinkphp/  laravel/        框架目录（异常文件多=被入侵）
├── .user.ini            ★ PHP 目录级配置（见 2.4）
└── .htaccess            Apache 重写/鉴权规则
```

**核心判据：目录职责与文件行为是否匹配。**

这张表不用背，看一眼站点的真实布局，把对应行填进去就行。

| 目录 | 正常内容 | 异常信号 |
|---|---|---|
| `static/` `img/` `css/` | 图片、样式、字体 | 出现 `.php` `.phtml` `.phar`，或 jpg/png 里含 `<?php` |
| `upload/` | 用户上传的图片/文档 | **出现任何可执行脚本**（除非业务明确允许） |
| `static/` 下的 `.js` | JS 代码 | 内容里出现 `eval(atob(`、`document.write(unescape(` |
| `cache/` `runtime/` | 缓存、临时文件 | 出现长期不变的 `.php`（缓存不该是可执行代码） |
| `vendor/` | 框架库 | mtime 与其他文件不一致、大小异常 |

<a id="section-4"></a>

### 2.2 WebShell 的落地形态

| 形态 | 特征 | 检测锚点 |
|---|---|---|
| **正常扩展名** | `shell.php` 就是个 PHP 文件 | **内容里的 PHP 危险函数**（见 2.3） |
| **双扩展名** | `x.php.jpg`、`x.jpg.php`、`x.phtml`、`x.php5`、`x.phar`、`x.pht` | **点号数量**、中间段是不是可执行扩展名 |
| **图片藏 PHP** | `a.jpg` 开头是 `GIF89a`/PNG magic，**后面跟 `<?php`** | `file` 说图片，`grep` 却命中 `<?php` → **两者矛盾=高危** |
| **无扩展名** | `upload/1738` 无后缀 | 上传目录里的无后缀可读文件 + 权限可写 |
| **`.user.ini` 劫持** | 目录级配置，**没有可疑 PHP 文件也能劫持** | 找 `.user.ini`，看 `auto_prepend_file` |
| **`.htaccess` 劫持** | Apache 改写把请求映射到别处 | 找 `.htaccess`，看 `RewriteRule`/`Redirect`/`php_value` |
| **藏在正常业务目录** | 后门放在 `vendor/`、`lib/`、`class/` 里 | 靠内容检测 + 时间戳，**文件名完全无异常** |

**双扩展名的判定逻辑**（最容易漏的一类）：**点号后面一段如果本身就是可执行扩展名，就很可疑**。

`x.php.jpg` 可疑，因为 `php` 是可执行扩展名。`x.min.js` 正常，`min` 不是。`report.2024.pdf` 正常，`2024` 也不是。

**可执行扩展名清单**（以实际环境为准，需结合 `mime.types` 与 PHP 配置确认）：

```
.php .php2 .php3 .php4 .php5 .php7 .phps .pht .phtm .phtml .phar .inc .shtml
```

<a id="section-5"></a>

### 2.3 PHP 危险函数：内容检测的核心

WebShell 的本质是"**调用系统能力的 PHP 函数**"。

查这些函数命中，比查文件名可靠得多。

| 类别 | 关键函数 | 说明 |
|---|---|---|
| **执行命令** | `system`、`exec`、`passthru`、`shell_exec`、`popen`、`proc_open` | 直接执行系统命令 |
| **代码执行** | `eval`、`assert`、`create_function`、`call_user_func`（+ 数组形式）、`preg_replace`（带 `/e`） | 动态执行代码 |
| **文件操作** | `file_put_contents`、`file_get_contents`、`fopen`/`fwrite`、`unlink`、`move_uploaded_file` | 落地后门、删痕迹 |
| **编码混淆** | `base64_decode`、`gzinflate`、`str_rot13`、`gzuncompress`、`hex2bin` | 隐藏真实载荷 |
| **信息收集** | `phpinfo`、`getenv`、`$_SERVER`、`php_uname`、`posix_getpwuid` | 侦察环境 |
| **网络** | `fsockopen`、`curl_exec`、`stream_socket_client` | 反连 C2、外传数据 |
| **变量函数** | `$_POST`/`$_GET`/`$_REQUEST`/`$_COOKIE` 直接拼进函数名 | 函数名运行期才确定，静态特征匹配不到 |

**必须注意的三点：**

1. `assert` 和 `preg_replace` 有历史歧义：`preg_replace` 的 `/e` 修饰符在 PHP 5.5 已移除，PHP 7 起 `assert()` 不再支持字符串求值。老站（PHP 5.x）上这两个是真漏洞，新站上不是——判定时必须结合站点实际 PHP 版本。
2. `call_user_func`、`array_map`、`usort` 等"回调型"函数可以把字符串变成函数名，只看这几个名字会漏。
3. **单个函数命中不等于后门**。业务代码里 `exec` 用于健康检查、`base64_decode` 用于处理附件都是正常的。**必须看上下文**：`$_POST` 直接当函数名的写法在任何正常业务里都极少见。

> **取证立场**：报告里应写"命中危险函数 X 次，其中 N 处存在『用户输入直接作为函数名』的模式"，而不是笼统的"发现 webshell"——这条在 [5.1 误判对照](#51-18426-个文件中筛出-4-个真后门的方法与误报分层) 有完整展开。

<a id="section-6"></a>

### 2.4 `.user.ini` 机制（本篇最重要的隐蔽点）

PHP 会**自动读取当前目录及其所有上级目录**下的 `.user.ini`，其中两个指令构成隐蔽后门：

```ini
; /www/wwwroot/digiforensics-site/.user.ini
auto_prepend_file=/tmp/.x.php
auto_append_file=/var/www/other.php
```

| 指令 | 行为 |
|---|---|
| `auto_prepend_file` | **在每个 PHP 脚本执行前，先执行这个文件** |
| `auto_append_file` | 在脚本执行**后**追加执行 |

**它的可怕之处在于：**

1. **站点目录里没有任何可疑 PHP 文件**，扩展名正常、内容正常，`grep` 危险函数也命中不到——因为后门在 `/tmp/` 或站点外。
2. **生效范围是整个目录树**，对该目录下所有 PHP 脚本生效，包括正常业务文件。
3. **文件名合法**：`.user.ini` 是 PHP 标准配置文件名，安全扫描常把它排除在扫描目标外。
4. PHP-FPM 的 `user_ini.cache_ttl` 默认 300 秒——写入后最长需 5 分钟生效（以实际环境为准），这也是攻击者"写后等一会儿再验证"的原因。

也就是说，"站内 PHP 全扫一遍没命中"这句话，在有 `.user.ini` 的情况下什么都不能证明。

> ⚠️ `auto_prepend_file` 指向自身会形成无限递归，正常配置不会这么写。若发现指向自身，是配置错误或人为破坏，需分别对待。

**排查时必须双向确认：**

```bash
# 方向一：找 .user.ini，看它指向哪
find /mnt/df/www/wwwroot -name '.user.ini' -exec sh -c 'echo "== $1"; cat "$1"' _ {} \;
# 方向二：把指向的路径拿去文件系统里核对是否真的存在
ls -la /tmp/.x.php 2>/dev/null
# 方向三：看 .user.ini 的 mtime，与入侵时间线是否吻合
stat -c '%n  mtime=%y' /mnt/df/www/wwwroot/digiforensics-site/.user.ini
```

**`/tmp` 是重点排查区**：`tmpfs` 目录**关机即失**，但内存镜像里还在——这也是"文件已消失但仍能取证"的原因，见[第 01 篇](../server-panel/server-panel-linux-server-artifact-map.md)。

真要找载荷落点，别忘了往站点目录外面看一眼。

<a id="section-7"></a>

### 2.5 时间戳是最便宜也最有力的线索

**攻击者改文件内容，mtime 通常会随之更新**（`cp -p` 这类刻意保留时间戳的操作除外，常规的 `cat >`/`vi`/`tee`/WebShell 写入都会更新）。所以：

| 时间戳 | 含义 | 取证价值 |
|---|---|---|
| **mtime** | 最后修改时间 | ★★★★★ 内容何时被改 |
| **ctime** | 元数据变更时间（权限、所有者、硬链接数） | ★★★★ ★**比 mtime 更难伪造**——`touch -m` 改不了 ctime |
| **atime** | 最后访问 | ★★★ 弱，易被 relatime 影响 |
| **btime** | 创建时间（需文件系统支持） | ★★★★ 新增文件必是新的 |

**ctime 是判断"是否被动过手脚"的关键**：如果 mtime 显示 2020 年但 ctime 显示 2024 年，说明有人用 `touch` 改过 mtime 掩盖痕迹——这是很强的篡改证据。

**找一个可信的时间基准**（日志时间、系统日志、数据库时间），然后按时间排序看哪些文件"扎堆"出现在入侵窗口内（命令见 3.5）。

时间戳只说明文件"什么时候被动过"。WebShell 上线之后做了什么，还得看应用层与主机层：`Web.config` 篡改、`App_Offline.htm` 投放、ViewState 反序列化与清理痕迹的识别见[第 04 篇](../server-log/server-log-web-attack-trace-reconstruction.md)。

---

<a id="section-8"></a>

## 三、操作步骤
<a id="section-9"></a>

### 3.1 第 0 步：只读挂载与基线固定（不可跳过）

```bash
# 1) 只读挂载：ro 不写入，noload 避免加载日志产生副作用，noatime 避免更新访问时间
sudo mount -o loop,ro,offset=1181696,noload,noatime \
  /work/DigiForensics.dd /mnt/df
findmnt -no OPTIONS --target /mnt/df/www/wwwroot | tr ',' '\
' | grep -x ro   # 确认 ro 生效

# 2) 站点目录整树哈希（后续所有分析基于这个基线）
cd /mnt/df/www/wwwroot/digiforensics-site && \
  find . -type f -exec sha256sum {} + | sort -k2 > /evidence/site-hashes.txt
wc -l /evidence/site-hashes.txt
```

<a id="section-10"></a>

### 3.2 第 1 步：文件类型与内容矛盾检测

**最高性价比的一步。**

`file` 说是什么，`grep` 说看见什么。两者矛盾就一定要看。

```bash
S=/mnt/df/www/wwwroot/digiforensics-site

# 1) 声明是图片/文档、实际含 PHP 标签的（★最高危）
#    注意：这里必须用 grep -a 而不是 -I。
#    -I 表示"忽略二进制文件"，会让本项【完全静默地失效】——
#    而图片藏 PHP 恰恰是二进制文件，这是最不能漏的一类。
find "$S" -type f \( -iname '*.jpg' -o -iname '*.png' -o -iname '*.gif' \
     -o -iname '*.jpeg' -o -iname '*.ico' -o -iname '*.pdf' -o -iname '*.txt' \) \
     -exec grep -laIE '<\?php' {} + 2>/dev/null

# 2) 逐个核对：file 说是 PHP 的，是否真的是纯 PHP（有没有二进制的图片头）
find "$S" -type f -iname '*.php' -exec file {} + 2>/dev/null | grep -vE 'PHP script|ASCII text|Unicode text|UTF-8'
# 输出里出现 "JPEG image data" "PNG image data" → 伪装

# 3) 双扩展名（两个方向都要覆盖，缺一不可）
find "$S" -type f -regextype posix-extended \
     -regex '.*\.(php|phtml|phar|pht|php[0-9]|inc|shtml)\.(jpg|jpeg|png|gif|ico|txt|html|zip|doc|xls|pdf)$' 2>/dev/null
find "$S" -type f -regextype posix-extended \
     -regex '.*\.(jpg|jpeg|png|gif|ico|txt|html|zip|doc|xls|pdf)\.(php|phtml|phar|pht|php[0-9]|inc|shtml)$' 2>/dev/null
```

> **原理**：静态资源里出现 `<?php` 只有两种可能——要么是模板里嵌的 PHP 代码（少见但合法，如邮件模板），要么是 WebShell。**必须逐个人工确认，不能批量定性。**

> 🔴 **一个极易踩的坑**：`grep -I`（忽略二进制）会让本项**完全静默地失效**，必须用 `grep -a`——详见 [陷阱 4](#section-22)。

<a id="section-11"></a>

### 3.3 第 2 步：PHP 危险函数内容扫描（三级递进）

```bash
S=/mnt/df/www/wwwroot/digiforensics-site
mkdir -p /evidence/webshell-scan

# 1) 一级：所有命中危险函数的文件
grep -rlE '\b(system|exec|passthru|shell_exec|popen|proc_open|eval|assert|create_function|preg_replace|base64_decode|gzinflate|gzuncompress|str_rot13|file_put_contents|fsockopen|curl_exec|stream_socket_client|phpinfo|move_uploaded_file)\s*\(' \
     "$S" 2>/dev/null | tee /evidence/webshell-scan/l1-hits.txt

# 2) 二级：只看"用户输入直接当函数名"的高危模式（正常业务几乎不会有）
grep -rnE '\$_(POST|GET|REQUEST|COOKIE)\s*\(' "$S" 2>/dev/null \
  | tee /evidence/webshell-scan/l2-dynamic.txt
grep -rnE '\$\{?\w+\}\s*\(\s*\$_(POST|GET|REQUEST)' "$S" 2>/dev/null \
  | tee -a /evidence/webshell-scan/l2-dynamic.txt
#   典型： $_POST['x']($_POST['y'])   /   $f=$_GET['cmd']; $f('whoami');
#   变量函数： $m='sys'.'tem'; $m('id');

# 3) 三级：回调型函数（绕过静态检测的手法）
grep -rnE '(call_user_func|array_map|array_filter|usort|preg_replace_callback|register_shutdown_function)\s*\(' \
     "$S" 2>/dev/null | tee /evidence/webshell-scan/l3-callback.txt

# 4) 看具体命中上下文（必须逐行人工判断）
grep -rnE '\b(eval|assert|base64_decode|system|shell_exec)\s*\(' "$S" 2>/dev/null | head -40
```

**排除误报的几条经验：**

| 命中形态 | 通常是 | 处理 |
|---|---|---|
| `vendor/`、`thinkphp/`、`laravel/` 里的 `preg_replace` | 框架自身代码 | 以官方包哈希比对后再判断 |
| `class Uploader { ... file_put_contents }` | 正常上传逻辑 | 看有无外部输入可控 |
| 只有 `base64_decode($str)` 且 `$str` 来自配置 | 正常解码 | 继续看 `$str` 来源 |
| `$_POST` 出现在 `if ($_POST['action'] == 'upload')` | 正常业务 | 正常 |
| `$_POST['x']($_POST['y'])` | **几乎必是后门**（用户输入直接作为函数名与实参，在正常业务中见不到这种写法） | 立即固定 |

<a id="section-12"></a>

### 3.4 第 3 步：`.user.ini` / `.htaccess` 全量排查

```bash
S=/mnt/df/www/wwwroot/digiforensics-site

# .user.ini：PHP 目录级劫持（详见 2.4）
find "$S" -name '.user.ini' -print 2>/dev/null | tee /evidence/user-ini-list.txt
while read -r f; do echo "===== $f"; stat -c 'mtime=%y ctime=%z %a %U:%G' "$f"; cat "$f"; done \
  < /evidence/user-ini-list.txt

# .htaccess：Apache 重写/鉴权/劫持
find "$S" -name '.htaccess' -print 2>/dev/null | tee /evidence/htaccess-list.txt
while read -r f; do echo "===== $f"; stat -c 'mtime=%y %a %U:%G' "$f"; cat "$f"; done \
  < /evidence/htaccess-list.txt

# 重点看这些指令：auto_prepend_file / auto_append_file / RewriteRule / Redirect / php_value
grep -rnE 'auto_(prepend|append)_file' "$S" 2>/dev/null
grep -rnE 'Rewrite(Rule|Map)|Redirect(Match)?|php_value|php_admin_value' "$S" 2>/dev/null

# .user.ini 指向的路径是否真实存在
grep -rhoE 'auto_(prepend|append)_file\s*=\s*(.+)' "$S" 2>/dev/null | cut -d= -f2 | tr -d ' "' \
  | while read -r t; do
    echo "== 目标: $t"; ls -la "$t" 2>/dev/null || ls -la "/mnt/df$t" 2>/dev/null || echo "   （未找到）"
done
```

<a id="section-13"></a>

### 3.5 第 4 步：时间戳与权限排查

```bash
S=/mnt/df/www/wwwroot/digiforensics-site

# 1) 入侵窗口内被改动的文件（时间从日志分析得出）
find "$S" -type f -newermt '2024-03-17 21:00' ! -newermt '2024-03-18 02:00' \
     -printf '%T+ %10s %m %p\
' 2>/dev/null | sort | tee /evidence/changed-window.txt

# 2) 权限异常：可写且可执行的普通文件（正常业务文件不该是 777）
find "$S" -type f -perm /777 -printf '%m %p\
' 2>/dev/null
find "$S" -type f -perm -u+w -printf '%m %p\
' 2>/dev/null | head -40

# 3) mtime 与 ctime 不一致 → 有人 touch 过，尝试掩盖
find "$S" -type f -printf '%T@ %C@ %p\
' 2>/dev/null | awk '
  { d = $1 - $2; if (d > 86400) printf "差 %.0f 天  mtime=%s ctime=%s  %s\
", d/86400, strftime("%F %T",$1), strftime("%F %T",$2), $3 }' \
  | sort -rn | head -30 | tee /evidence/mtime-ctime-diff.txt

# 4) 内存盘重点排查（后门常放这里，关机即失但镜像里还在）
find /mnt/df/tmp /mnt/df/dev/shm -type f -printf '%T+ %10s %m %p\
' 2>/dev/null | sort
```

<a id="section-14"></a>

### 3.6 第 5 步：证据固定与哈希

**发现可疑文件后，先固定证据，再分析：**

```bash
EV=/evidence/suspicious; mkdir -p "$EV"

# 1) 先记录镜像里的原始哈希
sha256sum /mnt/df/www/wwwroot/digiforensics-site/cache/1738.php
# 2) 复制到证据目录（保持属性与时间戳），副本哈希必须一致
cp -p /mnt/df/www/wwwroot/digiforensics-site/cache/1738.php "$EV/"
sha256sum "$EV/1738.php"
# 3) 记录完整元数据（mtime/ctime/权限/属主/大小/inode）与 MD5
stat /mnt/df/www/wwwroot/digiforensics-site/cache/1738.php | tee -a "$EV/metadata.txt"
md5sum /mnt/df/www/wwwroot/digiforensics-site/cache/1738.php
# 4) 只读看内容（分页，防终端刷屏）
cat -A /mnt/df/www/wwwroot/digiforensics-site/cache/1738.php | head -60   # ^I 制表符、行尾 $
xxd /mnt/df/www/wwwroot/digiforensics-site/cache/1738.php | head -20
strings -n 8 /mnt/df/www/wwwroot/digiforensics-site/cache/1738.php | head -30
# 5) 目录上下文也固定（同一个目录里往往还有更多东西）
cp -rp /mnt/df/www/wwwroot/digiforensics-site/cache "$EV/cache-dir/"
```

**证据台账建议字段**（这个表往往就是报告附件）：

| 编号 | 路径 | SHA-256 | 大小 | mtime | ctime | 权限 | 属主 | 命中规则 | 定性 |
|---|---|---|---|---|---|---|---|---|---|
| W-01 | `cache/1738.php` | `9f2c…` | 824 B | 2024-03-17 22:38 | 2024-03-17 22:38 | 644 | www | L1+L2 | 后门（待动态确认） |
| W-02 | `.user.ini` | `4a71…` | 68 B | 2024-03-17 22:36 | 2024-03-17 22:36 | 644 | www | auto_prepend | 劫持配置 |

<a id="section-15"></a>

### 3.7 一键排查脚本

下面是一个可直接使用的只读排查脚本。它只读、不执行任何被检文件，并把结果写入报告目录：

```bash
#!/usr/bin/env bash
# ws_sweep.sh —— 网站目录 WebShell 只读排查
# 用法: sudo bash ws_sweep.sh /mnt/df/www/wwwroot/digiforensics-site /evidence/ws-report
# 本脚本只做读取与哈希，绝不执行被检文件。
set -u
SITE="${1:?用法: ws_sweep.sh <站点根目录> <输出目录>}"
OUT="${2:?用法: ws_sweep.sh <站点根目录> <输出目录>}"
mkdir -p "$OUT"
SITE="$(readlink -f "$SITE")"
echo "站点: $SITE"; echo "输出: $OUT"

# 确认是只读挂载（强烈建议）
findmnt -no OPTIONS --target "$SITE" 2>/dev/null | tr ',' '\
' | grep -x ro \
  && echo "[提醒] 已只读挂载" || echo "[警告] 未检测到 ro 挂载，确认检材安全"

echo "== 0. 全树基线哈希 =="
( cd "$SITE" && find . -type f -exec sha256sum {} + | sort -k2 ) > "$OUT/00-baseline-hashes.txt"
echo "   文件总数: $(wc -l < "$OUT/00-baseline-hashes.txt")"

echo "== 1. 静态资源里含 PHP =="
# 必须用 -a：-I 会跳过二进制文件，而图片藏 PHP 恰恰是二进制的
find "$SITE" -type f \( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' \
  -o -iname '*.gif' -o -iname '*.ico' -o -iname '*.pdf' -o -iname '*.txt' \
  -o -iname '*.css' -o -iname '*.js' \) -exec grep -laIE '<\?php' {} + 2>/dev/null \
  > "$OUT/01-static-with-php.txt"; sed 's/^/   /' "$OUT/01-static-with-php.txt"

echo "== 2. file 声明与内容矛盾 =="
find "$SITE" -type f -iname '*.php' -exec file {} + 2>/dev/null \
  | grep -vE 'PHP script|ASCII text|Unicode text|UTF-8|empty' \
  > "$OUT/02-fp-mismatch.txt"; sed 's/^/   /' "$OUT/02-fp-mismatch.txt"

echo "== 3. 双扩展名（两个方向）=="
{
  find "$SITE" -type f -regextype posix-extended \
    -regex '.*\.(php|phtml|phar|pht|php[0-9]|inc|shtml)\.(jpg|jpeg|png|gif|ico|txt|html|zip|doc|xls|pdf)$' 2>/dev/null
  find "$SITE" -type f -regextype posix-extended \
    -regex '.*\.(jpg|jpeg|png|gif|ico|txt|html|zip|doc|xls|pdf)\.(php|phtml|phar|pht|php[0-9]|inc|shtml)$' 2>/dev/null
} | sort -u > "$OUT/03-double-ext.txt"; sed 's/^/   /' "$OUT/03-double-ext.txt"

echo "== 4. PHP 危险函数（一级）=="
grep -rlE '\b(system|exec|passthru|shell_exec|popen|proc_open|eval|assert|create_function|preg_replace|base64_decode|gzinflate|gzuncompress|str_rot13|file_put_contents|fsockopen|curl_exec|stream_socket_client|phpinfo|move_uploaded_file)\s*\(' \
  "$SITE" 2>/dev/null | sort > "$OUT/04-l1-danger-func.txt"
echo "   命中文件数: $(wc -l < "$OUT/04-l1-danger-func.txt")"

echo "== 5. 动态执行模式（二级，高危）=="
{ grep -rnE '\$_(POST|GET|REQUEST|COOKIE)\s*\(' "$SITE" 2>/dev/null
  grep -rnE '\$\{?[A-Za-z_]\w*\}?\s*\(\s*\$_(POST|GET|REQUEST)' "$SITE" 2>/dev/null
  grep -rnE '\$[A-Za-z_]\w*\s*=\s*[\x27"][a-z_]+[\x27"]\s*\.\s*[\x27"][a-z_]+[\x27"]' "$SITE" 2>/dev/null
} | sort -u > "$OUT/05-l2-dynamic.txt"
echo "   命中行数: $(wc -l < "$OUT/05-l2-dynamic.txt")"

echo "== 6. 回调型函数（三级）=="
grep -rnE '(call_user_func(_array)?|array_map|array_filter|usort|preg_replace_callback|register_shutdown_function)\s*\(' \
  "$SITE" 2>/dev/null | sort -u > "$OUT/06-l3-callback.txt"
echo "   命中行数: $(wc -l < "$OUT/06-l3-callback.txt")"

echo "== 7. .user.ini / .htaccess =="
find "$SITE" \( -name '.user.ini' -o -name '.htaccess' \) 2>/dev/null \
  | while read -r f; do
      echo "----- $f"; stat -c 'mtime=%y ctime=%z %a %U:%G' "$f"; cat "$f"
    done > "$OUT/07-ini-htaccess.txt"
grep -rnE 'auto_(prepend|append)_file' "$SITE" 2>/dev/null \
  | tee -a "$OUT/07-ini-htaccess.txt"
grep -rnE 'RewriteRule|Redirect(Match)?|php_(value|flag)|auto_prepend' "$SITE" 2>/dev/null \
  >> "$OUT/07-ini-htaccess.txt"

echo "== 8. 权限异常（可写文件 / 777）=="
{ find "$SITE" -type f -perm /777 2>/dev/null
  find "$SITE" -type f -perm -u+w 2>/dev/null | head -200
} | sort -u > "$OUT/08-perm-anomaly.txt"
echo "   异常条数: $(wc -l < "$OUT/08-perm-anomaly.txt")"

echo "== 9. mtime/ctime 差异（可能被 touch 掩盖）=="
find "$SITE" -type f -printf '%T@ %C@ %p\
' 2>/dev/null | awk '
  { d=$1-$2; if (d>86400) printf "%.0f\	%s\	%s\	%s\
", d/86400, strftime("%F %T",$1), strftime("%F %T",$2), $3 }' \
  | sort -rn > "$OUT/09-mtime-ctime-diff.txt"
echo "   异常条数: $(wc -l < "$OUT/09-mtime-ctime-diff.txt")"

echo "== 10. 最近 7 天内改动的文件 =="
find "$SITE" -type f -mtime -7 -printf '%T+ %10s %m %p\
' 2>/dev/null | sort \
  > "$OUT/10-recent-modified.txt"
echo "   条数: $(wc -l < "$OUT/10-recent-modified.txt")"

echo
echo "== 汇总 =="
for f in "$OUT"/0*.txt "$OUT"/1*.txt; do
  printf '  %-28s %6s 条\
' "$(basename "$f")" "$(wc -l < "$f")"
done
echo
echo "⚠️  以上均为【线索】，不是结论。请逐个人工确认后再定性。"
echo "⚠️  不要执行任何被检文件；需要确认后门功能时，在隔离沙箱中用原始样本副本。"
```

**用法：**

```bash
sudo bash ws_sweep.sh /mnt/df/www/wwwroot/digiforensics-site /evidence/ws-report

# 站点较多时批量跑
for s in /mnt/df/www/wwwroot/*/; do
  [ -d "$s" ] && sudo bash ws_sweep.sh "$s" "/evidence/ws-report/$(basename "$s")"
done
```

> ⚠️ **运行环境要求**：脚本使用 `find -printf` / `-regextype` / `-newermt`、`stat -c`、`findmnt` 等 GNU coreutils/findutils 特性，**在 Linux 上直接可用**。在 macOS/BSD 上 `find` 与 `stat` 的参数不同，需要改写（`stat -f`、BSD `find` 无 `-printf`）。本脚本面向的目标环境是 Linux 服务器，BSD 环境下请勿直接套用。
>
> 🔴 **脚本里两处最容易写错的细节**：`grep` 用 `-a` 而非 `-I`、双扩展名查两个方向——原因与失效形态见 [陷阱 4](#section-22) 与 [陷阱 5](#section-23)。

---
<a id="section-16"></a>

## 四、常见陷阱

网站目录排查的结论直接进入报告，而「站里有个可疑文件」这句话的定性偏差，可能是无罪释放，也可能是把运维误判成入侵。

本章把目录排查中反复出现的判断错误，按处置姿势、检测有效性、范围覆盖、证据保存、时间判读 五组拆开。

<a id="section-17"></a>

### 4.1 处置姿势：改变检材状态的操作

<a id="section-18"></a>

#### 陷阱 1：在分析机上执行了可疑脚本

**现象**

拿到疑似植入的 PHP 文件，为了「看看它做什么」，直接用 PHP 解释器跑一遍，
或者在 IDE 里点开运行。

**原因**

这个操作在取证语境下几乎没有安全收益。

PHP CLI 在解析文件时会完整走一遍初始化流程，包括 `auto_prepend_file`、`auto_append_file` 这两个由 `php.ini` 指定的自动包含项。如果植入者的持久化方案正是靠修改这两个配置项实现的，那么「执行」这个动作等于替对方把攻击链跑完了。

此外，脚本里可能含有向攻击者地址发起请求的代码，执行行为会**改变检材状态并向外产生流量**。

**影响**

检材的现场被自己破坏，且破坏方式无法在报告中如实描述。

如果脚本携带了删除逻辑，执行一遍可能连带销毁同目录的其他文件，而这些文件在事后已经无法证明曾经存在。

更麻烦的是，对方地址收到连接本身也是一种信息披露——对方会知道这份检材已经被查了。

**核查**

全程离线、只读、纯文本读取。可用手段只有三类：

- `xxd` / `hexdump -C` 看原始字节
- `strings` 提取可打印字符串
- `file` 判断类型

需要语法层面的检查时，**静态 token 化**是折中方案：用 `token_get_all()` 解析出
标识符与字符串常量，**不执行**任何顶层语句。绝不要用 `php -l` 之类的语法检查，
它同样会初始化运行时。

<a id="section-19"></a>

#### 陷阱 2：先移动文件再分析

**现象**

为了「把可疑文件挪出来单独看」，用 `mv` 把它移到 `/tmp` 或分析机的工作目录。

**原因**

`mv` 在同一文件系统内是重命名，跨文件系统则是复制加删除。两种情况都会**改变文件的原始位置**，而在不同文件系统上还会顺带丢掉原始的属主与权限上下文。

更重要的是，这个动作把「文件在这个目录里」这个事实本身给抹掉了。而目录中的相对位置关系，往往正是判断植入方式的关键信息。

**影响**

破坏证据的原始状态，且属于典型的不可逆操作。

事后即使把文件放回原位，也无法证明中间没有被做过手脚；`ctime` 会留下明显痕迹，报告里必须解释这个痕迹，而解释本身就是漏洞。

**核查**

原位保持不动。需要单独分析时用 `cp -p`（保留时间戳）或 `cp -a`（保留全部属性）
复制到工作副本，所有操作在副本上做。**分析结论引用的是原位文件的时间戳**，
副本的时间戳只用于保证同一份内容在各次分析之间一致。

<a id="section-20"></a>

#### 陷阱 3：用编辑器「预览」可疑文件

**现象**

双击文件、用代码编辑器打开、或者让 IDE 自动做语法高亮。

**原因**

现代编辑器对可执行文件的支持远超「显示文本」。语法高亮引擎会完整解析文件结构；部分编辑器带插件机制，检测到可执行类型会尝试调用相应解释器做更深入的解析；还有编辑器会尝试联网获取依赖或做符号解析。

**「我只是看一眼」这个假设在这里不成立。**

**影响**

轻则触发网络请求泄露检材路径与内容片段，重则执行了文件里的顶层逻辑。而且这类操作往往不留任何日志，报告里也无从记录。

**核查**

只用 `cat`、`xxd`、`strings`。要按行看就用 `sed -n 'Np'` 精确取行，
要按字节偏移看就用 `dd` 配合 `skip`/`count`。全程不引入任何会解析该文件的工具。

<a id="section-21"></a>

### 4.2 检测有效性：查了等于没查

<a id="section-22"></a>

#### 陷阱 4：`grep -I` 让检测静默失效

**现象**

用 `grep -r` 全站搜索特征串，命令跑完、耗时正常、**没有报错**，
但结果就是不对。

**原因**

`-I` 的语义是「跳过二进制文件」。

而基于内容的植入检测，目标恰恰经常是**伪装成图片的脚本文件**——这类文件在 `file` 的判定下就是二进制，于是被 `-I` 整体跳过。

整个检测过程没有任何错误输出，退出码是 0。「没查到」和「没查过」在结果上完全一样。

**影响**

报告里写下「已全站检索，未发现相关内容」，而实际上那些最可疑的文件从未被读过。

这是取证里最危险的一类错误——**阴性结论建立在无效的检测上**，比阳性误判更难被后续复核发现。

**核查**

内容检索一律用 `grep -a`，或者用 `grep -I` 加 `-r` 之后**单独确认**二进制文件数量
不为零。为避免这类静默失效，可以先用 `find` 统计文件类型分布，
确认待检范围内不存在「未知类型文件占比过高」这类异常。

<a id="section-23"></a>

#### 陷阱 5：双扩展名只查一个方向

**现象**

检查了 `x.php.jpg` 这类文件，没检查 `x.jpg.phtml`。

**原因**

这依赖 Web 服务器的解析顺序规则。

同一请求里先匹配到的处理器决定用什么解释器，而不同服务器的匹配顺序不完全一致，有的从左往右、有的从右往左。

「哪个后缀生效」是服务器配置决定的，不是文件名决定的。

如果站点的规则是从右往左匹配，那么 `x.jpg.phtml` 就会以 PHP 执行，而一个只查 `*.php.*` 模式的规则会完全漏掉它。

**影响**

覆盖面不足导致的漏检。而且这类漏检往往发生在对方刻意规避的形态上。

**核查**

两个方向都查：`*.php.*` 与 `*.*.php`。更彻底的做法是**不依赖文件名**——
列出站点目录下全部文件，按 MIME 判定与扩展名不一致的清单，
不一致项逐一过内容。文件头比扩展名可靠。

<a id="section-24"></a>

#### 陷阱 6：只看文件名就定性

**现象**

看到 `cache/1738.php` 或者 `images/upload/tmp1a8f.php` 这类名字，
判断为后门。

**原因**

这类名字在正常站点里大量存在：缓存生成、临时上传目录、备份脚本产物、框架的编译中间文件都会产生数字串命名的 PHP。

**文件名的异常度不等于内容的异常度。** 命名习惯因项目而异，同一个团队在不同站点上可能用完全不同的规则。

**影响**

把正常的运维脚本写进报告的发现清单。

对方或委托方看到这份清单，会花大量时间去解释一个不存在的安全问题，而真正的痕迹被淹没在噪音里。

**核查**

**内容检测 + 时间戳 + 上下文三者结合**。文件名只用来缩小候选范围。
判定依据按可信度排序：内容特征（`eval`/`base64_decode` 组合、加密串、混淆函数）
> 文件所在目录的写入权限 > 创建时间与站点部署时间的相对关系 > 文件名形态。

<a id="section-25"></a>

#### 陷阱 7：只看危险函数名

**现象**

在站点里搜 `eval`、`system`、`assert`、`preg_replace`，把命中的文件都列进可疑清单。

**原因**

现代 PHP 框架里这几个名字的出现频率极高。模板引擎的编译结果、Composer 依赖里的序列化实现、缓存层、反序列化辅助函数都会用到它们。

命中函数名只说明「这段代码会动态执行某些东西」，不说明「这段代码被用来执行了外部传入的内容」。

**影响**

误报率高到让报告失去可操作性。真正关键的那一两个文件淹没在上百条命中里。

**核查**

看**上下文**：函数名的实参是不是来自外部输入。

`eval($code)` 里的 `$code` 来自 `$_POST` 与来自配置文件常量，是完全不同的性质。命中之后要追问一句「这个值是谁决定的」。

框架代码可以建立一个白名单目录（`vendor/`、框架核心目录），对白名单内文件的命中单独标注为「待复核」而不是直接进可疑清单。

<a id="section-26"></a>

### 4.3 范围覆盖：查了但没查全

<a id="section-27"></a>

#### 陷阱 8：漏查 `.user.ini`

**现象**

全站搜完可疑 PHP 文件，一个都没有。结论写「站点目录未见明显异常」。

**原因**

`.user.ini` 是 PHP-FPM 的用户级配置文件，它会在**目录级别**生效，优先级低于主 `php.ini` 但高于代码里的显式设置。

关键点在于：这个机制可以让「目录里没有可疑文件」这件事本身失去意义。某个特定目录下的所有 PHP 请求都会自动包含一个指定文件。

如果那个文件在站点目录之外，或者名字看起来无害，目录内检索完全看不到这层关系。

**影响**

站点被劫持但站内检索为零结论。误判代价是「结论方向完全错误」。

**核查**

全量 `find` 出站点内所有 `.user.ini` 与 `.htaccess`，逐个读取并确认其中的 `auto_prepend_file`、`auto_append_file`、重写规则指向哪里。同时从 PHP 配置里确认这些指令在当前版本是否仍然可用。

一个站点的行为由站点目录内的文件和它引用的外部文件共同决定，只查前者不查引用关系，等于只看了半张图。

<a id="section-28"></a>

#### 陷阱 9：漏查内存文件系统目录

**现象**

检查了网站根目录、`/var/www`、用户家目录，报告写「未发现异常文件」。

**原因**

`/tmp` 与 `/dev/shm` 是内存文件系统，重启即失。

对方如果把活动载荷放在这里，**关机镜像里还有文件，运行时反而可能已经消失**——这形成了一个反直觉的时间关系：静态检材比运行时更「完整」。

只查持久化目录必然漏掉这类。

**影响**

对检材的完整程度做出错误估计，且这类位置是活动痕迹的主要落点。

**核查**

把 `/tmp`、`/dev/shm`、`/run`、`/var/tmp` 单独列为必查项。

在这些目录里要额外关注：属主为服务账号而非 root 的文件、修改时间明显晚于系统启动时间的文件、内容与 Web 目录内已发现文件有相似性的片段。

<a id="section-29"></a>

#### 陷阱 10：漏查依赖目录内的改动

**现象**

站点根目录自查干净，判定站点未被篡改。

**原因**

植入不一定要新增文件。

**直接修改依赖库文件**（比如给某个字符串处理函数加几行额外逻辑）比放一个新文件隐蔽得多：文件名正常、目录正常、代码风格一致、文件时间戳甚至可能因为包管理器安装而显得正常。

这个方向上，「只找新增文件」的检测逻辑是**结构性失效**。

**影响**

站点功能被劫持而排查结论为阴性。

**核查**

对 `vendor/`、`node_modules/` 这类依赖目录做**完整性比对**：拿官方发行包的哈希清单逐一对照，找出被修改的文件。

`composer.lock` 提供了可复现的版本坐标，npm 生态有 lockfile 同理。

没有基线时，至少检查这些目录内文件的时间戳分布是否异常集中。

<a id="section-30"></a>

### 4.4 证据保存与可复现性

<a id="section-31"></a>

#### 陷阱 11：复制时不保留时间戳

**现象**

用普通的 `cp` 把文件复制出来分析，事后发现原始 mtime 变成了复制时刻。

**原因**

`cp` 默认不保留时间戳，复制出的文件 mtime 等于复制动作发生的时刻。

时间戳是站点排查的核心证据之一，丢掉它等于让「这个文件比站点部署还新」这类判断彻底无法做出。

**影响**

时间线分析失效。报告里的时序结论全部失去支撑。

**核查**

`cp -p` 保留时间戳与属主，`cp -a` 保留全部属性（含权限、符号链接、目录结构）。
整个工作流统一用 `cp -a`，并把工作副本放在独立的证据目录下，
避免与检材目录混在一起造成后续误操作。

<a id="section-32"></a>

#### 陷阱 12：忘了记录工具版本

**现象**

报告里写「使用 grep 全站检索特征串」，但没有记录 grep 的版本与实际参数。

**原因**

不同版本的默认行为会变，同一个命令在不同环境下**输出不同**。

缺少版本与参数记录，结论无法被复现，也无法在质证阶段被验证。

当结论涉及阴性发现时，这一点尤其致命——**别人无法验证你的阴性结论，等于这个结论不存在。**

**影响**

报告在复核或庭审环节失去可采性。复现者跑出的结果与你不一致，
却无法判断是谁错了。

**核查**

在报告附录里记录：工具名、版本号、**完整命令行**、执行时间、检材哈希。
检索类操作建议把命令与输出一起归档成文本文件，作为附件随报告提交。

<a id="section-33"></a>

### 4.5 时间判读与结论表述

<a id="section-34"></a>

#### 陷阱 13：用错的文件当时间基准

**现象**

用 `find -newer reference` 圈定「可疑时间段」，参考文件随手选了一个。

**原因**

`-newer` 的结果完全由参考文件的 mtime 决定。

选系统安装日志、选数据库文件、还是选站点目录里最早的文件，会得到完全不同的集合。

如果参考文件本身的时间不可信，整条时间线全部作废。

比如服务器经历过镜像恢复或文件批量同步，站内文件的时间戳可能整体被重置。

**影响**

时间线错位，进而导致「哪个文件是本次改动引入的」判断错误。
这属于最基础也最常见的错误。

**核查**

参考文件必须**其时间来源可信**，优先级从高到低：

1. 系统启动时间（`uptime -s`）——不受文件操作影响
2. 服务进程的启动时间
3. 系统日志的记录时间
4. 站点配置文件（通常手工维护，不随部署批量刷新）

**永远不要用站点目录内的文件作为时间基准**——它本身就是待检对象。

<a id="section-35"></a>

#### 陷阱 14：只看 mtime 不看 ctime

**现象**

用文件的 mtime 推断文件是什么时候被创建的。

**原因**

mtime 是「内容最后修改时间」，它可以被 `touch` 或时间戳修改工具任意设置。

`ctime` 是「元数据最后变更时间」，在 Linux 上由内核维护，**不能用常规命令改写**（只能通过改系统时钟这类极端手段间接影响）。

一个文件 mtime 早于 ctime，通常意味着：文件被创建之后，有人改动过它的权限或属主，但没有再改内容。

**影响**

把伪造的时间当成可信时间，据此构建的整条时间线都不可靠。
在报告里还可能被对方或辩护方一眼看破，直接削弱全部结论。

**核查**

mtime 与 ctime 一起看，**两者的显著差异本身就是证据**。
常见的三种组合各有含义：

- mtime 早于 ctime：创建后改过权限或移动过位置
- ctime 早于 mtime：内容后来又被改过（正常编辑也产生这个）
- 两者都早于站点部署时间：这个文件**不属于本次部署**，需要单独追查来源

时间戳不可信时，用**内容层面的旁证**交叉验证：文件头里的构建时间、
嵌入的版本字符串、日志里对该文件的访问记录。

<a id="section-36"></a>

#### 陷阱 15：看到宽松权限就定性为后门

**现象**

发现某文件权限是 777，直接判定为后门。

**原因**

777 在权限管理宽松的老旧站点里较为常见，有些部署为了省事全站开 777。

**权限宽松是配置弱点，宽松权限下的文件是攻击产物**——这是两件不同的事。

前者是既有的运维习惯，后者需要内容与时间的证据支撑。把两者混为一谈，会把一个配置建议写成一个安全事件。

**影响**

结论定性错误。若这是委托方自己搭建的系统，这一条会直接损害报告的可信度。

**核查**

分开陈述：

- **配置弱点**：目录或文件权限过宽，给出了具体的路径与权限值
- **可疑文件**：内容特征 + 时间关系 + 上下文支持

判断「谁在什么时候改的」需要落到 `ctime` 与属主上。

一个 777 的文件如果属主是站点部署账号、ctime 与部署时间一致、内容是正常的框架代码，那它就只是一个配置问题。

<a id="section-37"></a>

#### 陷阱 16：批量检索命中后直接定性

**现象**

脚本扫出 200 个命中文件，报告里写「发现 200 个可疑文件」。

**原因**

内容特征检索必然有基线命中：测试脚本、开发时的调试页、框架的示例代码、备份里的旧版本，任何一个都能触发特征。

200 这个数字里，真正是后门的可能只有 1 个，也可能是 0 个。

把命中数直接当可疑数，报告就失去了可信度。

**影响**

报告结论不可用。委托方会要求逐条复核，工作量暴增，
而且在这个过程中真正的那一条反而更容易被淹没。

**核查**

分三步走：

1. **机器初筛**：特征检索给出候选集，人工不介入
2. **人工复核**：逐个读内容，判断「外部输入是否能到达这里」
3. **结论分层**：把结果分成「确认」「存疑」「排除」三档，
   每档都写明判定理由

「排除」这一档同样要写进报告。一份只有确认项的清单，
无法证明检测的覆盖面，也就无法支撑阴性结论。

<a id="section-38"></a>

#### 陷阱 17：把「没发现」写成绝对结论

**现象**

排查完站点目录，报告写「未发现 WebShell」。

**原因**

这个结论隐含了一个无法证明的断言：不存在任何植入。

但实际检查范围是有边界的——只查了一个站点目录、只查了当前文件系统快照、只查了明文可识别的特征。

对方可以删除文件、可以改用运行时加载、可以把载荷放在压缩包里，也可以放在内存文件系统里而恰好在关机后丢失。

**影响**

阴性结论被当作排除性证据。后续如果在其他证据里发现了痕迹，
这份报告会反过来成为「明知故查」的佐证。

**核查**

阴性结论必须写清三件事：

- **范围**：查了哪些目录、哪些文件类型、哪个时间点的快照
- **方法**：用了什么检测手段、覆盖了哪些特征
- **未覆盖**：明确列出查不到的地方

标准写法：

> 在站点根目录及其子目录（路径写明）的全部明文文件中，
> 基于内容特征检索与文件头类型一致性检查，未发现符合植入特征的文件。
> 本次检查未覆盖：压缩包内部内容、内存文件系统 `/tmp` 与 `/dev/shm`
> 在关机前已丢失的部分、运行时动态加载且不落盘的代码、
> 以及依赖目录内基于哈希比对的完整性校验（无官方基线可用）。

**阴性发现的能力边界与操作能力是两回事**——
一次彻底的阴性结论，同样是一份有价值的工作成果，前提是它把边界画清楚了。


<a id="section-39"></a>

## 五、案例示例

<a id="section-40"></a>

### 5.1 18426 个文件中筛出 4 个真后门的方法与误报分层

**场景**

查获一台 Ubuntu 22.04 + 宝塔云主机（`web01`）。委托方报告：网站首页被改成跳转博彩站。镜像 `DigiForensics.dd` 只读挂载到 `/mnt/df`，站点目录 `/www/wwwroot/digiforensics-site/`。

这条路径值得先走，是因为**站点目录动辄上万个文件，而真正的问题通常只有几个**。

直接按时间倒序翻文件会漏掉伪装成老文件的那个（见 5.2）；而按规则扫描又会淹没在框架代码的误报里。

**处置过程**

**第 1 步 · 只读挂载并跑一键脚本**（命令见 3.1、3.7）

```bash
sudo bash ws_sweep.sh /mnt/df/www/wwwroot/digiforensics-site /evidence/ws-report
```

站点共 **18426** 个文件（`wc -l /evidence/site-hashes.txt`）。

| 检查项 | 命中 | 需人工核对 |
|---|---|---|
| `01-static-with-php` | **3** | 静态资源含 PHP |
| `02-fp-mismatch` | **1** | `.php` 却是 JPEG |
| `03-double-ext` | **1** | 双扩展名 |
| `04-l1-danger-func` | 61（**多为框架误报**） | 逐个看上下文 |
| `05-l2-dynamic` | **4** | ★ 动态执行 |
| `07-ini-htaccess` | **2** | `.user.ini` + `.htaccess` |
| `08-perm-anomaly` | 137 | 多在 `upload/`，需看是否有代码 |
| `09-mtime-ctime-diff` | **2** | ★ 时间戳被改过 |
| `10-recent-modified` | **6** | ★ 只动了 6 个文件 |

61 个一级命中里，59 个在 `vendor/`（框架自身代码），可与官方包哈希比对排除。真正要看的只有 4 个二级命中。

**这个 59 : 61 的比例是本节的核心经验**：一级规则（"含危险函数"）在真实站点里几乎没有判别力，因为主流框架的自身代码普遍含有 `eval`、`exec`、`assert` 这类词。

只有二级规则（"危险函数的参数来自用户输入"）才有实用判别力。

**第 2 步 · 逐个人工核对（不执行）**

```bash
cat /evidence/ws-report/05-l2-dynamic.txt
# /www/wwwroot/digiforensics-site/cache/1738.php:11:$_POST['a']($_POST['b']);
# /www/wwwroot/digiforensics-site/cache/1738.php:19:$f = $_GET['f']; $f($_GET['c']);
# /www/wwwroot/digiforensics-site/vendor/x.inc:4:$_POST['x']($_POST['y']);   ← ★ 可疑
# /www/wwwroot/digiforensics-site/admin/ok.php:22:if ($_POST('act') == 'del') ← 正常业务
```

第三条**在 `vendor/` 里的**是关键——**攻击者改框架文件比放新文件更隐蔽**。第四条则是误报形态，见误判对照第 3 条。

第 3 步 · 伪装文件的识别必须用 `grep -a`

```bash
S=/mnt/df/www/wwwroot/digiforensics-site
file "$S/cache/1738.php" "$S/upload/avatar.jpg" "$S/upload/a.php.jpg"
# cache/1738.php:      PHP script, ASCII text executable
# upload/avatar.jpg:    JPEG image data, JFIF standard
# upload/a.php.jpg:     JPEG image data                          ← file 说是图片
grep -a -c '<?php' "$S/upload/a.php.jpg"
# 1                      ← ★ 若用 grep -I（默认），会被当成二进制文件静默跳过
```

`file` 说是 JPEG，`grep -a` 却命中 `<?php`——典型的图片藏 PHP。若改用 `grep -I`（遇到二进制就跳过），这条后门会被静默跳过，输出里连一行提示都没有。

**第 4 步 · `.user.ini` 双向确认**

```bash
cat /evidence/ws-report/07-ini-htaccess.txt
# ----- /www/wwwroot/digiforensics-site/.user.ini
# mtime=2024-03-17 22:36:11 ctime=2024-03-17 22:36:11 644 www:www
# auto_prepend_file=/www/wwwroot/digiforensics-site/old/helper.php
ls -la /mnt/df/www/wwwroot/digiforensics-site/old/helper.php
# -rw-r--r-- 1 www www 824 2024-03-17 22:38:02 /www/.../old/helper.php
```

`auto_prepend_file` 指向的 `helper.php` 确实存在，且 mtime `22:38` 晚于 `.user.ini` 的 `22:36`——**先写后门文件，再挂上自动包含，顺序合理。**

**第 5 步 · 证据固定**

```bash
EV=/evidence/suspicious; mkdir -p "$EV"
for f in cache/1738.php upload/a.php.jpg vendor/x.inc .user.ini old/helper.php; do
  cp -p "/mnt/df/www/wwwroot/digiforensics-site/$f" "$EV/"
done
( cd "$EV" && sha256sum * ) | tee "$EV/hashes.txt"
stat "$EV/cache/1738.php" | tee -a "$EV/metadata.txt"
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 存在 3 个可被远程执行的 PHP 后门 | 二级动态模式命中 + 实际代码内容 | 强（内容自证） |
| `upload/a.php.jpg` 是伪装成图片的 WebShell | `file` 判定 JPEG + 内部含 `<?php` | 强（双源矛盾） |
| 站点被 `.user.ini` 目录级劫持 | `.user.ini` 原文 + 目标文件存在 | 强 |
| 攻击者修改了框架文件 `vendor/x.inc` | 二级命中 + 该文件 mtime 异常 | 中（**需与官方包比对确认**） |
| 入侵窗口为 2024-03-17 22:36–22:44 | 6 个文件的 mtime 聚集 + [第 05 篇](server-web-nginx-apache.md) 日志印证 | 强（双源） |
| `admin/ok.php:22` 为后门 | 二级规则命中 | **不成立——误报，见误判对照** |

**本节能证明**：哪些文件可被远程执行代码、伪装文件的存在、目录级劫持的机制。

**本节不能证明**：`vendor/x.inc` 的改动是否改变了业务行为（需与官方包哈希比对）、`helper.php` 的完整功能（未执行）、入侵的初始入口。

**误判对照**

这个案例最容易出的错有三个方向，第二个是最隐蔽的技术细节。

1. 把"命中了危险函数"当成"这是 WebShell"。本案 61 个一级命中里 59 个是框架代码。判别力分层是这样的：**① 一级（函数名存在）几乎没有判别力**；② 二级（危险函数的参数直接来自 `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`）才开始有效；③ 三级（完整的数据流：用户输入 → 危险函数 → 无过滤）才可定性。报告里写"检出 N 个 WebShell"之前，必须至少走到第 ③ 级。
2. 用 `grep` 默认行为扫二进制，结果被静默跳过。这是本节最隐蔽的一个坑：`grep` 遇到含 NUL 字节的文件会判定为 binary 并**跳过匹配**（`grep -I` 的默认行为），只在有匹配且加了 `-a` 时才会提示 `Binary file ... matches`。对一个含 13 KB PHP 代码的伪装 JPEG 来说，默认 `grep '<?php'` 的输出是空的——它不会报错，也不会说"我跳过了"，只是什么都不打印。判据：任何针对网站目录的全文检索，必须显式加 `-a`（或 `-I` 去掉、`--binary-files=text`），并在报告里写明用了哪个选项。 一个漏了 `-a` 的扫描，产出的"未发现可疑内容"是**假的阴性**。
3. **判据**：`$_POST('act')` 这种写法本身是语法错误（`$_POST` 是数组不是函数），所以 `admin/ok.php:22` 那行**根本不会执行**。而 `$_POST['a']($_POST['b'])` 才是真正的动态调用形态。判别力来自这一点：把"看起来可疑的行"拿去实际解析，语法上不成立的那条直接出局。这也说明二级规则仍需人工过一遍——**规则匹配的是字符形态，不是可执行性**。
4. **判据**：`vendor/` 下的命中不能因为"框架代码"就默认排除。本案 `vendor/x.inc` 恰恰在 `vendor/` 里，且命中了二级规则。**排除框架文件的正确方式是哈希比对**（`composer.lock` 锁定的版本 + Packagist 官方包哈希），**不是"它在 vendor 目录"**。本案该比对**尚未做**，所以这一条结论强度只有"中"。

**按错误判据走的代价**：第 2 条踩中的代价是**漏掉伪装文件**——而伪装文件恰恰是最容易长期存活的一类后门（它躺在 `upload/` 里，看起来是用户上传的图片，运维巡检时几乎不会点开）。本案 `a.php.jpg` 若被漏掉，它会一直可被访问。更糟的是：报告里若写"全站扫描未发现伪装文件"，委托方会据此关闭这条线，而真实的假阴性会跟着报告一起归档。第 1 条踩中则会让报告里出现 61 个"WebShell"，委托方无法判断优先级，**最终可能一个都不处理**——**误报过载与漏检，在实务中的实际后果是一样的。**

<a id="section-41"></a>

### 5.2 mtime 与 ctime 相差 1425 天的伪装时间戳

**场景**

承接 5.1。委托方在看到扫描结果后提出一个很实际的问题："`cache/1738.php` 这个文件名和创建时间看起来都很正常（2020 年），能确定它是这次放进去的吗？"

这是 WebShell 取证里最经典的一类对抗——**伪造文件时间**。

而破解它的方法恰好是文件系统自带的一个字段——`ctime` **无法用 `touch`/`utimensat` 这类用户态接口改写**。

**处置过程**

**第 1 步 · 比对 mtime 与 ctime**

```bash
head -5 /evidence/ws-report/09-mtime-ctime-diff.txt
# 1425	2020-05-11 03:20:15	2024-03-17 22:40:31	/www/.../index.html
# 838	2019-08-02 11:04:00	2024-03-17 22:38:02	/www/.../old/helper.php
```

`index.html` 的 mtime 显示 2020 年，ctime 是 2024 年 3 月 17 日——有人用 `touch` 把它伪装成老文件。ctime 无法用常规命令伪造，这是本案最硬的一条篡改证据。

第 2 步 · 理解为什么 ctime 难以用常规命令伪造（这是判据成立的前提）

| 时间字段 | 含义 | 能否被 `touch` 伪造 |
|---|---|---|
| `mtime` | 最后一次**内容**修改 | **能**（`touch -d` / `touch -t`） |
| `atime` | 最后一次**读取** | 能（同上） |
| `ctime` | inode 元数据最后变更（权限、属主、链接数、**以及 mtime 本身**） | **不能** |

`ctime` 是内核在**任何 inode 元数据发生变更时自动更新**的，`touch` 修改 mtime 本身就会触发一次 ctime 更新。

用户态没有（也不可能有）"设置 ctime 为过去某时刻"的接口——`utimensat` 只能改 atime/mtime。

这就是它不可伪造的原因，也是它判别力强于 mtime 的根本。

**第 3 步 · 做出判断**

对 `index.html`：

| 字段 | 值 | 解读 |
|---|---|---|
| mtime | 2020-05-11 03:20:15 | 被 `touch -d` 回拨 |
| ctime | 2024-03-17 22:40:31 | **真实写入时刻** |
| inode 分配时间（若 ext4 且启用） | — | 需 `debugfs` 读块组，**本案未做** |
| 与站内其他正常文件的时间分布 | 无 2020-05 的同类 | **统计异常** |

**统计判别力在这里体现得最充分**：一个上线于 2022-09-14 的站点（见 [第 01 篇](../server-panel/server-panel-linux-server-artifact-map.md)）**不该有 2020 年 5 月的文件**。

`helper.php` 的 mtime 甚至是 **2019-08-02**——**比站点上线还早两年**。

**这两个时间都无法用站点自身上线以来的正常运维流程解释**——它们落在站点存续时间窗之外。

第 4 步 · 但 ctime 也不是万能的（这条限制必须写进报告）

```bash
# ctime 会被哪些"正常"操作更新？
#   chown / chmod / 链接数变化（文件被改名、硬链接增减）
#   chown 是极其常见的运维操作
stat -c '%n mtime=%y ctime=%z' /mnt/df/www/wwwroot/digiforensics-site/config/database.php
# mtime=2022-09-14 11:22:08  ctime=2025-06-01 09:14:33
#                                 ↑ ctime 远晚于 mtime，但这是 2025 年的运维 chown，不是入侵
```

**判据**：ctime 晚于 mtime 只说明"mtime 之后发生过元数据变更"，不必然是篡改。

区分方法有三：① ctime 本身是否落在**入侵窗口**内（本案 22:36–22:44）；② 是否有对应的**权限或属主变化**（`stat` 的第三/第四字段）；③ 是否伴随**内容层面的其他异常**（`.user.ini`、动态执行函数）。**三条联合才能定性。**

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| `index.html` 的 mtime 被回拨至 2020-05-11 | mtime 与站点上线时间矛盾（站点 2022-09 建立） | **强（统计异常）** |
| `index.html` 的真实变更时刻为 2024-03-17 22:40:31 | **ctime 无法用常规命令伪造** | **强（本案最硬的一条）** |
| `old/helper.php` 的 mtime 被回拨至 2019-08-02 | 比站点上线早两年 | **强** |
| 真实变更时刻为 2024-03-17 22:38:02 | ctime | 强 |
| 两个文件的 ctime 均落在入侵窗口 22:36–22:44 内 | ctime 聚集 | 强（**这是最强的单项证据**） |
| 该站所有"ctime 晚于 mtime"的文件都是篡改 | `database.php` 2025-06 的 chown 即为反例 | **不成立——见误判对照** |

**本节能证明**：文件时间被人工回拨这一行为本身，以及**真实的变更时刻**。
**本节不能证明**：篡改的具体操作者与操作命令、文件在回拨前的原始 mtime 值（只能推断，无法还原）。

**误判对照**

这个案例最容易出的错是**把 ctime 当成"最后的活动时刻"**——它是**inode 元数据**的最后变更时刻，不是文件内容的最后修改时刻。

1. **判据**：ctime ≠ mtime 的替代品，两者是不同性质的证据。`mtime` 描述**内容**，`ctime` 描述**元数据**。攻击者用 `touch` 回拨 mtime 时，**必然同时刷新 ctime**——**这就是 ctime 能揭穿它的原因**。但反过来，一次 `chmod` 或 `chown` **也会刷新 ctime 而完全不碰内容**。所以"ctime 是 2024-03-17"只证明"那时有人动过这个文件的元数据（极可能就是那次 touch 本身）"，不直接证明内容被改。 本案内容被改这一事实由另外两条独立支撑（篡改后的内容本身 + 站点时间分布矛盾）。
2. **判据**："ctime 晚于 mtime"是普遍现象，不是异常信号。整站扫一遍，运维 `chown` 过的文件、被打包解压覆盖过的文件、备份恢复过的文件，**普遍存在 ctime 远晚于 mtime 的情况**（本案 `database.php` 就是）。判别力来自"ctime 是否落在入侵窗口内"，而不是"ctime 是否晚于 mtime"。只按后一条筛，会把整站所有历史运维文件全部报成可疑。
3. **判据**：`touch -d` 回拨 mtime 之后，原来的 mtime 值就永久丢失了。ext4 的 inode 不保存旧 mtime，没有任何日志会记录"这个文件的 mtime 曾经是 X"。所以"它原来是什么时候创建的"这个问题在多数情况下**无法回答**。正确表述是"该文件的 mtime 已被回拨，回拨目标值为 2020-05-11；其原始 mtime 不可恢复"。**不要写"推测其原始创建时间为 X"**——那是编造。
4. **判据**：`cp -p` 也会造成 mtime 与 ctime 分离，但方向相反。`cp -p` 保留 mtime，**新文件的 ctime 是复制时刻**——这与 `touch` 回拨在文件系统上留下的痕迹是一样的（ctime 新、mtime 旧）。换句话说，单凭"ctime 新 mtime 旧"无法区分"篡改时间"与"复制了一个老文件"。区分要看 ctime 是否落在入侵窗口 + 该文件的内容是否为攻击者产物。这一点必须在报告里写明，否则一个"从备份恢复的老文件"会被误判为篡改。

**按错误判据走的代价**：第 2 条踩中（把"ctime 晚于 mtime"当异常）会让报告里出现**成百上千条"可疑文件"**——委托方拿到这样的清单不可能逐个处理，最终等于没有结论。**误报过载会淹没掉那条真正关键的证据**，而那条证据恰恰是本案里 ctime 落在入侵窗口内、与其他 5 个文件的 ctime 聚集这一事实。**把判据用对地方，是让证据产生价值的前提。**

<a id="section-42"></a>

## 六、扩展阅读方向

**先把"证据怎么固定"这件事做扎实。**

本篇发现的东西要能进报告、能被复核，靠的不是检测手法而是固定流程——这一组解决"怎么让发现可采信"。

- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md)：`ro,noload,noatime` 挂载、整树基线哈希、保管链的完整要求。
- [哈希与完整性校验](../../fundamentals/fundamentals-concepts/fundamentals-concepts-hashes-and-integrity-verification.md)：`vendor/` 目录与官方发行包比对的正确做法，以及为什么"没有基线"时只能退而求其次查时间戳分布。
- [证据文件格式](../../fundamentals/fundamentals-chain/fundamentals-chain-dd-e01-aff4-evidence-formats.md)：镜像挂载偏移、卷标、镜像格式的差异，以及挂载参数对证据可采性的影响。
- [证据保管链与委托证明](../../fundamentals/fundamentals-chain/fundamentals-chain-chain-of-custody-and-authorization.md)：`cp -a` 之后每一次操作的登记要求——本篇的检测动作全部会产生新的证据文件。

**再补时间判读。**

本篇最强的一条证据是 `mtime` 与 `ctime` 的差异，但它只有放进完整时间线才成立。

- [时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md)：文件时间戳与日志时间统一到同一时区，跨时区服务器上这一步不做，后面全错。
- [时间线重建](../../computer/computer-log/computer-log-linux-timeline-reconstruction.md)：从系统启动时间、服务进程时间、文件时间戳拼出可信基准，见 [4.5](#section-33) 里的参考文件优先级。
- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md)：`touch -m` 掩盖痕迹的**识别特征**，以及被清理的 `.bash_history` 与日志行如何判断。

**然后是本层的直接延续。** 目录里的发现要落到流量、配置和主机侧才能定性。

- [WebShell 工具流量特征](server-web-webshell-traffic-patterns.md)：用 access.log 确认哪些可疑文件真被访问过，以及"写入后验证"模式的识别。
- [Nginx 与 Apache 配置取证](server-web-nginx-apache.md)：`root` / `DocumentRoot` 映射与 `.htaccess` 生效条件（`AllowOverride`）的前置知识。
- [CDN 识别与源站挖掘](server-web-cdn.md)：发现站点目录下有站外路径时，如何判断源站是否已暴露。
- [取证工件地图（Linux 侧）](../../computer/computer-persistence/computer-persistence-persistence-artifact-map.md)：站点目录、日志目录在整机证据体系中的位置与优先级。
- [Linux 与 Android 内存取证](../../memory/memory-artifact/memory-artifact-linux-android.md)：`/tmp`、`/dev/shm` 关机即失的文件为什么在内存镜像里还在。

**最后是横向扩线与判据。** 一次目录排查结束前，必须回答"这是唯一入口吗"。

- [计划任务与持久化痕迹](../../computer/computer-persistence/computer-persistence-scheduled-tasks-and-persistence.md)：cron、at、systemd unit——目录里查不到持久化不代表主机上没有。
- [SSH 痕迹与密钥取证](../../computer/computer-persistence/computer-persistence-ssh.md)：`auth.log`、`wtmp` 与免密通道，用来判断攻击者是否还留了其他入口。
- [Shell 痕迹与命令历史](../../computer/computer-shell/computer-shell-shell.md)：`.bash_history` 的清理痕迹与 `HISTTIMEFORMAT` 缺失情况。
- [近似匹配与模糊哈希](../../fundamentals/fundamentals-concepts/fundamentals-concepts-fuzzy-hashing.md)：无官方基线时，判断被改的 `vendor/x.inc` 是否源自公开仓库的已知变种。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md)：在隔离沙箱中验证后门功能时的授权要求与脱敏呈现规范。
<a id="section-43"></a>

## 七、命令速查

```bash
# 完整命令见第 3 章各节；此处只列最高频的入口与"必须记住的参数"。

# ===== 只读挂载（三步之基线）=====
sudo mount -o loop,ro,offset=1181696,noload,noatime /work/DigiForensics.dd /mnt/df
findmnt -no OPTIONS --target /mnt/df | tr ',' '\
' | grep -x ro
cd /mnt/df/www/wwwroot/digiforensics-site && \
  find . -type f -exec sha256sum {} + | sort -k2 > /evidence/site-hashes.txt

# ===== 一键排查（推荐入口，覆盖 10 类检查）=====
sudo bash ws_sweep.sh /mnt/df/www/wwwroot/digiforensics-site /evidence/ws-report

# ===== 两个最关键的单项检测 =====
S=/mnt/df/www/wwwroot/digiforensics-site
# ① 静态资源藏 PHP —— ★必须 -a，用 -I 会静默失效
find "$S" -type f \( -iname '*.jpg' -o -iname '*.png' -o -iname '*.gif' -o -iname '*.pdf' \) \
     -exec grep -laIE '<\?php' {} + 2>/dev/null
# ② 用户输入直接当函数名 —— 正常业务几乎不会有
grep -rnE '\$_(POST|GET|REQUEST|COOKIE)\s*\(' "$S" 2>/dev/null

# ===== 时间戳异常（ctime 难以用常规命令伪造，判断是否被 touch 过）=====
find "$S" -type f -printf '%T@ %C@ %p\
' 2>/dev/null | awk \
  '{d=$1-$2; if(d>86400) printf "%.0f天\	%s\	%s\	%s\
", d/86400, strftime("%F %T",$1), strftime("%F %T",$2), $3}' | sort -rn

# ===== .user.ini 指向核实 =====
find "$S" -name '.user.ini' -print -exec cat {} \; 2>/dev/null
grep -rhoE 'auto_(prepend|append)_file\s*=\s*(.+)' "$S" 2>/dev/null | cut -d= -f2 | tr -d ' "' \
  | while read -r t; do ls -la "$t" 2>/dev/null || ls -la "/mnt/df$t" 2>/dev/null; done

# ===== 证据固定（先复制，再分析）=====
EV=/evidence/suspicious; mkdir -p "$EV"
cp -p "$S/cache/1738.php" "$EV/"; sha256sum "$S/cache/1738.php" "$EV/1738.php"
stat "$S/cache/1738.php" | tee -a "$EV/metadata.txt"; md5sum "$S/cache/1738.php"
cat -A "$S/cache/1738.php" | head -60; xxd "$S/cache/1738.php" | head -20
strings -n 8 "$S/cache/1738.php" | head -30
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 服务器与 Web 取证 — 网站目录与 WebShell 检测」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《网站目录与 WebShell 检测》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.vc` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
