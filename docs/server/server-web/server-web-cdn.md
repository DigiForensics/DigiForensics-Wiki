---
title: "CDN 识别与源站挖掘"
slug: "server-web-cdn"
canonical: "https://www.digiforensics.cn/wiki/server-web-cdn"
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

# CDN 识别与源站挖掘

> ⚖️ **本篇的边界（重要）**
>
> 源站挖掘是**取证中的合法技术手段**，前提是**已获得委托方授权**，目标是**找回自己委托资产的真实源站**，用于还原完整请求链路。
>
> 本篇**不涉及**：对**他人未授权**的资产进行源站探测、绕过访问控制、扫描不属于委托范围的 IP 段。任何探测动作都必须在委托方明确的资产清单范围内进行，并遵守目标所在司法辖区的规定。


<a id="section-1"></a>

## 一、概述

CDN 给网站带来性能与防护，也给取证制造了一个具体的麻烦：日志里的 IP 既不是真实访问者，也不是服务器本身。

站点接了 CDN 之后，`access_log` 里记录的是**边缘节点的地址**。

这时候你手里的日志看起来是"完整的"，实际上它缺了最关键的一段链路——**那个域名背后，那台真实的服务器在哪里？**

**为什么非找到它不可**：

| 若只有 CDN 侧证据 | 若找到源站 |
|---|---|
| 只能看到边缘节点日志 | **能看到完整请求，包括 CDN 未缓存的 POST** |
| 无法确定哪些路径被真正访问过 | **能核对两边日志，找出绕过 CDN 的直连** |
| 无法判断源站是否还留着 WebShell | **能直接检查源站文件系统——这通常才是案件关键** |
| 攻击者绕 CDN 直连源站的攻击**在 CDN 侧完全不可见** | **直连攻击完整记录在源站日志里** |

最关键的一点：CDN 缓存只加速 GET，POST 与动态请求通常回源。

攻击者上传 WebShell 用的正是 POST——这类请求在 CDN 侧往往只留下一行转发记录，真正的内容只有源站知道。

而绕过 CDN 直连源站的攻击，在 CDN 侧连一行记录都不会有。

**在取证流程中的位置**：本篇属于**分析环的链路补全层**，通常在文件层与流量层都卡住时启用——"日志里只有 CDN IP"是最常见的归因中断点。

上游依赖 [Nginx 与 Apache 配置取证](server-web-nginx-apache.md) 对 `$remote_addr` 语义与 `proxy_set_header` 的分析。

下游直接接上源站侧的全部工作（取证工件地图、WebShell 排查、流量分析），见 [3.5 第 5 步](#section-19)。

**涉及的证据形态**：

| 形态 | 位置 / 字段 | 取证价值 |
|---|---|---|
| **DNS 解析链** | `dig` 的 CNAME 链、`+noall +answer` | ★★★★★ CNAME 指向 `*.cdn.*` / `*.edge.*` 即已接 CDN |
| **HTTP 响应头** | `server`、`via`、`x-cache`、`cf-ray`、`age` | ★★★★ 二次确认 |
| **CT log** | 证书透明度日志，公开可查、**带时间戳、可哈希固定** | ★★★★★ **源站回溯的主力手段** |
| **未接 CDN 的子域** | 测试站、静态站、旧站、API 站的 A 记录 | ★★★★★ **优先级最高的突破口** |
| **历史 DNS** | 接入 CDN 之前的解析记录 | ★★★★ 直连攻击的原始来源 |
| **配置错误枚举** | 未设 `Host` 白名单、遗留测试域名、`mail`/`origin` 等命名习惯 | ★★★ |
| **源站指纹** | 自定义错误页、序列号、静态资源哈希、响应头顺序 | ★★★★ **验证候选的关键** |
| **CDN 与源站日志的差集** | 两侧记录的比对结果 | ★★★★★ 找出绕过 CDN 的直连 |

> 🔴 **取证价值最高的一条判据**：**同一域名下未接 CDN 的子域常常直接暴露源站。** 运维往往只把主站接入 CDN，测试站、静态站、旧站、API 站常常遗漏。但同时要记住边界：找到了源站 IP 不等于它就是攻击入口——IP 归属 CDN 厂商、或属于托管在同一台机器上的其他客户，都需要单独认定，见 [4.1 归属判断](#section-21)。

这个域名背后哪台是真实服务器；哪些子域没走 CDN；源站上是否还留着后门；绕 CDN 直连源站的攻击有没有发生过；源站 IP 上还托管着哪些其他域名；CDN 配置是否留下了绕过路径（未设 IP 白名单、未配 SNI 校验等）。

**CDN 边缘节点缓存了什么、什么时候缓存的**——这需要 CDN 厂商侧的配合或控制台权限。

未签发过证书的源站（CT log 里查不到）只能靠其他路径。

源站机器的内部情况？找到 IP 只是拿到入口，文件系统证据必须在授权范围内获取。

**源站 IP 上其他客户域名的内容**——超出委托范围就是越界，见 [4.3 范围与授权边界](#section-30)。

**读者前提**：需要 DNS 解析原理与 CNAME 链结构、TLS 握手与证书基本概念（SNI、证书 SAN）、HTTP 响应头语义、以及反向代理的基本模型。

反向代理如何在日志里隐藏真实 IP 的机制见 [第 1 篇](server-web-nginx-apache.md) 的 2.3 节。

建议先按 [3.1 第 1 步](#section-15) 确认 CDN 状态再往下——如果本来就没接 CDN，本篇的多数手段不适用。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 CDN 是怎么改变日志的

一个典型的 CDN 架构：

```
用户 ──► CDN 边缘节点 ──► 源站服务器
         （缓存 GET）        （所有请求最终都会到这里）
```

| 请求类型 | CDN 行为 | 边缘节点日志 | 源站日志 |
|---|---|---|---|
| `GET` 静态资源，缓存命中 | **不回源** | 有记录 | **无记录** |
| `GET` 动态页面，未命中 | 回源 | 有记录 | 有记录 |
| `POST`（登录、上传、执行） | **总是回源** | 有记录 | **有完整记录** |
| 攻击者**直连源站**（绕过 CDN） | 不经过 CDN | **无记录** | **有完整记录** |

**由此推出两条取证推论：**

1. **源站会生成访问日志**——只要 CDN 正常工作并转发，源站侧就会记录请求，因此源站日志通常比 CDN 日志更完整。但"通常"不等于"一定"：源站可能关掉了日志、只写错误日志、按采样率写入，或日志已在轮转周期内被删除。**拿到源站 IP 之后要先确认源站日志是否开启、保留策略是什么、目标时段的文件是否还在，再决定是否值得申请调取。**
2. CDN 侧日志里的 4xx/5xx 与状态码可能被 CDN 自己改写（CDN 配置了错误页缓存时尤其明显），**不能把 CDN 日志的状态码当作源站真实响应**。
<a id="section-4"></a>

### 2.2 CDN 识别：DNS 链

**最可靠的第一手判据是 DNS 解析结果。**

接入 CDN 时，域名通常不再是 A 记录直指服务器，而是 CNAME 到 CDN 厂商的域名。

```bash
dig +short digiforensics-site
# cdn.digiforensics-edge.example.net.        ← CNAME，说明接了 CDN

dig digiforensics-site CNAME +short
# cdn.digiforensics-edge.example.net.

# 完整链路
dig digiforensics-site +noall +answer
# digiforensics-site.		300	IN	CNAME	cdn.digiforensics-edge.example.net.
# cdn.digiforensics-edge.example.net. 60 IN A	203.0.113.20
```

| 现象 | 判断 |
|---|---|
| CNAME 指向 `*.cdn.*` / `*.edge.*` / `*.cloudfront.net` / `*.alicdn.com` 等 | **接了 CDN** |
| A 记录直接指向单个 IP，且该 IP 属于云厂商 | 可能是**独立主机**，也可能直连云厂商网络 |
| A 记录返回多个 IP | 可能 CDN，也可能是**DNS 轮询**（多台服务器）——需看 IP 归属 |
| 域名下部分子域有 CNAME、部分没有 | **典型的"CDN 接入不全"**，未接 CDN 的子域往往直达源站 ★ |

> 🔴 **取证价值最高的一条**：同一个域名下，未接 CDN 的子域常常直接暴露源站，运维往往只把主站接入 CDN，测试站、静态站、旧站、API 站常常遗漏——这条判据的边界（源站 IP 的归属认定）见 [4.1 归属判断](#section-21)。

<a id="section-5"></a>

### 2.3 CDN 识别：HTTP 响应头

```bash
curl -sI https://digiforensics-site/ | head -30
```

| 响应头 | 指向 |
|---|---|
| `Server: cloudflare` | Cloudflare |
| `X-Cache: HIT` / `MISS` / `EXPIRED` | 多种 CDN（Cloudflare、阿里云等） |
| `Via:` 中出现 `1.1 vegur`（蓝汛）、`ali-swift-*` | 阿里云 CDN |
| `X-Swift-Cache` | 又拍云等 |
| `X-Cache-Lookup` | 快网等 |
| `Age: 3600` | 任意 CDN，**表示该响应已缓存 3600 秒** ★ |
| `cf-ray`、`cf-cache-status` | Cloudflare |
| `X-Cache: TCP_HIT` | 腾讯云 |
| `Timing-Allow-Origin` | 各类 CDN |
| **完全没有上述头** | 可能是**直连源站**（★ 这本身就是源站线索） |

**`Age` 头特别有用**：它是标准 HTTP 头，**任何设置缓存的中间层都会返回**。

即使厂商换了自定义头，`Age: <秒数>` 通常还在。

<a id="section-6"></a>

### 2.4 CT log（证书透明度日志）—— 源站回溯的主力手段 ★

**这是当前最实用的源站回溯方法，本节重点展开。**

<a id="section-7"></a>

#### 原理

自 2017 年前后起，主流 CA 与主流浏览器逐步把**公开受信任 TLS 证书的 CT 记录**作为签发前提（Apple、Google、Mozilla 的证书政策要求、以及 2018 年 4 月起 Chrome 对 EV 证书的硬性要求，都推动了这件事）。

全球有多个公开的 CT log 汇总这些记录，例如 Google CT Log，以及 crt.sh 这类按域名聚合的第三方检索服务。

因此一张公开 CA 签发的受信任证书，其签发记录通常会进入 CT log 并被长期保留。

但这不是绝对覆盖——自签证书、内网私有 CA 签发的证书、以及历史上绕过该要求的签发，都可能查不到。

关键点：签发证书时必须提交所有 SAN 域名的公钥信息到 CT log，且无法事后删除。

由此得到取证的用途：

> 任何曾经为这个域名签发过证书的人，其证书上的所有域名都被公开记录了。 包括：源站常用的 `origin.example.com`、`direct.example.com`、内部测试域名、绑定在同一个 IP 上的其他客户域名。

**取证的直接价值：**

1. **得到可用于回溯 IP 的域名线索** —— CT 本身**不提供 IP**，但它给出的 `origin.` `direct.` `test.` `old.` `dev.` `admin.` 这类**非常规子域名**，是后续做 DNS 历史查询、证书下载比对、目标验证的**高价值抓手**。IP 最终要靠 DNS 历史、SNI 探测和日志交叉验证才能确定。
2. **得到源站专用子域名** —— `origin.` `direct.` `oss.` `static-origin.` 这类命名往往是内部用词。
3. **得到未公开的业务域名** —— 同一客户的其他站点。
4. **得到时间线** —— CT 记录含"证书签发时间"，可与入侵时间对照。

这四条里，第 1 条最关键——它不是直接给出答案，而是把搜索空间从"整个互联网"缩小到"十几个名字"。

> ⚠️ **重要局限**（必须在报告里写明）：
> - **CT log 只记录证书，不记录 IP 指向。** 它告诉你"这个域名签过证书"，但**域名现在解析到哪，CT 不管**。
> - 未使用公开 CA 证书的源站（自签证书、IP 直连无证书）不会出现在 CT log。
> - CT 记录与“未来”无关，回溯靠的是 log 自身保留的历史。 公开 CT log 自 2013 年前后开始运行并长期保留条目，因此**历史证书在多数情况下可以查到**；但保留策略、log 迁移与部分早期条目缺失都可能导致查不到，**必须以实际查询结果为准**。
> - 查询需要**联网**。在**离线或隔离的内网取证环境**中无法使用，必须提前在有网环境采集并**固定为证据**。

<a id="section-8"></a>

#### 实操查询

```bash
# 方式一：crt.sh（按域名聚合的 CT 记录）
# 注意：URL 中的 %25. 是对子域名通配的转义写法
curl -s 'https://crt.sh/?q=%25.digiforensics-site&output=json' \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print('\
'.join(sorted({n for r in d for n in r['name_value'].split()})))"

# 方式二：Google CT Log API（官方原始记录）
curl -s 'https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/v1/logs' -o /dev/null   # 探活
# 实际查询通常通过官方前端；离线取证时建议直接采集 crt.sh 结果并固定

# 方式三：证书指纹反查（已知证书序列号时）
# crt.sh 支持 ?sha256=<证书指纹> 查询同一张证书的所有 SAN
```

**查询结果要做的事：**

```bash
# 1) 落盘为证据（★ 关键：CT 是联网查询结果，必须当场固定，否则不可复现）
mkdir -p /evidence/ct
date -u '+%Y-%m-%dT%H:%M:%SZ' > /evidence/ct/collected-at.txt
curl -s 'https://crt.sh/?q=%25.digiforensics-site&output=json' \
  -o /evidence/ct/crt-$(date -u +%Y%m%dT%H%M%SZ).json
sha256sum /evidence/ct/crt-*.json | tee /evidence/ct/hashes.txt

# 2) 提取去重域名
python3 -c "
import json,glob,sys
f=sorted(glob.glob('/evidence/ct/crt-*.json'))[-1]
d=json.load(open(f))
names=sorted({n.strip() for r in d for n in r.get('name_value','').splitlines()})
for n in names: print(n)
" | tee /evidence/ct/domains.txt

# 3) ★ 筛出"源站味"的子域
grep -iE 'origin|direct|backend|server|node|host|panel|admin|^\*|raw|src|oss|upstream|inner' /evidence/ct/domains.txt

# 4) 逐个解析，看哪些没走 CDN
while read -r d; do
  [ "$d" = "*.digiforensics-site" ] && continue
  ip=$(dig +short "$d" A | head -1)
  [ -n "$ip" ] && echo "$d  ->  $ip"
done < /evidence/ct/domains.txt
```

**筛出来的典型结果：**

| 域名 | 解析结果 | 判断 |
|---|---|---|
| `www.digiforensics-site` | CNAME → CDN | 走 CDN |
| `origin.digiforensics-site` | **A → 198.51.100.24** | ★ **源站** |
| `api.digiforensics-site` | A → 198.51.100.24 | 源站（同 IP） |
| `old.digiforensics-site` | 无解析 | 历史域名，可能已下线 |

<a id="section-9"></a>

### 2.5 其他源站挖掘路径

<a id="section-10"></a>

#### 历史 DNS

域名在接入 CDN 之前的解析记录，或曾经被解析到源站的那段时期，都可能留在历史数据库里。
```bash
# 查权威 NS 与 SOA（先确认 DNS 托管方）
dig +short digiforensics-site NS
dig digiforensics-site SOA +noall +answer
# digiforensics-site. 3600 IN SOA ns1.provider.example. admin.provider.example. 2024031701 3600 600 1209600 3600
#                                     ^ SOA serial 号变化能反映 DNS 变更次数

# TTL 变化会暴露"曾做过切换"
dig digiforensics-site +noall +answer
```

**取证要点**：SOA 的 **serial 号**（如 `2024031701`）是管理员手动递增的，**每一次 DNS 记录变更都会让它变大**。

serial 异常大意味着历史上做过大量变更——包括可能的解析切换。

<a id="section-11"></a>

#### 配置错误导致的源站暴露（最常见的泄露途径）

| 错误类型 | 表现 | 检查方法 |
|---|---|---|
| **子域未接入 CDN** | `origin.` `direct.` `test.` `dev.` 直连源站 | CT log + 子域枚举 |
| **邮件记录** | DNS MX 记录通常**必须指向真实服务器** | `dig MX digiforensics-site` |
| **非标准端口服务** | 源站 8888/8080 等端口未做防护 | 端口核对（限委托范围） |
| **源站 IP 上部署的其他域名** | 同 IP 承载多站 | CT log + 证书反查 |
| **错误页泄露** | 源站 4xx/5xx 页面暴露了 upstream 地址 | 直连源站观察（授权范围内） |
| **源码与配置泄露** | `git` 仓库、备份文件暴露数据库/内网地址 | 属第 06 篇范围 |

**MX 记录是一个被低估的强线索**：

```bash
dig +short digiforensics-site MX
# 10 mail.digiforensics-site.
dig +short mail.digiforensics-site A
# 198.51.100.24                ★ 邮件服务器通常不走 CDN，暴露真实 IP
```

> 🔴 **必须强调合规**：`mail.` 主机是**真实存在的邮件服务**，对它做端口扫描或漏洞探测属于未授权行为。**取证中只做 DNS 解析与被动信息收集**，主动探测需委托方书面授权并限定范围。

<a id="section-12"></a>

#### `robots.txt` 与页面内容

```bash
curl -s https://digiforensics-site/robots.txt
# Disallow: /admin/
# Sitemap: https://cdn.digiforensics-site/sitemap.xml    ← 注意是 CDN 域名
```

**页面中常见的泄露点**：

| 泄露点 | 例子 |
|---|---|
| 页脚/源码里的邮箱域名 | 暴露内部邮件域名 → 查 MX |
| 第三方统计代码里的站点 ID | 关联到其他资产 |
| 图片资源直链（未走 CDN） | `img.origin.digiforensics-site` |
| 错误页里的内网地址 | `upstream 10.0.0.5 failed` |

> **取证立场**：网页内容属于**公开可获取**信息，采集与记录在授权范围内。**但不要把"能看到"等同于"可以随意探测"**。

<a id="section-13"></a>

### 2.6 验证源站候选

拿到候选 IP 后，必须验证"它确实是这个站点的源站"，而不是碰巧同 IP 的其他主机。

核心方法是**带正确 SNI 与 Host 头直连**：

```bash
IP=198.51.100.24

# ① 带 SNI 的 TLS 握手，看证书是否匹配目标域名
echo | openssl s_client -connect "$IP:443" -servername digiforensics-site 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
# subject=CN = *.digiforensics-site
# issuer=C=XX, O=Let's Encrypt, CN=R3
# X509v3 Subject Alternative Name:
#     DNS:*.digiforensics-site, DNS:digiforensics-site     ← 匹配！强证据
# notAfter=Jun  1 12:00:00 2024 GMT

# ② 带 Host 头直连，看响应是否与 CDN 一致
curl -skI -H "Host: digiforensics-site" "https://$IP/" | head -20
# HTTP/2 200
# server: nginx                     ← 源站是 nginx（CDN 侧是 cloudflare）
# x-cache-status: MISS               ← ★ 只在直连时出现
# content-length: 18472

# ③ 关键的判定：源站直连通常缺少 CDN 头，多出源站头
diff <(curl -sI https://digiforensics-site/ | sort) \
     <(curl -skI -H "Host: digiforensics-site" "https://$IP/" | sort)
# < server: cloudflare
# > server: nginx                       ← 差异本身就是证据
# > x-powered-by: PHP/7.4.33            ← ★ 暴露了真实技术栈与版本
```

**三个关键判定点：**

| 观察 | 意义 |
|---|---|
| **证书 SAN 匹配目标域名** | ★★★ 强证据 |
| **响应头差异**（`server` 从 `cloudflare` 变 `nginx`，多出 `x-powered-by`） | ★★★ 强证据 |
| `x-cache-status: MISS` / `X-Cache: MISS` | ★★ 只有直连才出现 |
| **响应体一致但 CDN 头消失** | ★★ 强证据 |
| 证书与域名不匹配 | ⚠️ 该 IP 可能只是**共享主机**，需要进一步核实 |

> ⚠️ **共享主机的陷阱**：云主机的默认 IP 常常是"共享网关"。直连可能返回"站点未绑定"之类的默认页，或返回**别人的站点**。如果 `Host` 头返回的不是目标站点，就不能认定这是源站。

---

<a id="section-14"></a>

## 三、操作步骤

<a id="section-15"></a>

### 3.1 第 1 步：确认是否接了 CDN

```bash
D=digiforensics-site

# ① DNS 链
dig +short "$D"; dig "$D" CNAME +short; dig "$D" +noall +answer

# ② HTTP 响应头
curl -sI "https://$D/" | head -30
curl -sI "http://$D/" | head -20

# ③ 关键头字段
curl -sI "https://$D/" | grep -iE 'server|via|age|x-cache|cdn|cf-|swift|ali|timing'

# ④ 从检材里的访问日志反推（不依赖联网）
awk '{print $1}' /mnt/df/www/wwwlogs/digiforensics-site.log | sort -u | head -20
# 若这里是 203.0.113.x / 47.x 等 CDN 段，说明日志记的是边缘节点
```

**判定表：**

| 结果 | 结论 |
|---|---|
| 有 CNAME + CDN 响应头 | 确认接入 CDN，**需要源站 IP** |
| 无 CNAME，IP 属于云厂商 | **可能是源站直连**（云厂商 ≠ CDN） |
| 日志里全是 CDN 段 IP | 确认 CDN，**源站日志是关键的未取证据** |

<a id="section-16"></a>

### 3.2 第 2 步：CT log 查询与固定 ★

```bash
mkdir -p /evidence/ct && cd /evidence/ct
date -u '+采集时间(UTC): %Y-%m-%dT%H:%M:%SZ' | tee collected-at.txt

# 采集（★ 联网动作，越早越好；离线环境需提前准备）
curl -s 'https://crt.sh/?q=%25.digiforensics-site&output=json' \
     -o "crt-$(date -u +%Y%m%dT%H%M%SZ).json"
sha256sum crt-*.json | tee hashes.txt

# 提取去重域名
python3 -c "
import json,glob
f=sorted(glob.glob('/evidence/ct/crt-*.json'))[-1]
d=json.load(open(f))
names=sorted({n.strip() for r in d for n in r.get('name_value','').splitlines()})
open('/evidence/ct/domains.txt','w').write('\
'.join(names)+'\
')
print(f'共 {len(names)} 个唯一域名')
" | tee extract.log

# 筛选"源站味"的子域
grep -iE 'origin|direct|backend|server|node|host|panel|raw|src|oss|upstream|inner|dev|test' domains.txt \
  | tee origin-candidates.txt
```

**每个候选域名的解析结果都要固定：**

```bash
while read -r d; do
  case "$d" in \**) continue;; esac
  printf '%-45s ' "$d"
  dig +short "$d" A | tr '\
' ' '; echo
done < /evidence/ct/domains.txt | tee /evidence/ct/resolution.txt
```

<a id="section-17"></a>

### 3.3 第 3 步：其他源站挖掘路径

```bash
D=digiforensics-site

# ① MX 记录（邮件服务器通常不走 CDN）★ 被低估的强线索
dig +short "$D" MX
dig +short mail."$D" A

# ② NS / SOA（serial 反映变更历史）
dig +short "$D" NS
dig "$D" SOA +noall +answer

# ③ 常见子域枚举（仅限授权范围，逐个 dig，不做端口扫描）
for s in origin direct backend src static-origin oss raw api admin test dev \
         panel old new v1 v2 node server h5 m img; do
  ip=$(dig +short "$s.$D" A 2>/dev/null | head -1)
  [ -n "$ip" ] && echo "$s.$D -> $ip"
done | tee /evidence/ct/subdomain-enum.txt

# ④ 站点内容里的泄露点（CDN 侧公开内容）
curl -s "https://$D/robots.txt"
curl -s "https://$D/" | grep -oiE '[a-z0-9.-]*(origin|direct|oss|internal|backend)[a-z0-9.-]*\.[a-z]+' | sort -u
# 页脚/统计代码里的内部域名

# ⑤ 检查检材里是否已有源站线索（最重要的来源：服务器自身配置）
grep -rniE 'cdn|cloudflare|aliyun|qcloud|upstream|proxy_pass|origin' \
     /mnt/df/www/server/nginx/conf/ 2>/dev/null | head -30
# ★ 源站服务器上的 Nginx 配置里，往往直接写着 CDN 回源用的域名或 IP
```

> 🔴 **第 ⑤ 项经常被忽略但价值极高**：**源站服务器本身就是最好的情报源。** 如果检材里已经有源站镜像（这在服务器取证中很常见），那么：
> - Nginx 的 `proxy_pass`、CDN 回源配置、`/etc/hosts`、防火墙规则、WireGuard 配置里，**通常直接含有 CDN 节点 IP 段和回源域名**。
> - **这比任何外部探测都可靠，而且是合法持有的证据。**

<a id="section-18"></a>

### 3.4 第 4 步：验证源站候选

```bash
IP=198.51.100.24
D=digiforensics-site

# ① 证书是否匹配（★ 最强判据）
echo | openssl s_client -connect "$IP:443" -servername "$D" 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
# notAfter 是否已过期？SAN 是否含目标域名？

# ② 带 Host 头直连，对比响应头
curl -skI -H "Host: $D" "https://$IP/" | head -20
diff <(curl -sI "https://$D/" 2>/dev/null | sort) \
     <(curl -skI -H "Host: $D" "https://$IP/" 2>/dev/null | sort) | tee /evidence/ct/header-diff.txt
# < server: cloudflare          ← CDN 侧
# > server: nginx                ← 源站侧
# > x-powered-by: PHP/7.4.33     ← ★ 暴露真实技术栈

# ③ 响应体比对（谨慎：不做写操作，只 GET）
curl -s "https://$D/" -o /evidence/ct/via-cdn.html
curl -sk -H "Host: $D" "https://$IP/" -o /evidence/ct/via-origin.html
sha256sum /evidence/ct/via-*.html
diff <(head -c 4000 /evidence/ct/via-cdn.html) \
     <(head -c 4000 /evidence/ct/via-origin.html) | head -20
# 两份内容高度相似 → 强证据；完全不同 → 可能不是源站（共享主机陷阱）

# ④ 共享主机陷阱的排除
curl -sk -H "Host: nonexistent.invalid" "https://$IP/" | head -20
# 若返回的不是"站点未绑定"之类的默认页 → 该 IP 确实按 Host 分发站点
```

<a id="section-19"></a>

### 3.5 第 5 步：源站证据的固定与交叉验证

**找到源站 IP 后，真正的取证动作才开始：**

```bash
# 1) 固定候选清单与判断依据
cat > /evidence/ct/origin-assessment.md <<'EOF'
# 源站判定记录

### 候选 1: 198.51.100.24
- 来源：CT log 中 origin.digiforensics-site
- 证书 SAN 匹配：✅ 含 *.digiforensics-site
- 响应头差异：✅ server: nginx（CDN 侧为 cloudflare）
- 响应体比对：✅ 前 4000 字节一致
- 采集时间（UTC）：____
- 采集命令记录：见 header-diff.txt
EOF

# 2) ★ 交叉：与检材内证据核对
# 源站 IP 是否出现在已有日志/配置里？
grep -rn '198.51.100.24' /mnt/df/www/server/panel/logs/ 2>/dev/null | head
grep -rn '198.51.100.24' /mnt/df/var/log/ 2>/dev/null | head
# 服务器自身的外连/入连日志里是否出现 CDN 节点段？
grep -rnE 'cdn|cloudflare' /mnt/df/www/server/nginx/conf/ 2>/dev/null | head
```

> **合规提醒**：第 3.4 节的 `curl` 请求是**向委托方资产发起的只读 GET 请求**，在授权范围内。但**必须遵守速率限制、不得进行端口扫描或漏洞探测**。若验证需要尝试其他协议或端口，**必须先取得书面授权并限定范围**。**取证人员不是渗透测试人员。**

---
<a id="section-20"></a>

## 四、常见陷阱

源站识别的核心困难在于：CDN 与源站都在同一个云厂商的基础设施里，从 IP 归属上看过去两者几乎一样。

而主动探测的行为边界，在授权取证里是需要精确控制的。

本章把源站挖掘中反复出现的判断错误，按**归属判断、证据可复现、范围与授权、证据优先级** 四组拆开。

<a id="section-21"></a>

### 4.1 归属判断：IP 属于谁不等于角色是谁

<a id="section-22"></a>

#### 陷阱 1：把 CDN 节点 IP 当成源站

**现象**

在证书透明度日志里发现一个 IP，解析出该 IP 直接提供目标站点的服务，
于是把它记为源站地址。

**原因**

CDN 节点的响应特征是**依赖 Host 头的**。

用无关的 Host 头访问一个 CDN 节点，它返回的是错误页或直接拒绝；而源站对同一个请求往往会返回默认站点内容。

这个差异是区分两者的关键，但只看「IP 能返回目标站点」是不够的——CDN 节点也能做到这一点，因为它有回源配置。

**影响**

把 CDN 节点写进源站清单，后续所有取证动作都打偏：取到的日志是边缘日志、拿到的配置是边缘配置、做的任何变更都落在 CDN 上而非真实主机。

**核查**

**IP 加 Host 头联合验证**，具体两项：

1. 用**无关的 Host** 访问该 IP，看是否返回该服务器的默认站点内容
2. 看响应头里的特征：CDN 通常会带自己的标识头、以及缓存命中的相关头

两项都支持「这是源站」时，结论才成立。
单独任何一项都不够，因为云厂商的虚拟主机与 CDN 都可能给出误导性结果。

<a id="section-23"></a>

#### 陷阱 2：把云主机 IP 当成 CDN 节点

**现象**

看到 IP 归属某云厂商，且响应里有该厂商的标识头，
判定为 CDN 节点并停止追踪。

**原因**

云厂商同时经营 CDN 业务和主机业务，**IP 段可能重叠**。

标识头的存在也不能作为判据——主机上运行的软件可以自行设置任意响应头。

更关键的是：CDN 节点与源站**可能属于同一厂商甚至同一 IP 段**，从归属信息上根本无法区分。

**影响**

追溯链在这里断掉。

源站地址始终没找到，后续的日志调取、镜像制作都无从谈起。

**核查**

区分依据是「响应是否随 Host 变化」，不是「IP 属于谁」。
判断一个地址是不是 CDN 节点，看的是：

- DNS 层面：目标域名是否有 CNAME 指向该厂商的 CDN 域
- 响应层面：无关 Host 是否返回 CDN 的错误页（而不是别的站点内容）
- 行为层面：同一路径多次请求，是否出现缓存命中相关响应头

三项都支持才写「CDN 节点」；任何一项不支持，就保持「未确定」。

<a id="section-24"></a>

#### 陷阱 3：把 CDN 侧状态码当成源站真实响应

**现象**

从客户端侧观察到大量 502，报告写「源站服务不可用」。

**原因**

CDN 会缓存**错误响应**。

源站短暂返回 503 时，如果 CDN 的缓存策略没有排除错误码，这个 503 会被缓存并持续返回给所有用户。

此时从客户端看到的状态码反映的是**缓存里的历史状态**，与源站的当前状态无关。

反过来，CDN 配置的「自定义错误页」也会把源站的 4xx 显示成 200。

**影响**

对源站的可用性做出错误判断；如果是安全事件，
还会把「源站确实曾经异常」这个线索用错误的方式固定下来。

**核查**

**状态码以源站侧证据为准。**
CDN 侧的观测只用于判断「客户端当时看到什么」，
不能用来推断「源站当时发生了什么」。

如果暂时拿不到源站日志，结论里要写明：
`以上状态码来自 CDN 边缘侧观测，反映客户端可见结果；
源站当时的实际响应需以源站访问日志为准，本次分析未获取该日志。`

<a id="section-25"></a>

#### 陷阱 4：把「CNAME 到某域名」直接当成 CDN

**现象**

DNS 查询显示目标域名 CNAME 到另一个域名，就判定接入了 CDN。

**原因**

CNAME 只是 DNS 的一种记录方式，用途远不止 CDN：负载均衡、灾备切换、指向自有主机的别名、某些 DNS 服务商自己的内部跳转、邮件服务的别名记录，都用 CNAME。

判断是否为 CDN，要看**目标域名属于谁、那个域名提供什么服务**。

**影响**

误判会让整个排查方向走偏——花大量时间去分析一个实际上只是普通主机的地址。

**核查**

顺着 CNAME 链往下追到底，看目标域名的归属与用途。
判断依据组合使用：CNAME 目标域名的注册者、
该域名的 NS 记录、以及目标地址的响应特征。
单一信号不足以下结论。

<a id="section-26"></a>

### 4.2 证据可复现

<a id="section-27"></a>

#### 陷阱 5：证书透明度日志的查询结果不留存

**现象**

在线查询证书透明度日志，得到几十条子域记录，
把结论写进报告，但没有保存查询结果本身。

**原因**

联网查询的结果**不可复现**。

服务端的数据在持续变化，你的查询时间、查询参数、返回的排序都会影响结果。

几个月后复核时，同样的查询可能返回不同的集合——新的证书签发会导致记录变化，老记录也可能有偏移。

**没有留存的查询结果，等于没有证据。**

**影响**

报告里的子域清单无法验证。这类结论在复核环节会变成
「你怎么证明当时查到了这个」的无解提问。

**核查**

**当场落盘 + 哈希 + 记录采集信息**，三项缺一不可：

1. 保存查询的原始响应全文（含查询条件、服务方、返回时间戳）
2. 对保存的文件计算哈希，写进报告
3. 记录采集时间、采集人、使用的查询接口与参数

报告里引用子域清单时，注明它来自哪次采集的哪个文件。
**这个文件本身就是一份需要纳入证据管理的检材。**

<a id="section-28"></a>

#### 陷阱 6：以为证书透明度日志能查出 IP

**现象**

从证书透明度记录里提取出子域名，然后试图从中直接得到源站 IP。

**原因**

证书透明度日志记录的是**证书内容**，而证书里的字段是域名（SAN 扩展），**不包含 DNS 解析结果**。

从证书能得到的只有域名，从域名才能解析出 IP。

这是一个两步操作，跳过第一步会得到「证书里有 IP」的错误印象。

**影响**

分析停滞，或者误用其他非规范手段去「找 IP」。

**核查**

严格两步走，并在报告里分开记录两个阶段的产物：

- 阶段一产物：域名清单（来自证书记录，标注来源接口与时间）
- 阶段二产物：解析结果（标注解析时点，因为 DNS 会变）

**DNS 记录本身是时间敏感的**，这一点必须写进报告：
`解析于 2024-03-20 14:30 完成，DNS 记录具有时效性，
后续可能变化；解析结果已落盘并计算哈希。`

<a id="section-29"></a>

#### 陷阱 7：在离线环境才想起需要外部数据源

**现象**

拿到的是内网隔离环境的服务器镜像，做完本地分析后才发现
需要外部信息才能确认某个域名的归属或历史解析记录。

**原因**

证书透明度日志、公开 DNS 解析、历史解析记录这些数据源**都需要联网访问**。

在隔离环境里它们全部不可用，而这类信息在事后往往没有第二种获取途径。

**影响**

要么分析做不下去，要么用不可靠的替代信息（比如凭记忆或推测），后者会把不确定的东西写成确定的事实。

**核查**

**在还能联网的阶段就把外部数据源采完并固定下来。**
在取证方案阶段就把「需要联网采集的外部数据」列成清单，
明确每项的用途与合法性依据，采集后统一落盘、计算哈希、纳入证据清单。

如果确实在离线环境且外部数据未采：
结论里必须写明「受采集环境限制，未能获取 X 数据，
导致 A 项无法确认」，并把 A 列为遗留事项。
把「无法确认」写成「确认不是」，是这一类环境限制最容易引发的错误。

<a id="section-30"></a>

### 4.3 范围与授权边界

<a id="section-31"></a>

#### 陷阱 8：误把共享主机环境下的默认站点当成源站

**现象**

测试某个候选 IP 时，去掉 Host 头访问，返回了一个看起来正常的企业网站，
于是把它记为源站。

**原因**

云主机的默认网关行为是：没有匹配到任何虚拟主机配置的请求，会被送到默认站点。

如果该 IP 上恰好有其他客户的服务，无关 Host 请求返回的就是那个默认内容。

这与「这是一个真实源站」的表现几乎一样，但结论完全不同。

**影响**

把一台承载多个业务的共享服务器当成目标业务的源站。
后续的动作会影响到这台机器上的其他业务——**这已经越出了授权范围。**

**核查**

确认「这个 IP 是专属于目标业务的」，需要多项证据：

- 无关 Host 请求返回的是**空站点或明确的服务商默认页**，
  而不是另一个真实业务的内容
- 目标业务的证书与该 IP 绑定
- 主机上的虚拟主机配置**只有**目标业务（需要主机侧证据，
  而这需要拿到镜像或登录权限）

**在这三项确认之前，不要把这个 IP 写进「源站清单」，
更不要基于它采取任何动作。** 记为「候选地址，待确认」。

<a id="section-32"></a>

#### 陷阱 9：把证书已过期作为匹配依据

**现象**

某 IP 上的证书域名匹配目标域名，判定为源站。

**原因**

证书有 `notBefore` 与 `notAfter` 两个时间字段。
一个**已过期**的证书仍然能完成 TLS 握手（握手本身不校验有效期），
所以「能连上且域名匹配」这个观察，在证书过期时依然成立。
但过期的证书属于历史状态，不能证明当前的运营关系。

**影响**

用弱证据做强结论。这类判定在复核时很容易被推翻。

**核查**

证书匹配要**三个字段同时核对**：

- 域名匹配（SAN 扩展或 CN 字段包含目标域名）
- 有效期覆盖当前时间
- 签发者合理（不是自签、也不是明显无关的签发者）

**过期证书的匹配结果记为「历史关联证据」**，
可以作为线索，但不能单独支撑「这是源站」的结论。
报告里写清楚有效期区间，并注明「证书已于 X 日过期」。

<a id="section-33"></a>

### 4.4 证据优先级：先看手里有什么

<a id="section-34"></a>

#### 陷阱 10：只看外部不看手里的服务器

**现象**

手里已经有目标源站的完整镜像，却还在通过 DNS、证书、外部探测
去反推源站地址，报告里的源站识别部分全靠外部数据。

**原因**

这是取证里最不该犯的顺序错误。

**已经拿到的检材是可靠性最高、合法性最清晰的证据**；外部查询结果不仅随时可能变化，还涉及第三方数据源的可用性与授权问题。

用可靠性最低的手段去替代已经握在手里的证据，是纯粹的风险增加。

**影响**

在外部手段上耗费大量时间，且报告的核心结论建立在了不可复现、时效性强、合法性存疑的数据上。

**核查**

**优先级顺序如下，从上往下查**：

1. **主机内的配置**：Web 服务器的配置文件里通常直接写着
   接入 CDN 的回源配置、绑定的域名、可能还有源站对外的地址
2. **主机内的 hosts 文件与防火墙规则**：本地解析与放行策略
3. **主机内的应用配置与日志**：日志里的请求处理记录
4. **外部数据**：证书透明度日志、公开 DNS 记录——作为补充与交叉验证

第 1 项在实践中命中率很高：接入 CDN 时，源站主机上通常会有一份配置记录了边缘节点列表或回源策略（是否存在须逐台核查该机配置）。

**这份配置还是「源站曾主动接入 CDN」的直接证据**，比任何外部推断都强。

<a id="section-35"></a>

#### 陷阱 11：把网络探测当成识别手段

**现象**

为了确认某个地址是否提供 Web 服务、开放哪些端口，
对候选地址做端口扫描。

**原因**

在授权取证的语境下，**主动探测的边界需要精确界定**。

特别是：目标域名下的某些子域（比如邮件相关的名字）对应的可能是完全不同的资产，甚至是第三方服务。

对这些地址做端口扫描，可能构成对未授权资产的探测。

**影响**

**这是合规风险，不是技术风险。** 超出授权范围的探测行为，
可能独立于取证结论构成一个法律问题，而且这个后果与报告写得好不好无关。

**核查**

**优先做被动数据采集，不做主动探测：**

- 可以做：DNS 解析、证书透明度日志查询、公开信息检索
- 需要谨慎：向目标地址发送应用层请求（本质仍是主动行为，
  需确认该地址的所有权与授权覆盖范围）
- **不做**：端口扫描、漏洞探测、任何超出「确认服务存在」必要性的网络交互

如果委托授权书里明确写了「允许主动探测」且范围清晰，按授权执行，
并把授权书作为证据链的一部分归档。
**授权范围不清晰时，默认不做。**

而且要记住：**检材内部的证据往往已经足够**。

手上如果有源站镜像，前面十个陷阱里的答案基本都能在里面找到，根本不需要走外部探测这条路。

<a id="section-36"></a>

#### 陷阱 12：把域名枚举结果等同于真实存在的服务

**现象**

通过证书透明度日志拿到一批子域名，逐个解析并记录，
把「解析成功」当作「该子域存在真实业务」。

**原因**

证书记录的子域只说明**某个证书曾经覆盖过这个名字**，
不代表解析到该名字的机器上部署了对应服务。
过期证书覆盖的名字、已下线业务的残留解析、
泛解析配置（`*.example.com` 匹配任意名字）——
这三种情况都会产生「域名存在但服务不存在」的结果。

**影响**

把不存在的业务项写进资产清单。资产清单是后续取证范围的基础，
一旦掺入不存在或不属于委托方的资产，后续动作就有越界风险。

**核查**

资产清单分三列记录，**不合并**：

- **域名来源**：来自证书记录 / 来自 DNS 解析 / 来自主机内配置
- **解析状态**：解析成功 / 解析失败 / 泛解析兜底
- **服务状态**：未验证 / 已确认

只有「服务状态」为「已确认」的条目才计入委托范围。
其余的作为线索列出，明确标注未验证。

**尤其要注意泛解析**：如果发现某个域名解析到的主机上，
任意子域都返回同一个默认页，那这份解析结果里的大部分条目都是假的。
检测方法很简单——用一个确定不存在的随机子域去解析，看是否也能解析成功。
<a id="section-37"></a>

## 五、案例示例

<a id="section-38"></a>

### 5.1 只拿到 CDN 日志时如何定位源站

**场景**

委托方是一家电商企业，站点 `digiforensics-site` 接入了 CDN。委托方报告站点被植入后门并发生数据外传。**委托方未能提供源站服务器**，只提供了 CDN 侧的访问日志。任务：还原完整请求链路并定位源站。

这条路径值得先走，是因为**CDN 日志本身不含源站信息**——它记录的是 CDN 边缘节点视角的请求，客户端 IP 已被替换成 CDN 节点地址。

不先定位源站，日志里所有的 `$remote_addr` 都会被误读成攻击者来源。

**处置过程**

**第 1 步 · 确认 CDN 状态**

```bash
dig +short digiforensics-site
# cdn.digiforensics-edge.example.net.
curl -sI https://digiforensics-site/ | grep -iE 'server|age|x-cache|cf-ray'
# server: cloudflare
# cf-ray: 8a1b2c3d4e5f6789-SJC
# age: 37
```

**确认接入 Cloudflare。** 更重要的是——**委托方手里的日志：**

```bash
awk '{print $1}' /evidence/cdn-side-access.log | sort -u | head -10
# 104.16.132.229
# 172.64.155.209
# 162.159.200.1        ← 全是 Cloudflare 段（162.158/162.159/172.64/104.16）
```

日志里全是 CDN 节点。委托方"没有源站日志"的原因清楚了——他们根本没拿到源站机器。

**第 2 步 · CT log 查询并固定证据**

```bash
mkdir -p /evidence/ct && cd /evidence/ct
date -u '+采集时间(UTC): %Y-%m-%dT%H:%M:%SZ' | tee collected-at.txt
curl -s 'https://crt.sh/?q=%25.digiforensics-site&output=json' \
     -o "crt-$(date -u +%Y%m%dT%H%M%SZ).json"
sha256sum crt-*.json | tee hashes.txt
```

得到 4 个唯一域名：

| 域名 | 解析结果 | 判断 |
|---|---|---|
| `digiforensics-site` | CNAME → CDN | 主站走 CDN |
| `www.digiforensics-site` | CNAME → CDN | 走 CDN |
| `origin.digiforensics-site` | **A → 198.51.100.24** | ★ **源站** |
| `mail.digiforensics-site` | A → 198.51.100.24 | 邮件服务（同 IP） |

两个未接入 CDN 的子域都指向同一个 IP——这就是源站。 CT log 在这里直接给出了答案。

**第 3 步 · 验证源站**

```bash
IP=198.51.100.24; D=digiforensics-site
echo | openssl s_client -connect "$IP:443" -servername "$D" 2>/dev/null \
  | openssl x509 -noout -subject -dates -ext subjectAltName
# subject=CN = *.digiforensics-site
# notAfter=Aug 14 03:12:00 2024 GMT
# X509v3 Subject Alternative Name:
#     DNS:*.digiforensics-site, DNS:digiforensics-site     ← 匹配

curl -skI -H "Host: $D" "https://$IP/" | grep -iE 'server|x-powered|x-cache'
# server: nginx
# x-powered-by: PHP/7.4.33      ← ★ CDN 侧没有这个头
```

**四项独立证据全部指向同一结论：**

| 证据 | 内容 | 强度 |
|---|---|---|
| CT log | `origin.` 域名签发过证书 | 强 |
| DNS | 该域名 A 记录直指 198.51.100.24（无 CNAME） | 强 |
| 证书 SAN | 含 `*.digiforensics-site` | **强** |
| 响应头差异 | `server: nginx` + `x-powered-by: PHP/7.4.33`（CDN 侧没有） | **强** |

第 4 步 · 关键发现：CDN 日志里看不到的东西

用源站候选对比 CDN 日志中同一时段的请求：

```bash
# CDN 侧：POST 请求的记录
grep 'POST' /evidence/cdn-side-access.log | awk '{print $1,$7}' | sort | uniq -c | sort -rn | head
# 1847 198.51.100.24 /api/v1/order/export
# 1203 198.51.100.24 /api/v1/user/profile

# ★ 但源站 IP 本身出现在 CDN 日志的 remote_addr 里，
#   说明这批请求是从源站服务器发出的（内部调用或 SSRF 造成）
```

**这是本案的关键转折**：CDN 日志里 `$remote_addr` 出现 `198.51.100.24`，**正是刚查到的源站 IP**。

也就是说，**部分 POST 请求的发起方就是源站自己**。

这在两种情况下成立：

1. 正常的内部 API 调用（应用服务器访问自己的接口）；
2. WebShell 通过源站向 CDN 发起请求，形成"看起来像合法流量"的伪装。

第二种的可能性必须结合其他证据判断，**不能仅凭这一点定性**。

**第 5 步 · 移交与固定**

```bash
# 把源站判定写成可移交的记录
cat > /evidence/ct/origin-assessment.md <<'EOF'
# 源站判定记录
结论：198.51.100.24 为 digiforensics-site 的源站服务器
判定依据（四项独立）：
  1. CT log 中 origin.digiforensics-site 签发过公开证书
  2. 该域名 A 记录直指该 IP，无 CNAME
  3. 证书 SAN 含 *.digiforensics-site，有效期至 2024-08-14
  4. 直连响应头 server:nginx / x-powered-by:PHP/7.4.33，CDN 侧无此头
采集时间（UTC）：____
局限性：本次仅做被动收集与只读 GET 验证，未做端口扫描或漏洞探测。
EOF
```

**结论要点**：

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| `198.51.100.24` 是源站 | CT log + DNS + 证书 SAN + 响应头差异 | 强（四源） |
| 委托方"没有日志"是因为未持有源站机器 | CDN 侧日志 IP 全为 Cloudflare 段 | 强 |
| 源站 PHP 版本为 7.4.33（EOL） | 直连响应头 | 中（响应头可伪造，但结合其他证据可信） |
| 部分 POST 的 remote_addr 是源站自身 | CDN 日志中该 IP 出现 3050 次 | 中（**原因待查，可能是正常内部调用**） |
| 攻击者是否经源站外传数据 | ❌ **无法确定** | **证据不足，需拿到源站机器** |

> **报告写法要点**：①本案的结论是"确定了源站位置"，不是"查明了入侵过程"——**必须明确区分这两件事**，否则会给出委托方超出证据的期待；②"源站出现在 CDN 日志的 remote_addr"是**待查项而非结论**，报告中应写明两种可能（正常内部调用 / 后门伪装），并建议下一步核查；③**CT log 是联网查询的结果，不可复现**——必须写明采集时间、URL 与文件哈希，这是本次取证的**关键证据固定动作**；④**合规声明要写进报告**：本次仅做被动信息收集与只读验证，**未做端口扫描或漏洞探测**，全程在委托方授权范围内；⑤**最重要的后续建议是：立即固定源站服务器镜像**——源站是整个案件的核心证据，而它目前仍在攻击者控制之下，**随时可能被清理**。**这个时间压力应当作为报告的第一条建议。**

**误判对照**

本案最容易得出的错误结论有两处，都出在「源站 IP 出现在 CDN 日志里」这一事实上。

错误结论一：把 CDN 日志里的 `$remote_addr` 当成攻击者来源 IP。 这是最常见的致命误判。在 CDN 架构下，边缘节点日志的 `$remote_addr` 字段记录的是**与 CDN 边缘通信的那一跳**——当请求经过 CDN 转发到源站时，CDN 记录的可能是 CDN 节点 IP，也可能是通过回源链路传递的原始 IP，**取决于 CDN 的日志配置与回源方式**。本案里这个字段出现的 10 个 IP 全部落在 `162.158/162.159/172.64/104.16` 段内，是 Cloudflare 的地址段，**没有一个是真实客户端**。按错误判据走，会把一整片 Cloudflare 网段写进报告的"攻击者 IP"列表，委托方据此去封禁，等于封了个寂寞。

**正确判据**：先确认日志里 IP 字段的语义，再决定能不能当身份用。**判据是查这段 IP 的归属**——用 `whois` 或既有资产台账确认这段地址属于 CDN 厂商，那么它就是基础设施地址，不是来访者。

错误结论二：源站 IP 出现在 `$remote_addr` 里，就判定"攻击者从源站内部发起外传"。 本案 3050 次 POST 的 `$remote_addr` 是 `198.51.100.24`，看上去像是"攻击者在源站上执行命令向外传数据"，很有说服力——但这个推断**缺一个前提**：这些请求是不是由攻击者发起的。PHP 应用为了拉取第三方数据（支付回调、地图 API、物流单号查询）主动 POST 到自己的 CDN 域名，是完全正常的业务行为，特征与后门外传几乎一样。

**正确判据**：要区分这两种情况，得看**请求的路径与时间分布，而不是只看来源 IP**。业务内部调用的路径是固定的少数几个（`/api/v1/order/export` 这类），且有明显的业务周期；后门外传的路径随机、User-Agent 单一、往往集中在异常时段。**判据是路径基数与时间分布的规律性**，光看 IP 无法定性。

**按错误判据走的代价**：本案是委托方已经报案、怀疑数据外传的场景。如果把 3050 次 POST 直接写成"已确认 3050 条数据外传记录"，给出的外传数据量级会严重误导后续的合规评估与责任认定——**取证最贵的错误不是没找到，是让人以为自己找到了**。

<a id="section-39"></a>

### 5.2 源站直连验证的授权边界

**场景**

5.1 定位到 `198.51.100.24` 后，需要验证它确实是源站。委托方是电商企业，源站也是自有资产，但取证人员手上只有 CDN 侧的授权说明——**「CDN 供应商的日志分析」**明确写在委托范围内，**源站服务器本身不在本次授权清单里**。

这个场景之所以要单独拿出来讲，是因为**验证源站的四种手段里，有两种会越过授权边界**，而它们恰恰是最直觉、最容易先做的那两种。
**处置过程**

按授权范围分四级，由低到高：

| 手段 | 是否越界 | 说明 |
|---|---|---|
| DNS 查询、CT log 查询 | 否 | 公开信息，被动收集 |
| 对已知 IP 发起 **TLS 握手 + 单次 HEAD/GET** | 否 | 属只读验证，**但需在报告中声明** |
| 端口扫描、`nmap` 全端口探测 | **是** | 未授权的探测行为 |
| 尝试登录、漏洞探测、路径探测 | **是** | 明确的未授权访问 |

只读验证的最小动作：

```bash
IP=198.51.100.24; D=digiforensics-site
# TLS 握手只读取证书，不发送应用层请求
echo | openssl s_client -connect "$IP:443" -servername "$D" 2>/dev/null \
  | openssl x509 -noout -subject -dates -ext subjectAltName

# 单次 HEAD，请求的是自己委托范围内的域名
curl -skI -H "Host: $D" "https://$IP/" | grep -iE 'server|x-powered|x-cache'
```

**结论**

- 源站判定成立，四项独立证据齐备（见 5.1）。
- **验证动作的合规边界已记录在案**：只做了 DNS/CT 被动查询与 TLS 握手、单次 HEAD 请求，**未做端口扫描，未尝试登录，未发送任何写操作**。
- **限定范围**：本次验证只覆盖 `443` 端口的 HTTP 服务，**未确认该主机还提供哪些其他服务**（这需要端口扫描，超出授权范围）。

**误判对照**

最容易出的错是**把"验证是只读的"理解成"验证不需要授权"**。

只读不代表无害——对一台不在授权清单内的主机发起请求，在某些司法辖区仍可能构成未授权访问。

判断依据不是"我有没有改数据"，而是**"这台主机在不在委托范围内"**。

第二个易错点是**在授权不明确时倾向于先做再说**。

直觉是"反正只是 GET"，但一旦出事，事后补授权书需要委托方重新出具，而委托方可能因为担心责任反悔而否认可证过程——**那时候连只读验证的证据都要重新采**。

正确做法是先书面确认范围，再动手。

第三个易错点是**把"没做某项检查"写成"不存在"**。

报告里如果写"该主机仅开放 443 端口"，这句话在未做端口扫描的前提下是**没有依据的**。

正确表述是「本次在授权范围内仅验证了 443 端口的 HTTP 服务，**其他端口状态未知**」。

<a id="section-40"></a>

### 5.3 反例：CT log 查不到子域时的替代路径

**场景**

另一宗委托，站点 `digiforensics-portal` 也接了 CDN，但 CT log 查询结果是空的——查不到任何为该域名签发的公开证书。

这看起来是"CT log 这条路走不通"，但**它本身就是一个发现**：接入 CDN 的站点，主域名的证书由 CDN 厂商统一签发并分发，通常不会为每个客户域名单独出现在 CT log 里。

**处置过程**

此时应转向其他被动来源，按信息价值排序：

```bash
# 1. 历史 DNS 解析记录（源站 IP 曾直接指向过主域名的时代）
dig +short digiforensics-portal
dig +trace digiforensics-portal 2>&1 | grep -E 'CNAME|A ' | head

# 2. 邮件与 DNS 记录常暴露同一台主机
dig +short MX digiforensics-portal
# 10 mail.digiforensics-portal.digiforensics-portal.example.net.

# 3. 源站 IP 段反查：同 IP 托管的其他站点
host 198.51.100.24
whois 198.51.100.24 | grep -iE 'netname|org|descr'
```

**报告里的邮件头是另一条常被忽略的路径**：如果站点曾给用户发过邮件（注册验证、订单通知），邮件原始头里的 `Received:` 链会记录直连的源站 IP。收集时必须拿原始邮件源（`.eml` 或 MIME 原文），从客户端本地或归档系统取，而不是让用户转发——转发会重写头信息。

**结论**

- 通过 MX 记录与邮件 `Received:` 链，定位到同一台主机承载邮件服务，该 IP 为源站。
- **明确写入报告**：本次**未能通过 CT log 取得源站证据**，改用 DNS 与邮件头路径，**两条路径的证据强度不同，不可混为一谈**。

**误判对照**

这个反例最容易出的错是把"CT log 无结果"当作"查不到源站"，然后得出"无法定位源站"的结论。实际上 CT log 无结果本身携带信息：它区分了两种情况——

1. **域名从未签发过公开证书**（可能是内部自签证书，源站不对公网暴露证书）
2. **证书由 CDN 厂商托管签发**（正常情况，证书不出现在该域名的 CT 记录里）

这两种情况对源站定位的启示完全相反，但 CT log 的"空结果"无法区分它们。

**正确判据**：看**主域名的 DNS 记录形态**。如果主域名是 CNAME 指向 CDN 厂商域名，且历史上有过 A 记录直指某个 IP，那么就是情况 2，源站很可能通过 MX、邮件头或同一 IP 段的其他站点间接暴露出来。

**按错误判据走的代价**：本案如果停在"CT log 查不到，无法定位源站"，会向委托方交付一份"技术手段不足"的结果报告，而实际上有三条可用的替代路径。把一条路径不通写成"结论不可得"，和"结论为阴性"一样，都是在替自己的工具能力背书。

---
<a id="section-41"></a>

## 六、扩展阅读方向

**先补证据可复现的规范。**

CT log、历史 DNS、响应头都是**在线查询拿到的、会随时间变化的结果**——不记录采集时间与哈希，报告里的结论就无法被第三方复核。

- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md)：在线取证动作的登记要求、URL 与查询参数的完整留档方式。
- [哈希与完整性校验](../../fundamentals/fundamentals-concepts/fundamentals-concepts-hashes-and-integrity-verification.md)：CT log JSON 响应这类外部证据的固定方式，参见 [3.2 第 2 步](#section-16) 里的做法。
- [证据保管链与委托证明](../../fundamentals/fundamentals-chain/fundamentals-chain-chain-of-custody-and-authorization.md)：**资产清单与授权范围是本篇全部动作的合法性基础**，须在动手前完成登记。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md)：对未授权资产进行源站探测的法律风险，以及探测频率与范围的合规尺度。

**再补流量与代理链。**

找到源站 IP 只是拿到了入口，真正的链路要在日志与流量里拼出来。

- [网络流量与 PCAP 取证](../../memory/memory-network/memory-network-pcap.md)：SNI 提取、会话重组，验证候选源站的响应内容是否与站点一致。
- [网络连接与流量痕迹](../../memory/memory-artifact/memory-artifact-memory-network-artifacts.md)：CDN 回源时源站侧的连接特征——源站只在 CDN 前置节点处才可见来访。
- [Web 访问日志深度分析](../server-log/server-log-web-access-log-analysis.md)：W3C 格式下带 `X-Forwarded-For` 的日志分析，**代理链有多层时如何判断哪一跳可信**。

**然后是源站侧的直接延续。**

找到 IP 之后，才真正开始源站取证。

- [取证工件地图（Linux 侧）](../../computer/computer-persistence/computer-persistence-persistence-artifact-map.md)：拿到源站 IP 后的第一步——确认主机角色、证据优先级与采集顺序。
- [网站目录与 WebShell 检测](server-web-webshell-detection.md)：直连上传的 WebShell 在 CDN 侧不可见，只能在源站文件系统里找。
- [WebShell 工具流量特征](server-web-webshell-traffic-patterns.md)：CDN 与源站日志的差集比对方法，以及"CDN 未缓存的 POST"这类请求的识别。
- [Nginx 与 Apache 配置取证](server-web-nginx-apache.md)：源站的回源配置（`proxy_pass`）、IP 白名单、SNI 校验等**配置层是否留下绕过路径**。

**最后是判据与应急决策。**

归属认定和处置顺序是这一篇最容易被忽略的两件事。

- [取证概念与分类](../../fundamentals/fundamentals-concepts/fundamentals-concepts-digital-forensics-concepts.md)：证据的关联性、解释力、可采性三维度，用来给"源站 IP 属于 CDN 厂商"这类判断定强度。
- [远程控制工具痕迹](../server-panel/server-panel-remote-control-artifacts.md)：源站失守后常见的下一步动作，用于判断"直连入侵"与"远控驻留"的先后关系。
- [Web 攻击痕迹还原](../server-log/server-log-web-attack-trace-reconstruction.md)：源站暴露后结合 `Web.config` 篡改与清理痕迹还原完整攻击路径。
<a id="section-42"></a>

## 七、命令速查

```bash
# ===== 1. 是否接了 CDN =====
D=digiforensics-site
dig +short "$D"; dig "$D" CNAME +short; dig "$D" +noall +answer
curl -sI "https://$D/" | grep -iE 'server|via|age|x-cache|cf-|swift|ali|timing'
# 从日志反推： awk '{print $1}' access.log | sort -u | head

# ===== 2. CT log 查询与固定（★联网动作，先固定再分析）=====
mkdir -p /evidence/ct && cd /evidence/ct
date -u '+采集时间(UTC): %Y-%m-%dT%H:%M:%SZ' | tee collected-at.txt
curl -s 'https://crt.sh/?q=%25.digiforensics-site&output=json' -o "crt-$(date -u +%Y%m%dT%H%M%SZ).json"
sha256sum crt-*.json | tee hashes.txt
python3 -c "
import json,glob
f=sorted(glob.glob('/evidence/ct/crt-*.json'))[-1]
d=json.load(open(f))
names=sorted({n.strip() for r in d for n in r.get('name_value','').splitlines()})
open('/evidence/ct/domains.txt','w').write('\
'.join(names)+'\
')
print(f'共 {len(names)} 个唯一域名')"
grep -iE 'origin|direct|backend|server|node|host|panel|raw|src|oss|upstream|dev|test' domains.txt \
  | tee origin-candidates.txt

# ===== 3. 其他挖掘路径 =====
dig +short "$D" MX; dig +short mail."$D" A          # ★ 邮件服务器常不走 CDN
dig +short "$D" NS; dig "$D" SOA +noall +answer    # serial 反映变更历史
# 子域枚举（只做 DNS，不做端口扫描）
for s in origin direct backend src static-origin oss raw api admin test dev panel old node; do
  ip=$(dig +short "$s.$D" A 2>/dev/null | head -1); [ -n "$ip" ] && echo "$s.$D -> $ip"
done
curl -s "https://$D/robots.txt"

# ===== 4. ★ 检材内的源站线索（最合法可靠，勿遗漏）=====
grep -rniE 'cdn|cloudflare|aliyun|qcloud|upstream|proxy_pass|origin' /mnt/df/www/server/nginx/conf/ 2>/dev/null | head -30
grep -rn 'cdn\|edge' /mnt/df/etc/hosts /mnt/df/etc/sysconfig/ 2>/dev/null | head
# iptables 白名单： /etc/iptables/rules.v4  /etc/nftables.conf

# ===== 5. 验证源站候选 =====
IP=198.51.100.24; D=digiforensics-site
echo | openssl s_client -connect "$IP:443" -servername "$D" 2>/dev/null \
  | openssl x509 -noout -subject -dates -ext subjectAltName
curl -skI -H "Host: $D" "https://$IP/" | grep -iE 'server|x-powered|x-cache'
diff <(curl -sI "https://$D/" 2>/dev/null | sort) \
     <(curl -skI -H "Host: $D" "https://$IP/" 2>/dev/null | sort)   # 响应头差异
# 共享主机陷阱排除：curl -sk -H "Host: nonexistent.invalid" "https://$IP/" | head
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 服务器与 Web 取证 — CDN 识别与源站挖掘」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《CDN 识别与源站挖掘》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.vc` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
