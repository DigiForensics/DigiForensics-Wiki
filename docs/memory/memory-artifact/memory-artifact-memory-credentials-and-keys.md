---
title: "内存中的凭据与密钥"
slug: "memory-artifact-memory-credentials-and-keys"
canonical: "https://www.digiforensics.cn/wiki/memory-artifact-memory-credentials-and-keys"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:51+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "memory"
space: "内存与专项取证"
node_path: ["内存工件"]
---

# 内存中的凭据与密钥

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/memory-artifact-memory-credentials-and-keys)

<a id="section-1"></a>

## 一、概述

内存是**唯一一个能拿到运行时明文密钥的地方**。

磁盘上的加密数据，密钥要么以密文形式存在，要么需要用户提供口令。而只要系统处于解锁或已登录状态，密钥与凭据就在内存里以可直接读取的形态存在。

这决定了取证侧的一个基本分工：**落盘加密的破局点在内存，不在密码学。**

一台加密的机器，磁盘镜像里只有包裹态的密钥；但它一旦开机登录，解密后的会话密钥、域凭据、应用令牌就驻留在内存里。

要解决的是"如何把凭据相关的结构体和内存区域**固定为证据**"——定位、转储、离线分析、记录。这里明确**不提供明文口令的具体提取实现**，原因在[二、核心原理](#section-2)里说得很清楚：合规要求、最小化原则，以及证据价值的严重不对称。

这一步落在**分析环节**，上游是已获取并完成合规确认的内存镜像，下游是"这条凭据能证明什么"的定性。两个位置约束必须先说清楚。

一是它与加密卷取证是**互补而非替代**关系——内存里拿到的是运行态密钥，磁盘侧拿到的是可复现的密文与包裹密钥，两条路径各自独立可采。

二是提取动作本身必须可复现、可交代，[三、操作步骤](#section-9)的第 0 步"合规确认"不可跳过。

Windows 凭据分三层存储（2.1 详述）：`hashdump` 从内存中已解密的 SAM hive 取本地账户哈希，`lsadump` 与 `cachedump` 从 SECURITY hive 取 LSA Secret。六个目标及其载体与判据：

| 目标 | 内存中的载体 | 关键判据 |
|---|---|---|
| 本地账户哈希 | 已解密的 `SAM` / `SYSTEM` hive | `hashdump` 输出，BOOT_KEY 关系 |
| 域凭据 | LSA Secret 结构 | `lsadump` 输出，条目时间与类型 |
| 缓存域凭据 | SECURITY hive 的 `Cache` 键 | `cachedump` 输出的用户名 / 域名 / 16 字节缓存哈希 |
| LSASS 完整内存 | 进程转储 `lsass.dmp` | 独立哈希，体积与进程匹配 |
| 卷密钥 | 驱动上下文中的明文 FVEK | 与该卷的保护器组合对应 |
| 应用层密钥 | 内存中的 API Key、Token、JWT 结构 | 上下文（哪个进程、哪个应用） |

第四行与第六行是反复强调的边界：**LSASS 转储必须逐个哈希后单独保管**，而内存里扫出的字符串不等于可用凭据——一个 `Bearer` 开头的串可能是过期令牌，也可能属于另一个用户。

据此能回答的是这些：某账户的口令哈希是什么、某账户是否曾在本机登录、内存中是否存在某把会话密钥、某个应用是否持有令牌、加密卷在采集时是否处于解锁状态。

回答不了的是这些。它不能回答"某条凭据当前是否仍然有效"——哈希存在不等于凭据可用，撤销与轮转在内存外发生。也不能据此认定"某人实施了某行为"，凭据归属与行为归属之间隔着账户使用记录这一层。

动手之前，先确认你已经具备：明确的取证授权与合规意识、内存镜像与 Volatility 基础操作能力、以及对 Windows 凭据存储体系（SAM/SECURITY/DPAPI 层次）的基本理解。合规意识缺失时先看[合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md)；

镜像还没有则看[内存采集方法](../memory-acquire/memory-acquire-memory-acquisition-methods.md)。

凭据落到磁盘侧后怎么固定，去[远程工具凭据解密](../../crypto/crypto-app/crypto-app-remote-tool-credential-preservation.md)；加密卷密钥的落盘路径看[BitLocker 全卷加密取证](../../crypto/crypto-volume/crypto-volume-bitlocker.md)。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 Windows 凭据的三层存储

| 层 | 位置 | 内容 | 保护机制 | 内存版插件 |
|---|---|---|---|---|
| **SAM** | `System32\config\SAM` | 本地账户的 NTLM 哈希（RID + hash） | SYSTEM hive 中的 `BOOT_KEY` XOR 加密 | `windows.registry.hashdump` |
| **SECURITY hive** | `System32\config\SECURITY` | 域凭据、缓存的域登录、服务账号口令、EFS 私钥 | DPAPI（系统密钥 + 用户密钥双重加密） | `windows.registry.lsadump`、`windows.registry.cachedump` |
| **LSASS 进程** | `lsass.exe` 地址空间 | 正在使用的凭据、会话票据、已解密的用户数据 | Windows 内部机制 | 无专用转储插件，用 `windows.memmap --pid --dump` |

> **层与插件不是一一对应**：SECURITY hive 这一层上同时有 `lsadump`（遍历 `Policy` 下的 `Secrets`）和 `cachedump`（遍历 `Cache` 键下的缓存条目）两个插件，**「三层存储」不等于「三个插件」**。

> **重要区别**：SAM 里是**哈希**（不可逆），LSA Secret 里是 **DPAPI 加密的密文**（`lsadump` 利用内存中已解密的 DPAPI 主密钥解开），LSASS 内存里是**使用中的凭据状态**。

三者信息量不同，**不可互相替代**。

> **插件名核实**：Volatility 3 **没有** `windows.lsass_dump` 这个插件。

LSASS 内存转储的规范做法是用 `windows.memmap --pid <PID> --dump` 导出该进程内存映射。

任何声称提供 `lsass_dump` 的教程都在误导。

<a id="section-4"></a>

### 2.2 `hashdump`：从内存中的 SAM 提取本地账户哈希

**流程**：遍历内存中的注册表 hive（依赖 `windows.registry.hivelist`）→ 定位 `SAM` 与 `SYSTEM` → 取出 `BOOT_KEY` 与 `HBootKey` → 逐账户用 `HBootKey` 解密 NTLM 哈希。

**Volatility 3 输出的是四列表格**：

```text
User            rid   lmhash                               nthash
Administrator   500   aad3b435b51404eeaad3b435b51404ee   31d6cfe0d16ae931b73c59d7e0c089c0
Guest           501   aad3b435b51404eeaad3b435b51404ee   31d6cfe0d16ae931b73c59d7e0c089c0
```

> 格式澄清（vol2 → vol3 迁移中最常见的错误）：Volatility 2 的 `hashdump` 输出是冒号分隔的 `user:rid:lm:nt:::`，而 vol3 是 `User/rid/lmhash/nthash` 四列。网上大量教程仍在用 vol2 的冒号格式，脚本按冒号切分在 vol3 上会直接失败。
>
> ⚠️ **`hashdump` 没有 `--sam` 参数**——它通过 automagic 自行定位 hive，失败时检查 `hivelist` 是否同时列出 `SAM` 与 `SYSTEM`。
>
> **空口令判读**：`nthash` 为 `31d6cfe0d16ae931b73c59d7e0c089c0` 即为空口令（MD4("")，源码中以 `empty_nt` 常量定义）。`lmhash` 的 `aad3b435b51404eeaad3b435b51404ee` 同样是空值标记。

<a id="section-5"></a>

### 2.3 `lsadump`：解密 LSA Secret

**原理**：从内存中的 SECURITY hive 取出 `BOOT_KEY`（依赖 `hashdump` 的解密链路）→ 由它导出 **LSA 密钥（lsakey）** → 遍历 `Policy\Secrets` 下的每个子键 → 读取其 `CurrVal` 并跳过前 4 字节长度头 → 用 AES 解密（Vista 之前走 RC4 派生）。

输出 `Key` / `Secret` / `Hex` 三列。

> ⚠️ **列语义（源码核实，与多数教程的说法不同）**：框架 CLI 渲染器对这两列的呈现方式**都不是**网上常见的"可读明文"或"连续 hex 串"：
>
> - `Secret` 列类型是 `format_hints.HexBytes`，渲染成 **hex + ASCII 双栏 dump**（每 16 字节一行，非打印字符显示为 `.`），**并且每行前后都带换行符**——它会**跨行输出**。
> - `Hex` 列类型是 `bytes`，渲染成 **空格分隔的逐字节 hex**（`4b 4c 53 41`），**不是** `0x4b4c5341` 那种连续串。
>
> **实践影响有两条**：① `lsadump` 的 `quick`/`pretty` 输出不能按行 `awk '{print $1}'` 取 Key——多行字段会打乱列对齐；② 要稳定提取 Key 名，**必须用 CSV 渲染器**（换行会被 csv 模块转义为字段内的 `\
`），见 3.4。
>
> 这也是**本文只讲凭据转储与离线分析、不讲明文提取**的技术原因之一：`lsadump` 给的是**密钥材料**（DPAPI/Session Key），不是账号口令；把它变成明文需要额外的、口令驱动的解密步骤，属于本文范围之外。

**依赖关系（源码核实）**：框架层面 `lsadump` 声明了对 `hashdump`（版本 1.1.0）与 `hivelist`（版本 2.0.0）的版本依赖——`hashdump` 失败时 `lsadump` 也会失败，两者共享 hive 定位与 BOOT_KEY 解密逻辑。

<a id="section-6"></a>

### 2.4 `cachedump`：缓存的域凭据条目

**原理**：域环境下 SECURITY hive 的 `Cache` 键下缓存着上次登录的域凭据，**用当前用户口令派生的 `NL$KM` 密钥加密**。`cachedump` 的处理链是：从 `Policy` 取出 **LSA 密钥** → 用它解开 `Policy\Secrets\NL$KM` 拿到 `NL$KM` 本身 → 遍历 `Cache` 键下的每个条目（跳过 `NL$Control`）→ 解析条目头拿到用户名长度、域名长度、校验 `ch` → 用 `NL$KM` 解密条目尾部 → 从明文里按偏移切出用户名、域名和**哈希**：

```text
Username   Domain   Domain name   Hash
zhangsan   CONTOSO  contoso.com   <bytes 类型，MS-CACHE v2 哈希>
```

> ⚠️ **三处必须核实过的澄清**：
>
> - 列名是 **`Domain name`（含空格）**，不是 `DomainName`。CSV 表头是 `TreeDepth,Username,Domain,Domain name,Hash`。
> - `Hash` 列不是「加密材料」，而是已用 `NL$KM` 解密后取出的哈希（明文缓冲区的头 16 字节，MS-CACHE v2 形式）。它的类型是 `bytes`——**不是口令，也不是可直接登录的凭据**，而是需要候选口令才能比对的缓存哈希。
> - **输出里没有时间戳。** 插件只产出 `Username` / `Domain` / `Domain name` / `Hash` 四列，「条目更新时间」这个判据在 `cachedump` 的输出里根本不存在。要拿缓存条目本身的时间，得回到 `Cache` 键下各值项的注册表时间戳，或改用 `windows.registry.printkey` 直接读键。
>
> 框架中它只声明了 kernel / hivelist / lsadump / hashdump 四项依赖，`cachedump` 不接受 `--password` 参数——它做的是**在已解密的内存镜像上直接给出缓存哈希**。把缓存哈希还原为口令需要**外部**用已获授权的候选口令做验证，**这是另一个工具的工作，不在本文范围内。**

<a id="section-7"></a>

### 2.5 LSASS 进程内存转储（无专用插件）

LSASS 是 Windows 凭据处理的中心进程，其地址空间里同时存在**已解密的凭据、会话票据、缓存的用户数据**。

Volatility 3 **没有** `lsass_dump` 插件，导出方式是 `windows.memmap --pid <PID> --dump`（命令见 3.5）。

其正当用途是离线反汇编分析、检测注入（正常 LSASS 内不应有非微软模块）、时间点取证。

**明文口令提取本篇不涉及实现。**

**合规提示**：LSASS 进程内存包含**当前所有登录用户的凭据材料与会话票据**。

导出到文件系统意味着**扩大了敏感数据的暴露面**，必须有明确授权，且导出文件应按与内存镜像同等级别保护。

<a id="section-8"></a>

### 2.6 内存中的加密密钥与应用层令牌

**BitLocker FVEK**：内存中真正有价值的是 `fvevol.sys` 驱动维护的 **FVE context** 结构。

其中实际加密扇区的密钥在卷解锁期间以可直接读取的形态驻留。

相关内容见[加密取证板块](../../crypto/crypto-volume/crypto-volume-bitlocker.md)。

> **现实约束**：提取 FVEK 需要解析 FVE context 的内部结构，**目前没有成熟的现成 Volatility 插件**，通常需要自定义插件或 WinDbg + IDA 手工分析。**技术门槛高，不建议作为首选路径。**

**EFS 私钥**：EFS 的 RSA 私钥在 DPAPI 保护下存储于用户配置单元，内存中可见其**明文 PEM 形态**（`BEGIN RSA PRIVATE KEY`）。

**VeraCrypt** 挂载卷后，派生密钥材料在驱动上下文中以缓存形式存在（搜 `VeraCrypt` / `TrueCrypt` / `\\.\PhysicalDrive`）。

完整路径见 [EFS](../../crypto/crypto-volume/crypto-volume-efs.md)、[VeraCrypt](../../crypto/crypto-volume/crypto-volume-veracrypt.md)——**本篇只说明"内存是它们的第三条路径"。**

**应用层密钥**通常以明文或简单编码形式驻留内存。

**这是低成本高回报的搜索方向**：

| 类型 | 典型特征 |
|---|---|
| **API Key** | `api_key`、`apiKey`、`x-api-key`、`Authorization: Bearer` |
| **Token / JWT** | `access_token`、`refresh_token`、`Bearer eyJ...`（三段 Base64 用 `.` 分隔） |
| **数据库连接串** | `Server=...;Database=...;User Id=...;Password=...` |
| **云厂商密钥** | AWS `AKIA...`、Google API key（`AIza...`）、Azure 连接串 |
| **SSH 私钥** | `BEGIN OPENSSH PRIVATE KEY` / `BEGIN RSA PRIVATE KEY` |
| **Webhook** | `hooks.slack.com/services/...`、Discord webhook |

从内存明文反推浏览器的 DPAPI 与 App-Bound 保护范围、以及落到磁盘后的解密路径，见[浏览器密码库与 Token 解密](../../crypto/crypto-app/crypto-app-browser-passwords-and-tokens.md)。

---

<a id="section-9"></a>

## 三、操作步骤

<a id="section-10"></a>

### 3.1 第 0 步：**合规确认（不可跳过）**

```text
在执行任何凭据提取前，确认：
☐ 是否有针对该设备/该账户的明确取证授权？
☐ 授权范围是否覆盖"提取账户凭据"？
☐ 提取出的凭据将如何使用（验证身份 / 破解加密 / 关联分析）？
☐ 谁有权接触提取结果？是否有保密协议与销毁要求？
☐ 是否已通知相关方（依法律要求）？
```

> ⚠️ 未取得明确授权而提取他人账户凭据，在多数司法辖区可能构成犯罪。 本节不是形式主义——它是本篇的前置条件。

<a id="section-11"></a>

### 3.2 第 1 步：确认 hive 可用

```bash
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.registry.hivelist \
  | grep -iE 'SAM|SYSTEM|SECURITY'
```

> 没有 `SAM` / `SYSTEM` / `SECURITY` 就说明凭据提取这条路走不通（可能原因：内存采集不完整、系统使用特定配置、hive 已被换出到页面文件）。

<a id="section-12"></a>

### 3.3 第 2 步：本地账户哈希

```bash
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.registry.hashdump | tee /work/hashdump.txt
python3 vol.py -f DigiForensics-mem.raw -r csv  windows.registry.hashdump > /work/hashdump.csv
head -1 /work/hashdump.csv
# TreeDepth,User,rid,lmhash,nthash
#   ↑ 首列是渲染器自动加的，实体列从第 2 列开始
```

| 观察 | 含义 |
|---|---|
| 无输出 | hive 未定位，或符号/镜像问题（先查 `hivelist`） |
| 仅有少量账户 | 可能是域环境（本地账户少），需转向 `lsadump` |
| `nthash` 为 `31d6cfe0...` | 空口令（该值是空哈希的标准形式） |
| 账户数与磁盘 SAM 不一致 | **记录为异常**——可能存在被删账户或内存与磁盘不同步 |

<a id="section-13"></a>

### 3.4 第 3 步：域凭据与 LSA Secret

```bash
# 必须用 csv 渲染：quick/pretty 下 Secret 列是多行 hex+ASCII dump，列会错位
python3 vol.py -f DigiForensics-mem.raw -r csv windows.registry.lsadump \
  > /work/lsadump.csv 2>/work/lsadump.err
chmod 600 /work/lsadump.csv

# 取 Key 名（多行字段已被 csv 转义为字段内的 \
）
python3 - <<'PY'
import csv
with open("/work/lsadump.csv", newline="") as fh:
    for row in csv.DictReader(fh):
        print(row["Key"])
PY

# cachedump 遍历 SECURITY 的 Cache 键（跳过 NL$Control），不接受口令参数
python3 vol.py -f DigiForensics-mem.raw -r csv windows.registry.cachedump > /work/cachedump.csv
# 表头：TreeDepth,Username,Domain,Domain name,Hash
#   Hash 是 NL$KM 解密后取出的 MS-CACHE v2 缓存哈希；输出无时间戳
```

> ⚠️ **此命令的输出即为已解密的凭据材料。** 处理规则：立即重定向到受控目录，不要在共享终端滚动显示；该文件按与内存镜像同等级别保护；分析完毕后按授权要求销毁或归档。

<a id="section-14"></a>

### 3.5 第 4 步：LSASS 进程转储（离线分析）

```bash
# 1) 确认 LSASS 的 PID
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.pslist | grep -i lsass

# 2) 转储其内存映射（无 lsass_dump 插件，这是规范做法）
mkdir -p /work/lsass
python3 vol.py -f DigiForensics-mem.raw -o /work/lsass \
  windows.memmap --pid <LSASS_PID> --dump

# 3) 离线初筛：检查是否有非微软模块或凭据提取工具的痕迹
strings -a -n 8 /work/lsass/*.dmp | grep -iE 'mimikatz|sekurlsa|wdigest' | head -20
```

> **本篇到此为止。** LSASS 转储后的深度分析（反汇编、凭据提取的具体实现）属于需要专门授权与技术条件的操作，不在本文范围内。

<a id="section-15"></a>

### 3.6 第 5 步：应用层密钥与令牌搜索

**大镜像必须分块扫描**，否则会耗尽内存：

```bash
cat > /work/memstrings.sh <<'EOF'
#!/bin/bash
# 分块提取字符串，避免一次性加载整个镜像
# 用法: ./memstrings.sh <镜像路径> <块大小MB> <输出文件>
set -e
IMG="$1"; BLOCK_MB="${2:-512}"; OUT="$3"
MB=$((1024 * 1024)); BS=$((BLOCK_MB * MB))
TOTAL=$(wc -c < "$IMG" | tr -d ' ')
: > "$OUT"
NBLK=$(( (TOTAL + BS - 1) / BS ))
i=0
while [ "$i" -lt "$NBLK" ]; do
  START=$(( i * BLOCK_MB ))            # 以 MiB 为单位的起始块位置
  REMAIN=$(( TOTAL - i * BS ))         # 本块起始处还剩多少字节
  if [ "$REMAIN" -ge "$BS" ]; then CNT=$BLOCK_MB; else CNT=$(( (REMAIN + MB - 1) / MB )); fi
  dd if="$IMG" bs=1M skip="$START" count="$CNT" status=none 2>/dev/null | strings -a -n 6 >> "$OUT"
  i=$(( i + 1 ))
done
EOF
chmod +x /work/memstrings.sh
/work/memstrings.sh DigiForensics-mem.raw 512 /work/strings-all.txt
```

> ⚠️ **三个容易写错的地方**：
> ① **不要用 `bs=1`**——`dd` 会退化为逐字节系统调用，读 512 MB 需要数十亿次，**实际不可用**。
> ② **不要写成 `skip="$i"`**——`bs=1M` 时 `skip` 的单位是**块（即 MiB）**，不是块索引。第 N 块的起点必须是 `N * BLOCK_MB`（MiB），写成 `i` 会导致**大量重复读取与漏读**。
> ③ **`wc -c` 兼容 GNU/BSD**，而 `stat -c %s` 只有 GNU coreutils 有；macOS 上用 `wc -c`。
>
> **已知局限**：块边界可能切断跨块的字符串。对密钥搜索影响不大（密钥通常在单个内存页内），但需意识到。

**定向搜索**（完整命令集见第七节速查）：

```bash
grep -iE 'api[_-]?key|client[_-]?secret|access[_-]?token' /work/strings-all.txt | sort -u | head -40
grep -oE 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' /work/strings-all.txt | sort -u | head -20
grep -iE 'mysql://[^:]+:[^@]+@|postgres(ql)?://[^:]+:[^@]+@' /work/strings-all.txt | sort -u | head -20
grep -oE 'AKIA[0-9A-Z]{16}' /work/strings-all.txt | sort -u
grep -c 'BEGIN RSA PRIVATE KEY' /work/strings-all.txt
grep -ic 'fvevol' /work/strings-all.txt   # 卷加密驱动存在性：定位 ≠ 提取
```

> **注意定位与提取的区别**：搜索到驱动名**只能证明"该机安装了/加载了这个软件"**。要证明"卷已解锁"，需要更进一步的证据（如 `manage-bde -status` 输出、卷可读性验证）。不能把"内存里有 fvevol 字符串"等同于"已获得 FVEK"。

<a id="section-16"></a>

### 3.7 第 6 步：验证与记录

**任何提取出的凭据，在作为证据引用前必须验证**：

| 验证方式 | 适用 | 说明 |
|---|---|---|
| **哈希比对** | NTLM 哈希 | 与磁盘 SAM 提取的哈希比对，两者应一致 |
| **实际解锁验证** | BitLocker 密钥 | `manage-bde -unlock` 成功，**不是格式匹配** |
| **签名验证** | SSH 私钥、证书 | 用公钥对已知内容验签成功 |
| **API 调用验证** | API Key | 实际调用一次（**在授权环境内**） |
| **候选口令验证** | 缓存凭据 | 外部工具用授权口令能解出条目 = 口令正确 |

```bash
# 内存侧（TreeDepth 第 1 列、User 第 2 列、nthash 第 5 列）
python3 vol.py -f DigiForensics-mem.raw -r csv windows.registry.hashdump \
  | awk -F',' 'NR>1 {gsub(/"/,""); print $2","$5}' | sort -u > /tmp/mem_hashes.csv

# 磁盘侧（SAM 提取与解析见注册表取证篇目）
awk -F: '{print $1","$2}' /work/sam_hashes.txt | sort -u > /tmp/disk_hashes.csv

# 比对：一致则双源印证
diff /tmp/mem_hashes.csv /tmp/disk_hashes.csv && echo "两源一致，双源印证"
```

---
<a id="section-17"></a>

## 四、常见陷阱

凭据分析有两个独立的失败模式。

**技术层面**——把哈希当明文、把定位当提取、把跨行字段当单行解析。

**合规层面**——把授权当形式、把受控材料降级保护、把"存在"当"泄露"。

后者一旦出问题，性质与前者完全不同。本章按合规前置、插件行为判读、字符串扫描、结论表述与收尾四组展开。

<a id="section-18"></a>

### 4.1 合规与授权

<a id="section-19"></a>

#### 陷阱 1：未取得明确授权就提取账户凭据 ★

**现象**：现场处置时直接跑 `hashdump` / `lsadump`，把输出留在分析机上，之后补授权。

**原因**：3.1 把合规确认列为「**第 0 步（不可跳过）**」并给了五个勾选项，其中第一项就是"是否有针对该设备/该账户的明确取证授权"、"授权范围**是否覆盖'提取账户凭据'**"。1 列出的三条理由里第一条是**合规要求**——提取他人口令涉及未授权访问他人凭据，司法场景下必须有明确授权，而 3.1 的警告框直接写明「未取得明确授权而提取他人账户凭据，在多数司法辖区可能构成犯罪」。

**影响**：**不可逆，且性质与技术错误完全不同**。

技术错误影响的是结论质量，合规错误影响的是整个取证主体的合法性——委托方可能因此丧失证据资格，你个人可能面临法律责任。

而且**授权是前置条件而非事后补记项**，事后补的授权不能覆盖已经发生的提取行为。

**核查**：把 3.1 的五项勾选作为流程的硬门槛，并在报告里留痕。

案例第 1 步之前的处理就是范式——授权文件编号（A-2026-0314）、范围包含"账户凭据相关分析"、接收人指定、报告交付后销毁，**记录在案**。

这四项记录在报告中承担两个功能：证明提取有授权、界定凭据材料的使用与销毁义务。

<a id="section-20"></a>

#### 陷阱 2：无差别提取全部凭据，违反最小化原则

**现象**：把 `lsadump` 的 7 条 LSA Secret 全部复制到个人电脑、U盘、聊天工具里"以防万一"。

**原因**：1 列的第二个理由是**最小化原则**——内存镜像中往往包含所有用户的全部明文数据，无差别提取既不必要也不适当。

这不只是合规要求，也是风险控制：多一份副本就多一个泄露点，而这份材料的敏感性等同于内存镜像本身。

**影响**：**泄露面扩大且不可回收**。

凭据材料一旦离开受控环境，就再也无法证明它没被接触过。

委托方审计时的第一个问题永远是"谁接触过这些材料"。

**核查**：**按需提取、按授权范围限定**。

只提取与委托事项相关的账户（案例委托的是"某外部账户的异常登录"，那就是与该域账号相关的 LSA Secret 与缓存条目）。

凭据材料存放在**受控目录**（案例用 `/work/`），`chmod 600`，并按与内存镜像同等级别保护。

**分析副本与交付报告分离**——报告里写结论和验证方法，凭据本身留在受控存储（见陷阱 14）。

<a id="section-21"></a>

### 4.2 插件行为与输出判读

<a id="section-22"></a>

#### 陷阱 3：把 `hashdump` 输出当"明文口令"

**现象**：报告里写"从内存中恢复了 Administrator 的口令 123456"。

**原因**：2.2 的输出示例是四列 `User / rid / lmhash / nthash`，输出的是 **NTLM 哈希**——它是不可逆的单向摘要，**本身不包含口令**。1 的对比表也把它标为"磁盘能不能拿到 ✅（SAM hive 提取）"，即磁盘侧本来就有。2.1 的引文强调了三层存储的信息量差异：SAM 里是哈希（不可逆），LSA Secret 里是 DPAPI 加密的密文，LSASS 内存里是使用中的凭据状态——三者信息量不同，不可互相替代。

**影响**：**在报告里写一个你没有的东西**。

这不仅是表述错误——如果报告进入司法程序，"恢复了口令"这句话会成为质证的重点，而实际上你手里只有一个哈希。

1 的第三个理由说得很准：**NTLM 哈希已经足以证明"该账户的口令是 X"**，多数案件根本不需要明文。

**核查**：**报告表述必须准确到工件类型**。

写"从内存中的 SAM 提取到该账户的 NTLM 哈希（`nthash` 值 aad3b435b51404eeaad3b435b51404ee），与磁盘 SAM 提取结果一致"，不写"恢复了口令"。

案例第 2 步的表述与结论表都是这个分寸：结论写的是"内存中提取的本地账户哈希与磁盘 SAM 一致"，**没有任何一处把哈希表述成口令**。

<a id="section-23"></a>

#### 陷阱 4：按 vol2 的冒号格式切分 `hashdump` 输出

**现象**：用 `awk -F: '{print $1","$2}'` 处理 vol3 的 `hashdump` 输出，得到一堆空字段或错位数据。

**原因**：2.2 的引文框把这条标为「**vol2 → vol3 迁移中最常见的错误**」：vol2 的输出是冒号分隔的 `user:rid:lm:nt:::`，vol3 是 `User/rid/lmhash/nthash` 四列。而 3.7 的磁盘侧比对代码里 `awk -F: '{print $1","$2}' /work/sam_hashes.txt` 用的正是冒号格式——**那是磁盘侧 SAM 工具的输出格式**。同一个脚本里两种格式并存，凭印象写 `cut -d:` 就会用错。

**影响**：静默失败。

冒号切分在四列表格上得到的是空字符串或整个行，比对时 `diff` 报"两源不一致"，你会以为是内存与磁盘真的不一致——**一个语法错误被误读为一个取证发现**。

**核查**：**内存侧用 `-r csv` 后按列号切分**（3.3 与 3.7 都给了 `awk -F','` 的写法，注意 `TreeDepth` 是第 1 列、`User` 第 2 列、`nthash` 第 5 列），**磁盘侧用冒号**。

两侧格式不同是事实，**在代码注释里写明哪一侧用哪种分隔符**。

<a id="section-24"></a>

#### 陷阱 5：以为 `hashdump` 有 `--sam` 参数

**现象**：`vol.py -f mem.raw windows.registry.hashdump --sam \\REGISTRY\MACHINE\SAM`，报未知参数，改用 `-s` 又指向了符号目录。

**原因**：2.2 的警告框明确——`hashdump` 没有 `--sam` 参数，它通过 automagic 自行定位 hive。而 `-s` 在 vol3 里是 `--symbol-dirs`（[第 03 篇](../memory-acquire/memory-acquire-volatility3.md)），传 hive 路径进去会被当成符号目录去找 ISF，**报错信息与"你传错了插件参数"毫无关联**。

**影响**：排查方向完全偏离。

会去检查符号目录、镜像格式、框架版本，而真正的原因只是这个参数不存在。

**核查**：**定位失败时查 `hivelist`**（2.2 的原话）。

先 `windows.registry.hivelist` 看 `SAM` 与 `SYSTEM` 是否都在输出里（3.2 的命令），两者齐全而 `hashdump` 仍无输出，才往符号与镜像方向查。

3.3 的观察表把"无输出"的第一个原因就是"hive 未定位"。

<a id="section-25"></a>

#### 陷阱 6：`lsadump` 失败时从头排查

**现象**：`lsadump` 报错或无输出，逐个试插件名、符号、镜像完整性，耗掉大量时间。

**原因**：2.3 的"依赖关系（源码核实）"给出了一条明确的传导链——框架层面 `lsadump` 声明了对 `hashdump`（版本 1.1.0）与 `hivelist`（版本 2.0.0）的版本依赖，`hashdump` 失败时 `lsadump` 也会失败，两者共享 hive 定位与 `BOOT_KEY` 解密逻辑。原理链也是串的：从 SECURITY hive 取 `BOOT_KEY`（依赖 hashdump 的解密链路）→ 导出 LSA 密钥 → 遍历 `Policy\Secrets` → AES 解密。**任何一环断了，后面全是空的。**

**影响**：**把依赖问题当成独立问题排查**。

你可能会去怀疑 `lsadump` 插件本身、怀疑符号、怀疑 Windows 版本，而实际问题在 `hashdump` 或 `hivelist` 那一层。

**核查**：**按依赖顺序逐层验证**——`hivelist`（三个 hive 在不在）→ `hashdump`（BOOT_KEY 解密链通不通）→ `lsadump`。

案例第 1 步先查 hive、第 2 步跑 `hashdump` 成功、第 3 步 `lsadump` 才出 7 条，**顺序本身就是排查路径**。

<a id="section-26"></a>

#### 陷阱 7：在 `quick`/`pretty` 输出上按行取 `Key` 名

**现象**：`lsadump` 输出了数据，但用 `awk '{print $1}'` 提取出来的全是 hex 字节而不是 `Key` 名，或者字段错位到不可用。

**原因**：2.3 的引文框做了源码核实并指出两列的渲染形态都与多数教程的说法不同：`Secret` 列类型是 `format_hints.HexBytes`，渲染成 hex + ASCII 双栏 dump（每 16 字节一行，非打印字符显示为 `.`），并且每行前后都带换行符——它会跨行输出。而 `Hex` 列是 `bytes`，渲染成**空格分隔的逐字节 hex**（`4b 4c 53 41`），不是 `0x4b4c5341` 那种连续串。原文直接点名了后果：「`lsadump` 的 `quick`/`pretty` 输出不能按行 `awk '{print $1}'` 取 Key——多行字段会打乱列对齐」。

**影响**：**得到一份看起来有数据、实际错位的结果**。

跨行输出让"行"这个单位失效，按行切分取到的是 hex 片段。

案例第 3 步专门解释了为什么用 CSV——用 `awk '{print $1}'` 会取到 hex 字节而不是 Key 名。

**核查**：**必须用 CSV 渲染器**（2.3 的实践影响第 ② 条：换行会被 csv 模块转义为字段内的 `\
`），**再用 `csv.DictReader` 按列名取**（3.4 给了完整代码）。

**不要按列号取，要按列名取**——`Secret` 的多行内容会让列号法在其它渲染器下失效，而 `DictReader` 天然处理引号转义。

<a id="section-27"></a>

#### 陷阱 8：以为 `cachedump --password` 能解出明文

**现象**：给 `cachedump` 传一个口令参数，期望它直接输出域凭据明文。

**原因**：2.4 的引文给了三处澄清：列名是 `Domain name`（含空格），不是 `DomainName`；`Hash` 列是 `NL$KM` 解密后取出的缓存哈希、不是口令；输出里根本没有时间戳。而关于参数，它写得很明确——`cachedump` 不接受 `--password` 参数。把一个需要候选口令才能比对的缓存哈希当明文，或者想从它推出「这个账号在什么时间登录过」，两种都会得出错误的结论强度。

**影响**：三种。

① 试图传参数，报错后在各种参数里试，浪费时间；

② 把 `Hash` 列的输出当成"域凭据已获取"写进报告。那一列是 MS-CACHE v2 缓存哈希，不是可用凭据；

③ **拿"条目更新时间"当判据写进时间线**——`cachedump` 根本不输出时间，编一个时间出来就是伪造证据。

**核查**：`cachedump` 的输出只能表述为"内存中缓存了某域账号的凭据条目，可取其 MS-CACHE v2 缓存哈希"。要时间就回 `Cache` 键下的值项时间戳，要明文就在**外部**用已获授权的候选口令做验证。

列名带空格这一点在写解析脚本时要留意（`Domain name` vs `DomainName`）。

明文验证属于 3.7 表格里的"候选口令验证"——**外部工具 + 已获授权的口令**，本篇明确不在范围内。

<a id="section-28"></a>

#### 陷阱 9：使用不存在的 `windows.lsass_dump`

**现象**：跑 `vol.py -f mem.raw windows.lsass_dump`，找不到插件，判定"无法导出 LSASS 内存"。

**原因**：2.1 的引文框直接点名——Volatility 3 没有 `windows.lsass_dump` 这个插件；任何声称提供 `lsass_dump` 的教程都在误导。正确做法是 `windows.memmap --pid <PID> --dump`（2.5 与 3.5 都是这个）。这个名字看起来非常合理（LSASS 是众所周知的凭据进程，`dump` 类插件名在其他工具里也确实存在），**"合理"正是它有欺骗性的原因**。

**影响**：丢掉 LSASS 这条线。

LSASS 是 Windows 凭据处理的中心进程，其地址空间里有已解密的凭据、会话票据、缓存的用户数据（2.5），是离线反汇编与注入检测（正常 LSASS 内不应有非微软模块）的目标。

**核查**：先 `pslist | grep -i lsass` 拿 PID，再用 `windows.memmap --pid <PID> --dump`（3.5 的四步）。

导出后做**离线初筛**——`strings -a -n 8 /work/lsass/*.dmp | grep -iE 'mimikatz|sekurlsa|wdigest'`，检查是否有非微软模块或凭据提取工具的痕迹。

**深度分析超出本篇范围**，3.5 的收尾引文说得很清楚：LSASS 转储后的凭据提取具体实现属于需要专门授权与技术条件的操作。

<a id="section-29"></a>

### 4.3 字符串扫描与密钥定位

<a id="section-30"></a>

#### 陷阱 10：`strings` 直接读大镜像导致 OOM

**现象**：`strings -a -n 6 DigiForensics-mem.raw > all.txt` 跑了很久后被 kill，或分析机内存耗尽。

**原因**：3.6 的标题就写着「**大镜像必须分块扫描，否则会耗尽内存**」。`strings` 会缓冲输入并输出全部匹配，16–32 GB 的镜像直接读进管道会耗尽内存。**更隐蔽的是**：命令被 kill 后**已写入的输出文件是不完整的**，而你可能没注意到它提前中断了——得到一份看起来正常但不完整的字符串清单，然后基于它做阴性结论。

**影响**：**得到一份静默不完整的结果**。

这比命令失败更危险——失败你会知道，不完整你不会知道。

**核查**：用 3.6 的 `memstrings.sh` 分块脚本。

它按 `BLOCK_MB`（默认 512）逐块处理，内存占用恒定。

三个容易写错的地方（3.6 的引文）要照做：

① **不要用 `bs=1`**——`dd` 会退化为逐字节系统调用。

② `skip="$START"` 的单位是 MiB 块，第 N 块起点是 `N * BLOCK_MB`，写成 `i` 会导致大量重复读取与漏读。

③ **`wc -c` 兼容 GNU/BSD**，`stat -c %s` 只有 GNU coreutils 有。

**已知的块边界局限要意识到**——对密钥搜索影响不大（密钥通常在单个内存页内），但要在报告里说明。

<a id="section-31"></a>

#### 陷阱 11：把"内存里有 fvevol 字符串"当成"已获得 FVEK"

**现象**：`grep -ic 'fvevol'` 命中，报告写"已获取该机的 BitLocker 卷密钥"。

**原因**：3.6 的最后一条引文把定位与提取的区分讲得很明确——搜索到驱动名只能证明"该机安装了/加载了这个软件"。要证明"卷已解锁"，需要更进一步的证据。而 2.6 给出的现实约束是：提取 FVEK 需要解析 FVE context 的内部结构，**目前没有成熟的现成 Volatility 插件**，通常需要自定义插件或 WinDbg + IDA 手工分析，**技术门槛高，不建议作为首选路径**。

**影响**：**把"能力"当成"已获取"**。

这类结论一旦写进报告，委托方会按"你已拿到密钥"来安排后续动作（解锁卷、取证数据），而实际上什么都没拿到。

BitLocker FVEK 是能绕开启动加密的核心材料，虚报它的存在或获取会造成严重的误导。

**核查**：**分三档表述**。

① "内存中检出 `fvevol.sys` 驱动字符串 → **该机安装或加载了 BitLocker**"（这是 `grep -ic` 能支撑的）；② "卷解锁状态需另行确认"（`manage-bde -status` 的输出、卷可读性验证）；③ "FVEK 本身未获取，需自定义符号解析"。

3.7 的验证表把 BitLocker 密钥的验证方式定为"实际解锁验证，`manage-bde -unlock` 成功，不是格式匹配**"**——这个标准不可降级。

<a id="section-32"></a>

#### 陷阱 12：把 API Key 的存在当成"证明泄露"

**现象**：内存里搜到一枚 AWS Access Key ID，报告写"发现凭据泄露"。

**原因**：2.6 的表格说明了这类材料的性质——**应用层密钥通常以明文或简单编码形式驻留内存**，API Key / Token / 连接串在**任何正常使用该应用的机器上都会在内存里**。它们的存在本身是应用运行的正常结果，**不是异常事件**。案例第 4 步搜到 AWS Key ID 与数据库连接串，结论表的措辞是"内存中驻留多个应用的明文凭据"（强度"强（**但'是否已被滥用'需另证**）"）——**"驻留"与"泄露"是两个不同强度的命题**。

**影响**：**把正常状态定性为安全事件**。

委托方据此启动应急响应、轮换密钥、追查人员，成本巨大且可能完全是误报。

反过来，真正的滥用（凭据已被用于访问外部资源）需要另外的证据——云厂商审计日志、API 调用记录。

**核查**：**区分"驻留"与"被使用"**。

报告里至少要说明三件事：该凭据是什么类型、它属于哪个应用/服务、它当前是否仍然有效。

是否被滥用需要另证（云厂商审计日志、API 调用记录，见 2.6 出方向表里的"凭据泄露溯源"）。

案例第 4 步的内部 CRM JWT 特意注明"内网服务，影响有限"——**影响面评估是凭据类结论的必要组成**，不是可选的补充。

<a id="section-33"></a>

### 4.4 结论表述、验证与收尾

<a id="section-34"></a>

#### 陷阱 13：只报内存侧哈希，不与磁盘 SAM 交叉验证

**现象**：`hashdump` 输出了三个账户的哈希，直接写进报告作为发现。

**原因**：3.7 的第一条原则是**任何提取出的凭据在作为证据引用前必须验证**，而 NTLM 哈希的验证方式是**与磁盘 SAM 提取的哈希比对，两者应一致**。单源的证明力不足——哈希值本身无法自证它来自哪个账户、是否被正确解析（尤其在符号不匹配或结构偏移异常时可能解析出错误的账户-哈希配对）。

**影响**：**单源的凭据结论在质证中站不住**。

而"双源印证"在这个领域恰恰很容易做到——磁盘 SAM 本来就存在，1 的对比表第一行就写着"磁盘能不能拿到 ✅"。

**核查**：**双源比对**（3.7 的完整代码）。

内存侧 `-r csv` + `awk -F',' 'NR>1 {print $2","$5}'`，磁盘侧 `awk -F: '{print $1","$2}'`，`sort -u` 后 `diff`。

案例第 2 步的三个账户逐条一致，结论表标为"强（**双源印证**）"——**这四个字是这类结论强度的来源**。

域凭据同理：`lsadump` 提取 + 认证日志 4624 成功事件，也是双源。

<a id="section-35"></a>

#### 陷阱 14：在报告里粘贴凭据明文

**现象**：把 `lsadump` 的 Secret 值、数据库连接串的完整口令写进报告正文。

**原因**：案例的引文把处置原则说得很直接——凭据本身是"调查发现的敏感信息"，不是"报告要展示的内容"：展示结论、展示验证方法，但把凭据本身留在受控存储里。

报告是会被广泛传阅的（委托方、律师、可能进入司法程序），**明文出现在报告里等于把它分发到了所有读者手上**。

**影响**：**不可逆的泄露**。

报告一旦分发，无法回收。

案例第 3 步的处置是标准的——CSV 存受控目录、`chmod 600`、单独登记，报告里只写"存在 7 条 LSA Secret、域凭据已验证可用"。

**核查**：**结论与方法进报告，材料留受控存储**。

需要展示时用**脱敏形式**（保留前缀与长度，如 `AKIA7X2M…NRT`、`mysql://appuser:***@10.20.30.12:3306/inventory`），完整值留在受控文件里并记录其哈希。

**这不是形式主义**——凭据材料本身就是案件发现的成果之一，它的价值在受控保存中，不在报告里。

<a id="section-36"></a>

#### 陷阱 15：凭据文件保护级别低于内存镜像

**现象**：`lsadump.csv` 存在普通的工作目录，权限是默认的，备份系统会同步它，同事能访问。

**原因**：2.5 的合规提示点明了这一层——LSASS 进程内存包含当前所有登录用户的凭据材料与会话票据，导出到文件系统意味着扩大了敏感数据的暴露面，导出文件应**按与内存镜像同等级别保护**。

`lsadump` 的输出同理——3.4 的警告说「**此命令的输出即为已解密的凭据材料**」。

**影响**：**降级保护**。

原始内存镜像是受控的（可能加密存储、限制访问、有完整保管链），而派生的凭据文件是明文、可能进了备份系统、可能同步到云盘。

攻击面从"需要突破受控存储"变成了"任何有目录读权限的人都能看到"。

**核查**：**按同等级别保护并记录哈希**（3.4 的 `chmod 600` + `sha256sum` + 案例第 3 步的 `.sha256` 文件）。

凭据文件所在目录应与镜像同处受控存储、同样加密、同样限制访问。

**派生文件的保管链要单独记录**——它与母本镜像的哈希不同，是一份独立证据。

<a id="section-37"></a>

#### 陷阱 16：分析完成后不销毁临时凭据文件

**现象**：案件结束后，`/work/lsadump.csv`、`/work/strings-all.txt`、LSASS 转储的 `.dmp` 文件留在分析机上。

**原因**：**销毁不是可选的收尾动作，而是授权条件的一部分**。

3.1 的勾选项里明确有"谁有权接触提取结果？是否有保密协议与**销毁要求**？"，案例的授权条件里也写了"报告交付后凭据材料销毁"。

分析机是长期复用的机器，**残留文件会污染后续案件**——下一位分析师打开 `/work/` 就看到了上一案的凭据。

**影响**：**违约 + 横向泄露**。

委托方审计时会检查销毁记录；分析机残留则意味着**下一个案件的处理者获得了未经授权的敏感材料**。

**核查**：**按授权要求销毁并记录销毁动作**（速查第 9 步的 `shred -u lsadump.csv 2>/dev/null || rm -f`）。

注意 `shred` 只在部分文件系统上有效（`|| rm -f` 是兜底），**销毁记录要写明时间、执行人、销毁对象与方式**——案例的结论表里凭据相关结论标为"强"但没有任何凭据值，这一事实本身就依赖销毁动作被正确执行。

<a id="section-38"></a>

#### 陷阱 17：把"内存中有凭据"直接写成"该凭据可用"

**现象**：`lsadump` 列出了 `PolCreds` 条目，报告写"内存中存在可用的域凭据"。

**原因**：2.4 说明了 LSA Secret 与 cachedump 的内容性质——域凭据以 DPAPI 保护或 NL$KM 加密的形式存在，`lsadump` 输出的是**密钥材料**（DPAPI/Session Key），2.3 的引文还专门说明「`lsadump` 给的是**密钥材料**，不是账号口令；把它变成明文需要额外的、口令驱动的解密步骤」。

所以"内存里存在某个 LSA Secret 条目"与"该凭据当前可用"之间还差一步**可用性验证**。

**影响**：结论强度虚高。

案例的做法是**把可用性验证交给第二个独立证据**——Security.evtx 里 4625 失败后紧接 4624 成功，这两条日志证明"**该凭据在采集时刻处于可用状态且被成功使用过**"，结论表标为"强（**双源印证**）"。

如果没有认证日志，就只能写"内存中存在该凭据条目，可用性未经验证"。

**核查**：**可用性要有独立证据**（3.7 的验证表列了五种验证方式：哈希比对、实际解锁验证、签名验证、API 调用验证、候选口令验证）。

**每种验证都有各自的门槛**——BitLocker 必须是"实际解锁成功，不是格式匹配"，SSH 私钥必须"用公钥对已知内容验签成功"。

**验证未做或未通过的，结论强度必须相应下调**。
<a id="section-39"></a>

## 五、案例示例

> **本章的授权前提**：以下案例均基于**书面取证授权**开展，授权文件编号 A-2026-0314，范围明确包含"账户凭据相关分析"，指定接收人 2 名分析师，报告交付后凭据材料按约定销毁。未取得明确授权时，不得开展本章所述的任何凭据提取工作 —— 无论技术上是否可行。
>
> **脱敏约定**：本章所有凭据值一律以掩码形式呈现（`8846f7ea…`、`AKIA****NRT`）。完整值只存在于受控存储中，不进入 Wiki、报告正文、命令行历史与 shell 记录。

<a id="section-40"></a>

### 5.1 本地账户哈希的内存与磁盘双源印证

**场景**

查获一台 Windows 11 工作站内存镜像 `DigiForensics-mem.raw`（16 GB RAM）。委托方要求确认"该机是否存在凭据泄露迹象，以及是否与某外部账户的异常登录有关"。

委托方持有该设备的书面取证授权，授权范围包含账户凭据分析，接收人指定 2 名分析师，凭据材料在报告交付后销毁 —— 这三项约定决定了本次工作的处置流程。

这条路径的价值在于：凭据类结论最容易被质疑"你是不是自己算错的"，而双源印证是成本最低的自证方式。

**处置过程**

先确认 hive 可用性，决定提取链路是否可行：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -r pretty windows.registry.hivelist \
    | grep -iE 'SAM|SYSTEM|SECURITY'
0x1a2b3c000   \REGISTRY\MACHINE\SAM
0x1a2b50000   \REGISTRY\MACHINE\SYSTEM
0x1a2b60000   \REGISTRY\MACHINE\SECURITY
```

三个关键 hive 都在。这一步是"能不能做"的前置判断，不做就往下走会导致后面拿到空结果却不知道原因。

提取后立即建立受控存储与访问限制：

```bash
$ umask 077
$ python3 vol.py -f DigiForensics-mem.raw -r csv windows.registry.hashdump \
    > /work/restricted/mem_hashes.csv
$ chmod 600 /work/restricted/mem_hashes.csv
$ ls -l /work/restricted/mem_hashes.csv
-rw------- 1 foren foren 842 ...    # 仅属主可读写
```

内存侧结果（掩码呈现）：

```bash
$ python3 - <<'PY' /work/restricted/mem_hashes.csv
import csv, sys
for r in csv.DictReader(open(sys.argv[1], encoding='utf-8')):
    print('%-16s %-5s lm=%s…  nt=%s…' % (
        r['User'], r['rid'], r['lmhash'][:8], r['nthash'][:8]))
PY
Administrator    500   lm=aad3b435…  nt=31d6cfe0…
Guest            501   lm=aad3b435…  nt=31d6cfe0…
zhangsan         1001  lm=aad3b435…  nt=8846f7ea…
```

`lmhash` 三条全为 `aad3b435b51404eeaad3b435b51404ee`，这是空口令的标准 LM 哈希值。

`nt=31d6cfe0d16ae931b73c59d7e0c089c0` 同样是空口令的标准 NTLM 哈希。

与磁盘 SAM 逐条交叉：

```bash
$ diff <(sort /work/restricted/mem_hashes.csv | cut -d, -f1-3) \
       <(sort /work/sam_hashes.txt | cut -d: -f1-3) && echo "两源一致"
两源一致
```

注意比对方式：只比账户名、RID 与哈希值三列，不导出账户的其他属性。 全列导出会带出密码最后修改时间、账户锁定时间等与本案无关的敏感信息，违反最小化原则。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 内存提取的本地账户哈希与磁盘 SAM 完全一致 | 逐条 `diff` 一致 | 强（双源印证） |
| `Administrator` 与 `Guest` 启用且为空口令 | `nthash = 31d6cfe0…`（空口令标准值）+ 磁盘 SAM 印证 | 强 |
| `zhangsan` 账户已设置口令 | `nthash = 8846f7ea…` 与前两者不同 | 强 |
| 三个账户的 `lmhash` 均为空口令值 | 三条 LM 哈希完全相同且为已知空口令值 | 强（配置缺陷） |

**能证明的**：采集时刻该机的本地账户哈希与磁盘 SAM 一致；两个内置账户处于空口令状态。

**不能证明的**：
- **不能证明凭据已被泄露或被滥用。** 哈希存在于内存是系统的正常状态，不是泄露行为
- **不能证明空口令账户被他人使用过**。要证明使用需认证日志
- **不能证明哈希的明文是什么** —— 本次分析不需要、也不应当去做口令恢复

**误判对照**

这个案例里最常见的误判是：**把"内存里有哈希"写成"发生了凭据泄露"。**

判据在于区分**状态**与**事件**：

| 表述 | 性质 | 依据 |
|---|---|---|
| 内存中存在账户哈希 | 状态描述 | `hashdump` 输出 |
| 存在凭据泄露 | 事件断言 | 需要泄露载体（外发、异常访问、导出）证据 |

SAM 缓存在内存中是 Windows 的正常设计 —— `lsass.exe` 每次认证后都会加载账户信息。

把正常状态读成异常事件，是凭据类分析最常见也最伤可信度的错误。

第二个误判：把空口令账户直接定性为"安全事件"。

判据要看**该账户是否可被网络登录**。

本次 `Administrator` 与 `Guest` 的 `lmhash`/`nthash` 为空值确实构成配置缺陷，但配置缺陷的严重度取决于：账户是否被禁用、是否有登录限制、该机是否有网络暴露。

**这三项本次均未核查**（未读账户的 `Flags` 属性、未确认 RDP/网络策略），所以结论强度只到"配置缺陷"，不到"可被利用"。

第三个误判更微妙：**双源一致被当作结论正确的充分证明**。

两源一致确实排除了单侧工具错误，但两源的**来源是否独立**才决定印证的价值。

本案内存侧由 `hashdump` 从内存中的 SAM hive 副本读出，磁盘侧由 SAM 文件读出 —— 两者在采集时刻是同一份数据的两个副本，**属于"同源双读"而非"独立双源"**。

它的作用是排除提取环节的错误，不是排除采集环节的错误。

真正独立的第三源是认证日志（`4624`/`4625` 事件），那才是本案在 5.2 用来印证域凭据的证据。

按错误判据走的代价：报告写"发现凭据泄露"，委托方据此追责；而实际上只能证明"凭据在内存中可用"。

**这两种表述在法律与合规后果上完全不同。**

<a id="section-41"></a>

### 5.2 LSA Secret 的域认证关联与应用层凭据的发现

**场景**

承接 5.1。委托方追问了具体问题：那个外部账户的异常登录，用的是哪个凭据？以及该机上是否还驻留着其他可被复用的凭据材料。

这条路径要走的是**"凭据发现"与"凭据验证"两个不同层次** —— 前者回答"有什么"，后者回答"能用吗"，需要完全不同的证据类型。

**处置过程**

第一步，提取 LSA Secret。

**输出格式的选择在这里是技术问题，不是风格问题**：

```bash
$ python3 vol.py -f DigiForensics-mem.raw -r csv windows.registry.lsadump \
    > /work/restricted/lsadump.csv 2>/work/restricted/lsadump.err
$ chmod 600 /work/restricted/lsadump.csv
$ sha256sum /work/restricted/lsadump.csv | tee /work/restricted/lsadump.csv.sha256
```

用 `csv` 而非 `pretty` 的原因很具体：`Secret` 列在 `quick`/`pretty` 下是跨行的 hex+ASCII dump，用 `awk '{print $1}'` 取到的是 hex 字节而不是 Key 名。

格式选错会导致整张表的 Key 名全部错位。

第二步，统计并归类（只统计，不展示内容）：

```bash
$ grep -c 'PolSecret' /work/restricted/lsadump.csv
7
$ python3 - <<'PY' /work/restricted/lsadump.csv
import csv, sys
for r in csv.DictReader(open(sys.argv[1], encoding='utf-8')):
    if r['Name'].startswith('PolSecret'):
        print('%-12s 创建时间=%s  Hint=%s  长度=%d' % (
            r['Name'], r.get('CreateTime', 'N/A'),
            r.get('Hint', ''), len(r.get('Secret', '')) // 2))
PY
PolSecret   创建时间=N/A   Hint=  长度=1232
PolSecret   创建时间=N/A   Hint=  长度=1232
...
```

7 条 `PolSecret`，长度 1232 字节（1024 + 208），这是 Windows 域机器密钥（Machine Credentials）的标准长度。

说明该机与域存在实际认证关系。

第三步，验证这个凭据**是否被使用过** —— 这是从"存在"到"可用"的关键跨越：

```bash
$ grep -iE '4624|4625' /work/Security.evtx.csv \
    | grep -i '<域用户名已脱敏>' | head -3
2026-03-14 09:12:33  4625  <域用户名已脱敏>  10.20.30.45  失败
2026-03-14 09:15:02  4625  <域用户名已脱敏>  10.20.30.45  失败
2026-03-14 09:18:44  4624  <域用户名已脱敏>  10.20.30.45  成功
```

同一域账号在 6 分 11 秒内先两次 4625 失败、后一次 4624 成功。 这是独立于内存的第三方证据。

第四步，检查应用层凭据材料。同样只报类型与位置，不报值：

```bash
$ /work/memstrings.sh DigiForensics-mem.raw 512 /work/restricted/strings-all.txt

$ grep -oE 'AKIA[0-9A-Z]{16}' /work/restricted/strings-all.txt \
    | sed -E 's/(AKIA.{4}).*(.{3})/\1****\2/' | sort -u
AKIA****NRT              # AWS Access Key ID

$ grep -oE 'mysql://[^:]+:[^@]+@' /work/restricted/strings-all.txt \
    | sed -E 's#://([^:]+):[^@]+@#://\1:****@#' | sort -u
mysql://appuser:****@10.20.30.12:3306/inventory
```

**`sed` 掩码管道是这类输出的标准做法** —— 匹配、掩码、落盘三步在同一个管道内完成，**原始值不经过中间文件、不进入 shell 历史**。

第五步，评估影响面与边界：

```bash
# AWS Key：仅 ID 不足以使用，需配套的 Secret Access Key 才构成完整凭据
$ grep -cE 'aws_secret_access_key|AKIA' /work/restricted/strings-all.txt
1
# → 只找到 ID，未找到配套 Secret → 凭据不完整
```

这个判断很重要：只发现 Access Key ID 而无 Secret Access Key 时，不构成可用的完整凭据。

报告里若写成"发现可用的 AWS 凭据"，属于结论强度高估。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 内存中存在 7 条 LSA `PolSecret`，长度 1232 字节 | `lsadump` 统计 + 标准长度吻合域机器凭据特征 | 强 |
| 该机与域存在实际认证关系 | `PolSecret` 的存在与长度形态 | 中（存在性为强，关系性质为推断） |
| 某域凭据在采集前后被成功使用 | `4625` × 2 后紧接 `4624`，时间跨度 6 分 11 秒 | 强（独立来源） |
| 内存中驻留一枚 AWS Access Key **ID** | 字符串提取，掩码呈现 | 强（存在性） |
| 该 AWS 凭据**不完整** | 未找到配套 Secret Access Key | 中（阴性范围见下） |
| 内存中驻留 inventory 数据库的明文连接串 | `mysql://appuser:****@10.20.30.12:3306` | 强 |
| 内网 CRM 的 JWT 存在于内存 | HTTP 头提取 | 中（内网服务，影响有限） |

**能证明的**：域凭据存在于内存**且**在采集前 20 分钟内被成功使用过；内存中驻留若干应用层的部分凭据材料。

**不能证明的**：
- **不能证明这些凭据被用于攻击行为**。`4624` 成功只证明认证通过，不证明行为异常 —— 需要结合登录类型、源地址合理性、后续操作
- **不能证明 AWS 凭据可用**。只找到 ID
- **不能证明数据库连接串被实际使用** —— 它可能在应用初始化时读取后未发起连接

**未覆盖范围与阴性边界**：
- AWS Secret Access Key 的检索仅覆盖 `strings-all.txt`（512 字符以上序列）。**未覆盖**：以非文本形式存储、被分片分散、或以 DPAPI 加密形态存在的密钥
- 未对 `4624` 事件做登录类型（Type 2/3/7/8/10/11）细分，**无法区分交互式登录与网络登录**
- 未核查 `10.20.30.45` 的归属与合理性

**误判对照**

这个案例的核心误判有两个方向，都很常见。

方向一：把"凭据存在于内存"直接写成"凭据泄露"。

判据是事件证据的齐备度。

凭据在内存中属于系统常态；构成"泄露"需要至少一个**转移载体**证据：凭据被写入非预期位置（注册表 Run 项、日志、临时文件）、被写入外发内容、或被非预期进程读取。

**本次三类载体均未发现** —— 5.1 证明的是"存在"，5.2 证明的是"被使用过"，两者都不等于"泄露"。

方向二：把凭据"不完整"这个判断省掉，直接报"发现 AWS 访问密钥"。

这是结论强度高估的典型。判据是**凭据的完整性**：

| 发现物 | 是否构成可用凭据 | 判据 |
|---|---|---|
| 仅 Access Key ID（`AKIA...`） | 否 | 认证需要 ID + Secret + 签名算法 |
| ID + Secret 齐全 | 是 | 构成完整凭据对 |
| 完整的 API 请求签名（含 `X-Amz-Signature`） | 是，且已使用 | 更强，含时间戳与调用证据 |

本次只发现 ID。报告里正确的写法是"发现一枚 AWS Access Key ID，配套 Secret Access Key 在本次检索范围内未发现，故不构成完整可用凭据" —— 这句话同时报告了发现和边界，比只报前者或只报后者都准确。

按错误判据走的代价：委托方若据此认为"云资源可能已泄露"，可能触发不必要的云侧凭据轮换与业务中断；而实际风险等级并不支持这个动作。

反之，若省掉边界说明，日后真的发生该 Key 的滥用，报告里那句无保留的"发现 AWS 访问密钥"就会变成责任证据。

第三个实操层面的误判：用 `pretty` 输出处理 LSA Secret。

前面已提到 `Secret` 列在 `pretty` 下是跨行 hex+ASCII dump。**后果是 Key 名提取全错位**，进而把不相关的 Secret 关联到错误的账户。

这类错误不报错、不中断，只在结论里体现 —— 属于最难自查的一类。

判据是处理 Secret 类数据一律用 `csv`，取字段一律用 `csv.DictReader`，不用 `awk '{print $N}'`。

**脱敏纪律**：本章所有掩码处理在管道内完成。

若先把原始值写入中间文件再掩码，中间文件就是新的泄露点，且它不会被登记进证据目录。

凭据类工作的基本原则是原始值在磁盘上只出现一次，且那个位置有访问控制、有哈希、有销毁记录。

<a id="section-42"></a>

## 六、扩展阅读方向

凭据议题的难点从来不是"怎么拿到"，而是**边界画在哪里、拿到之后能说到什么程度**。

下面四组材料分别补的是**体系结构、落盘路径、验证与替代来源、合规边界**。

<a id="section-43"></a>

### 6.1 体系结构：凭据到底存在哪一层

这一组解决"为什么不同凭据要走不同工具"。SAM / SECURITY / DPAPI 是三个不同的层次，插件的工作面也不同；不搞清楚这层结构，工具选择就是试错。

- [注册表取证](../../computer/computer-registry-log/computer-registry-log-registry-forensics.md)——hive 的离线解析与 BOOT_KEY 解密原理，内存侧转储的落盘对照。
- [取证工件地图（Windows）](../../computer/computer-registry-log/computer-registry-log-windows-artifact-map.md)——凭据相关工件的全景，用于判断哪些已在磁盘侧、哪些只在内存。
- [Windows 内存 Profile 机制](../memory-acquire/memory-acquire-windows-profile.md)——结构偏移不匹配时字段值会以"看似合理"的方式出错，是本主题最隐蔽的错误来源。
- [Volatility 3 框架与插件选择](../memory-acquire/memory-acquire-volatility3.md)——`hashdump`/`lsadump`/`dumpfiles` 的适用边界与导出机制。
- [内存取证总览](../memory-acquire/memory-acquire-memory-forensics-overview.md)——易失性顺序决定了凭据只有一次提取窗口，这是全部时间压力的来源。

<a id="section-44"></a>

### 6.2 落盘路径：同一批凭据的另一种固定方式

这一组解决"内存灭失怎么办"。内存里的凭据是运行态的、一次性的；磁盘侧的固定版本虽然不一定是明文，但可复现、可归档、可持续引用。

- [远程工具凭据解密](../../crypto/crypto-app/crypto-app-remote-tool-credential-preservation.md)——远控软件凭据在磁盘侧的定位与固定，与内存侧互为补充。
- [浏览器密码库与 Token 解密](../../crypto/crypto-app/crypto-app-browser-passwords-and-tokens.md)——浏览器凭据的 DPAPI 保护链与 App-Bound Encryption 的能力边界。
- [BitLocker 全卷加密取证](../../crypto/crypto-volume/crypto-volume-bitlocker.md)——FVE metadata 与恢复密码的四条路径，内存里拿到的是运行态 FVEK。
- [EFS 文件系统加密取证](../../crypto/crypto-volume/crypto-volume-efs.md)——`$EFS` 数据流与用户私钥，内存中的私钥与落盘证书的对照。
- [数据库与配置文件加密](../../crypto/crypto-app/crypto-app-database-configuration-decryption.md)——配置文件中加密字段的固定与定位，是应用层密钥的落盘侧。

<a id="section-45"></a>

### 6.3 验证、脱敏与替代来源

这三件事在凭据主题上是一体的：提取物要能复核、要能安全留存，而内存里没有的还得从别处找。

- [哈希与完整性校验](../../fundamentals/fundamentals-concepts/fundamentals-concepts-hashes-and-integrity-verification.md)——每个转储独立哈希，导出动作本身也要留痕。
- [证据保管链与委托证明](../../fundamentals/fundamentals-chain/fundamentals-chain-chain-of-custody-and-authorization.md)——敏感提取物的单独保管要求与访问记录。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md)——最小化原则在流程层面的表述，决定提取范围。
- [Keychain 与 Safari 痕迹](../../computer/computer-security/computer-security-keychain-safari.md)——macOS 侧凭据的落盘体系与内存差异。
- [SSH 痕迹与密钥取证](../../computer/computer-persistence/computer-persistence-ssh.md)——Linux 侧的私钥、authorized_keys 与内存中的会话。

<a id="section-46"></a>

### 6.4 合规边界：授权与最小化

这一组专门处理红线。凭据提取是本库中合规要求最严格的操作之一，授权范围、提取必要性、脱敏与留存期限都必须在动手前确认。

- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md)——提取他人口令、访问 LSA Secret 的授权要求与最小化原则。
- [通用密码恢复](../../crypto/crypto-app/crypto-app-passware-and-password-recovery.md)——哈希与口令恢复的授权、最小化与脱敏要求，是本篇的延伸口径。
- [取证概念与分类](../../fundamentals/fundamentals-concepts/fundamentals-concepts-digital-forensics-concepts.md)——提取物在证据体系中的地位，以及它与账户归属之间的证据距离。
- [内存证据的可采性与报告](memory-artifact-memory-evidence-and-reporting.md)——如何描述提取动作、披露敏感材料的存在而不暴露内容。
- [赛事与靶场](../../fundamentals/fundamentals-chain/fundamentals-chain-forensics-competitions-and-practice.md)——在授权靶场环境中练习本主题的完整流程，避免在真实案件上试错。
<a id="section-47"></a>

## 七、命令速查

```bash
# ===== 1. hive 可用性（合规确认后第一步；确认授权范围覆盖"凭据提取"）=====
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.registry.hivelist \
  | grep -iE 'SAM|SYSTEM|SECURITY'

# ===== 2. 本地账户哈希（vol3 是四列表格，不是 vol2 的冒号格式）=====
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.registry.hashdump | tee hashdump.txt
python3 vol.py -f DigiForensics-mem.raw -r csv windows.registry.hashdump > hashdump.csv
#   列：TreeDepth,User,rid,lmhash,nthash；hashdump 无 --sam 参数
#   空口令 nthash = 31d6cfe0d16ae931b73c59d7e0c089c0

# ===== 3. 域凭据与 LSA Secret（输出即已解密凭据，务必受控处理）=====
python3 vol.py -f DigiForensics-mem.raw -r csv windows.registry.lsadump > lsadump.csv
chmod 600 lsadump.csv ; sha256sum lsadump.csv > lsadump.csv.sha256
#   列：Key / Secret（HexBytes → hex+ASCII 跨行 dump）/ Hex（bytes → 空格分隔 hex）
#   必须用 -r csv：quick/pretty 下 Secret 跨行，列会错位
#   依赖 hashdump 链路；hashdump 失败则 lsadump 也失败

# cachedump 遍历 SECURITY 的 Cache 键（无 --password 参数，无时间戳输出）
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.registry.cachedump
#   列：Username / Domain / Domain name / Hash
#   Hash = NL$KM 解密后取出的 MS-CACHE v2 缓存哈希（非口令）；无时间戳列

# ===== 4. LSASS 转储（仅离线分析；无 lsass_dump 插件）=====
python3 vol.py -f DigiForensics-mem.raw -r pretty windows.pslist | grep -i lsass
mkdir -p /work/lsass
python3 vol.py -f DigiForensics-mem.raw -o /work/lsass windows.memmap --pid <PID> --dump
strings -a -n 8 /work/lsass/*.dmp | grep -iE 'mimikatz|sekurlsa|wdigest' | head

# ===== 5. 分块提取字符串（大镜像必须分块，避免 OOM；脚本见 3.6）=====
/work/memstrings.sh DigiForensics-mem.raw 512 /work/strings-all.txt
# 三个坑：① 不用 bs=1；② skip 单位是 MiB 块不是块索引（要 N*BLOCK_MB）；③ wc -c 兼容 BSD

# ===== 6. 应用层密钥搜索 =====
grep -iE 'api[_-]?key|client[_-]?secret|access[_-]?token' /work/strings-all.txt | sort -u | head -40
grep -oE 'Bearer [A-Za-z0-9._~+/-]{20,}' /work/strings-all.txt | sort -u
grep -oE 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' /work/strings-all.txt | sort -u
grep -iE 'mysql://[^:]+:[^@]+@|postgres(ql)?://[^:]+:[^@]+@' /work/strings-all.txt | sort -u
grep -oE 'AKIA[0-9A-Z]{16}' /work/strings-all.txt | sort -u
grep -c 'BEGIN RSA PRIVATE KEY' /work/strings-all.txt
grep -c 'BEGIN OPENSSH PRIVATE KEY' /work/strings-all.txt

# ===== 7. 卷加密存在性定位（定位 ≠ 提取）=====
grep -ic 'fvevol' /work/strings-all.txt
grep -iE 'VeraCrypt|TrueCrypt' /work/strings-all.txt | head
# 关键结论必须实际验证（如 manage-bde -unlock），不能只凭字符串命中

# ===== 8. 交叉验证（TreeDepth 第 1 列，User 第 2 列，nthash 第 5 列）=====
python3 vol.py -f DigiForensics-mem.raw -r csv windows.registry.hashdump \
  | awk -F',' 'NR>1 {gsub(/"/,""); print $2","$5}' | sort -u > /tmp/mem_hashes.csv
awk -F: '{print $1","$2}' /work/sam_hashes.txt | sort -u > /tmp/disk_hashes.csv
diff /tmp/mem_hashes.csv /tmp/disk_hashes.csv && echo "两源一致，双源印证"

# ===== 9. 收尾：按授权要求销毁凭据材料文件，并记录销毁动作 =====
shred -u lsadump.csv 2>/dev/null || rm -f lsadump.csv
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 内存与专项分析 — 内存中的凭据与密钥」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《内存中的凭据与密钥》（CC BY-SA 4.0）`

文中 `DigiForensics-mem.raw`、`DigiForensics-masterkey.bin`、`DigiForensics.dd` 均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。

---
