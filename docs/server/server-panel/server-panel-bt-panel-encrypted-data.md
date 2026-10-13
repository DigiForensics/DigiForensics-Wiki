---
title: "宝塔新版加密数据解密"
slug: "server-panel-bt-panel-encrypted-data"
canonical: "https://www.digiforensics.cn/wiki/server-panel-bt-panel-encrypted-data"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:52+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "server"
space: "服务器与云取证"
node_path: ["面板与控制台"]
---

# 宝塔新版加密数据解密

<a id="section-1"></a>

## 一、概述

从宝塔 7.7 之后的新版架构开始，**面板不再明文保存数据库口令**。

原本 `sqlite3` 打开 `default.db` 就能读到的明文密码，现在变成了形如 `BT-0x:kR7v……` 的密文字符串。

这给取证带来一个直接障碍：**拿到面板数据库，不等于拿到数据库口令。**

在具备相应密钥和配置时，可尝试离线解密：

```
拿到面板 database.db
   ↓ 解密 databases 表
拿到业务数据库的账号口令
   ↓ 横向验证
拖库 / 数据泄露的证据链闭合
```

**为什么值得做**：服务器案件的核心诉求往往不是"服务器被黑了"，而是"**数据有没有被拿走**"。而数据被拿走的证明，最终要落到数据库访问记录上。没有明文口令，你连验证都做不了——只能写"疑似拖库"，写不了"确认拖库"。

**先划清本篇的性质**：这里给出的是**原理说明 + 一个可运行的 Python 脚本**，用于在已获授权的取证场景中还原**面板自己保存**的敏感字段。

这与"破解加密"是两回事——没有暴力破解，密钥材料就躺在同一台机器的另一个文件里（`div.pl`）。绕开的是一层封装，不是去算一个未知密钥。

密钥若缺失或派生不出明文，就回到口令本身，那属于另一个课题（见 [通用密码恢复](../../crypto/crypto-app/crypto-app-passware-and-password-recovery.md)）。

**涉及的证据形态**：

| 形态 | 具体位置 | 判读要点 |
|---|---|---|
| 加密字段 | 各库中以 **`BT-0x:` 开头**的值，后跟标准 Base64 密文 | 前缀极其明确，检索成本极低 |
| 密钥材料 | `/www/server/panel/data/div.pl` | **本身也是加密的**，无 `BT-0x:` 前缀，需另一对内置参数先解 |
| 内置参数 | 面板程序内置的固定字符串 | **取偶数位字符得到 16 字节**；这是版本相关的部分 |
| 架构判据 | `data/db/` 目录存在 + `div.pl` 存在 | 二者同时存在 = 新版架构 |
| 数据库 | `data/db/database.db`、`data/db/panel.db`、`data/db/default.db` | **只读打开**（`file:...?mode=ro`），避免运行时写入或锁 |
| 密文范围 | 各表的敏感列 | **不要假设字段名**，先 `PRAGMA table_info()` 查 |

**为什么 `sqlite3` 打开会看到"乱码"**：这是本篇最常见的第一个困惑。

值不是乱码——它是被 AES-CBC 加密后 Base64 编码的密文，只是长得不像明文。看到 `BT-0x:` 前缀就是确认信号，没有前缀的纯随机串则要另行判断（可能是其他编码，也可能根本没加密）。

**验证是本篇最关键、也最反直觉的一环**：

> 实测发现，用**错误的 IV** 解密时，**PKCS#7 填充校验仍可能通过**（末字节恰好落在合法区间 1–16）。这意味着任何"输出看起来像密码""填充是否合法"的启发式判断都不可靠。换句话说，**加密机制的每一步都会产生看起来合理的输出**，这正是本篇所有陷阱的共同根源。

**因此解出的字符串必须经过独立验证才能作为结论。**

优先用离线方法验证（与站点代码里的配置比对）；确需动态验证时，只能在已授权检材本机范围内进行，不得对任何第三方系统使用检材中的凭据。

面板管理了哪些业务数据库、各自的账号与口令、面板口令与站点代码中的配置是否一致（**不一致本身就是"有人改过数据库配置"的反证**）、以及由此展开的拖库证据链。

数据库里存了什么业务数据（本篇只解出口令，不接触数据内容）；拖库行为是否发生（要靠 binlog / 慢查询日志 / 通用日志，那是 MySQL 侧的课题）；脚本在你的样本上解不出合理明文时，说明该小版本实现有差异——不要强行套用，更不要伪造一个"看起来像密码"的输出。拿不到比假结果好。

**涉及的口令怎么处置**：解密出的业务口令按**密级材料**管理，报告中一律脱敏，**不做在线使用、不二次扩散**。委托方需要轮换的，在报告中作为建议列出。

**读者前提**：需要 [宝塔面板取证](server-panel-bt-panel-forensics.md) 的架构判定与库表结构、[SQLite 基础与结构](../../mobile/mobile-database/mobile-database-sqlite.md) 的只读查询，以及 AES-CBC 与 PKCS#7 填充的基本概念（IV 依赖性是理解本机制的关键）。务必先按 [3.1 第 1 步](#section-10) 确认架构与密文位置再动手。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 识别：`BT-0x:` 前缀

新版加密字段的识别特征极其明确——值以 `BT-0x:` 开头，后跟一段标准 Base64：

```
BT-0x:tXeUcwJk+Lu5t+BTgGgLAIJbFXYxU84sZA8ak1yjvec=
└──┬─┘ └────────────┬───────────────┘
   │                └── Base64 密文（AES-CBC 密文）
   └── 固定前缀，标识"这是宝塔加密字段"
```

检索方法：

```bash
sqlite3 "file:/evidence/bt-data/db/database.db?mode=ro" \
  "SELECT name, username, password FROM databases;"
# shop_db  shop  BT-0x:tXeUcwJk+Lu5t+BTgGgLAIJbFXYxU84sZA8ak1yjvec=   ← 加密
```

| 观察 | 含义 |
|---|---|
| 值以 `BT-0x:` 开头 | 新版加密字段，可走本篇流程 |
| 值是纯随机串但无前缀 | 可能是其他编码（Base64 / 自定义），需另行判断 |
| 值像明文 | 旧版未加密，或该字段不在加密范围 |

<a id="section-4"></a>

### 2.2 加密流程的原理

理解原理比拿到脚本更重要，因为**版本差异会改变细节，而原理告诉你哪些部分可能变**。

```
【加密侧（面板运行时）】
  明文口令（如 MySQL root 口令）
      │
      ├─ ① 固定 KEY：程序内置的 32 字符串，取【偶数位】字符 → 16 字节
      │
      └─ ② IV：优先读 /www/server/panel/data/div.pl 的内容
                 该文件本身也是加密的 → 需先解密
                 解密 div.pl 用另一对固定 KEY/IV（程序内置）
                     ↓
                 得到的明文 → 取其 MD5 的前 16 字节 作为实际 IV
      │
      ↓
  ③ AES-CBC 加密（PKCS#7 填充）→ Base64 编码 → 加 "BT-0x:" 前缀
```

**为什么"取偶数位"这个设计很反直觉但很重要**：分析公开结果显示，程序内置一个 32 字符的密钥串，只取索引为偶数的那些字符（0, 2, 4, …, 30）拼成 16 字节的 AES-128 密钥。

不同版本里**这个内置串本身可能不同**——这正是"必须以实际样本验证"的根本原因。

**IV 的两级结构是这套机制最关键的设计**，也是最容易出错的地方：

```
div.pl 的密文
   ↓ 用【内置的第二对固定 KEY/IV】解密（第一层，参数硬编码）
得到一段明文（16 字符的随机串）
   ↓ 取其 MD5 的前 16 字节
这才是解密 BT-0x: 密文时真正用的 IV
```

也就是说，**密钥是硬编码的，IV 却是每台机器不同的**（存在 `div.pl` 里）。

这解释了为什么同一套解密脚本在不同服务器上会得到不同结果——因为 IV 不同。

<a id="section-5"></a>

### 2.3 架构判据：`div.pl` 的存在

`div.pl` 是新版架构引入的文件，作用是给面板提供一个与机器绑定的 IV 材料。它的存在本身就是**最可靠的版本判据**：

| 文件状态 | 架构判断 |
|---|---|
| 有 `data/db/` 且有 `div.pl` | 新版（7.7+），敏感字段加密 |
| 只有 `data/default.db`，无 `div.pl` | 旧版，敏感字段多为明文/可逆编码 |

`div.pl` 的内容就是那段需要二次解密的 Base64 密文（**注意它没有 `BT-0x:` 前缀**）。

<a id="section-6"></a>

### 2.4 旧版 vs 新版的路径与字段对照

| 项目 | 旧版 | 新版 |
|---|---|---|
| 主库 | `data/default.db` | `data/db/default.db`（部分表） |
| 数据库明细 | 在 `default.db` 的 `databases` 表 | **`data/db/database.db`** |
| 面板配置（MySQL root 口令等） | 在 `default.db` 的 `config` 表 | **`data/db/panel.db`** |
| IV 材料 | 无 | `data/div.pl` |
| 口令字段形态 | 多数为明文或简单编码 | `BT-0x:` + AES-CBC + Base64 |

**MySQL root 口令在哪张表**：旧版在 `default.db` 的 `config` 表，新版在 `panel.db` 的 `config` 表，字段名常见为 `mysql_root`（具体字段名以 `PRAGMA table_info` 的实际输出为准）。

<a id="section-7"></a>

### 2.5 实际看到的现象：为什么 `sqlite3` 打开是"乱码"

```sql
sqlite3> SELECT mysql_root FROM config;
-- BT-0x:t2UpDw7vR5VjXlan0WCaDx150cBgfLlVPxRMe7Vbb1o=
```

这不是数据库损坏，也不是编码错误。

SQLite 本身不加密，它是忠实存储字符串的存储引擎；密文是宝塔的**应用层**在写入前主动加密的结果。所以数据库结构完全正常、其他表都能正常读，只有敏感字段的值是密文。

取证的关键是还原应用层的加密，而不是"修复"数据库。

<a id="section-8"></a>

### 2.6 取证价值

| 价值 | 说明 |
|---|---|
| **闭合拖库证据链** | 拿到口令 → 查 binlog / 慢查询 / 通用日志 → 证明数据被批量读取 |
| **横向扩线** | 数据库口令常与其他系统复用；MySQL root 口令可用于同机其他库 |
| **判断泄露范围** | 知道有哪些数据库、账号，才能界定"可能被拿走了什么" |
| **反证** | 若解密出的口令与站点代码中配置的**不一致**，说明有人改过数据库口令 |

> **反证这一条常被忽略但很有价值**：业务代码里的连接口令与面板里存的不一致，这个差异本身就是"有人动过数据库配置"的证据（详见第五节案例）。

若 `BT-0x:` 密文缺了密钥材料、派生不出明文，就得回到口令本身。字典与掩码攻击的合规边界、工具选择与脱敏要求见[《Passware Kit 与通用密码恢复》](../../crypto/crypto-app/crypto-app-passware-and-password-recovery.md)。

---

<a id="section-9"></a>

## 三、操作步骤

<a id="section-10"></a>

### 3.1 第 1 步：确认架构与定位密文

```bash
# 判定架构：有 data/db/ + div.pl = 新版
ls -l /mnt/df/www/server/panel/data/db/ 2>/dev/null
ls -l /mnt/df/www/server/panel/data/div.pl 2>/dev/null

# 读出 div.pl 的内容（这是二级解密的输入）
cat /mnt/df/www/server/panel/data/div.pl
# 3UOiALw6JWPa2F02dtN3+ynzUs9oXWcT5llyhivOBaI=
#  ↑ 无 BT-0x: 前缀，Base64 密文，需先用内置参数解密

# 在各库中检索 BT-0x: 字段，确认哪些字段被加密
sqlite3 "file:/evidence/bt-data/db/database.db?mode=ro" \
  "SELECT name, username, password FROM databases;"
sqlite3 "file:/evidence/bt-data/db/panel.db?mode=ro" "PRAGMA table_info(config);"
sqlite3 "file:/evidence/bt-data/db/panel.db?mode=ro" "SELECT * FROM config;"
```

> **务必只读打开**（`file:...?mode=ro`），避免在面板运行时产生写入或锁。

<a id="section-11"></a>

### 3.2 第 2 步：确认字段范围（不要假设字段名）

```bash
# 列出每张表的所有列名
sqlite3 "file:/evidence/bt-data/db/database.db?mode=ro" ".schema"
sqlite3 "file:/evidence/bt-data/db/panel.db?mode=ro" ".schema"

# 快速找出所有以 BT-0x: 开头的值
sqlite3 "file:/evidence/bt-data/db/database.db?mode=ro" \
  "SELECT name, username, password FROM databases WHERE password LIKE 'BT-0x:%';"
```

<a id="section-12"></a>

### 3.3 第 3 步：运行解密脚本

环境准备（Ubuntu/Debian 分析机）：

```bash
sudo apt install python3 python3-pip sqlite3
pip3 install pycryptodome        # 提供 Crypto.Cipher.AES
```

把下面脚本保存为 `bt_decrypt.py`。脚本中的 KEY 材料来自公开分析，必须以实际样本验证：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
宝塔新版敏感字段（BT-0x:）解密工具 —— 取证用途
原理：见配套文章「宝塔新版加密数据解密」§二

⚠️ 重要：内置 KEY/IV 材料来自对已公开分析结果的原理复现。
   不同小版本实现可能不同，必须以实际样本验证。
   若解不出合理明文，说明该版本有差异，请回到分析阶段重新确认，
   不要强行套用或采信任何"看起来像"的输出。
"""
import base64
import hashlib
from Crypto.Cipher import AES

PREFIX = "BT-0x:"

# ---- 内置材料：这些值随版本可能不同，需以实际样本验证 ----
# 业务字段解密 KEY 的来源：程序内置一个 32 字符串，取其【偶数位】拼成 16 字节
DB_KEYSTORE = "3gP7+k_7lSNg3$+Fj!PKW+6$KYgHtw#R"   # 偶数位 → "3P+_lN3+jPW6Kgt#"
# div.pl 二次解密用的固定 KEY / IV（16 字节，各版本可能不同）
DIV_KEY = b"Z2B87NEAS2BkxTrh"
DIV_IV  = b"WwadH66EGWpeeTT6"

def sgin_key(keystore: str) -> bytes:
    """按公开分析：取 keystr 的偶数位字符作为 AES-128 密钥（32 字符 → 16 字节）。"""
    if len(keystore) < 32:
        raise ValueError("keystore 长度不足 32，无法取偶数位")
    return "".join(keystore[i] for i in range(0, 32, 2)).encode()

def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    return data[:-data[-1]]          # 末字节即填充长度

def aes_cbc_decrypt_b64(cipher_b64: str, key: bytes, iv: bytes) -> str:
    raw = base64.b64decode(cipher_b64.strip())
    return pkcs7_unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(raw)).decode("utf-8", "replace")

def get_iv_from_div(div_text: str):
    """div.pl 内容 → 二次解密 → 取 MD5 前 16 字节作为实际 IV。
    返回 (iv, 二次解出的明文)，后者仅供人工核对。"""
    inner_plain = aes_cbc_decrypt_b64(div_text, DIV_KEY, DIV_IV)
    return hashlib.md5(inner_plain.encode("utf-8")).digest()[:16], inner_plain

def bt_decrypt(cipher_field: str, iv: bytes, keystr: str) -> str:
    if not cipher_field.startswith(PREFIX):
        return cipher_field          # 未加密，原样返回
    return aes_cbc_decrypt_b64(cipher_field[len(PREFIX):], sgin_key(keystr), iv)

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="宝塔 BT-0x: 字段解密（取证用途）")
    ap.add_argument("--div", required=True, help="div.pl 文件路径（提供 IV 材料）")
    ap.add_argument("--keystr", default=DB_KEYSTORE, help="内置 keystr（默认取本版公开值）")
    ap.add_argument("value", help="待解密的 BT-0x: 字段值（不含前缀也可）")
    args = ap.parse_args()

    div_text = open(args.div, encoding="utf-8").read().strip()
    iv, inner = get_iv_from_div(div_text)
    field = args.value if args.value.startswith(PREFIX) else PREFIX + args.value
    print(bt_decrypt(field, iv, args.keystr))
```

运行方式：

```bash
# 1) 先单独验证 IV 提取（IV 错则后续全错，这是唯一的结构性检查）
python3 -c "
import bt_decrypt as b
iv, inner = b.get_iv_from_div(open('/evidence/div.pl').read().strip())
print('二次解密明文 =', repr(inner))   # 应为 16 字符的随机串（IV 材料），不是乱码
print('IV =', iv.hex())                 # 应为 32 位十六进制
"
```

> **注意**：即使 IV 步骤输出"看起来合理"，也**不能**据此认为解密成功——原因与唯一可靠判据见 [陷阱 4](#section-21) 与 [3.5 验证](#35-第-5-步验证关键不可跳过)。

<a id="section-13"></a>

### 3.4 第 4 步：批量解出全部敏感字段

```bash
mkdir -p /evidence/scripts
cat > /evidence/scripts/bt_batch.py <<'EOF'
import sqlite3, sys
sys.path.insert(0, '/evidence')
import bt_decrypt as b

iv  = b.get_iv_from_div(open('/evidence/bt-data/div.pl', encoding='utf-8').read().strip())[0]
con = sqlite3.connect("file:/evidence/bt-data/db/database.db?mode=ro", uri=True)
print("=== databases 表 ===")
for name, user, pwd in con.execute("SELECT name, username, password FROM databases"):
    print(f"  {name:15s} user={user:12s} pass={b.bt_decrypt(pwd or '', iv, b.DB_KEYSTORE)}")
con.close()

con = sqlite3.connect("file:/evidence/bt-data/db/panel.db?mode=ro", uri=True)
print("=== config 表 ===")
for k, v in con.execute("SELECT * FROM config"):
    if isinstance(v, str) and v.startswith(b.PREFIX):
        print(f"  {k:20s} = {b.bt_decrypt(v, iv, b.DB_KEYSTORE)}")
con.close()
EOF
python3 /evidence/scripts/bt_batch.py
```

> **脚本只读打开数据库**（`mode=ro`），保证不修改证据。

<a id="section-14"></a>

### 3.5 第 5 步：验证（关键，不可跳过）

解出一个"看起来像密码"的字符串，不等于解密成功。 必须做动态验证：

```bash
# 验证一（决定性）：用解出的口令实际登录数据库
mysql -u root -p'解出的口令' -e "SELECT VERSION(); SHOW DATABASES;"
# 成功 → 口令正确；报 Access denied → 口令错误或版本不匹配

# 验证二（反证）：与业务代码中的配置比对
grep -rE "DB_(HOST|USER|PASS)|db_password|mysql.*password" /evidence/site/ 2>/dev/null | head
# 面板存的 vs 代码里写的，不一致 = 有人改过（反证价值）
```

> ⚠️ **为什么必须动态验证**：错误 IV 下 PKCS#7 填充校验仍可能通过（末字节落在 1–16 区间），任何"检查输出是否像密码/填充是否合法"的启发式判断都不可靠——详见 [陷阱 4](#section-21)。**唯一的成功判据是口令实际可用。**

**如果动态验证失败**：①检查 `div.pl` 二次解密的 KEY/IV 是否与该版本匹配；②检查内置 keystr 是否与该版本一致（用样本面板程序里的相关函数确认）；③**不要**用"看起来像密码"作为结论——写"该版本加密机制与本文所述不一致，需进一步分析"。

---
<a id="section-15"></a>

## 四、常见陷阱

这一章的陷阱有一个共同根源：**把「解出了一个字符串」当成「解出了正确的东西」**。

加密机制的每一步都会产生看起来合理的输出，而 PKCS#7 填充校验恰恰在最关键的地方失效。

还有一个容易被忽略的根源：解密成功这件事本身不是证据，「解密出的值可用」才是证据。 中间隔着一次真实的系统调用，而跳过它的人拿到的只是一段看起来像口令的字节。

本章按「前置条件 → 解密流程 → 结论与合规 → 能力边界」四段归组。

<a id="section-16"></a>

### 4.1 前置条件与材料

<a id="section-17"></a>

#### 陷阱 1：以为脚本对所有宝塔版本通用

**现象**：拿本文的脚本直接跑某个新装的面板库，解出的值像乱码，就下结论「该面板用了未知加密方案，无法解密」。

**原因**：这套机制里有**两处版本相关参数**：

① 业务字段解密的 KEY 来源——程序内置一个 32 字符串，取其**偶数位**字符拼成 16 字节 AES-128 密钥，**这个串在不同版本里可能不同**。

② `div.pl` 二次解密用的那对固定 KEY/IV，**同样随版本变化**。

本文的内置材料来自对已公开分析结果的原理复现，**不是通用值**。

**影响**：**把「参数不匹配」误判成「加密方式不同」**，结论方向完全错了。

正确判断是「需要重新确认该版本的密钥推导路径」，而报告里写成「无法解密」就等于放弃了这个取证方向——而密钥材料其实就躺在同一台机器上。

**核查**：每个新样本都要先做 `div.pl` 二次解密的验证。

如果这一步解出的不是干净的 16 字符随机串，而是乱码，**流程到此为止**：记录「该版本的二级解密参数与已知分析不一致，需重新分析密钥材料来源」，然后回到分析阶段——从该版本面板程序的相关函数里确认内置串与 IV 生成方式，**不要因为本文没覆盖就断言「无法解密」**。

```bash
# 版本判定的第一手材料：面板程序本身的版本号
cat /case/DigiForensics/panel/data/version.pl 2>/dev/null
ls -l /case/DigiForensics/panel/ 2>/dev/null | head

# 取程序内嵌的密钥串：在程序文件里找 32 字符的字母数字符号混合串
strings /case/DigiForensics/panel/pyenv/bin/python 2>/dev/null | grep -E '^[A-Za-z0-9!@#$%^&*_+=-]{32}$'
```

**架构判定先于解密动作。** 2.3 节已经说明 `div.pl` 的存在是最可靠的版本判据——`data/db/` 存在且 `div.pl` 存在才走本篇流程；只有 `data/default.db` 的旧版单库架构则本篇流程整体不适用，字段多半是明文或简单编码。跳过这一步就拿脚本去解旧版库，得到的一定是乱码，而这不是「参数不匹配」，是「走错了分支」。

<a id="section-18"></a>

#### 陷阱 2：跳过 IV 提取直接解业务字段

**现象**：拿到 `BT-0x:` 密文后直接用某组 KEY/IV 去解，输出乱码。

**原因**：AES-CBC 的 IV 不是可选参数，它就是解密过程的一部分。

这套机制是两级结构：`div.pl` 的密文 → 用内置的第二对固定 KEY/IV 解出明文 → **取该明文的 MD5 前 16 字节** → 这才是解 `BT-0x:` 密文时真正用的 IV。

**密钥是硬编码的，IV 却是每台机器不同的**（`div.pl` 每台一份）。所以跳过第一步、或拿一个固定 IV 去解所有机器，解出的都不是该机器的值。

**影响**：**同一套脚本在不同服务器上结果不同**——这恰恰是正确的行为，而不是 bug。

分析员容易把它当成「这台机器有特殊加密」，进而怀疑数据被改过或 `div.pl` 被替换。

**核查**：严格三步：① 用内置参数解 `div.pl` → ② 对结果取 MD5 取前 16 字节作为 IV → ③ 用它解业务字段。

脚本里 `get_iv_from_div` 就是这个结构。

**排查时先验证第 ① 步的输出是否合理**（应为 16 字符随机串），第 ① 步不对就不要再往下走——**这是全流程唯一的结构性检查点**。

```bash
# 结构性检查点：div.pl 解出的是不是 16 字符
python3 -c "
import base64,hashlib
from Crypto.Cipher import AES
raw=open('/evidence/div.pl','rb').read().strip()
p=AES.new(b'Z2B87NEAS2BkxTrh',AES.MODE_CBC,b'WwadH66EGWpeeTT6').decrypt(base64.b64decode(raw))
p=p[:-p[-1]]
print('len =',len(p),'iv =',hashlib.md5(p).digest()[:16].hex())
print('OK' if len(p)==16 else '★长度不是 16，参数不匹配，流程到此为止')"
```

<a id="section-19"></a>

#### 陷阱 3：直接在目标机上跑脚本

**现象**：为了省事，把脚本拷到还在运行的面板服务器上，直接读 `/www/server/panel/data/db/database.db` 解密。

**原因**：目标机上的文件是**活证据**。SQLite 打开数据库的方式会影响它本身：读写方式打开会创建 `-wal`/`-shm`、可能触发 checkpoint 把 WAL 合并回主库；面板进程也在同时写。在活文件上操作既可能读到半写入状态，又改动了证据。

**影响**：**对运行中的证据文件做了写入**，而这类破坏往往不留明显痕迹——事后你手上的文件和原始镜像里的文件已经不同，「证据完整性」这层论证随之失效。

读到的半写入数据还会被当成事实写进报告。

**核查**：**先 `cp` 到分析机，在副本上做全部解密工作。**

复制时 `cp -rp` 保留权限与时间戳，并对 `data/db/` 下所有文件和 `div.pl` 逐一 `sha256sum` 登记。

所有 SQLite 访问一律 `file:...?mode=ro`——这是硬性要求，原件只读、离线分析。

如果必须在原件上操作（现场时间不允许复制），同样要 `mode=ro`，并把「原件操作时刻」写进证据说明。

<a id="section-20"></a>

### 4.2 解密流程与验证

<a id="section-21"></a>

#### 陷阱 4：★ 用 PKCS#7 填充校验判断解密成功

**现象**：解出的值末尾没有出现 `UnicodeDecodeError`，长度也合理，于是认为解密成功，把结果当口令去用。

**原因**：这是本篇最关键的技术事实，实测确认：使用错误的 IV 解密时，PKCS#7 填充校验仍可能通过。

原因是末字节决定填充长度，它只是密文最后一个字节，在错误的 IV 下它落在 1–16 这个合法区间的概率并不低；一旦落在合法区间，`pkcs7_unpad` 就不会报错，`.decode("utf-8", "replace")` 又保证不会抛异常——**整条链都不报错，但结果是垃圾**。

**影响**：**一个「静默失败」被当成成功。**

后续所有基于它的操作都建立在错误值上：用错误口令去连数据库会失败，于是转而去验证别的字段，最后报告里那个「解出的口令」是编造的。

**这比解不出来糟糕得多**——它让一个错误结论看起来有技术过程支撑。

**核查**：任何启发式判断（填充合法、长度合理、字符可打印、有 `MyPa**` 形态）都不是判据。

唯一可靠的成功判据是**口令实际可用**——3.5 节的 `mysql -u root -p'...' -e "SELECT VERSION();"` 实际登录成功。

反过来说，**如果动态验证失败，就说明前面某一步错了**，要回去检查 KEY/IV，而不是「再解一次试试」。

**这条同时反向约束了另外两件事**：一是不能把「解出的值看起来像口令」写进报告（陷阱 9），二是不能把「填充校验通过」当成筛选候选的过滤器（下面一条）。

<a id="section-22"></a>

#### 陷阱 5：把「解出乱码」当成成功，或当成加密方式不同

**现象**：解出的东西是一串不可读的字节，转成字符串后是乱码。两种处理方式都错：一种是「反正有输出了，算部分成功」，另一种是「这个版本用了别的加密方案」。

**原因**：乱码意味着**某个参数错了**，但「参数错了」和「算法不同」是完全不同的结论。判别方法是**看结构而非看内容**：AES-CBC 解密后的第一个块是**完全可预测的填充字节**（1–16 的重复），无论明文是什么；所以正确解出来的值，其**长度必然是 16 的倍数减填充**、末尾有一段规律填充。如果长度不是 16 的倍数，说明密文本身被截断或前置数据不对（最常见的是**把 `BT-0x:` 前缀一起当密文解了**）。

**影响**：**放弃一个其实能解开的字段**，或把一个参数错误包装成「使用了未公开的加密机制」写进报告。

后者尤其糟糕——它给出了一个听起来合理、实则毫无依据的技术判断。

**核查**：**按结构逐层排查，顺序固定**：

① 密文是否含 `BT-0x:` 前缀（含则先剥离）。

② Base64 解码后的字节数**是否为 16 的倍数**（不是则密文被截断或格式判断错了）。

③ `div.pl` 的 Base64 解码后字节数。

④ KEY 长度是否恰好 16 字节（偶数位拼接的结果）。

⑤ 才是内容合理性。

任何一步不通过就停在那一步报告，不要跳到「算法不同」的结论上。

<a id="section-23"></a>

#### 陷阱 6：假设字段名固定

**现象**：直接 `SELECT mysql_root FROM config`，报 `no such column`，于是以为「该面板没有存 MySQL root 口令」。

**原因**：**字段名随版本变化**，而且不同小版本的命名习惯不同（`mysql_root`、`password`、`db_password` 都可能）。更麻烦的是**列名相似但含义不同**的情况——`config` 表里可能有多个看起来像口令的字段，有的不加密。

**影响**：**「字段不存在」被当成「数据不存在」**，进而漏掉 MySQL root 口令这个最高价值的凭据；而 MySQL root 口令恰恰是横向扩线最有用的东西——它往往能访问同机所有库。

**核查**：先 `.schema` 或 `PRAGMA table_info` 看实际列名，再写查询。

定位加密字段用 `WHERE value LIKE 'BT-0x:%'` 这种**按值形态筛**而不是按列名猜——两个库（`database.db` 的 `databases` 表、`panel.db` 的 `config` 表）都要扫，不要只解 `database.db` 而漏了 `panel.db` 里的 `mysql_root`。

```bash
# 先看列名，不猜
sqlite3 "file:/evidence/panel.db?mode=ro" "PRAGMA table_info(config);"

# 再按值形态筛，与列名无关
sqlite3 "file:/evidence/panel.db?mode=ro" \
  "SELECT name FROM pragma_table_info('config') WHERE type='TEXT';"
```

「`no such column`」和「该列为空」是两个不同结果，脚本里必须分开处理：前者说明字段名错了（回去看 `table_info`），后者才可能说明该版本没存这个值。

<a id="section-24"></a>

#### 陷阱 7：只解业务库，漏掉 `panel.db` 的 `config` 表

**现象**：只处理了 `database.db` 的 `databases` 表，解出两个业务库口令就收工。

**原因**：**新版把面板自身配置拆到了另一个库**——`mysql_root` 在 `data/db/panel.db` 的 `config` 表里。`database.db` 里只有业务库的 `databases` 表。**这两个库解决的是不同层次的问题**：`database.db` 告诉你「有哪些业务数据可能被拿走」，`panel.db` 给你「能访问所有库的凭据」。

**影响**：**丢失了权限最高的那一个凭据**。报告里列出两个业务库口令却没有 root 口令，委托方轮换时只处理了业务库——而攻击者手上的 root 口令能访问全部库。业务库口令泄露和 root 口令泄露是两个不同量级的结论。

**核查**：两个库都扫，且都按值形态（`BT-0x:` 前缀）而不是按列名去找。

在报告里明确区分「业务库凭据（x 个）」与「数据库管理账号凭据（1 个）」，**并说明后者的影响面覆盖全库**。

若 `mysql_root` 解不出来，同样要区分「字段不存在」与「解密失败」——前者是能力声明，后者是分析缺口。

<a id="section-25"></a>

#### 陷阱 8：把 `div.pl` 缺失当成「IV 可以省略」

**现象**：新版架构的判定依据是 `div.pl` 存在（2.3 节）。某台机器上 `data/db/` 存在但 `div.pl` 找不到，分析师于是改用一个「默认 IV」把 `panel.db` 解了一遍，输出可读，报告写「已成功还原」。

**原因**：`div.pl` 不是可选组件，它是 IV 的唯一来源。

`div.pl` 是**每台机器一份**的 IV 材料，正是它让「同一套脚本在不同服务器上得到不同结果」。它缺失只有三种可能：① 采集时该文件未被包含（`data/db/` 被复制而 `data/div.pl` 被漏掉）；② 面板版本在引入该文件之前（那属于旧版分支，不该走本篇流程）；③ 它被删除了——**而 ③ 本身就是一条独立的发现**。

用「默认 IV」或「全零 IV」去解，本质上等同于陷阱 4 里的错误 IV，只是更隐蔽：它连「参数不匹配」都不会报。

**影响**：产出「已还原」的假结论，而且这个假结论带着完整的解密过程记录，比单纯解不出来更具迷惑性。更实际的问题是**第三条成因被略过了**——`div.pl` 被删除这件事本身可能指向清理行为。

**核查**：`div.pl` 缺失要分三档写，并顺手查它为什么不在。

```bash
# ① 确认真的不在（含被改名、被移到其它位置）
ls -l /evidence/data/div.pl 2>&1
find /evidence -name 'div.pl' -o -name '*.pl' 2>/dev/null | head

# ② 查 data 目录本身的 mtime —— 最近被改过是「被删」的线索
stat -c '%n mtime=%y ctime=%z' /evidence/data

# ③ 查备份与旧位置：面板备份、/www/backup/
find /evidence -path '*panel*' -name 'div.pl' 2>/dev/null
```

报告三档：采集未包含 → 「本次采集未包含 `data/div.pl`，IV 材料不可得，该库字段未能还原，属采集局限」；版本早于该机制 → 「**该面板属旧版单库架构，本流程不适用**」（此时字段多半是明文，直接读）；目录近期被改 → 「`div.pl` 不存在且 `data/` 目录 mtime 为 `<时间>`，疑被删除，属发现项；IV 材料不可得」。**三档都不是「已还原」。**

<a id="section-26"></a>

### 4.3 结论表述与合规

<a id="section-27"></a>

#### 陷阱 9：★ 把解密出的业务口令写进报告正文

**现象**：把解出的 `mysql_root` 口令明文写进报告正文，方便委托方核对。

**原因**：**这是一个「顺手」的动作**，不涉及任何技术判断，所以特别容易在无意中发生。但它是**真实生产数据库的完整凭据**——写入报告就等于把它交给了所有拿到报告的人：委托方法务、可能的对方当事人、可能进入诉讼材料的附件。

**影响**：凭据泄露范围从「一台被入侵的服务器」扩大到「所有读过报告的人」，且报告的流转是不可控的。事后追责几乎不可能——文本一旦进了邮件和网盘就没有撤回。

**核查**：**报告里只写存在性与属性**：「已还原 MySQL root 口令（21 位，含大小写字母、数字与符号，已脱敏保管）」。

**完整值单独加密保管、单独登记哈希、单独走移交流程**，不放正文、不进附件明文、不进聊天工具。

取证原则是**最小化**——「证明口令被获取了」这一事实本身通常就足以支撑结论，**证明它的具体内容并非必要**。确需交付时（如轮换验证），在受控环境内完成并留痕。

<a id="section-28"></a>

#### 陷阱 10：未通过动态验证就断言「数据库口令是 X」

**现象**：解出了值，写进报告「该服务器数据库口令为 X」，然后没有再验证，或者验证失败但没写进报告。

**原因**：**未验证的解密结果是推测，不是结论。** 尤其是本篇这种机制——错误 IV 仍能通过填充校验（陷阱 4），意味着**未经动态验证的输出有相当概率是错的**。委托方拿这个错口令去改密码，会把正常服务改瘫。

**影响**：**一个可能错误的凭据被当成事实写进报告**，并可能触发委托方基于它的处置动作——改口令、改配置、封禁 IP。

处置本身可能造成生产事故，而事故的责任会回到这份报告上。

**核查**：**结论强度必须与验证状态绑定。**

验证通过（实际登录成功）→ 可以写「已获取并验证」。
只过了结构检查 → 只能写「已还原，**动态验证未完成，口令正确性未确认**」，并把「验证」列为待办。
连 `div.pl` 那一步都不对 → 写「该版本机制与已知分析不一致，**未能还原**」。

**报告里必须写明验证方式**（实际登录 / 仅结构检查 / 未验证），而不是笼统写「已解密」。

<a id="section-29"></a>

#### 陷阱 11：把「binlog 里没记录读操作」当成「没有拖库」

**现象**：用解出的口令去查 binlog，发现没有 `INTO OUTFILE` 也没有 `DUMP`，报告写「未发现拖库行为」。

**原因**：**binlog 默认只记录写操作**（以及在特定配置下的少量管理语句），**拖库是读操作，binlog 天然不记**。

能看到 `SELECT` 通常是配置或工具的产物，不是默认行为。

能真正记下所有 `SELECT` 的是 `general_log`，而它**默认关闭**且体积巨大，往往从未开启。所以「binlog 无记录」和「无拖库」之间没有推理关系。

**影响**：**「日志里没有」被当成「事情没做」**。

这个错误在数据泄露案件里后果最重——委托方会据此认为数据安全、不通知监管、不做补救，而数据可能已经被完整导出。

**核查**：**先确认日志配置，再定结论。**

查 `slow_query_log`（慢日志能捕捉长耗时全表 `SELECT`，是拖库的间接证据）、`general_log`、`log_bin`、`binlog_format`、`expire_logs_days`。然后按能力说话：

① `general_log` 开着且覆盖案发时段 → 可以据它判断读操作量。

② 只有 binlog → 只能写「**未发现直接的拖库日志证据**（binlog 不记录读操作），**不能据此认定无拖库**」。

③ `expire_logs_days` 已过 → 写「binlog 已于 `<日期>` 过期，案发时段记录不可得」——**「记录已过期」和「没有发生」是两个完全不同的结论**。

间接证据（慢查询密度、连接数、异常时段的应用日志）也要写明是间接的。

<a id="section-30"></a>

### 4.4 能力边界与阴性表述

<a id="section-31"></a>

#### 陷阱 12：没搜到 `BT-0x:` 就写「该面板未加密」

**现象**：把 `database.db` 与 `panel.db` 里的敏感字段按值形态扫了一遍，没有任何值带 `BT-0x:` 前缀，报告写「该面板数据库未采用加密存储，数据库凭据为明文保存」。

**原因**：本篇 2.1 识别加密字段的依据就是 `BT-0x:` 前缀，**但「没有这个前缀」至少有四种成因，含义完全不同**：① **旧版架构根本没有这一层加密**——按 2.4 的对照表，7.7 之前的单一 `data/default.db` 里值本来就是明文；② 判定为新版架构的条件本身不满足——`data/db/` 不存在或 `div.pl` 缺失（见 2.3），说明走的是另一条分支；③ 库是空的、或表结构随版本变化导致没扫到目标字段（陷阱 6 讲的就是这件事）；④ 扫描范围只覆盖了本文列举的两个库。其中只有 ① 和 ③ 算「未加密」，② 是「不在本文适用范围」，④ 是「分析缺口」——三者在报告里长得一模一样。

**影响**：把「不在适用范围」写成「未加密」，等于给出一个**没有边界的安全结论**。

委托方据此认为「凭据只是明文存储、风险可控」，实际可能只是你打开的不是正确的库、没扫到正确的字段，或者这个版本的加密形态本文根本没覆盖。

更麻烦的是这个结论的措辞听起来比「未能确认」积极得多，一旦后续发现确有加密或确有未覆盖的库，这份报告会很难解释。

**核查**：阴性发现按「范围 + 结论 + 未覆盖」三段式写，**并且把架构判定作为一个独立的前置结论先落地**：

> 「架构判定：`/www/server/panel/data/db/` 存在且 `div.pl` 存在 → 属新版架构（2.3）。在此前提下，于 `database.db`（表 `<N>` 张）与 `panel.db`（表 `<M>` 张）的全部 TEXT 类型字段中按值形态 `BT-0x:%` 扫描，**未检出加密字段**。**未覆盖范围**：本文未覆盖的旧版单库架构、版本不明时的字段命名差异，以及库外来源——`/www/backup/` 下的数据库 dump、站点配置文件、面板生成的环境变量文件，这些位置在旧版里常以明文保存口令。」

**注意最后那一条**：阴性发现的覆盖面不限于你手上这两个库。面板的实际部署中，备份与配置是凭据的常见副本来源，只扫了库就宣布「明文存储」，等于漏掉了更容易被忽略的那部分。

<a id="section-32"></a>

#### 陷阱 13：把 `.pl` 密钥材料当普通配置项随手 copy 走

**现象**：把 `/www/server/panel/data/div.pl`、以及从程序文件里提取出的内置 KEY 材料，和数据库副本一起打包塞进案件证据目录，还把 `div.pl` 的内容贴进了工单系统。

**原因**：`div.pl` 与从程序里提取的内置串，合起来就是这台服务器的完整解密能力。 分析员的心态是「这些都是技术文件，放进证据目录方便复核」——这个动作本身没错，错的是**它没有分级**：证据目录会随案流转给委托方、可能进入诉讼材料，而解密材料一旦扩散，任何持有者都能还原这台机器上所有 `BT-0x:` 字段。

另一头是**数据库副本与密钥材料的分离问题**：两者分开放时，谁单独拿到都解不开；而把它们放进同一个目录，等于把「需要两样才能做的事」变成「拿到一个包就能做」。

**影响**：**解密能力的扩散是不可撤回的**——它不像口令那样可以随时轮换，`div.pl` 换了面板就认不出旧值，而内置串是公开可得的。委托方若据此发现自己的 `mysql_root` 早已被还原，会同时质疑报告的保密控制与机构的操作规范。

**核查**：按「能解密什么」给材料分级，副本与密钥分目录存放。

```text
/evidence/
  ├── db/                     # 数据库副本，可随案流转
  │   ├── database.db   sha256:...
  │   └── panel.db      sha256:...
  ├── crypto/                 # ★ 解密材料，受限，不随案
  │   ├── div.pl        sha256:...
  │   └── README.txt    # 说明用途与保管责任人
  └── hashes.txt
```

**分级判据是一句话：「拿到这个文件的人能做什么」。** 拿到 `div.pl` + 程序内置串就能还原全机数据库口令，所以它们属受限级；拿到 `panel.db` 只能看到密文，属可流转级。报告正文只写「已具备解密能力并完成还原」，不写材料路径。 移交时受限目录单独走授权流程，并在移交清单上标注该目录的解密能力说明。

<a id="section-33"></a>

#### 陷阱 14：解密失败归因于「密码错」，而实际是版本判断错

**现象**：脚本跑完，业务库字段全部输出乱码，分析员在报告里写「该服务器凭据疑似已被人为篡改或用其它方案加密，本机无法解密」。

**原因**：这里有三个完全不同的失败层级，而它们的排查顺序被搞反了。

| 层级 | 失败表现 | 真实含义 |
|---|---|---|
| 架构层 | 找不到 `data/db/` 或 `div.pl` | **版本分支判断错**，流程整体不适用 |
| 参数层 | `div.pl` 解出长度 ≠ 16 | 内置 KEY/IV 与该版本不匹配 |
| 密文层 | Base64 解码后不是 16 的倍数 | 密文被截断或前缀未剥离 |

分析员通常直接跳到「密文层」，因为它离眼前的现象最近。而**架构层的判断只需要一条 `ls`**，却在流程里被跳过了——本篇 3.1 第 1 步的「确认架构与定位密文」正是为此存在。

**影响**：**「被人为篡改」是一个指向性指控**。委托方读到「凭据疑似被篡改」，会把调查方向转向「谁改的凭据、为什么改」，而真实原因只是版本分支走错——一个检查 `ls` 就能澄清的问题被写成了一份技术性怀疑。更严重的是，它掩盖了「本次分析根本没做架构判定」这个方法论缺口。

**核查**：失败时按架构 → 参数 → 密文的顺序倒推，每一层单独记录。

```bash
# 第 1 层：架构判定（最先做，也最容易跳过）
ls -d /evidence/data/db 2>&1; ls -l /evidence/data/div.pl 2>&1

# 第 2 层：参数判定（div.pl 能否解出 16 字符）
# 见陷阱 2 的结构性检查点命令

# 第 3 层：密文判定
python3 -c "
import base64
for v in ['<取一条 BT-0x: 值>']:
    raw=base64.b64decode(v.strip().removeprefix('BT-0x:'))
    print('bytes =',len(raw),'OK' if len(raw)%16==0 else '★不是 16 的倍数')"
```

结论按三层分档写：第 1 层不通过 → 「**架构判定未通过，本流程不适用于该版本**，属流程适用性问题，非加密异常」；第 2 层不通过 → 「该版本二级解密参数与已知分析不一致，需重新确认密钥材料来源」；第 3 层不通过 → 「密文结构异常（Base64 解码后 `<N>` 字节，非 16 的倍数），疑被截断或前置数据处理错误」。三档都不写「被人为篡改」——除非有独立的证据指向篡改。
<a id="section-34"></a>

## 五、案例示例

> **本章的前置条件**：以下操作涉及还原数据库明文口令。全部步骤**仅在委托方书面授权范围内**执行，且须满足三条硬性要求——① 授权书明确写明"允许还原数据库口令"；② 解密在**离线隔离环境**内进行，**不连接生产数据库服务器**（除第 4 步的验证登录外，且该登录使用 `SELECT VERSION()` 这类无副作用语句）；③ 所有明文口令**只存在于 `/evidence/` 受限目录**，**不进报告正文、不进邮件、不进工单**。任一条不满足，本章的处置过程**不应启动**。

<a id="section-35"></a>

### 5.1 二次解密参数验证与 IV 提取的分水岭判定

**场景**

查获一台 Ubuntu 20.04 云主机（承接[第 01 篇](server-panel-linux-server-artifact-map.md)、[第 02 篇](server-panel-bt-panel-forensics.md)主线）。已确认宝塔新版架构，站点 `digiforensics-site` 疑被拖库。

镜像 `DigiForensics.dd` 只读挂载到 `/mnt/df`，面板数据已复制到 `/evidence/bt-data/`。目标：确认数据库口令以验证拖库。

这条路径值得先走，是因为解密类任务最容易出的错不是"解不出来"，而是"解出了一个看起来对的东西"。

宝塔新版的 `BT-0x:` 密文结构，如果参数不匹配，解密结果也是一段**长度正确、看起来像口令的乱码**——**光看输出无法判断成败**。

所以必须设计一个**先于业务字段的验证关卡**。

**处置过程**

**第 1 步 · 确认架构与读取材料**

```bash
ls -l /evidence/bt-data/db/
# database.db  panel.db  default.db        ← 新版
ls -l /evidence/bt-data/div.pl
cat /evidence/bt-data/div.pl
# 3UOiALw6JWPa2F02dtN3+ynzUs9oXWcT5llyhivOBaI=
```

**第 2 步 · 定位密文**

```bash
sqlite3 "file:/evidence/bt-data/db/database.db?mode=ro" \
  "SELECT name, username, password FROM databases;"
# shop_db   shop  BT-0x:tXeUcwJk+Lu5t+BTgGgLAIJbFXYxU84sZA8ak1yjvec=
# df_db     df_app BT-0x:9xQm...==

sqlite3 "file:/evidence/bt-data/db/panel.db?mode=ro" "SELECT * FROM config;" | grep mysql_root
# mysql_root|BT-0x:t2UpDw7vR5VjXlan0WCaDx150cBgfLlVPxRMe7Vbb1o=
```

**第 3 步 · 验证 IV 提取（关键分水岭）**

```bash
python3 -c "
import bt_decrypt as b
iv, inner = b.get_iv_from_div(open('/evidence/bt-data/div.pl').read().strip())
print('二次解密明文 =', repr(inner))
print('IV =', iv.hex())
"
# 二次解密明文 = 'xJBavlXDfwvV6mcs'      ← 16 字符随机串，正是 IV 材料本身（结构正确）
# IV = 1c5deec5291d462b21a8fc6bcdc08e89
```

这一步证明了二次解密参数（`DIV_KEY`/`DIV_IV`）与该样本版本匹配——`div.pl` 解出的是一个干净的 16 字符串，而不是乱码。若此处输出乱码，**流程到此为止**：记录"该版本加密机制与已知分析不一致"，转向重新分析，不硬套。

> 但请注意：**这仍不是解密成功的证明**。IV 结构正确只说明第一层参数对了，业务字段能否解开还需下一步动态验证。

**为什么这一关必须先过**：16 个可打印字符、长度精确、字符集均匀——**满足这三条的随机字节串概率极低**，所以"输出干净 16 字符串"确实是有判别力的。

但它判别的是**第一层参数**，不是**最终结果**。**两件事必须分开写进报告。**

**第 4 步 · 批量解密并动态验证**

```bash
python3 /evidence/scripts/bt_batch.py
```

```
=== databases 表 ===
  shop_db  user=shop    pass=<解出的业务库口令>
  df_db    user=df_app  pass=<解出的业务库口令>
=== config 表 ===
  mysql_root = <解出的 MySQL root 口令>
```

对 `mysql_root` 做决定性验证：

```bash
# ★ 仅在授权范围内执行，且只使用无副作用语句
mysql -u root -p'<解出的MySQL root口令>' -h 127.0.0.1 -e "SELECT VERSION();"
# 5.7.44-0ubuntu0.20.04.2       ← 登录成功，口令正确
```

**这一步是整个解密流程的定论**——只有动态登录成功，才能在报告中写"已获取并验证数据库口令"。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 该面板为新版加密架构 | `data/db/` + `div.pl` 存在 | 强（文件存在性） |
| 第一层解密参数与该版本匹配 | `div.pl` 解出结构正确的 16 字符 IV | 强（**仅证明第一层**） |
| 成功还原 MySQL root 口令 | 解密 + **`mysql` 实际登录成功** | 强（**动态验证，非格式匹配**） |
| 成功还原 2 个业务库口令 | 解密 + 业务代码比对/登录验证 | 强 |
| **明文口令的处置** | 仅存 `/evidence/` 受限目录，报告一律脱敏 | **合规要求，非可选** |

**脱敏规范**：本章及最终报告中，数据库口令**一律写作 `<解出的…口令>`**。

`div.pl` 的 44 字符密钥材料**不写入报告正文**——它是解密的关键材料，写进报告等于把解密方法一并交付。本案把它作为**附件单独加密存放**，仅在需要向委托方移交取证工具链时提供。

**误判对照**

这个案例最容易出的错是**把"解出来了"当成"解对了"**，以及**跳过第 3 步直接看业务字段**。

1. **判据**：**"输出长度正确"不构成解密成功的判据**。AES-CBC 的输出长度由密文长度决定，与正确与否无关；参数错误时输出同样是定长的 base64 字符串。

   判据必须来自**语义层**——第 3 步的 16 字符可打印串是**语义层证据**（IV 本应是随机可打印串），第 4 步的 `mysql` 登录成功是**行为层证据**。**三层强度递增，不可互相替代。**

2. **判据**：**参数不匹配时的正确动作是停下，不是硬套**。如果第 3 步输出乱码，说明该面板版本（面板版本号、Python 依赖版本）可能与已知分析不同，**继续套用会得到一段稳定的错误输出**——而那段输出看起来和正确结果没有区别。

   本案在这道关卡上通过，**不代表所有版本都能过**；报告里应写明"本方法已在本样本（面板版本 X.Y.Z）验证通过"。

3. **判据**：**动态验证必须用最小权限、最小影响的方式**。判别口令正确与否有三种手段，副作用递增：(a) 本地 socket 登录 + `SELECT VERSION()`（本案用法，**无数据访问、无配置变更**）；(b) 远程 TCP 登录——会产生连接日志，且本案数据库 `accept` 为 `127.0.0.1`，远程登录本就不该成功，用它做验证等于制造一次失败的入侵记录；(c) 尝试读业务表——**越界，且会污染数据访问审计**。

   **只有 (a) 恰当。**

   **判据**："登录成功"证明的是"口令当前有效"，不是"口令从未被改过"。本案 5.3 会发现攻击者改过业务库口令——**同一个解密出的值，在不同时间点的有效性可能不同**。报告里写"已获取并验证数据库口令"时，**必须附上验证的时间戳**。

**按错误判据走的代价**：第 1 条踩中（凭长度或格式判定成功）会让报告写下一个**看似完整、实则错误的凭据清单**。

委托方拿这份清单去做轮换，会轮换掉一批实际上没被泄露的口令，同时漏掉真正被改过的那个——后者恰恰是本案发现的第二个损害点（5.3）。

第 3 条踩中则会造成**取证行为本身污染了被取证系统的日志**：一次远程失败登录可能触发 fail2ban、可能告警、可能被对方察觉，**反过来影响正在进行的调查**。

<a id="section-36"></a>

### 5.2 凭据篡改的独立发现 面板口令与代码口令不一致

**场景**

承接 5.1。委托方在拿到解密后的三个口令后，提出一个他们自己没注意到的疑点："我们核对了一下，面板里存的 `shop` 库口令，和站点代码配置文件里写的不一样。哪个是对的？"

这个疑问是本次调查的**意外收获**。它不来自解密流程本身，而来自解密**之后**的交叉核对——**而这个交叉核对本可以跳过。**

**处置过程**

第 1 步 · 三方比对（面板 / 代码 / 实际验证）

```bash
# 来源 A：面板数据库（已解密）
#   shop_db  user=shop  pass=<面板口径业务库口令>
# 来源 B：站点代码配置
grep -rn "DB_PASSWORD" /mnt/df/www/wwwroot/digiforensics-site/ 2>/dev/null \
  | sed -E "s/(DB_PASSWORD['\"]?\s*[=:]\s*['\"]?)([^'\"]+).*/\1<代码口径口令>/"
# /mnt/df/.../config/database.php:8  DB_PASSWORD => '<代码口径口令>'
# /mnt/df/.../.env:14                 DB_PASSWORD=<代码口径口令>
```

**两者不一致。** 此时有两种可能，**必须区分**：

| 假设 | 验证方式 | 预期结果 |
|---|---|---|
| A：代码用的是**旧口令**，面板存的是**新口令**（管理员改过库口令但没改代码） | 查代码文件的 mtime 与口令变更记录 | 代码文件早于变更日 |
| B：面板存的是**被篡改后的口令**，代码里的是**原始正确口令** | 查 `ALTER USER` 类痕迹 + 用两者分别登录 | 假设 B 下，面板口径能登录、代码口径不能 |

第 2 步 · 用两个口令分别做无副作用验证（决定性）

```bash
# 验证 A：面板口径的口令
mysql -u shop -p'<面板口径业务库口令>' -h 127.0.0.1 -e "SELECT CURRENT_USER();" 2>&1 | head -2
# mysql: [Warning] Using a password on the command line interface can be insecure.
# CURRENT_USER()
# shop@localhost                       ← 登录成功

# 验证 B：代码口径的口令
mysql -u shop -p'<代码口径业务库口令>' -h 127.0.0.1 -e "SELECT CURRENT_USER();" 2>&1 | head -2
# mysql: Access denied for user 'shop'@'localhost'
```

**假设 B 成立**：面板存的口令有效，代码里的旧口令已失效。**这意味着面板口令是当前有效值，而代码配置是过时的**——**而攻击者拿到的正是面板口径的那个**。

**第 3 步 · 找篡改时刻**

```bash
# root 的历史命令（本案的直接证据）
grep -aE 'ALTER USER|CREATE USER|GRANT' /mnt/df/root/.bash_history | head
# mysql -e "ALTER USER 'shop'@'localhost' IDENTIFIED BY '<新口令>';"

# 该文件里这条命令前后的上下文与时间线索
grep -an 'ALTER USER' /mnt/df/root/.bash_history
# 412:mysql -e "ALTER USER 'shop'@'localhost' IDENTIFIED BY '...';"

# bash_history 无时间戳，交叉用文件 mtime 与 MySQL 日志
stat -c '%y %n' /mnt/df/root/.bash_history
# 2024-03-18 02:05:41
grep -a 'ALTER USER' /mnt/df/var/log/mysql/error.log 2>/dev/null | head
# 2024-03-18T02:05:39 8 [Note] 已在 user 表中为用户 'shop' 更改密码
```

**两个独立来源**（`.bash_history` 的 mtime + MySQL error.log 的明确时间戳）都指向 **2024-03-18 02:05**。

**第 4 步 · 这个时间点在攻击时间线里的位置**

```
22:41:07  面板登录成功
22:48:03  上传 WebShell
01:02:33  首页篡改
02:05:39  ★ 数据库口令被改（ALTER USER）
02:10–02:40  binlog 中的异常密集 SELECT
```

**02:05 恰好在首页篡改之后、大范围读取之前。**

顺序上说得通：先改口令拿到稳定的访问权，再读数据——**但这只是顺序一致，不构成因果证明**，见误判对照。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 面板存的口令是**当前有效**的，代码里的已失效 | 面板口径登录成功 + 代码口径 `Access denied` | **强（双侧验证）** |
| 业务库 `shop` 口令于 **2024-03-18 02:05** 被修改 | `.bash_history`（mtime 02:05:41）+ MySQL error.log 时间戳 | **强（双源）** |
| 该修改早于大范围数据读取（约 02:10） | 时间线排序 | 强（**时间关系，非因果证明**） |
| 攻击者获得了修改数据库口令的权限 | 该操作需 root 或 `ALTER` 权限，而攻击者经面板已具备 | 强 |
| 站点代码配置中的口令为**过时值**，可能导致业务异常 | 代码口径登录失败 | 强（**该缺陷在本案之前已存在还是被引入，未确认**） |

**这是一个独立于"拖库"的损害**：即便不讨论数据是否被读取，**凭据被篡改本身就是一个需要独立立项的发现**。它意味着——**攻击者在事件结束后仍保有对该数据库的访问能力**（因为新口令是攻击者自己设的），除非委托方立即轮换。

**误判对照**

这个案例最容易出的错是**把"代码里是旧口令"当成常态而不深究**，以及**把时间先后当成因果**。

1. **判据**："面板与代码不一致"本身不是发现，"不一致 + 代码口径失效"才是。

   很多站点长期存在"面板里改过口令但代码没同步"的历史不一致，那是运维疏漏，与入侵无关。

   **判别力来自第 2 步的双侧登录验证**——只有当**面板口径能登录、代码口径被拒**时，才能确认"当前有效值是面板那个"，从而把不一致指向"有人改过"。跳过这一步，就会把一起普通的运维疏漏写进入侵报告。

2. **判据**：`.bash_history` 里的 `ALTER USER` 记录只能证明"这条命令被执行过"，不能证明"执行者是攻击者"。`root` 的 `.bash_history` 混有运维与攻击者两类操作，且**bash_history 无时间戳**，条目顺序不等于时间顺序。

   本案成立，是因为 MySQL error.log 提供了独立的、精确到秒的时间戳，且该时间落在攻击窗内。只有 `.bash_history` 孤证时，结论强度应降为"中"。

3. **判据**："02:05 改口令、02:10 开始读数据"是时间关系，不是因果关系。两者也可能互不相关——改口令可能是为了**独占访问**（避免与业务方同时操作留下混淆痕迹），也可能是攻击者的**独立准备动作**。要主张"改口令是为了拖库"，需要额外证据（如该口令在别处的使用记录）。正确表述是"**口令篡改发生在大范围读取之前，两者时间相邻**"。

   **判据**："业务库口令被改"与"代码配置过时"是两个独立问题。后者可能是本次事件**之前**就存在的运维缺陷，也可能是攻击者改完库口令后**故意不动代码**（让业务照常运行以免被发现）。**本案未确认这一点**，报告里应把它列为待确认项而不是结论。

**按错误判据走的代价**：第 1 条踩中——本案最可能的下场是**这个发现被完全略过**。

略过的代价是直接的：**攻击者设定的那个新口令仍然有效**，委托方在不知道的情况下继续让站点带着这组凭据运行，**事件被"结束"了但访问通道还开着**。

第 2 条踩中则会把一条运维人员的正常操作写成"攻击者行为"，若该运维恰好是委托方的员工，这会直接造成内部关系问题，且这个错误结论很难撤回。

<a id="section-37"></a>

### 5.3 反例 binlog 不足以否定拖库时的结论边界

**场景**

委托方拿到凭据后立刻做了两件事：让 DBA 查数据库访问日志、让取证方查 binlog。**两边都没查到"谁读了数据"**。委托方据此问："所以没有拖库对吧？"

这个提问的推理方式在取证报告里出现频率极高：**两个日志都没记录，就等于没发生**。

但本案的数据流里，**读取动作恰好是这两类日志的盲区**。

**处置过程**

第 1 步 · 确认各类日志的记录边界（先搞清"它们本来就不记什么"）

```bash
# general_log：记录所有 SQL（含 SELECT），但默认关闭
mysql -u root -p'<root口令>' -h 127.0.0.1 -N -e "SHOW VARIABLES LIKE 'general_log%';"
# general_log        OFF          ← ★ 关闭，所以没有"全量 SQL 日志"可用
# general_log_file   /var/log/mysql/mysql.log

# binlog：默认只记写操作，SELECT 是否记录取决于 binlog_format
mysql -u root -p'<root口令>' -h 127.0.0.1 -N -e "SHOW VARIABLES LIKE 'binlog_format';"
# binlog_format      ROW          ← ROW 格式下，未提交的事务型 SELECT 也不写 binlog
mysql -u root -p'<root口令>' -h 127.0.0.1 -N -e "SHOW BINARY LOGS;"
# mysql-bin.000012  2024-03-10  1024
# mysql-bin.000013  2024-03-17  4096
# mysql-bin.000014  2024-03-18  8192   ★ 事件窗口落在这一份
```

**这张表就是本案的关键**：

| 日志 | 是否记录 SELECT | 状态 | 对拖库的可见性 |
|---|---|---|---|
| `general_log` | **是**（全量） | **OFF** | **完全不可见** |
| binlog（ROW） | 否（仅写操作） | ON | **SELECT 完全不记** |
| 慢查询日志 | 是（仅超 `long_query_time` 的） | 见下 | 部分可见 |
| MySQL `error.log` | 否（仅服务层事件） | ON | 不可见 |

第 2 步 · 慢查询日志能补一点，但要非常小心解读

```bash
mysql -u root -p'<root口令>' -h 127.0.0.1 -N -e "SHOW VARIABLES LIKE 'long_query_time';"
# long_query_time  10.000000
ls -l /mnt/df/var/log/mysql/mysql-slow.log* 2>/dev/null
# mysql-slow.log  2024-03-18  18422 bytes
```

```bash
grep -cE '^# Time: 2024-03-18 0[12]:' /mnt/df/var/log/mysql/mysql-slow.log
# 214    ← ★ 01–02 点共 214 条

grep -A2 '^# Time: 2024-03-18 02:1' /mnt/df/var/log/mysql/mysql-slow.log | head -9
# # Time: 2024-03-18T02:11:04.118491Z
# # User@Host: shop[shop] @ localhost []  Id:  4412
# # Query_time: 31.204  Lock_time: 0.000115
# SELECT * FROM shop_db.orders WHERE created_at >= '2024-01-01' ORDER BY id
#                              ↑ 12 秒一次，符合全表遍历特征
```

`User@Host` 是 `shop[shop] @ localhost`——这条信息本身就说明访问来自**本机**（配合 5.1 的取证，攻击者的操作确实在同机进行）。

第 3 步 · 慢查询日志能证明什么、不能证明什么

| 能证明 | 不能证明 |
|---|---|
| 02:10–02:40 存在**大量耗时查询**（214 条） | 这些查询**读了多少行** |
| 查询形态为**无 WHERE 条件或宽范围的全表扫描** | 是否**只读未改** |
| 访问身份是 MySQL 层的 `shop@localhost` | 是**攻击者本人**还是**业务方** |
| 时间与入侵窗口吻合 | 数据**是否被外传** |

**关键盲区**：慢查询日志**只记超过 10 秒的查询**。如果攻击者用了分页、限速、或者拆成小批次查询，每条都低于 10 秒——日志里就一条都没有。

本案的 214 条说明他的查询很"重"，但**这是攻击者的做法决定的，不是日志的完整性保证的**。

第 4 步 · 唯一能直接覆盖读操作的证据：binlog 里的异常写

```bash
mysqlbinlog /mnt/df/var/lib/mysql/mysql-bin.000014 --base64-output=DECODE-ROWS -v 2>/dev/null \
  | grep -iE 'SELECT|INTO OUTFILE|DUMP' | head -20
```

即便在 ROW 格式下，仍有**少量 SELECT 会被写进 binlog**——例如在**非事务表**（MyISAM）上的操作、或者触发器/事件中的语句。本案这批 `shop_db.orders` **是 InnoDB**，所以 binlog 里**没有对应的 SELECT 记录**——这恰恰证实了"binlog 记不到它"，而不是"没发生读取"。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 02:10–02:40 存在**大量长耗时查询**，形态为宽范围读 | 慢查询日志 214 条 + `Query_time` 21–34 秒 | 强（**现象层**） |
| 这些查询以 `shop` 身份从 `localhost` 发起 | 慢查询日志 `User@Host` | 强 |
| **拖库（大规模数据外传）已发生** | 无直接证据 | **不成立——见误判对照** |
| general_log 关闭、binlog 为 ROW 格式 | `SHOW VARIABLES` 实测 | 强（**这是判定盲区的直接依据**） |
| 该批慢查询是否由攻击者发起 | 无 | **未决项**（需与业务侧正常作业时间比对） |

**限定范围**：「`/var/log/mysql/mysql-slow.log` 单文件 + `SHOW VARIABLES` 实测输出 + `mysql-bin.000014` 全量解码」。

**未覆盖**：`general_log`（**已关闭，不存在**）；**未采集**网络侧流量（**这是本案最关键的缺口**——外传必须经过网络，而网络侧证据本案完全没有）；**未查** MySQL 审计插件（`audit_log`）或 `performance_schema.events_statements_history_long`（若开启可覆盖读操作，**需在授权下确认其保留时长**）；**未覆盖** 03-18 02:40 之后的时段；**未查** DBA 侧的操作审计与堡垒机日志（这可能是唯一能区分"攻击者查询"与"业务查询"的证据源）。

**误判对照**

这个反例最容易出的错是**把"日志里没有"当成"事情没发生"**——而且这个错一旦犯，**代价是让一个真实的数据泄露事件被关闭**。

1. **判据**：否定一个行为之前，必须先确认承载它的日志本来就会记录它。

   本案的判据链是：① `general_log=OFF` → 全量 SQL 日志不存在；② `binlog_format=ROW` + 表为 InnoDB → **SELECT 不进 binlog**；③ `long_query_time=10` → 慢查询日志只覆盖慢查询。

   三条合起来才能得出"读操作在现有日志体系内不可见"。 只做第 ③ 条就下"无拖库"结论，是把"日志的覆盖范围"当成了"事实的覆盖范围"。
2. **判据**：**214 条慢查询 ≠ 拖库**。判别力在三个问题：(a) 这些查询**读了多少行**——慢查询日志**不记行数**；(b) 结果**去了哪里**——可能只查不看，也可能落盘或外传，**日志两者都不区分**；(c) 是不是**业务方的正常批量作业**——**这是必须先排除的**：委托方若有凌晨跑批的定时任务，形态同样是宽范围读。

   正确表述是"存在 214 条宽范围读查询，性质待与业务作业比对"，而不是"发现了拖库行为"。
3. **判据**：**"数据外传"需要网络侧证据，而本案完全没有**。数据在 MySQL 里被读出后，要离开这台机器必须过网卡。判别力最强的证据是：目的 IP 的流量记录、目的 IP 的接收侧日志、或该主机上落地的导出文件。 本案三者皆无。

   **在没有网络侧证据时，正确结论是"存在大范围读取，**是否外传无法认定**"**——这个表述听起来弱，但它才是准确的。

   **判据**：**"未发现拖库日志证据"与"未发现拖库"是两个句子**，前者是本案的结论，后者不是。

   在报告里，前者后面必须跟一句"现有日志体系不记录 SELECT 类型的读操作，故本项阴性发现不具排除力"——把这句话写上，委托方就不会据此关闭事件；不写上，他们会。

**按错误判据走的代价**：这是本批案例里代价最高的一个误判。

假设实际发生了拖库，而报告写"未发现拖库"，后果链条是：委托方**关闭事件** → 不启动数据泄露的**法定告知义务**（多地监管要求泄露后 72 小时内报告）→ 合规风险由委托方独自承担，而交付方因一句不准确的结论成为共犯。

反过来，若报告写成"存在大范围读取，性质待查"，委托方会去调 DBA 排班、堡垒机日志、网络流量——**而这三样里只要有一样能确认，事件就能正定性**。

为了一句听起来确定的结论，付出整个事件被关闭的代价，这是取证写作里最不划算的交易。

<a id="section-38"></a>

## 六、扩展阅读方向

本篇解决的是一个很具体的问题：**新版面板的密文怎么还原**。解出口令之后，工作才真正开始——下面几组文章接住后续。

**数据侧：口令的用途在这里**

- [MySQL 数据库取证](../../mobile/mobile-database/mobile-database-mysql.md) —— **拿到口令之后唯一该做的事**：binlog、慢查询日志、`general_log` 里的拖库证据。`ROW` 格式 binlog 能还原每行改动的旧值与新值，是拖库最硬的证据。
- [数据库与配置文件加密](../../crypto/crypto-app/crypto-app-database-configuration-decryption.md) —— 真加密与 base64 编码的区分方法。本篇开头的判断表（有无 `BT-0x:` 前缀）在那一篇有更一般的表述。
- [NoSQL 与 Redis 取证](../../mobile/mobile-database/mobile-database-mongodb-and-redis-forensics.md) —— 面板里若有 Redis / MongoDB 配置，口令适用范围不同。

**前置与同层**

- [宝塔面板取证](server-panel-bt-panel-forensics.md) —— **本篇的前提**。架构判定、库表结构、`users` 表与 `request.log` 都在那一篇。
- [SQLite 基础与结构](../../mobile/mobile-database/mobile-database-sqlite.md) —— 只读查询、页大小读错这类问题的排查。
- [其他面板取证](server-panel-hosting-control-panel-forensics.md) —— 1Panel、Webmin、aaPanel 是否采用类似加密。判据相同（值的外观、密钥材料是否另存），但细节不同。

**结论表述与合规**

- [通用密码恢复](../../crypto/crypto-app/crypto-app-passware-and-password-recovery.md) —— **密钥材料缺失时该往哪走**，以及授权、最小化、脱敏的完整要求。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 本篇那条"动态验证必须在已授权检材本机范围内"的纪律出处。
- [证据保管链与委托证明](../../fundamentals/fundamentals-chain/fundamentals-chain-chain-of-custody-and-authorization.md) —— 解密后的产物与脚本一并作为证据固定时，编号与交接的要求。

**判据与反例**

- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— `div.pl` 被删、`default.db` 被换过版本的识别。密钥材料缺失有时不是"这套机制如此"，而是被清理过。
- [哈希与完整性校验](../../fundamentals/fundamentals-concepts/fundamentals-concepts-hashes-and-integrity-verification.md) —— **脚本解出的值与样本程序里的内置参数做比对**，这是判断版本是否匹配的唯一可靠办法。
<a id="section-39"></a>

## 七、命令速查

```bash
# ===== 环境 =====
sudo apt install python3 python3-pip sqlite3
pip3 install pycryptodome

# ===== 1. 确认架构与读取材料 =====
ls -l /mnt/df/www/server/panel/data/db/ 2>/dev/null        # 新版架构判据
ls -l /mnt/df/www/server/panel/data/div.pl 2>/dev/null
cat /mnt/df/www/server/panel/data/div.pl                    # IV 材料（无 BT-0x: 前缀）

# ===== 2. 定位密文（先看列名，不假设字段）=====
sqlite3 "file:/evidence/bt-data/db/database.db?mode=ro" ".schema"
sqlite3 "file:/evidence/bt-data/db/panel.db?mode=ro" ".schema"
sqlite3 "file:/evidence/bt-data/db/database.db?mode=ro" \
  "SELECT name, username, password FROM databases WHERE password LIKE 'BT-0x:%';"

# ===== 3. 解密（用配套脚本 bt_decrypt.py）=====
# 3.1 先单独验证 div.pl 二次解密（不通则停止，不要硬解）
python3 -c "
import bt_decrypt as b
iv, inner = b.get_iv_from_div(open('/evidence/bt-data/div.pl').read().strip())
print('二次解密明文 =', repr(inner))   # 应为 16 字符随机串，不是乱码
print('IV =', iv.hex())
"
# 3.2 解单个字段
python3 bt_decrypt.py --div /evidence/bt-data/div.pl "BT-0x:t2UpDw7vR5VjXlan0WCaDx150cBgfLlVPxRMe7Vbb1o="
# 3.3 批量解（见正文 bt_batch.py，只读打开数据库）

# ===== 4. 验证（决定性证据，不可跳过）=====
mysql -u root -p'<解出的口令>' -e "SELECT VERSION(); SHOW DATABASES;"   # 实际登录
grep -rE "DB_(HOST|USER|PASS)|db_password" /evidence/site/ 2>/dev/null   # 与代码配置比对（反证）

# ===== 5. 拖库行为验证 =====
mysqlbinlog /var/lib/mysql/mysql-bin.0000* 2>/dev/null | grep -iE 'SELECT|INTO OUTFILE|DUMP' | head -40
# 注：binlog 默认只记写操作；无 general_log 时不能断言"没有拖库"
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 服务器与 Web 取证 — 宝塔新版加密数据解密」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《宝塔新版加密数据解密》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.vc` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
