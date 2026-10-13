---
title: "数据库与配置文件加密的识别与解密"
slug: "crypto-app-database-configuration-decryption"
canonical: "https://www.digiforensics.cn/wiki/crypto-app-database-configuration-decryption"
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

# 数据库与配置文件加密的识别与解密

<a id="section-1"></a>

## 一、概述

"文件打不开"是取证中最常见的求助之一，但**"打不开"至少有五种完全不同的原因**，混为一谈会让整个处置方向跑偏：

| 现象 | 真正的原因 | 处理方向 |
|---|---|---|
| 磁盘整体读不出 | 卷加密（BitLocker / VeraCrypt） | 见 01、03 篇 |
| 整个分区是乱码 | 文件系统层加密 | 见 01、03 篇 |
| **单个文件打不开，但目录能列** | 应用层加密或文件损坏 | **本文** |
| 能打开但内容乱码 | 编码错配（UTF-8/GBK）或二次编码 | 用 `file`/`uchardet` 判断 |
| 根本没读全 | 截断、镜像不完整 | 回到成像环节 |

必须先建立一个概念区分：

- **卷/文件系统层加密**（BitLocker、EFS、LUKS）：数据落盘时整体加密，**明文从不在磁盘上**，密钥由系统统一管理。
- **应用层加密**（MySQL TDE、SQL Server TDE、pgcrypto 应用层、SQLCipher）：数据文件本身仍是普通文件，**能列目录、能读文件头**，只是某些表/列/文件的内容是密文。

后者是本文重点。它有一个共同弱点：应用必须先读到密钥才能解密，所以密钥几乎总是以某种形式存在于配置或内存中，而应用层加密的密钥管理通常比卷加密薄弱得多。这既是取证突破口，也是企业运维的常见盲区。

**在取证流程中的位置**：本篇属于**分析**环节的诊断分支，而且它的第一个动作是**分类而不是破解**——三步判定路径（文件头 → 加密层级 → 引擎与版本）必须在动手读数据之前走完。走错分支的代价不是浪费时间，是把一份损坏的文件当成加密文件上报，或者反过来。**上游依赖**是 [BitLocker 全卷加密取证](../crypto-volume/crypto-volume-bitlocker.md)（先排掉卷加密）、[EFS 文件系统加密取证](../crypto-volume/crypto-volume-efs.md)（用户级透明加密的判定）与[数据库取证通用方法](../../mobile/mobile-database/mobile-database-database-forensics-methods.md)（表空间与数据字典的常规路径）。密钥在内存中时，提取方法走 [内存中的凭据与密钥](../../memory/memory-artifact/memory-artifact-memory-credentials-and-keys.md)；走不通时按 [通用密码恢复](crypto-app-passware-and-password-recovery.md) 的优先级表退守。

**本篇处理的证据形态**，按引擎分四类，文件名与配置键是判定的第一手依据：

| 引擎 | 加密落在哪 | 密钥材料在哪 | 判据 |
|---|---|---|---|
| **MySQL / MariaDB** | `ibdata1` 与各 `.ibd` 表空间的页内部分（**文件头与空闲页仍是明文**） | keyring 文件（路径写在 `my.cnf` 的 `early-plugin-load` 与 `keyring_file_data`，插件为 `keyring_file` / `keyring_encrypted_file`） | `information_schema.innodb_tablespaces` 与文件头的加密标志位 |
| **PostgreSQL** | 两条路径：文件系统加密（外部，见 02 篇）或 `pgcrypto` 应用层 | `pgcrypto` 的密钥在会话里、密钥文件或环境变量 | 表里出现 `\x...` 开头的十六进制串 |
| **SQL Server** | `.mdf` / `.ndf` 的页级 TDE | **主密钥 → 证书 → DEK 三层链**，证书私钥受服务主密钥（DPAPI）保护 | `sys.dm_database_encryption_keys` 的 `encryption_state` |
| **SQLCipher / 应用自加密** | 整个库文件（含文件头） | 应用配置、`sqlcipher.conf` 或代码常量 | 文件头不是 SQLite 的 `SQLite format 3`，也不是明文，头 16 字节为随机值 |

配置文件这一侧的"伪加密"要单独看：`base64` 编码、`gzip` 压缩、自定义异或、以及 `.pgpass`、`my.cnf` 的 `password=`、`~/.my.cnf`、`.env`、Kubernetes Secret 的 base64 字段（base64 只是编码，不是加密，但 k8s 的 Secret 默认就是 base64，很多报告在这里写成"已加密"是错的）。Linux 上的 `shadow` 哈希属于认证哈希而非加密，走爆破路径而不是解密路径。

某个文件打不开的真实原因是哪一类、加密发生在哪一层、是哪种引擎与哪个版本、密钥材料是否存在于检材内的可及位置、**在拿到密钥后能否实际解密并读出可读内容**（这是唯一的定论标准，`strings` 看到可疑结构不算）。

**密钥不在检材内就到此为止**——本篇不提供任何密钥恢复或暴力破解手段，那些方法论在 [通用密码恢复](crypto-app-passware-and-password-recovery.md)，且必须先确认授权范围。引擎与版本判断不出来时，所有偏移与结构结论都不成立，**这是硬前提**：同一引擎不同版本的密钥结构与解密方式都不同，套错版本会得到"能解密但全是乱码"的假成功。判定为加密**不等于**判定为恶意，企业的数据保护、备份加密、云厂商的静态加密都会产生同样的表象，这两者在证据上无法区分。阴性结果同样要限定范围："在 `my.cnf` 与常见 keyring 路径下未发现密钥文件引用"，未覆盖的是用户级 `~/.my.cnf`、systemd 环境变量与容器内挂载的 Secret。**Base64 出来的东西不等于解开了密文**，用它凑出"可读"的结果是本领域最常见的一类假结论。

**读者前提**：需要能读十六进制并理解页与文件头的差别（为什么"能列目录能读文件头"就排除了卷加密）；需要分清认证哈希、口令派生、对称加密这三类不同机制各自需要什么才能反推——这个区分错了，整个处置方向会偏到爆破上去；需要知道 MySQL、PostgreSQL、SQL Server 各自的数据文件与配置文件分别叫什么、各自的密钥管理机制完全不同；还需要掌握"结论必须经过实际读取验证"这条纪律，格式匹配与工具报成功都不构成定性依据。

---
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 三步判定路径

```
① 是加密还是损坏？        → 用对应工具的报错信息 + 文件头特征区分
      ↓
② 应用层还是文件系统层？   → 能列目录 = 应用层；整块乱码 = 文件系统层
      ↓
③ 密钥来源在哪？          → 配置文件 / 密钥环 / 注册表 / 环境变量 / 进程内存
```

第 ① 步的关键技巧：看报错信息，不要只看"打不开"。

| 工具 | 加密时的典型报错 | 损坏时的典型报错 |
|---|---|---|
| `sqlite3` | `file is not a database` | `database disk image is malformed` |
| `7z t` | `Wrong password?` / `Data Error` | `Headers Error` / `Unexpected end of archive` |
| `openssl` | `bad decrypt` | `bad magic number` |
| `mount` | `wrong fs type` | `wrong fs type`（**相同，不能区分**） |
| 各类 GUI 解压 | "需要密码" 对话框 | "文件已损坏" 对话框 |

> SQLite 的 `file is not a database` 既可能是加密也可能是损坏，不能凭这一条定性，必须看文件头。

<a id="section-4"></a>

### 2.2 用文件头判断"加密 vs 损坏 vs 编码"

损坏的文件几乎总是保留了原格式的文件头；加密的文件头则是随机的（除非加密方案保留了一段 magic）。
```bash
xxd -l 32 evidence.db    # 看前 32 字节
```

| 文件头（hex） | 判断 |
|---|---|
| `53 51 4c 69 74 65` = `SQLite f` | SQLite，正常 |
| `50 4b 03 04` = `PK..` | ZIP（docx/xlsx/apk） |
| `25 50 44 46` = `%PDF` | PDF |
| `d0 cf 11 e0` | 旧版 Office OLE（.doc/.xls） |
| `52 61 72 21` = `Rar!` | RAR 压缩包 |
| `ef bb bf` / `ff fe` | UTF-8 / UTF-16 BOM，是**编码问题** |
| 全零或高熵随机 | **疑似加密或已损坏** |

**熵值是辅助判据**：正常文本/数据库文件通常在 4.0–5.5 bit/byte，加密块或压缩块接近 8.0（计算命令见第七节 1）。

> **取证纪律**：熵值高只能说明"高度随机"，**不能单独定性为加密**——压缩包、部分二进制格式、已损坏的文件同样熵值高。**定性必须有第二个独立证据**（工具报错、密钥材料存在、跨文件一致性）。

> **关于 SQLCipher 的重要更正**：SQLCipher **没有固定 magic**。它把 SQLite 前 16 字节当作 salt 随机化，因此表现为"文件头损坏的 SQLite"——前 16 字节随机，但偏移 16 字节起仍是合法的 SQLite 页结构（`0x0D 0x00 0x01` 等）。识别 SQLCipher 的正确方法是这个组合特征；任何声称"SQLCipher 有固定 magic"的说法都是错的。

<a id="section-5"></a>

### 2.3 MySQL / MariaDB 的表空间加密

MySQL 8.0 的 InnoDB 表空间加密（TDE）由 **Keyring 组件/插件**提供密钥管理，三层结构：

```
表空间（.ibd 文件） ──用 tablespace key 加密──> master key（主密钥）
                                                  └─ 存放在 keyring 文件里
```

关键取证事实：主密钥不在数据文件里，在 keyring 文件里。

拿到加密 `.ibd` 而没有 keyring，等于拿到一整块随机字节。

```ini
# /etc/my.cnf 或 /etc/mysql/my.cnf
[mysqld]
early-plugin-load=keyring_file.so              # 必须在启动时加载，否则加密表打不开
keyring_file_data=/var/lib/mysql-keyring/keyring
# 新版本推荐：
early-plugin-load=component_keyring_file.so
component_keyring_file_data=/var/lib/mysql-keyring/keyring
```

> `keyring_file` 插件自 MySQL 8.0.34 起已弃用，新部署用 `component_keyring_file`。取证时**两种都要查**，配置能直接区分实例用的是哪种。

```sql
-- 插件/组件是否加载 + 密钥文件实际路径
SELECT PLUGIN_NAME, PLUGIN_STATUS FROM INFORMATION_SCHEMA.PLUGINS WHERE PLUGIN_NAME LIKE '%keyring%';
SHOW GLOBAL VARIABLES LIKE 'keyring_file_data';
SELECT * FROM performance_schema.keyring_keys;   -- KEY_ID 形如 INNODBKey-<uuid>-1
SELECT SPACE, NAME, SPACE_TYPE, ENCRYPTION
  FROM INFORMATION_SCHEMA.INNODB_TABLESPACES WHERE ENCRYPTION = 'Y';
```

> 关于 `performance_schema.keyring_file_instances`：这是 **Oracle Key Vault（OKV）组件**的表（`master_key_id`、`keyring_file_path` 等字段），**不是 `keyring_file` 插件**。用插件时元数据在 `performance_schema.keyring_keys`（component 场景另有 `keyring_component_status`），密钥本体在 `keyring_file_data` 指向的文件里。这一点常被写错。

**keyring 文件的初筛**：keyring 是**密钥后端**，**不是**统一的私钥容器——后端形态随实现而变（`component_keyring_file` / `component_keyring_encrypted_file` 是本地文件；`keyring_okv` 走 KMIP、`keyring_aws` 走 AWS KMS、`keyring_hashicorp` 走 Vault、`component_keyring_oci` 走 OCI Vault，后者的数据**根本不在本地文件里**）。官方定义的密钥类型也不止私钥：`keyring_aws` / `keyring_okv` 支持 AES 与 SECRET，`keyring_hashicorp` 还支持 DSA / RSA，而 **InnoDB 表空间加密用的主密钥属于 SECRET 类型（对称密钥材料）**，并非 ASN.1/DER 编码的非对称私钥。因此 `openssl pkey -inform DER` **不构成通用判据**——它最多在"某条记录恰好像 DER 私钥"时成功。**决定性验证始终是把 keyring 挂到同版本实例上查加密表**，见步骤 3。

<a id="section-6"></a>

### 2.4 PostgreSQL 的两条加密路径

PostgreSQL 没有内置整库 TDE，常见两条路径，取证时必须区分：

| 路径 | 机制 | 密钥位置 | 取证难点 |
|---|---|---|---|
| **A. 存储加密** | 数据目录跑在文件系统层加密或 LUKS 上 | 挂载/启动时提供 | **低**——与 01 篇相同 |
| **B. 列级/应用层** | `pgcrypto` 的 `pgp_sym_encrypt()`，或应用自行 AES | 密钥在**应用配置或代码**里 | **中**——重点在这里 |

**路径 B 的取证要点**：`pg_authid.rolpassword` 保存的是（通常是 SCRAM/md5 的）**账户口令摘要，不是 pgcrypto 的加密密钥**。

pgcrypto 密钥的真实来源是应用配置——`application.yml` / `settings.py` / `.env` / `config.php` / `appsettings.json`。

```bash
grep -rE "pgp_sym_decrypt|pgp_sym_encrypt|pgcrypto" /mnt/image/opt/ 2>/dev/null
```

**一个容易被忽略的高价值点**：`pg_stat_activity` 的 `query` 列能看到**当前连接的查询文本**，其中可能残留解密函数调用与密钥：

```sql
SELECT pid, usename, application_name, client_addr, state, query
  FROM pg_stat_activity WHERE state <> 'idle';
```

这是极高价值的现成明文，但**只在运行时存在，关机后就没了**。所以对数据库服务器，**运行中/内存取证的优先级高于静态磁盘分析**（见 [内存中的凭据与密钥](../../memory/memory-artifact/memory-artifact-memory-credentials-and-keys.md)）。

<a id="section-7"></a>

### 2.5 SQL Server TDE

SQL Server TDE 的密钥体系是**三层父子关系**，取证必须从最外层的备份找起：

```
服务主密钥 SMK（由操作系统凭据保护，导出为 .bak）
  └─ SMK 保护 数据库主密钥 DMK
       └─ DMK 保护 证书私钥
            └─ 证书公钥 保护 数据加密密钥 DEK
                 └─ DEK 加密 数据文件

★ 关键：保护 DEK 的是证书的**公钥**，解密 DEK 需要**私钥**。
  这就是"必须同时拿到证书与私钥"的原因——只有公钥无法解开 DEK。
```

关键取证事实：**证书与私钥必须与 `.bak` 一起被备份**。

微软文档明确要求 *"you must have backups of both the certificate and the private key or you'll not be able to open the database"*。原因是保护链里 **DEK 由证书公钥加密**——只有公钥无法解开 DEK。反过来说，**只拿到加密的 `.bak` 而没有证书+私钥，不具备恢复条件**；同样，**只导出 `.cer`（公钥）也不够**。这是设计意图，防止 DBA 单独拿走数据。

```sql
SELECT EncryptionState, key_length, algorithm FROM sys.dm_database_encryption_keys;
SELECT name, thumbprint, pvt_key_encryption_type_desc, pvt_key_algorithm_desc
  FROM msdb.dbo.master_keys;   -- 私钥受密码还是 Windows 服务账户保护，决定后续要什么材料
```

**导出证书与私钥**（**必须在原实例的克隆/恢复副本上做**）：

```sql
USE master;
OPEN MASTER KEY DECRYPTION BY PASSWORD = '<SMK 密码>';

-- ★ 必须带 WITH PRIVATE KEY，否则只导出公钥 .cer，不足以恢复
BACKUP CERTIFICATE [TDE_Cert] TO FILE = 'C:\evidence\TDE_Cert.cer'
  WITH PRIVATE KEY (
    FILE = 'C:\evidence\TDE_Cert.pvk',
    ENCRYPTION BY PASSWORD = '<私钥保护密码>'
  );

BACKUP SERVICE MASTER KEY TO FILE = 'C:\evidence\SMK.bak';
```

> **★ 三个文件缺一不可**：`TDE_Cert.cer`（证书）+ `TDE_Cert.pvk`（**私钥**）+ `SMK.bak`（服务主密钥备份）。漏掉 `.pvk` 是最常见的疏漏——命令能成功执行、`.cer` 也会生成，很容易误以为导出完成，**但那只有公钥**。报告里应逐个列出这三个文件并记录哈希。

> ⚠️ **只读原则**：`BACKUP` 会写文件。取证环境应使用**原始实例的克隆或恢复副本**，详见 [BitLocker 全卷加密取证](../crypto-volume/crypto-volume-bitlocker.md) 中的只读要求。

<a id="section-8"></a>

### 2.6 应用自加密数据库：明文不在磁盘上

另一类"数据库加密"不依赖 TDE，而是**库文件整体被应用层密码保护**，典型是移动端与桌面客户端：

| 形态 | 机制 | 密钥来源 |
|---|---|---|
| **SQLCipher** | 用 `PRAGMA key` 把整个 SQLite 文件加密，**磁盘上没有明文页** | 应用配置、代码常量、用户口令派生 |
| Realm / Core Data 加密 | 库文件自带密钥 | 应用 bundle 内的 key 文件 |
| 桌面端自建"库"（Navicat、DBeaver 等） | 见 06 篇 | 配置目录中的字段 |

这类库与 TDE 的取证逻辑**正好相反**：

- TDE 要找 **keyring 文件**（在文件系统里）。
- 应用自加密要找 **应用配置/代码/用户口令**（在配置文件、bundle、内存里）。

**明文只有在应用运行时才存在于内存中**，磁盘上永远是密文。

检材是关机镜像时，只能走"找密钥 → 离线解密"；有内存镜像时应优先做内存取证（见 [内存中的凭据与密钥](../../memory/memory-artifact/memory-artifact-memory-credentials-and-keys.md)）。

**验证方式永远是实际打开**：SQLCipher 用 `PRAGMA key` 试解，能查询即证明密钥正确。

```bash
# SQLCipher 的离线验证（拿到口令/密钥后）
sqlite3 evidence.db "PRAGMA key='<key>'; SELECT count(*) FROM sqlite_master;"
sqlite3 evidence.db "PRAGMA key='<key>'; SELECT name FROM sqlite_master;"   # 报错即密钥错误或非 SQLCipher
```

<a id="section-9"></a>

### 2.7 配置文件的"伪加密"：base64 不是加密

取证中大量被误认为"加密"的，实际是 base64 编码——base64 是**可逆的公开编码，不提供任何机密性**。
| 现象 | 实际是什么 | 危害 |
|---|---|---|
| `kubeconfig` 里的 `token` | **base64**，不是加密 | 拿到文件即拿到完整集群权限 |
| `~/.docker/config.json` 的 `auth` | **base64(user:password)** | 同上 |
| K8s Secret 的 `data` 字段 | **base64**（除非启用 etcd 静态加密或 KMS） | 同上 |
| `Authorization: Basic` | **base64** | 抓包即可还原 |
| `Bearer` JWT | base64url 编码 header/payload + HMAC 签名 | payload 明文可读 |
| URL 里的 `user:pass@host` | 百分号编码，非加密 | 日志中即明文 |

```bash
echo "YW5kcmVmaW46cGFzc3dvcmQ=" | base64 -d; echo
# 看 JWT 的 header / payload（签名验证不了不代表内容是假的）
python3 -c "
import base64, json
t = open('token.txt').read().strip().split('.')
for n, s in zip(('header','payload'), t[:2]):
    print(n, '=', json.loads(base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))))
"
```

> **报告中的正确表述**："该文件包含 base64 编码的 Kubernetes 服务账户令牌，**任何持有该文件的主体均可直接使用该令牌访问集群**。"——写成"该文件包含加密的令牌"是错误的，会让后续处置走错方向。

<a id="section-10"></a>

### 2.8 Linux 与云环境中的配置凭据

| 路径 | 内容 | 要点 |
|---|---|---|
| `/etc/shadow` | `$y$`=yescrypt（libxcrypt 默认）/`$6$`=SHA-512 crypt | 强，hashcat 难破（模式 1800） |
| | `$1$`=MD5 crypt | **老旧，insecure**，hashcat 模式 500，秒破 |
| | `$2y$`/`$2b$`=bcrypt | 强，模式 3200 |
| `/etc/mysql/*.cnf` | `[client]` 段的 `user`/`password` | **通常明文** |
| `docker-compose.yml` / `.env` | `MYSQL_ROOT_PASSWORD`、`*_PASSWORD=` | **通常明文** |
| `~/.pgpass` | `host:port:db:user:password` | 明文，格式规整 |
| `~/.aws/credentials` | `aws_access_key_id` / `aws_secret_access_key` | **明文** |
| `~/.aliyun/config.json` | `accessKeyId` / `accessKeySecret` | **明文** |
| `~/.kube/config` | 集群地址 + base64 token + client 证书 | base64 |
| `~/.config/gcloud/credentials.db` | SQLite，blob 已加密 | 需解 DPAPI 类保护 |
| `~/.azure/accessTokens.json` | 访问令牌 | JSON 明文 |

> **取证价值排序**：云厂商的 `accessKeySecret` 是**明文**的，且通常同时拥有**创建/删除实例、读取对象存储**的权限，**泄露影响面远超单个应用口令**。报告中应标注权限范围，但**不得写入完整 key 值**。

---
<a id="section-11"></a>

## 三、操作步骤

<a id="section-12"></a>

### 步骤 1：确定是加密还是损坏

三件事各跑一条命令：`file` + `xxd` 看文件头、熵值看随机度、用对应工具试探（报错信息本身就是证据）。

完整命令见第七节，此处只强调判读规则：

- `sqlite3` 报 `file is not a database` → 可能是加密，**也可能是损坏**，必须结合文件头判断。
- 熵值 > 7.5 → 只是"高度随机"，压缩与损坏同样高熵，**不能直接定性**。
- 截断的镜像、坏道、编码错配都表现为"打不开"，**先确认镜像完整性再谈加密**。

<a id="section-13"></a>

### 步骤 2：确定加密层级

一条命令定性：**能列目录 = 应用层，整块乱码 = 文件系统层**。

```bash
mount -o ro,loop DigiForensics.dd /mnt/image
ls /mnt/image/var/lib/mysql/                        # 能列目录 = 应用层
file /mnt/image/var/lib/mysql/ibdata1                # 正常 InnoDB → 应用层
mount -o ro,loop DigiForensics.dd /mnt/x 2>&1 | tail -1   # wrong fs type → 见 01/03 篇
```

<a id="section-14"></a>

### 步骤 3：MySQL 路径——从配置反查 keyring 并验证

命令见第七节 3。判读顺序：

1. `grep` 配置文件 → 命中 `keyring_file_data=` 说明主密钥路径明确，**主密钥不在 `.ibd` 里**。
2. 按路径取 keyring，**保留时间戳**（`cp --preserve=timestamps`）。
3. `openssl pkey -inform DER` 只能作**格式线索**，不是验证手段——InnoDB 的密钥材料是 `SECRET` 类型，本就不是 DER 私钥。
4. **决定性验证**：把 keyring 挂到**同版本**实例上 `SELECT` 加密表。跨版本可能读不出密钥，**这一条必须写进报告方法论**。

<a id="section-15"></a>

### 步骤 4：SQL Server 路径——找证书

命令见第七节 7，**全部在原实例的克隆上执行**。判读要点：

1. `msdb.dbo.master_keys` 的 `pvt_key_encryption_type_desc` 告诉你私钥受**密码**还是**Windows 服务账户**保护 → 决定下一步要什么材料。
2. 有 `.bak` 又有 `.cer` 才可能恢复；`pvt_key_encryption_type` 为密码时还要拿到该密码。
3. 恢复后 `SELECT COUNT(*)` 能返回行数才算验证通过。

<a id="section-16"></a>

### 步骤 5：配置凭据的批量清点

用第七节 5 的两条命令做广度扫描，再对命中的文件逐个判断：**明文 / base64 / 真正加密**（判据见 2.7）。

> 同类"客户端连接凭据"（Navicat、Xshell、FinalShell、DBeaver 等）的定位与离线解密方法见 [远程工具凭据解密](crypto-app-remote-tool-credential-preservation.md)。

<a id="section-17"></a>

### 步骤 6：可运行的批量识别脚本

**只用 Python 标准库**。它给出的是**线索**而非定性结论（见 2.2 的取证纪律）。

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scan_encrypted.py — 批量识别文件的编码/加密/损坏特征（只读）
用法：python3 scan_encrypted.py /mnt/image/var/lib/mysql"""
import os, sys, math, collections

MAGIC = [(b"SQLite format 3\x00", "SQLite 数据库"), (b"PK\x03\x04", "ZIP/OOXML(docx,xlsx)"),
         (b"Rar!\x1a\x07", "RAR 压缩包"), (b"7z\xbc\xaf\x27\x1c", "7-Zip 压缩包"),
         (b"%PDF", "PDF"), (b"\xff\xd8\xff", "JPEG"), (b"\x89PNG", "PNG"),
         (b"\xd0\xcf\x11\xe0", "OLE2 复合文档(旧 Office/MSG)"), (b"-----BEGIN", "PEM 证书/私钥"),
         (b"eyJ", '疑似 JWT(header 为 base64url 的 {"alg")')]
BOMS = [(b"\xef\xbb\xbf", "UTF-8 BOM"), (b"\xff\xfe", "UTF-16 LE BOM"),
        (b"\xfe\xff", "UTF-16 BE BOM")]

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = collections.Counter(data)
    n = len(data)
    return -sum(v / n * math.log2(v / n) for v in c.values())

def sqlcipher_suspect(head: bytes) -> bool:
    """SQLCipher 无 magic：前 16B 是随机 salt，但偏移 16 处仍是合法 SQLite 页结构。
    16 字节理论最大熵正好 4.0，所以不用熵阈值，改用字节种类丰富度。"""
    if len(head) < 100 or head.startswith(b"SQLite format 3\x00"):
        return False
    if len(set(head[:16])) < 12:        # 正常 SQLite 文件头字节种类很少
        return False
    return head[16] in (0x0D, 0x00, 0x01, 0x02)

def classify(path: str) -> str:
    try:
        with open(path, "rb") as f:
            head, body = f.read(4096), f.read(65536)
    except PermissionError:
        return "权限不足（需以合适权限只读挂载后重试）"
    except OSError as e:
        return f"读取失败: {e}"
    for sig, name in MAGIC:
        if head.startswith(sig):
            return f"已识别类型: {name}"
    for sig, name in BOMS:
        if head.startswith(sig):
            return f"已识别类型: {name}（可能是编码问题而非加密）"
    h = entropy(body)
    if sqlcipher_suspect(head):
        return f"疑似 SQLCipher（前16B随机salt，偏移16处为SQLite页结构，熵={h:.2f}）—— 需用 PRAGMA key 复验"
    if h > 7.5:
        return f"高熵 {h:.2f} —— 疑似加密或压缩，**需进一步确认**，不能直接定性"
    return f"低/中熵 {h:.2f} —— 多为明文或类型未识别的结构化数据"

def walk(root: str, limit=2000):
    n = 0
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            p = os.path.join(dirpath, fn)
            try:
                print(f"{p}\	{os.path.getsize(p)}\	{classify(p)}")
            except OSError:
                continue
            n += 1
            if n >= limit:
                print(f"...已达上限 {limit}"); return

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    walk(sys.argv[1])
```

```bash
sudo mount -o ro,loop DigiForensics.dd /mnt/image
python3 scan_encrypted.py /mnt/image/var/lib/mysql | head -40
```

---
<a id="section-18"></a>

## 四、常见陷阱

本章按「识别加密形态 → 定位密钥材料 → 执行解密与验证 → 结论表述与最小化」归组，每条给出：现象、为什么会误判、误判代价、正确做法。
★ 标记表示该操作会导致原始检材永久灭失或不可逆改变，执行前必须停下来确认。

<a id="section-19"></a>

### 4.1 识别加密形态：把"打不开"归因到错误的原因

<a id="section-20"></a>

#### 陷阱 1：把"打不开"一律归因为加密

**现象**：某个 `.db` 文件用 `sqlite3` 打开报 `file is not a database`，报告直接写"该库已加密"。

**原因**：**"打不开"在取证里至少有五种成因**（见 2.1 的对照表），而 `file is not a database` 这一条报错本身就有两种合法解释——文件被 SQLCipher 之类整体加密，或者文件只是被截断、被坏道打坏、页结构错乱。

`sqlite3` 只看第 100 字节的页头魔数，**它不区分"魔数被人为换掉"和"内容本身烂掉"**。而镜像层面的问题更常见：全盘镜像如果不是完整读取（坏道跳过、dd 提前退出、目标盘写满），切出来的分区尾部会是一段空洞，解析器读到哪里算随机。

**影响**：把成像缺陷报告成"数据被加密"，委托方接下来会要求你"解密"，而这条线索实际上应该回到成像环节重做。更糟的是它会掩盖真实成因——如果是坏道导致的缺失，真正该回答的问题是"哪些数据没取到"，这直接关系到证据的完整性表述。

**核查**：定性加密必须三件事同时满足：

```bash
# 1) 镜像层面先排除：分区大小是否与设备标称容量一致
fdisk -l DigiForensics.dd            # 分区末扇区 × 扇区大小 vs 设备容量
# 2) 文件层面看头：真加密=头随机，损坏=头通常还在
xxd -l 64 DigiForensics-t_user.ibd
# 3) 分辨率层面看报错语义：SQLite 两种错误文案不同
sqlite3 DigiForensics-t_user.ibd "SELECT count(*) FROM sqlite_master;"
```

**报告写法**：在排除镜像完整性之前，只能写"该文件头不符合已知格式魔数，成因待定（疑似加密或损坏）"，不能写"已加密"。

<a id="section-21"></a>

#### 陷阱 2：用高熵值或 `file` 报 `data` 定性为加密

**现象**：熵值算出 7.92，`file` 命令输出 `data`，于是写"该文件已加密"。

**原因**：**熵只是"随机度"，不是"机密性"**。

所有经过无损压缩或强加密的块都会趋近 8.0；反过来，一个被截断到只剩高熵片段的正常数据库同样会得到 7.9。`file` 命令靠 magic 表匹配，**没有 magic 的格式一律报 `data`**，而 SQLite 之外的很多合法格式（某些序列化的 `.bin`、固件 blob、protobuf 消息流）本来就没有 magic。

这两个判据的假阳性来源完全不同，但都指向"高随机"这一个现象。

**影响**：这是本领域最常见的定性过度——"已加密"是一个会改变委托方后续所有动作的结论，它意味着"需要口令/密钥"，也意味着"没有密钥就是死路"。定性错了，案件会卡在一条根本走不通的路上。

**核查**：熵和 `file` 只能用作**筛选器**，不能用作**结论**。

定性加密要求存在第二个独立证据：对应工具的特定报错文案、密钥材料在检材中确实存在、同一目录下其他文件呈现同类特征、跨文件的一致性。

报告里写"高熵（7.92）且对应工具报 `bad decrypt`，判定为加密"，而不是"熵值高，故加密"。

<a id="section-22"></a>

#### 陷阱 3：以为 SQLCipher 有固定文件头 magic

**现象**：脚本按 `SQLite format 3\0` 魔数扫描，报告"未发现任何加密 SQLite 库"，结论是"检材内无应用层加密数据库"。

**原因**：**SQLCipher 没有固定 magic**（见 2.2 的更正）。

它把 SQLite 页头的前 16 字节当作随机 salt 覆写，因此扫描器看到的是"魔数不对的 SQLite"，而不是"某个已知的加密库 magic"。魔数扫描是格式识别工具，它在原理上就找不到没有魔数的格式。

**影响**：这是一条缺乏覆盖范围支撑的**否定性结论**，可能让"数据库被加密且已删除"这类真实情形被写成"检材中无相关加密痕迹"，且这个错误在报告里完全无声。

**核查**：识别 SQLCipher 要用组合特征，判据见 2.2 与第七节 1 的脚本：前 16 字节字节种类异常丰富（正常 SQLite 文件头这段字节种类很少），且**偏移 16 之后仍是合法的 SQLite 页结构**。

批量扫描时把该判据写成独立的一类输出，不要依赖 `MAGIC` 列表。

<a id="section-23"></a>

### 4.2 定位密钥材料：找错文件、找错版本

<a id="section-24"></a>

#### 陷阱 4：拿到加密 `.ibd` 就以为能解

**现象**：检材里找到 `t_user.ibd` 且 `INNODB_TABLESPACES` 显示 `ENCRYPTION='Y'`，报告写"加密表已定位，数据可恢复"。

**原因**：**MySQL InnoDB 的表空间加密是三层结构**（2.3）：`.ibd` 里的数据是用 tablespace key 加密的，tablespace key 又被 master key 加密，而 master key 存在**独立的 keyring 文件**里，不在 `.ibd` 里。

这是密钥分层存放的通用设计——把数据文件和解钥材料放在同一个目录，等于没加密。只拿到 `.ibd` 拿到的是一整块高熵密文，缺了 keyring 什么也做不了。

**影响**：「数据可恢复」是一个关于**未来可恢复性**的承诺，委托方往往据此决定是否继续投入。写成之后才发现 keyring 不在检材里，报告的可信度受损，且要回头向委托方解释"可恢复性尚未确认"。

**核查**：判断可解密性按三步走，且**结论落在第三步**：

```bash
# 1) 从配置反查 keyring 路径（注意插件与组件两套配置都要看）
grep -rniE "keyring" /mnt/image/etc/mysql/my.cnf
# 2) 按路径取 keyring 文件，保留时间戳
cp --preserve=timestamps /mnt/image/var/lib/mysql-keyring/keyring \
   ./DigiForensics-masterkey.bin
# 3) 决定性验证：在同版本实例上实际 SELECT 加密表（见下条）
```

在第 3 步完成前，报告只能写"已定位加密表与 keyring 文件，二者对应关系待验证"。

<a id="section-25"></a>

#### 陷阱 5：keyring 能被 `openssl` 解析，就认为能解表空间 ★

**现象**：`openssl pkey -inform DER -in DigiForensics-masterkey.bin -text` 成功输出了私钥结构，报告直接写"密钥提取成功，加密数据已解密"。

**原因**：解析成功只证明"这是一个合法的密钥材料容器"，不证明"它是这个实例的 master key"。

keyring 是**密钥后端**，记录格式随实现而变，OpenSSL 解析成功只说明"其中存在一段能被当作非对称私钥解析的字节"——它既可能是真的私钥记录，也可能是恰好符合 DER 结构的其他数据。**同一容器里可能有多条密钥**（多个实例、多次轮转、历史版本都留痕），而 `.ibd` 的 tablespace key 是被**特定那一条** master key 加密的。

选错了密钥，后面所有操作都会在"解不开"这个症状上打转。此外还有版本因素（见下条）。

**影响**：这是**"以为自己找到了"**的典型形态。报告一旦写"已解密"，委托方会直接采用解密内容做后续处置（交给执法、通知数据主体、用于诉讼），而这些内容其实一行都没解出来——**下游所有环节都建立在空结论上**。

**核查**：把 `openssl` 的成功严格限定为"确认是密钥材料"，解密与否只看实际查询：

```sql
-- 在与检材同版本的实例上，指向该 keyring 后执行
SELECT SPACE, NAME, ENCRYPTION FROM INFORMATION_SCHEMA.INNODB_TABLESPACES
 WHERE ENCRYPTION = 'Y';
SELECT COUNT(*) FROM t_user;   -- 能返回行数，才叫解密成功
```

报告里"提取到密钥材料"与"数据解密成功"是两句不同的话，必须分开写。

<a id="section-26"></a>

#### 陷阱 6：用错版本实例验证 keyring

**现象**：检材里是 MySQL 8.0.32，取证机上装的是最新版本 8.4，指向该 keyring 后查 `INNODB_TABLESPACES`，加密表列表为空，于是判定"keyring 与数据库不匹配，密钥失效"。

**原因**：**keyring 的记录格式与加载机制随版本变化**。

插件方式（`early-plugin-load=keyring_file.so`）与组件方式（`component_keyring_file.so`）是两套完全不同的实现，8.0.34 之后 `keyring_file` 插件已弃用，新部署走组件。

用错实现，读不出密钥是预期结果，与密钥本身是否正确无关。 跨版本还可能遇到 InnoDB 表空间格式版本、重做日志格式等一串兼容性问题。

**影响**：会把"工具不兼容"误判成"证据不具备可恢复性"。前者是你能解决的问题，后者是一个关于案件可行性的负面结论——一旦写进报告，委托方很可能就此终止投入，而真相只是版本没对上。

**核查**：验证环境必须**与检材版本严格一致**，并在报告的方法论部分写明这一点：

```bash
# 先从检材自身确认版本，不要凭包管理器或镜像里的默认版本
strings /mnt/image/usr/sbin/mysqld | grep -m1 -oE '8\.0\.[0-9]+'
# 再按 2.3 的 SQL 确认检材用的是插件还是组件
#   插件 → keyring_file_data ；组件 → component_keyring_file_data ；两者都要查
```

**报告写法**："因密钥容器格式随 MySQL 版本变化，本项验证在与检材一致的第 X.Y.Z 版本实例上完成；若版本无法复现，则结论为'密钥与表空间的对应关系未验证'。"

<a id="section-27"></a>

### 4.3 执行解密与验证

<a id="section-28"></a>

#### 陷阱 7：★ 在原始检材或原始服务器上执行 `BACKUP CERTIFICATE`

**现象**：为了导出 SQL Server 的 TDE 证书，直接在委托方的生产实例上跑了 `BACKUP CERTIFICATE` 与 `BACKUP SERVICE MASTER KEY`，把 `.cer` 和 `SMK.bak` 写到了 `C:\evidence\`。

**原因**：这类导出语句在 DBA 语境里完全是常规操作，**但取证语境里它是对证据载体的写入**。

它会在原始卷上新建文件、改动 MFT 记录与目录时间戳，如果目标路径落在待分析的数据目录内，甚至可能覆盖业务文件。

更关键的是：它同时**把受保护的私钥以明文形式落到了磁盘上**，一旦该目录也在取证范围内，等于给检材增加了一份本不该存在的新材料。

**影响**：**原始检材被改变，完整性论证出现缺口。** 之后所有基于该实例得出的结论，都要额外解释"这些文件是我们写入的，不是原有的"。如果案件涉及争议或需要向对方提供"未经改动的原始副本"，这一动作可能直接让材料无法使用。

**核查**：**任何写操作都在克隆或恢复副本上进行**（2.5 已强调）：

```sql
-- 正确顺序：先恢复 .bak 到一个独立实例，再在恢复副本上导出
USE master;
OPEN MASTER KEY DECRYPTION BY PASSWORD = '<SMK 密码>';
BACKUP CERTIFICATE [TDE_Cert] TO FILE = 'C:\evidence\TDE_Cert.cer'
  WITH PRIVATE KEY (
    FILE = 'C:\evidence\TDE_Cert.pvk',
    ENCRYPTION BY PASSWORD = '<私钥保护密码>'
  );
BACKUP SERVICE MASTER KEY TO FILE = 'C:\evidence\SMK.bak';
```

**动手前的检查清单**：目标实例是恢复副本而非原实例、导出目录不在待分析范围内、已记录副本与原镜像的哈希一致性。MySQL 的 `keyring` 文件也同理——只读取与复制（`cp --preserve=timestamps`），绝不在原镜像上让实例去写它。

> 补一条容易被忽略的完整性要求：`BACKUP CERTIFICATE` **必须带 `WITH PRIVATE KEY`**。漏掉它时命令照样成功、`.cer` 照样生成，但那只有公钥——**拿到一个"看起来导出成功"的目录，却不具备恢复条件**。

<a id="section-29"></a>

#### 陷阱 8：把单向哈希的"解不开"当成失败，反复换工具

**现象**：`ToDesk` 的 `access_pin_hash`、AnyDesk 的 `ad.anynet.pwd_hash` 用各种工具试了一遍都没出明文，分析员判断"工具不对"，转而去找流解密工具。

**原因**：**这些字段本来就不是加密，是单向哈希**（2.2 的第四种格式）。`access_pin_hash` 是 PBKDF2-SHA256 加盐的输出，AnyDesk 是 `pwd_hash` + `pwd_salt` + `token_salt` 三件套。单向函数没有逆运算，找错工具不是因为工具弱，而是因为这个方向不存在。

继续换工具只会浪费时间，且很容易在这个过程中滑向对检材的越权操作。

**影响**：一是浪费算力与工时；二是**报告里会出现"无法解密"这种含糊表述**，而正确表述是"该字段为加盐单向哈希，本阶段不可还原，其存在本身即证明该设备设置了访问口令"。三是一个真实风险——为找"能解的工具"而尝试在线撞库，性质已经从取证变成攻击。

**核查**：按格式分流（2.2 的四种格式），单向哈希这一类**到此为止**，只固定三件事——字段名、所在文件路径、文件修改时间。弱口令的离线验证走 [04 通用密码恢复](crypto-app-passware-and-password-recovery.md) 的方法论，并且**用自制样本先自测工具**。

<a id="section-30"></a>

### 4.4 结论表述与最小化

<a id="section-31"></a>

#### 陷阱 9：把 base64 写成"加密"，导致处置方向跑偏

**现象**：`~/.kube/config` 里的 `token` 字段、`.docker/config.json` 的 `auth` 字段是长串 base64，报告写成"该文件包含加密的访问令牌"。

**原因**：**base64 是公开的可逆编码，不提供任何机密性**（2.7 的完整对照表）。

它的字符集只有 `A-Za-z0-9+/=` 加上可能的 `=` 补位，人眼一眼就能看出"这不是密文"，但**"长串看不懂的字符"与"密文"在直觉上很像**。

同一类还包括 JWT——header/payload 是 base64url 明文，只有签名是 HMAC，而**签名不可验证不代表内容是假的**。

**影响**：方向性错误。"加密"暗示需要暴力破解或申请密钥，会把调查引向不存在的技术难点；而"base64"意味着**任何拿到文件的主体都可以直接使用该凭据**——这是两种完全不同的风险定级。委托方读到"加密"会低估泄露影响面，读到"base64"才会启动凭据轮换。

**核查**：报告里的表述按 2.7 的示例写——"该文件包含 base64 编码的 Kubernetes 服务账户令牌，任何持有该文件的主体均可直接使用该令牌访问集群"。判别只需一条命令：

```bash
echo "<字段值>" | base64 -d 2>/dev/null; echo
# 能出可读 ASCII → 是编码不是加密
```

<a id="section-32"></a>

#### 陷阱 10：在报告正文里写入完整凭据

**现象**：报告附件里贴出 `aws_secret_access_key`、数据库口令、连接串的完整值，说是"便于复核"。

**原因**：复核确实需要知道"拿到的是什么"，于是自然地把值本身写进去。

但取证报告的传播范围通常远大于分析环境——它会给委托方、可能进卷宗、可能在质证环节公开。凭据是二次泄露的源头，而报告恰恰是最容易被广泛传阅的那份文件。

**影响**：泄露影响面极大。案例中那个具备 S3 读权限的 AK 一旦流到公开渠道，**责任在报告作者而不在原始泄露者**，而这通常也构成新的安全事件，需要立刻启动凭据轮换与事故通报。

**核查**：报告正文只写**存在性、类型、归属、权限范围、所在路径**，值本身按最小化原则处理：

- 云 AK/SK：只写账号 ID、权限范围（能读哪些资源）、所在文件路径；
- 数据库与系统口令：只写哈希位置、算法、验证过程，明文单独受控存放；
- 需要复核时，用"字段 + 掩码前后若干位 + 校验方式"替代完整值。

**同一原则适用于云凭据这类附带发现**：它们不在委托范围内，但**必须被发现并上报**，只是上报格式受最小化约束。

<a id="section-33"></a>

## 五、案例示例

<a id="section-34"></a>

### 5.1 MySQL keyring 加密表：应用层加密的识别与验证闭环

**场景**

查获一台 Ubuntu 22.04 的电商服务器（`DigiForensics.dd`，2 TB）。委托方（平台方）需要证明「用户资料表已被加密，且该表内容包含手机号等个人信息」。

注意：本案诉求是「数据是否被加密、能否读取」，不是「谁加密的」。

这条路径值得先走，是因为**「加密表空间」在文件系统层面完全不可见**。`.ibd` 文件就是普通文件，`mount` 成功、`ls` 正常，只有把表读出来才能确认它是加密的。

**处置过程**

第 1 步，确认镜像完整性并排除成像问题：

```bash
fdisk -l /evidence/DigiForensics.dd
# 文件系统有非致命错误 → 记录在案，但不影响后续只读挂载
```

第 2 步，判断加密层级——这一步只有一条命令，却决定后续全部工作方向：

```bash
mount -o ro,loop /evidence/DigiForensics.dd /mnt/est
ls /mnt/est/var/lib/mysql/
# ibdata1  ib_logfile0  t_user.ibd  t_order.ibd    ← 能列目录
# 结论：不是卷级加密，是应用层
```

第 3 步，读取配置判定加密实现方式：

```bash
grep -rniE "keyring|encryption" /mnt/est/etc/mysql/
# early-plugin-load=keyring_file.so
# keyring_file_data=/var/lib/mysql-keyring/keyring     ← 插件方式，非企业版 TDE
```

MySQL 版本从镜像中的二进制确认，**这一步不能靠配置文件里的注释**。

第 4 步，提取 keyring：

```bash
icat -o 2048 /evidence/DigiForensics.dd <keyring-inode> > /evidence/DigiForensics-masterkey.bin
openssl pkey -inform DER -in /evidence/DigiForensics-masterkey.bin -noout -text 2>&1 | head -5
# ↑ 仅作格式线索：InnoDB 用 SECRET 类型密钥材料，本就不是 DER 私钥，
#   解析成功不能证明这就是本实例的主密钥，也不能证明能解开表空间
# 能解析出私钥结构 → 确认是密钥材料（但还不能证明能解密）
```

第 5 步，**受控环境验证（决定性步骤）**：搭建**同版本**（8.0.32）MySQL 指向该 keyring。

```bash
mysqld --keyring_file_data=/evidence/DigiForensics-masterkey.bin --datadir=/mnt/est/var/lib/mysql
mysql> SELECT tablespace_name, encryption FROM information_schema.INNODB_TABLESPACES
   ->   WHERE encryption='Y';
# users.t_user_ibd      ← 确认哪几张表是加密的
mysql> SELECT COUNT(*) FROM t_user;
# 返回行数             ← 决定性证据：加密表能被读取
```

第 6 步，交叉印证外泄（**与解密是两件事**）：

```bash
mysql> SELECT * FROM mysql.general_log WHERE argument LIKE '%SELECT%t_user%';
# 2024-03-11 一次全表导出，客户端 IP 位于境外 → 直接回答「数据有没有被拿走」
```

第 7 步，附带发现的云凭据按最小化处理：

```bash
grep -rn 'aws_secret_access_key' /mnt/est/root/.aws/credentials
# 存在具备 S3 读权限的 AK → 只记录「存在 + 前 4 位 + 账号 ID + 权限范围」
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 该表处于加密表空间状态 | `INNODB_TABLESPACES.encryption='Y'` | 强 |
| keyring 内含对应密钥材料 | `openssl pkey` 可解析 | **弱**（仅为格式线索，非决定性） |
| 该密钥可解密此表 | 同版本实例成功执行 `SELECT` 返回行数 | **强（唯一决定性判据）** |
| 数据曾被导出至境外 | `general_log` 记录 + 客户端 IP | 强（需 general_log 已启用） |

**不能证明的**：本次**未确认加密操作由谁执行**——keyring 文件的 MFT/Mtime 只能说明文件何时被改动过，不能区分是 DBA 按规范配置、还是入侵者加密后勒索。

**keyring 与 MySQL 版本必须匹配**，用 8.4 打开 8.0.32 的 keyring 可能读不出密钥，这一点要写进报告的方法论部分。

**误判对照**

本案最容易犯的错误是因为数据读不出来，就判定「数据库被整盘加密了，磁盘级加密无法突破」。

**为什么这个推断不成立**：第 2 步已经给出了反证——`mount -o ro,loop` 成功且能列出 `.ibd` 文件。**卷级加密下系统根本挂载不上去**，能看到目录结构就说明加密发生在应用层，密钥就在镜像内部，路径是完全通畅的。

**正确判据有两条**：

1. **用能否挂载 + 能否列目录来定位加密层级**。`mount` 成功且 `.ibd` 可见 → 应用层；挂载失败但分区类型 GUID 指向加密 → 卷级。两个层级的处置路径、所需材料、委托方配合方式完全不同，判错层级会让整条路径走偏。
2. 用 `INNODB_TABLESPACES.encryption` 确认是「表级」而非「库级/表空间级」。**只有确认到具体哪些表加密，才能判断解密范围**——本案只有 `t_user` 加密，误判成全库加密会让工作量估算与结论范围都出错。

**按错误判据走的代价**：把应用层加密误判为卷级加密，报告结论会变成「数据因技术加密不可获取」。委托方据此向监管报告或对用户作出「数据已不可恢复」的告知，**而事实上数据当天就能读出来**。这类结论一旦作出，纠正成本极高，且会直接损害委托方对报告的信任。

<a id="section-35"></a>

### 5.2 密钥结构可解析但读不出数据：版本不匹配的假失败

**场景**

另一台 Ubuntu 22.04 服务器，同样是 MySQL keyring。分析员把 keyring 拷出来，`openssl` 能正常解析出私钥结构，于是认为"密钥材料没问题"，**但在实例上执行查询时报错中止**。

若就此收工，结论会写成「密钥材料损坏，不具备解密条件」。

**处置过程**

按版本与格式逐层排除：

```bash
# 第 1 步：从二进制与配置确认两端的真实版本，而不是靠配置文件注释
file /mnt/est/usr/sbin/mysqld
mysqld --version
# /usr/sbin/mysqld  Ver 8.0.32 for Linux on x86_64
grep -rn 'early-plugin-load' /mnt/est/etc/mysql/
```

```bash
# 第 2 步：用取证机上的版本复现，注意必须是同版本
mysqld --version
# Ver 8.4.1     ← 版本不同，这正是本次失败的直接原因

# 第 3 步：切回同版本实例后再验证
mysqld --keyring_file_data=/evidence/DigiForensics-masterkey.bin \
       --datadir=/mnt/est/var/lib/mysql --innodb_undo_tablespaces=0
mysql> SELECT COUNT(*) FROM t_user;
# 返回行数
```

第 4 步，把版本要求写进方法论说明，并固定证据：

```bash
printf 'keyring_offset=0x%x\
mysqld_version=%s\
recovery_mysql_version=%s\
' \
  <keyring偏移> '8.0.32' '8.0.32' > /evidence/tde-offsets.txt
```

**结论**

- 首次失败**不是密钥不可用**，而是**验证环境版本与检材版本不匹配**。换回同版本实例后解密成功。
- **未覆盖范围**：本次未验证该 keyring 是否对**其他数据目录**（如其他实例的独立 datadir）同样有效，也未确认 keyring 中是否还包含未在 `INNODB_TABLESPACES` 中出现的、已废弃表空间的密钥。
- 报告必须写明**验证实例的版本号与检材版本号的对应关系**，否则「已解密」这个结论无法被复核。

**误判对照**

错误结论是「keyring 已损坏 / 密钥材料不完整，无法解密」。

**为什么它容易出现**：`openssl pkey` 成功给人很强的心理暗示——「密钥结构没问题，那问题应该在密钥内容」。

于是顺着「密钥坏了」的方向继续排查，甚至推断「入侵者在加密过程中损坏了密钥」。但格式可解析与内容可用是两回事，两者之间隔着版本这一层。

**正确判据有三条**：

1. 必须比对 `mysqld --version` 的两端取值。**验证环境版本 ≠ 检材版本**时，失败信息不具参考价值，应直接排除而不是解读。
2. `openssl` 解析成功只证明「其中存在一段结构合法的密钥字节」，既不能证明那是本实例的主密钥，也不能证明「这个密钥对得上本实例的表空间」——InnoDB 用的是 SECRET 类型密钥材料，本就不是 DER 私钥。跨版本、跨实例的 keyring 都可能解析成功但解不开。
3. **必须在与检材完全一致的版本上重试一次**，才允许写「无法解密」。

**按错误判据走的代价**：写下「密钥已损坏」之后，委托方会认为数据永久灭失，从而放弃解密诉求、转向其他赔偿或合规处理。而真相只是换了个版本的实例就解开了。一个基于错误前提的「不可恢复」结论，会直接终结掉一条本来通畅的取证路径。

<a id="section-36"></a>

### 5.3 反例：附带云凭据的最小化上报边界

**场景**

在 5.1 的同一台服务器上，还发现了 `/root/.aws/credentials` 里有明文 `aws_secret_access_key`，且该 AK 具备 S3 读权限。**它与委托方要问的「用户表是否加密」毫无关系**，但它出现在检材里。
**处置过程**

按范围与最小化双重约束处理：

```bash
# 1. 记录存在性与权限范围，不复制完整值
icat -o 2048 /evidence/DigiForensics.dd <credential-inode> > /evidence/aws-credentials
python3 -c "import configparser;c=configparser.ConfigParser();c.read('/evidence/aws-credentials');\
print('profile=%s key_prefix=%s' % (c.sections()[0], c['default']['aws_access_key_id'][:4]))"
# profile=default key_prefix=AKIA    ← 只到前 4 位

# 2. 用 API 只读列出该 AK 实际可见的桶，作为「权限范围」的客观证据
aws s3api list-buckets --profile <仅在受控环境使用>
```

**结论**

- 该凭据属**附带发现**：不在委托范围内，**必须上报而不是丢弃**，但**上报格式受最小化约束**。
- 报告正文写「在 `/root/.aws/credentials` 中发现具备 S3 读权限的访问密钥（前 4 位 `AKIA`），已按最小化原则记录」，完整值作为受控附件单独封存，**并明确提示委托方立即轮换**。
- **不能证明的**：本次**未使用该 AK 访问任何 S3 资源**。「具备读权限」来自凭据文件中的策略声明与 API 列举结果，**不等于已发生数据外泄**。
- **未覆盖范围**：未检查云端 CloudTrail 侧的访问记录（需云服务商配合），**因此无法判断该 AK 在检材形成前是否已被使用**。

**误判对照**

两种方向的错误都很常见，一种是把范围外凭据丢掉，另一种是**把凭据完整值直接抄进报告正文**。

**为什么第二种更危险**：报告正文会流转给委托方的法务、业务、乃至对方当事人，而完整的 AK/SK 一旦进入正文流转链，就等于**把一个可用凭据分发到了最小授权范围之外**。

取证报告的传播范围通常远大于取证工作站——**在工作站上是受控的，在报告流转中就不是了**。

**正确判据有三条**：

1. **范围外的凭据必须上报**。丢弃会让委托方误以为「没有云凭据」，进而作出错误的风险评估——**这属于漏报，性质比格式问题严重**。
2. 正文只写「存在 + 类型 + 权限范围 + 位置」，不写完整值。位置写到文件路径即可，值一律脱敏。**判断标准是：这份报告会交给谁看。**
3. **必须同时写明「未使用该凭据」**。这一句把报告的责任边界划清，也避免委托方误以为取证方已经用该凭据访问过云端资源。

**按错误判据走的代价**：完整值进入报告正文后，一旦报告在多方之间流转，**该凭据的轮换成本与责任归属就会变得无法追溯**。

而如果只是丢弃不上报，委托方可能在毫不知情的情况下继续沿用一台已被查扣服务器上的云凭据。

两种做法一个是扩大暴露面，一个是制造漏报盲区——正确做法只有一个：上报，且按最小化格式上报。

<a id="section-37"></a>

## 六、扩展阅读方向

下面三组按"你在这条路上会卡在哪"组织。

第一组：判层级之后——不同数据库的密钥结构完全不同

- [MySQL 数据库取证](../../mobile/mobile-database/mobile-database-mysql.md) —— 读出 `.ibd` 内容之后，InnoDB 页结构、redo log、binlog 的解析路径都在那篇。本篇解决的是"能不能读"，那篇解决的是"读到之后怎么认字段、怎么排时序"。要往下走还需要商业 TDE 的对照：MySQL 企业版 File Keyring、AWS RDS/Glue 的 TDE 与外部 KMS 集成，它们的密钥都不在数据目录里。
- [数据库取证通用方法](../../mobile/mobile-database/mobile-database-database-forensics-methods.md) —— 引擎识别、时区处理、时间线重建。这三件事在加密场景解完之后立刻要用，而且**时区错误会让"数据被导出"的时间线整体偏移**，属于会一路传下去的错误。
- [BitLocker 全卷加密取证](../crypto-volume/crypto-volume-bitlocker.md) —— 层级判错时的上游。卷级加密下应用层那套"挂载、找配置、找 keyring"的路径全都不存在，两种形态的处置第一步就分岔。

**第二组：密钥从哪来——配置与内存两条线**

- [内存中的凭据与密钥](../../memory/memory-artifact/memory-artifact-memory-credentials-and-keys.md) —— 本篇 2.4 与 2.6 反复指向它。`pg_stat_activity`、SQLCipher 主密钥、连接串明文缓存都只在进程存活期间存在，关机镜像里一个都没有。这一条决定了"要不要赶在关机前取证"。移动端与嵌入式的对应议题也在这条线上：SQLCipher（`PRAGMA key`）参数与调优、Android 轻量数据库、iOS 数据保护（`kSecAttrAccessible`）的密钥都在应用侧而非系统侧。
- [远程工具凭据解密](crypto-app-remote-tool-credential-preservation.md) —— Navicat、Xshell、DBeaver 这类客户端的凭据定位与离线解密，方法论与本篇 2.7 同源：**先判明文 / base64 / 真加密，再选工具**。
- [EFS 文件系统加密取证](../crypto-volume/crypto-volume-efs.md) —— Windows 上的"文件级加密"。一台 Windows 服务器可能同时有 SQL Server TDE、EFS、DPAPI 保护的应用凭据三层，三层的密钥存放位置完全不同，判层级那一步在这里收益最大。SQL Server 侧的完整链条（SMK → DMK → DEK、`BACKUP SERVICE MASTER KEY` 的密码保护机制）见 2.5。

**第三组：判据与合规——结论怎么写、密钥能不能碰**

- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md) —— 陷阱 7 的 `BACKUP CERTIFICATE`、步骤 5 的"用哪个 AK 验证权限"，都属于"技术上能做但要先拿到授权"的动作。**哪一步之前必须有书面授权，这篇给判据。** HSM 与云 KMS 的职责边界同属这一组——这也是 `keyring_file` 被判定为不适用于合规场景的原因：密钥明文落在一个普通文件里，谁拿到那个文件谁就能解。
- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— keyring 的 Mtime、"谁加密的"这类推断都需要反证。本案"不能区分 DBA 配置与入侵者加密"这句话，本身就是一个需要这条方法论支撑的结论。 集群场景同理：K8s Secret 静态加密、`kubeconfig` 权限模型、etcd 落盘加密都会改变"配置里那份凭据还算不算秘密"这个判断。

**说明**：**应用层加密的密钥几乎总在镜像里。** 这和卷级加密的根本差别是——应用必须先读到密钥才能解密，所以密钥不可能只存在于硬件而不落盘。

因此本篇的顺序是：先判层级（一条挂载命令），再判加密还是损坏（报错语义 + 文件头），最后才找密钥。跳过前两步直接找密钥，是这一类分析里最常见的浪费。

<a id="section-38"></a>

## 七、命令速查

```bash
# ===== 1. 加密 vs 损坏 vs 编码 =====
file evidence.db ; xxd -l 64 evidence.db | head -4
python3 -c "
import math,collections
d=open('evidence.db','rb').read(65536);c=collections.Counter(d)
print('熵 =',round(-sum(v/len(d)*math.log2(v/len(d)) for v in c.values()),2))"
sqlite3 evidence.db "SELECT count(*) FROM sqlite_master;"   # 报错信息即线索
7z t evidence.zip 2>&1 | tail -3

# ===== 2. 层级判定 =====
mount -o ro,loop DigiForensics.dd /mnt/image
ls /mnt/image/var/lib/mysql/        # 能列 = 应用层；不能 = 见 01/03 篇

# ===== 3. MySQL keyring（验证 SQL 见 2.3）=====
grep -rniE "keyring|encryption" /mnt/image/etc/mysql/my.cnf
cp --preserve=timestamps /mnt/image/var/lib/mysql-keyring/keyring ./DigiForensics-masterkey.bin
openssl pkey -inform DER -in ./DigiForensics-masterkey.bin -text -noout 2>&1 | head -5
# ↑ 仅格式线索，非决定性；决定性验证是挂到同版本实例上 SELECT

# ===== 4. SQLCipher 离线验证 =====
sqlite3 evidence.db "PRAGMA key='<key>'; SELECT count(*) FROM sqlite_master;"

# ===== 5. Linux / 云配置凭据 =====
grep -rniE "password|passwd|secret|token|api[_-]?key" \
  /mnt/image/etc/mysql/ /mnt/image/opt/ /mnt/image/root/.pgpass 2>/dev/null | head -50
cat /mnt/image/root/.aws/credentials ; cat /mnt/image/root/.kube/config
echo "YW5kcmVmaW46cGFzc3dvcmQ=" | base64 -d; echo      # 验证 base64 不是加密
python3 -c "
import base64,json
t=open('token.txt').read().strip().split('.')
for n,s in zip(('header','payload'),t[:2]):
    print(n,'=',json.loads(base64.urlsafe_b64decode(s+'='*(-len(s)%4))))"

# ===== 6. 批量识别脚本 =====
python3 scan_encrypted.py /mnt/image/var/lib/mysql | head -40

# ===== 7. SQL Server（全部在克隆上执行，SQL 见 2.5）=====
sqlcmd -S localhost -E -Q "SELECT name, thumbprint, pvt_key_encryption_type_desc FROM msdb.dbo.master_keys;"

# ===== 8. PostgreSQL（应用层看配置，不是 pg_authid）=====
grep -rE "pgp_sym_decrypt|pgp_sym_encrypt|pgcrypto" /mnt/image/opt/ 2>/dev/null
# SELECT pid, usename, client_addr, state, query FROM pg_stat_activity WHERE state <> 'idle';
#   ↑ query 列可能残留解密函数与密钥，仅在运行时有效
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 加密取证 — 数据库与配置文件加密的识别与解密」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《数据库与配置文件加密的识别与解密》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.vc` 均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
