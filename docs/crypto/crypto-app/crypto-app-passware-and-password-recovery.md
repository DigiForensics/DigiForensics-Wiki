---
title: "Passware Kit 与通用密码恢复方法论"
slug: "crypto-app-passware-and-password-recovery"
canonical: "https://www.digiforensics.cn/wiki/crypto-app-passware-and-password-recovery"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:51+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "crypto"
space: "加密与密码取证"
node_path: ["应用与数据库加密"]
---

# Passware Kit 与通用密码恢复方法论

<a id="section-1"></a>

## 一、概述

前面几篇讨论的是**加密存储**：BitLocker 的 FVE metadata、EFS 的 `$EFS` 流、VeraCrypt 的卷头。它们有一个共同点——**密钥或密钥材料留在系统的某个可利用位置上**，取证是"找到它"的过程。

本篇处理的是完全不同的一类问题：当系统里没有留下任何可直接使用的密钥时，如何在合法授权下从哈希或密文中恢复口令。

在真实案件里，后一类远比前一类常见——用户自己设的口令、改过的文件密码、加密压缩包，主人都忘了或者不想说。

这个领域有一个特别容易让人走偏的特征：它在互联网上主要以"渗透测试"和"账号爆破"的面貌出现，几乎所有公开教程都默认目标是无授权的第三方系统。

而在取证语境下，操作顺序和合规约束与攻击场景有本质区别。

本篇最重要的一半内容是这些约束，而不是工具参数。

> ### ⚠️ 三条合规红线（写在这里，不是写在下文）
>
> **红线一：只能在有授权的检材上做。** 授权范围必须覆盖三件事：检材来源合法、恢复目的明确、恢复结果的使用方式被授权书限定。模糊的"客户送来的机器"不构成授权；"送来的机器"也不自动授权你去做 GPU 集群爆破。**把授权书和检材编号绑定归档**，开工前先记录。哈希爆破本身在多数司法辖区不必然构成犯罪，但未经授权对他人系统实施的行为落在计算机系统入侵的射程内，而密码恢复是侵入行为的典型前置动作。
>
> 红线二：暴力破解是「最后的手段」，不是「第一反应」。多数案件中不需要爆破。真实的口令来源，按实操价值排序是：
>
> | 优先级 | 来源 | 说明 |
> |---|---|---|
> | ★★★★★ | **证据内的明文残留** | 配置文件、脚本、聊天记录、Excel 表格、`.env`、shell 历史 |
> | ★★★★★ | **同机复用** | 同一用户换设备/换系统时复用了同一个口令 |
> | ★★★★ | **其他账户的口令** | 同一管理员在其他服务上用过同一口令 |
> | ★★★★ | **上下文候选** | 用户名、生日、车牌、项目名 + 用户习惯后缀 |
> | ★★★ | **键盘模式 / 掩码** | 仅在已知格式特征时（如"6 位生日"） |
> | ★★ | **纯暴力** | 仅在长度极短（如 4 位 PIN）时才现实 |
> | ★ | **彩虹表** | 对加盐现代格式几乎无用，见 2.4 |
>
> **先把上表走完，再考虑 hashcat。** 报告里要写清楚"为什么走了爆破"——跳过了同机复用分析就直接跑字典，说明流程有缺陷。
>
> 红线三：破解得到的口令涉及第三人隐私时，报告里要做脱敏与最小化。一条 NTLM 哈希背后可能是一个真实的人：他用于支付、邮箱、社保的同一个口令。写进鉴定报告的应该是——该哈希**存在于哪个文件的哪个偏移**、属于**哪个账户（RID / 域名）**、**是否能与本案的某个关键文件相互印证**。而不是"该账户口令为 `P@ssw0rd2024`"。**只有当口令本身是案件核心事实时**（例如它是受害者的胁迫来源、或是访问被删数据的唯一途径），才在受控附件中给出，且单独存放、加密、限定访问人。法庭上"我们拿到了口令"这句话，需要的是可复现的验证过程，不是口令本身。

**本篇处理的证据形态**（`*2john` 家族能处理的输入是理解本篇的第一步）：

| 证据 | 提取物 | 前提 |
|---|---|---|
| `SAM` hive | NTLM 哈希 + RID | hive 已离线提取 |
| `SECURITY` hive | 缓存域凭据、DCC（Meterpreter 格式） | hive 已离线提取 |
| `/etc/shadow` | crypt 格式串 | 需 root 读取权限记录 |
| Windows 凭据管理器 | 通用凭据 blob | `cmdkey /list` + 内存分析配合 |
| 加密文件（7z / RAR / Office / PDF） | 经 `*2john` 转换后的"哈希" | 必须先判断是加密还是压缩 |
| 抓包 | NetNTLMv2 / Kerberos / WPA 的 `.hc22000` | 需 [网络流量与 PCAP 取证](../../memory/memory-network/memory-network-pcap.md) 作为前置 |

**先确认文件类型**，再选择提取方式与恢复工具。

7z 的加密头、Office 的 Agile 加密、PDF 的标准安全处理器，处理方式与算力需求差了几个数量级。

用错方式的开局，往往导致用几倍的算力去攻一个根本不该攻的目标。

**在取证流程中的位置**：本篇属于**分析**环节的专项处理，通常在明文路径全部走完之后才被启用。

**上游依赖**是[镜像制作](../../imaging/imaging-acquire/imaging-acquire-disk-imaging-and-evidence-preservation.md)（所有提取都必须在已镜像的检材副本上做，原件不动）与[注册表取证](../../computer/computer-registry-log/computer-registry-log-registry-forensics.md)（SAM/SECURITY hive 的提取手法）。

[浏览器密码库与 Token 解密](crypto-app-browser-passwords-and-tokens.md)与[远程工具凭据解密](crypto-app-remote-tool-credential-preservation.md)产出的**单向哈希字段**，最终要按本篇的方法论决定是"固定存在性"还是"进入离线验证"。

**下游支撑**的是报告层。本篇的每一条产出都必须附带可复现的验证过程，方法论见[取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md)。

检材里有哪些可攻对象、每个对象的加密类型与算力可行性、非爆破路径是否已经穷尽、选定方式后能否恢复——以及，**恢复结果是否经过"实际打开"级验证**。

**"打不开"不等于"打不开"**——工具报 `no key` / `unsupported` / `Invalid hash` 在多数实现里语义并不统一，很可能只是"我没读懂这个格式"。

KDF 强度高的格式（密码管理器主密码）通常只能靠线索，不能靠算力。

以及最重要的一条：本篇不提供针对特定真实目标的口令字典、默认口令库或任何绕过技巧。方法论与纪律，不等于能解开任何东西。

**读者前提**：你需要先理解哈希与完整性校验在取证中的双重角色（既用来验证证据，也用来做口令验证，见[哈希与完整性校验](../../fundamentals/fundamentals-concepts/fundamentals-concepts-hashes-and-integrity-verification.md)）、授权书与委托证明的基本要求（[证据保管链与委托证明](../../fundamentals/fundamentals-chain/fundamentals-chain-chain-of-custody-and-authorization.md)）、以及 GPU 算力的基本概念。

如果你还没有确定委托范围，先不要读下面的操作步骤。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 商业工具的定位：Passware Kit 的模块划分

Passware Kit Forensic 是这个领域最常见的商业方案（"Passware"本身即源自 "Password Recovery Software"）。

理解它的模块划分，等于理解了整个取证密码恢复的能力地图。

| 模块 | 作用 | 与开源工具的差异 |
|---|---|---|
| **Find Encrypted Files** | 全盘扫描并报告所有加密文件/容器及其加密类型与复杂度 | 开源工具通常需要逐个试错判断类型 |
| **Full Disk Encryption** | 解密 BitLocker / FileVault2 / LUKS(LUKS2) / TrueCrypt / VeraCrypt / APFS / PGP 等镜像 | 见 [BitLocker 全卷加密取证](../crypto-volume/crypto-volume-bitlocker.md) 与 [VeraCrypt 加密卷取证](../crypto-volume/crypto-volume-veracrypt.md) |
| **File Recovery** | Office / PDF / Zip / RAR / 7z 等 400+ 文件类型的口令恢复 | 覆盖的私有格式远多于 hashcat/JtR |
| **Database Passwords** | 从应用配置文件/注册表中提取并恢复数据库连接口令 | 见 [数据库与配置文件加密](crypto-app-database-configuration-decryption.md) |
| Windows / Standalone System | 从外置注册表 hive 中提取系统账户口令 | 见 [内存中的凭据与密钥](../../memory/memory-artifact/memory-artifact-memory-credentials-and-keys.md) |
| **Internet & Network** | 浏览器、邮件客户端、网络连接的保存凭据 | 见 [远程工具凭据解密](crypto-app-remote-tool-credential-preservation.md) 与 [浏览器密码库与 Token](crypto-app-browser-passwords-and-tokens.md) |
| **Memory Analysis** | 分析内存镜像/休眠文件，提取其中的密钥与口令 | 见 [内存中的凭据与密钥](../../memory/memory-artifact/memory-artifact-memory-credentials-and-keys.md) |
| **Password Managers** | KeePass / 1Password / LastPass 等主密码恢复 | 属于 KDF 高强度类型，通常只能靠线索 |
| **Agents（分布式）** | 把恢复任务分发到多台机器（Windows / Linux / 云） | hashcat 也能做，但管理成本高 |

<a id="section-4"></a>

### 2.2 与开源工具的差异（必须写进报告的方法论说明）

| 维度 | Passware Kit Forensic | hashcat / John the Ripper |
|---|---|---|
| 覆盖格式 | **400+**，含大量厂商私有格式（QuickBooks、FileMaker、Lotus Notes、财资软件） | 数百种哈希，但**需能表达为"哈希"或可转换的文件格式** |
| 交互 | 图形化，可拖文件进去 | 纯命令行 |
| 批量 / 分布式 | 内置批量队列 + Agent 管理器 | 需自己脚本编排与搭建 |
| 复杂度评估 | **能报告"这个加密有多难"** | 不评估 |
| 成本 | **闭源 + 按年订阅收费** | 免费开源 |
| 可复现性 | 闭源算法，**外部无法独立验证**，法庭上难辩护 | **开源、可审计、可复现** |

> **关键判断**：商业工具的真正优势在于格式识别广和能给出复杂度评估，速度通常不是差距所在。

它的弱点是闭源——在需要为结论辩护的司法场景里，开源工具的可复现性往往比覆盖率更重要。

一个稳妥做法是：商业工具用于发现与初筛（找出哪些是加密的、哪些值得攻），开源工具用于确认与验证。

<a id="section-5"></a>

### 2.3 通用恢复流程的四个阶段

```
① 哈希提取 → ② 攻击方式选择 → ③ 工具执行 → ④ 实际验证
```

这四步的顺序不能颠倒。

跳过 ① 拿到不明格式的"哈希"直接喂给 hashcat，典型结果是 `Invalid hash`，或者更糟——格式猜错时 hashcat 可能"破解成功"，但解出的明文是垃圾数据。

**① 哈希提取的合法来源**（全都必须是已镜像的检材或合法取得的配置）：

| 来源 | 提取物 | 工具 |
|---|---|---|
| SAM hive | NTLM 哈希 | `secretsdump.py` / `hashdump` / RegRipper |
| SECURITY hive | 缓存域凭据、DCC | `secretsdump.py` |
| `/etc/shadow` | crypt 格式 | 直接读取 |
| Windows 凭据管理器 | 通用凭据 blob | `cmdkey /list` + 内存分析 |
| 应用配置文件 | 明文或弱编码口令 | 见 05、06、07 篇 |
| 网络抓包 | NetNTLMv2 / Kerberos / WPA | `secretsdump.py` / `hcxpcapngtool` |
| 加密文件 | 需 `*2john` 转换 | 见 2.5 |

**② 攻击方式选择**——这是决策而非穷举：

| 方式 | 何时选 | 关键前提 |
|---|---|---|
| **字典攻击** `-a 0` | 口语化环境（个人机器、中文用户）、已知泄露口令 | 词表覆盖度；配合规则 |
| **规则攻击** `-a 0 -r` | 怀疑是"某词 + 变形" | 变形假设（首字母大写 + 数字后缀） |
| **掩码攻击** `-a 3` | **已知格式特征**（生日、手机号后 8 位、6 位 PIN） | 必须能说清每个 `?` 对应什么 |
| **组合 / 混合** `-a 1 / -a 6,7` | 怀疑是"词 + 数字后缀""两词拼接"这类企业口令模式 | 词表规模可控 |
| **PRINCE** `--prince` | 强规则词典存在但机器上不方便维护 | 内存占用大 |
| **暴力** `-a 3 ?a?a?a?a?a?a?a?a` | 仅当长度 ≤ 7–8 且全字符集 | 算清 keyspace 再启动 |
| **彩虹表** | 仅 unsalted 旧格式 | 见 2.4 |

> **掩码的纪律要求**：使用掩码前必须在报告中写清**掩码的依据来源**。`?d?d?d?d?d?d?d?d` 攻击 8 位生日数字，理由是"该用户在另一社交平台公开的生日为 1990-05-17"——这是可辩护的。"没有依据就用全字符集暴力"是不被接受的。

**掩码语法（hashcat）**：

| 占位符 | 含义 | 占位符 | 含义 |
|---|---|---|---|
| `?l` | 小写字母 | `?a` | `?l?u?d?s` 全组合 |
| `?u` | 大写字母 | `?b` | `0x00–0xff` 全字节 |
| `?d` | 数字 | `?1`–`?4` | 自定义字符集 1–4 |
| `?s` | 符号 | `**` | 拒绝当前规则候选 |

**③ 工具定位**：

- **hashcat**：**GPU 优先**。对**快哈希**（MD5/SHA1/SHA256/NTLM/NetNTLM）通常具有吞吐量优势——这类算法计算量低，瓶颈在吞吐量，GPU 的并行计算能力可提高吞吐量。`--example-hashes` 可列出全部模式，`-I` 看设备。
- **john the ripper**：**CPU 优先、支持格式更杂**。对**慢哈希**（bcrypt/scrypt/PBKDF2）差别不大（都受限于算法本身而非算力），但它对畸形/非标准格式的容错更好，且 `*2john` 系列格式转换器更全。

**④ 验证——用恢复结果实际打开目标文件。**

`hashcat` 报 `Cracked` **只意味着"我算出了一个输入，它的哈希值等于目标"**。

它不意味着这个输入真的是那个口令（碰撞极罕见但不是零），不意味着那个口令真能打开目标文件，也不意味着你提取的哈希确实来自这个文件。

**合格的验证必须落到"实际打开"**：

```bash
# 验证 1：加密文件类——真正用解出的口令打开（7z 的 -p 只写一次）
7z l -p'<解出的口令>' 'evidence.zip' >/dev/null 2>&1 \
  && echo "VERIFIED: 可用该口令打开" || echo "NOT VERIFIED"

# 验证 2：数据库类——真正执行 SELECT
mysql -h <host> -u <user> -p'<解出的口令>' -e "SELECT VERSION();"

# 验证 3：算法自洽——用已知明文复算，确认你选的 -m 是对的
echo -n "test" | md5sum     # 应等于你构造的测试哈希，否则说明选错了 -m
```

> 绝对不要把"hashcat 输出了 Status: Cracked"写进报告的验证环节。 那只是"候选已产生"，不是"结论已成立"。

<a id="section-6"></a>

### 2.4 彩虹表为什么在本领域基本失效

彩虹表用空间换时间：预先算好 `hash → 明文` 的全量表，攻击时 O(1) 查表。

前提是哈希不加盐（否则每用户一个盐，表就废了）、迭代次数低、哈希空间足够小。

现实对照：bcrypt / scrypt / Argon2 / `/etc/shadow` 的 `$y$`（yescrypt）/ KeePass 主密码**全部不可能**；无盐 MD5/SHA1 早期口令理论可行；NTLM 无盐但按需计算已比查表快，**表无优势**。

**结论：现代取证中彩虹表已基本退出。**

<a id="section-7"></a>

### 2.5 哈希提取工具：`*2john` 家族

加密文件不是"哈希"，但可以**把它降维成一个"可用指定口令验证正确性"的对象**。

这就是 `*2john` 工具的思路：解析文件格式，抽取验证参数，输出一个 hashcat/JtR 能接受的哈希行。

```bash
# *2john 随 John the Ripper 一起分发（进入其 run 目录）
cd /usr/share/john/run
ls *2john | head -30        # 形如 pdf2john.py、office2john.py、7z2john.py

# 典型用法：文件 → JtR 格式哈希
python3 pdf2john.py     evidence.pdf  > evidence_pdf.hash
python3 office2john.py  evidence.xlsx > evidence_xlsx.hash
python3 7z2john.py      evidence.7z   > evidence_7z.hash
python3 keepass2john.py vault.kdbx   > evidence_kdbx.hash
```

**注意事项**：

- `*2john` 的输出是**特定版本的实现**。同一文件换 John 版本可能输出不同参数。
- 转换后**必须先用已知口令自测**（用一个自己加密的测试文件走通全流程），确认你的转换 → 攻击 → 打开链路是通的，再对检材动手。

**这条自测是发现"版本不匹配导致解错"的唯一办法。**

- 一些格式（尤其 Office 2007+ 的 Agile 加密）有大量实现变体，转换失败时先查该格式的独立说明。

---
<a id="section-8"></a>

## 三、操作步骤

<a id="section-9"></a>

### 步骤 1：确定授权边界并书面记录

在碰任何工具之前，先在案件记录中写清：检材编号、哈希值、授权书编号、**本次恢复的合法目的**、**恢复结果的使用限制**。

没有这一条，后面所有操作都可被质疑为越界。

<a id="section-10"></a>

### 步骤 2：清点检材中的"可攻对象"

```bash
# 提取注册表 hive（示例检材）
reged -x DigiForensics.dd "/WINDOWS/system32/config/SAM"     /tmp/SAM
reged -x DigiForensics.dd "/WINDOWS/system32/config/SECURITY" /tmp/SECURITY

# SAM → NTLM（SECURITY 中的 BOOT_KEY 用于解开 SAM 内部加密）
# 注意：-nthashes 取 NT 哈希；-ntds 是"从注册表提取 NTDS.dit"，**本地 SAM 用不上**
python3 secretsdump.py -sam /tmp/SAM -security /tmp/SECURITY -nthashes > ntlm.txt
cat ntlm.txt
# 输出格式：username:rid:lmhash:nthash:::
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
#                    ^^^^ RID
#                                 ^^^^ 第3列恒为 aad3b435b51404eeaad3b435b51404ee，
#                                      这是空 LM 哈希占位符，不是该账户的 LM 哈希
#                                                           ^^^^ 第4列才是 NT 哈希（hashcat -m 1000 用它）

# Linux 侧
sudo cat /mnt/image/etc/shadow            # crypt 格式口令
```

先按 RID 结合对象类型与名称梳理"这是一个真实的人"还是"这是一个服务账户"。RID 只给出账户所属类别的默认值，**不能单独作为判定依据**：域环境的内置账户 RID 是相对 SID 的偏移，`RID 512` 为 Domain Admins、`RID 513` 为 Domain Users；`RID 500`（Administrator）、`RID 501`（Guest）同理。RID ≥ 1000 是分配给新建对象的默认区间，但落在该区间的既可能是域用户，也可能是计算机账户或服务账户，需结合对象类型、`sAMAccountName` 结尾的 `$` 与所属域判断。

人工账户通常是**优先攻**的对象；Guest 与服务账户的口令多为机器生成，长度长、无语义结构，通用字典和规则攻击对其基本无效，可据此排除以节省算力——但这同样是默认而非定论，弱口令的人工账户与被复用口令的服务账户都存在。

<a id="section-11"></a>

### 步骤 3：先做"非爆破"分析，并建立小候选集

在跑任何 GPU 之前，先在镜像中搜"这个人的口令可能以明文存在哪"，再把用户上下文压缩成**小而准的候选表**（比 8000 万词通用字典有效得多）：

```bash
# 关键字：用户个人线索 + 常见明文配置位置
# （.bash_history、.zsh_history、.env、config.php、application.yml 等）
strings -n 6 DigiForensics.dd | grep -iE "zhangsan|zs123|1989|birthday" | head -40
strings -n 8 DigiForensics.dd | grep -iE "password|passwd|pwd|口令|密码" | head -60

# 候选集：来自检材中提取的个人线索
cat > candidates.txt <<'EOF'
zhangsan
zhangsan@2024
Zhs@2024
dianhua-13800138000
EOF
wc -l candidates.txt
```

这一步常常比后续的爆破工作更容易见效，成本也更低。

<a id="section-12"></a>

### 步骤 4：选择攻击方式并执行

```bash
# 0) 先确认设备与支持范围
hashcat -I                       # 列出可用设备（GPU/AMD/OpenCL）
hashcat --example-hashes | less  # 权威的模式号与示例哈希对照（以本机版本为准）

# 1) 字典攻击：NTLM（模式 1000）
hashcat -m 1000 -a 0 hash.txt wordlist.txt

# 2) 字典 + 规则（最常用组合）
hashcat -m 1000 -a 0 hash.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# 3) 掩码攻击：8 位数字（已知为手机号/生日场景）
hashcat -m 1000 -a 3 hash.txt ?d?d?d?d?d?d?d?d

# 4) 混合攻击：候选词 + 4 位数字后缀
hashcat -m 1000 -a 6 hash.txt candidates.txt ?d?d?d?d

# 5) 交互：s=状态 p=暂停 b=绕过 c=检查点 q=退出
```

**John the Ripper 对应写法**：

```bash
john --format=NT hash.txt --wordlist=wordlist.txt
john --format=NT hash.txt --wordlist=wordlist.txt --rules
john --format=NT --show hash.txt        # 只显示已破解的
```

<a id="section-13"></a>

### 步骤 5：结果管理与可复现性

```bash
# --show：随时查看当前 pot 中已解出的结果（无需重新跑）；--left：列出尚未解出的哈希
hashcat -m 1000 hash.txt --show
hashcat -m 1000 hash.txt --left

# 断点续跑：命名会话
hashcat -m 1000 -a 0 hash.txt wordlist.txt --session=case2024_01
hashcat --session=case2024_01 --restore     # 中断后恢复

# 指定的 potfile 路径（把结果与本案绑定，便于归档）
hashcat -m 1000 -a 0 hash.txt wordlist.txt --potfile-path=./ntlm.pot

# 运行时状态：另开终端观察
hashcat --status
```

> `--potfile` 是本案最该被归档的产物之一：它记录了"该哈希最终被哪个候选解开的"，且带时间戳。

`--potfile-path` 把它固定到案卷目录，避免与其他案件混淆。

不要用默认的 `~/.hashcat/hashcat.pot`，那个文件在多案件并行时会互相污染。

<a id="section-14"></a>

### 步骤 6：实际验证（不可跳过）

```bash
# 若目标是加密文件：用解出的口令真正打开
7z t -p'<解出的口令>' evidence.zip && echo VERIFIED

# 若目标是数据库：真正查询（只读、最小化）
mysql --skip-column-names -h <host> -u <user> -p'<解出的口令>' \
      -e "SELECT COUNT(*) FROM information_schema.tables;"

# 若目标只能验哈希：做"自洽性测试"——用解出的明文重新计算哈希，与原始哈希比对
python3 -c "
import hashlib
print('NTLM 复算：', hashlib.new('md4', '<解出的口令>'.encode('utf-16le')).hexdigest())
" 2>/dev/null || echo "该平台无 md4，请用 impacket 计算比对"
```

> 上面的 `hashlib.new('md4')` 在新版 OpenSSL 3.x 中已被移除，在受控的 Python 3.8 环境或用 `impacket` 计算。不要照抄到没有验证过的环境里。

---
<a id="section-15"></a>

## 四、常见陷阱

本章按「授权与前提 → 格式与模式选择 → 执行与结果管理 → 验证与结论表述」归组，每条给出：现象、为什么会误判、误判代价、正确做法。
★ 标记表示该操作会导致原始检材永久灭失或不可逆改变，执行前必须停下来确认。

<a id="section-16"></a>

### 4.1 授权与前提：还没做完就该做的事

<a id="section-17"></a>

#### 陷阱 1：★ 没有把授权书与检材编号绑定就开工

**现象**：设备送来做口令恢复，直接提取 SAM 哈希开始跑字典，中途委托方补来了授权书。

**原因**：直觉上"设备是客户送来的"本身就构成授权。

但**授权书要覆盖三件事**（红线一）：检材来源合法、恢复目的明确、**恢复结果的使用方式被限定**。

"客户送来的机器"只解决了第一件，而暴力破解这种高强度操作恰恰落在第二、三件的范围内。

**"送来的机器"不自动授权你去做 GPU 集群爆破**——这是两个不同性质的行为，在法律定性上也被分别评价。

**影响**：一旦进入争议程序，"你当时有没有授权做爆破"这个问题会决定全部产出是否可用。

**而事后补的授权书在举证上效力远弱于开工前记录的**——对方完全可以主张"授权是在知道结果之后才补的"。这个损失事后无法弥补。

**核查**：**碰任何工具之前**先在案件记录里写清五项（步骤 1）：检材编号、哈希值、授权书编号、本次恢复的合法目的、恢复结果的使用限制。

```bash
# 开工前固定：哈希与授权书编号绑定归档
sha256sum DigiForensics.dd | tee /tmp/case_hash.txt
```

**还应额外写明禁止性条款**，例如"本案禁止连接任何远程服务""结果不得用于登录"——案例第 1 步就是这种写法。

这类条款在事后能直接拦住越界动作，而不用临场判断。

<a id="section-18"></a>

#### 陷阱 2：跳过"非爆破"分析直接上全量字典

**现象**：拿到 NTLM 哈希后直接挂 8000 万词字典加规则跑了两天，一无所获，报告写"该账户口令强度较高"。

**原因**：字典的命中率高度依赖词表覆盖度，而通用字典恰恰覆盖不到用户自创口令。真实案件里口令的来源有明确的优先级分布（红线二），**排在最前面的四项全都不需要算力**：证据内的明文残留、同机复用、其他账户的口令、上下文候选。案例里 `密码提示.txt` 一个明文文件就解决了全部问题——**而它在镜像里躺了好几天没人看**。

跳过的不是"一个可选步骤"，是成本最低的那一档。

**影响**：一是浪费数天算力。

二是一个**方向性的能力误判**——"口令解不开"往往被误读成"该账户不存在可疑活动"，而真实原因只是"你没找到正确的来源"。

三是报告方法论存在缺陷，一份没有说明"为什么选择这个攻击方式"的破解结论，本身就是无法辩护的。

**核查**：**先把上表走完再考虑 hashcat**，并把个人线索压缩成小候选集（步骤 3）：

```bash
# 明文残留：往往一击命中
strings -n 6 DigiForensics.dd | grep -iE "zhangsan|zs123|1989|birthday" | head -40
strings -n 8 DigiForensics.dd | grep -iE "password|passwd|口令|密码" | head -60
# 案例中这一步命中"密码提示.txt"，候选集最终只有 4 条
```

**报告里要写清"为什么走了爆破"**——这既是方法论要求，也是把"没解出来"与"解不出来"区分开来的唯一办法。

<a id="section-19"></a>

#### 陷阱 3：把服务账户和 Guest 一起丢进字典

**现象**：把 SAM 里全部账户的哈希导出后一并提交，跑了 6 小时，返回 3 个"破解成功"，其中 2 个是机器账户。

**原因**：**服务账户与 Guest 的口令通常是机器生成的**，长度长、字符集混杂、无语义结构——通用字典和规则攻击对它们基本无效。RID 能给出账户类别的默认值（域环境下 `RID 500`/`RID 512`/`RID 513` 分别是 Administrator/Domain Admins/Domain Users，RID ≥ 1000 是新建对象的默认区间），但**RID 不能单独定案**：判断机器账户要结合对象类型、`sAMAccountName` 结尾的 `$` 以及所属域，`MSSQL$SVC` 这类名称本身就是比 RID 更直接的线索。人工账户应优先攻；Guest 与机器账户可据此排除。"解出机器账户的口令"不仅无用，还会污染结果表**——它看起来像一条有效发现，实际是纯噪声。

**影响**：算力浪费，以及**报告里混入无意义的"发现"**。

更麻烦的是，如果一个机器账户的口令被写成"已破解账户"，读者无法判断哪些是真人账户，分析价值被稀释。

**核查**：**先按 RID 与账户名模式分流，再决定攻哪些**：

```bash
python3 secretsdump.py -sam /tmp/SAM -security /tmp/SECURITY -nthashes > ntlm.txt
# 按 RID 与命名分流（注意 -nthashes 取 NT 哈希；-ntds 是提取 NTDS.dit，本地 SAM 用不上）
# ★ 纯 RID 阈值分不出机器账户：机器账户的 RID 同样落在 1000+ 区间。
#   必须结合"名称含 $ 美元符号"这个特征，否则 MSSQL$SVC / WIN-DIGI-01$ 会被误标为优先。
awk -F: '{
  name=$1; rid=$2+0
  if (name ~ /\$/)       print "排除:", name, "(机器/服务账户, 含 $, RID " rid ")"
  else if (rid==501 || rid==502 || rid==503)          print "排除:", name, "(内置非登录账户, RID " rid ")"
  else if (rid==500)                                  print "优先:", name, "(内置 Administrator, RID 500)"
  else if (rid>=1000)                                 print "优先:", name, "(用户候选, RID " rid ")"
  else                                                print "待议:", name, "(RID " rid ")"
}' ntlm.txt
# 机器账户命名特征：MSSQL$SVC、SQLAgent$、$ 后缀、无对应真人用户目录
```

**报告里只写人工账户的破解情况**，并说明"已排除 N 个服务账户（机器生成口令，字典攻击不适用）"。

<a id="section-20"></a>

#### 陷阱 4：把"无依据的全字符集暴力"写进报告

**现象**：对 8 位口令用了 `?a?a?a?a?a?a?a?a` 全字符集，跑了一周没出来；报告里写"已尝试暴力破解"。

**原因**：**掩码攻击的全部正当性来自它的依据**（2.3 的纪律要求）。

`?d?d?d?d?d?d?d?d` 攻击 8 位生日数字，依据是"该用户在社交平台公开的生日为 1990-05-17"——**可辩护**。

而全字符集暴力的 keyspace 是天文数字，实际不可能跑完；用一个注定跑不完的方案"尝试"了一下，写进报告后**它既不能证明什么，也不能反驳什么**。

**影响**：报告里出现一条**无法辩护的方法论描述**，会削弱整份报告的技术可信度。

对方只需指出"这个 keyspace 你根本跑不完"，你在这一节的所有内容都会被重新审视。

**核查**：**使用掩码前先写清每个 `?` 的依据来源**，并把 keyspace 算清楚：

```bash
# 算 keyspace，确认方案可行再启动
python3 -c "
import math
cs=95; n=8
print('keyspace = %.3e' % (cs**n))
print('bits = %.1f' % (n*math.log2(cs)))"
# 只在长度极短（如 4 位 PIN）时全字符集才现实
```

**报告表述模板**："本次掩码攻击针对 `<格式特征>`（依据：`<证据来源，如公开生日/工号格式>`），keyspace 为 `<数值>`，耗时 `<时长>`。"无依据的方案不要写进报告，宁可写"未采用纯暴力，原因：keyspace 超出可承受范围"。

<a id="section-21"></a>

### 4.2 格式与模式选择

<a id="section-22"></a>

#### 陷阱 5：只信 `-m 数字` 不看格式，模式选错得到垃圾明文

**现象**：从某个来源导出一批哈希，直接指定 `-m 1000` 跑字典，返回 `Status: Cracked`，但解出的"明文"是 `4gH8fJk2Lm9p` 这类不可能的口令。

**原因**：格式猜错时 hashcat 可能"破解成功"，但解出的明文是垃圾数据（2.3 明确点出）。

原因很朴素：hashcat 只比对"用该模式定义的算法算出的值"，**它不知道你手里的字符串是什么**。

一段 MD5 十六进制串被当成 NTLM 送进去，与正确 NTLM 的计算值偶然相等是完全可能的（尤其是短口令）。

而"Cracked"这个状态只表示某个候选与输入匹配，不表示这个候选是真实口令。

**影响**：这是本领域**最典型的"以为自己找到了"**。

报告里写下一个看似合理的口令，会被用来做交叉印证、账户同一性认定、乃至出现在鉴定意见中。

一旦被对方用同样的方法验证，就会发现"破解"根本不可复现——而那时其他所有技术结论的可信度都会被一起质疑。

**核查**：永远用 `--example-hashes` 核对格式，并做一次自测试：

```bash
# 1) 权威的模式号与示例对照（以本机版本为准）
hashcat --example-hashes | grep -A3 "^NTLM"
# 2) 关键：先确认你的哈希串长度与结构符合该模式
#    NTLM = 32 位十六进制；MD5 = 32 位；SHA1 = 40 位
awk -F: '{print $1, length($4)}' ntlm.txt
# 3) 自测试：用自制样本走通全流程，再上检材（*2john 同理）
```

**自测试的做法**：拿一个你自己知道明文的口令，跑完整流程，**确认能解出且解出的是那个明文**。

这一步只需要几分钟，能挡掉本节所有错误。

<a id="section-23"></a>

#### 陷阱 6：用 `--remove` 破坏原始哈希集

**现象**：跑完 `hashcat --remove` 后查看原始 `hash.txt`，发现已破解的行被删除；再复跑时无法确认哪些是原始行、哪些是工具删的。

**原因**：`--remove` 会在破解成功后**改写输入的 hash 文件**，删掉已解出的行。

这个行为在日常渗透测试里很方便，**在取证里却有一个严重问题：它销毁了原始证据载体**。

你无法再向委托方证明"这份哈希列表是从检材里完整提取的、包含哪些账户"——因为原始列表已经被工具修改过了。

**影响**：**原始哈希集是证据，它的完整性需要可证**。

被工具改写之后，你手里只剩一个"工具认为剩下的部分"，而这个集合的完整性无法再论证。

委托方或审计方会问"原始的完整哈希列表在哪里"，答案将是"被工具删了"。

**核查**：原始 hash 文件只读保存、单独归档，恢复作业在副本上进行：

```bash
# 提取后立即固定：只读 + 记录哈希
chmod 444 ntlm.txt
sha256sum ntlm.txt | tee /tmp/ntlm_hash.txt
# 恢复作业在副本上跑
cp ntlm.txt work_hashes.txt
hashcat -m 1000 -a 0 work_hashes.txt candidates.txt -r /usr/share/hashcat/rules/best64.rule
```

**报告里写明三个哈希**：检材哈希、原始哈希列表哈希、工作副本哈希。**同一个值出现三处且可相互印证，这条证据链才完整。**

<a id="section-24"></a>

#### 陷阱 7：共享 potfile 导致串案

**现象**：用默认 potfile 跑了几个案件，某天审查结果时发现另一个案件的口令出现在了本案的结果里。

**原因**：hashcat 的 potfile 会**自动加载并合并已解出的结果**——这在长期作业里是巨大便利（不用重跑），**但它意味着不同案件的结果会混在同一个文件里**。

默认路径是当前目录下的 `hashcat.pot`，**多个案件在同一个工作目录下跑就会互相污染**。

而这个错误在单案视角下完全不可见——你看到的是"结果里多了一条本来就有的"。

**影响**：**串案是取证里性质严重的程序错误**。

把 A 案的发现写进 B 案报告，意味着两案的证据链被污染，且污染方向不确定（可能把无关口令带进来，也可能把本案的关键结果算到别的案件名下）。

一旦发生，报告的可信度不是"打折"，而是需要全部重做。

**核查**：**每个案件显式指定独立的 potfile 路径**，路径里带案件编号：

```bash
hashcat -m 1000 -a 0 hash.txt wordlist.txt \
  --potfile-path=./DigiForensics-case2024_01.pot
# 查看某案已解结果时也必须带同一路径
hashcat -m 1000 hash.txt --show --potfile-path=./DigiForensics-case2024_01.pot
```

**归档时把 potfile 视为该案的专属材料**，随案固定并记录哈希。

<a id="section-25"></a>

#### 陷阱 8：依赖彩虹表

**现象**：花时间下载并挂载彩虹表，跑了三天，效率远低于字典攻击。

**原因**：**彩虹表只对未加盐的旧格式有效**（2.4）。

现代哈希几乎都带盐——`/etc/shadow` 的 crypt 格式每个条目独立随机生成 salt；NTLM 虽不加盐但现代规则表已足够高效；`$y$`/`$2y$` 这类慢哈希更是完全无法用预计算表。

彩虹表的经济性建立在"同一哈希对应同一明文"这个前提上，而这个前提对现代格式已经不成立。

**影响**：下载与挂载彩虹表要占用几十上百 GB 磁盘，还要消耗大量时间。

在这段时间里，同一台机器用字典+规则能完成的工作量高出几个数量级。

**核查**：**先看格式的加盐情况再决定**：

```bash
# /etc/shadow 开头字符即算法标识：$1$=MD5 $y$/$6$=SHA-512 $2y$/$2b$=bcrypt
cut -d: -f2 /mnt/image/etc/shadow | cut -c1-4 | sort | uniq -c
# hashcat 模式对照：500=MD5 1800=yescrypt/SHA-512 3200=bcrypt
hashcat --example-hashes | grep -E "^[0-9]+ : (MD5|bcrypt|SHA-512|yescrypt)"
```

带盐或慢哈希 → **直接走字典/规则/掩码**；只有未加盐的旧格式才考虑彩虹表，且现代 hashcat 模式下这个场景基本不存在。

<a id="section-26"></a>

### 4.3 验证与结论表述

<a id="section-27"></a>

#### 陷阱 9：把 `Status: Cracked` 当作验证通过

**现象**：hashcat 返回 `Status: Cracked`，报告直接写"口令已恢复，账户 `zhangsan` 的口令为 `<某串>`"。

**原因**：**破解成功 ≠ 口令正确 ≠ 能打开文件**（步骤 6 把它列为不可跳过的阶段）。

`Cracked` 只说明"某候选与哈希值匹配"——在格式选错（见陷阱 5）时，这个匹配可以是毫无意义的巧合。

而且它连"这个账户能被这个口令登录"都证明不了，因为真正的验证需要该口令能通过系统的认证路径。

**影响**：账户同一性认定、口令复用风险提示、乃至诉讼中的举证，都可能建立在这个未经验证的值上。

报告里的一个具体口令字符串，会被人拿去实际使用——**一旦用不了，所有基于它的推断同时崩塌**。

**核查**：**实际打开某个受该口令保护的东西**，这是唯一的决定性验证（步骤 6）。案例第 6 步做得很标准：

```bash
# 方式 A：数据库恢复实例上只读执行（不修改任何数据）
sqlcmd -S localhost -E -Q "SELECT TOP 5 name FROM sys.tables;"
# 方式 B：LSA Secret 交叉印证（案例第 7 步，独立证据）
# 方式 C：把口令投喂给对应的哈希提取路径，验证能解出同一值
```

**注意验证手段的合规边界**：验证必须是**在检材副本或受控的恢复实例上"打开"**，绝不能是**登录远程系统**（红线一与案例的禁止性条款）。

这两者的区别在于"用口令在本地解密一个文件"和"用口令去访问一台不属于你的机器"。

**报告写法**："该 NTLM 哈希对应的口令已恢复，并通过 `<具体方式>` 完成验证（`<返回结果>`）。完整口令见受控附件 `<编号>`。"

<a id="section-28"></a>

#### 陷阱 10：★ 把明文口令写进报告正文

**现象**：鉴定报告正文里直接写出 `zhs@Fin2024`，作为"该账户弱口令"的证据。

**原因**：写进去的理由通常是"复核方便"和"这是核心事实"。

但**一条 NTLM 哈希背后可能是一个真实的人**（红线三）——**他用于支付、邮箱、社保的也许是同一个口令**。

报告的传播范围远大于分析环境：交给委托方、可能进卷宗、可能在质证中公开。

**影响**：泄露的责任在报告作者，而不在原始设备持有者。

**更现实的风险是口令复用**——一个口令同时是财务系统、银行、邮箱的，一旦公开，受影响的是本人完全不知道的系统。

这类事件通常构成一宗需要立即启动全量改密的安全事件。

**核查**：**报告正文只写可复现的验证过程，不写口令本身**：

- 写：该哈希存在于哪个文件的哪个偏移、属于哪个账户（RID/域名）、**是否能与本案某个关键文件相互印证**；
- 写：验证方式与返回结果（案例第 6 步的只读 SQL 及其结果）；
- **只有当口令本身是案件核心事实时**（如它是受害者的胁迫来源，或是访问被删数据的唯一途径），才在**受控附件**中给出——**单独存放、加密、限定访问人**。

法庭上"我们拿到了口令"这句话，需要的是可复现的验证过程，不是口令本身。

这条原则在实践中也给分析员自己留了保护：方法论经得起复核，比一个值更有说服力。

<a id="section-29"></a>

#### 陷阱 11：无依据的推断与"未解出"的结论表述

**现象**：某账户口令没解出来，报告写"该账户采用了高强度口令，攻击者无法破解，说明其具备一定安全意识"。

**原因**：**"我没解出来"包含的信息量远小于它看起来的样子**。

它至少可以由七种成因造成：字典覆盖不足、规则假设错误、掩码依据不成立、用了彩虹表（对加盐格式无效）、跳过了同机复用分析、算力或时间不足、**或者那个账户根本没有被使用过**。

同一个"未解出"现象有多种成因，且在离线状态下无法区分。 把其中一种成因当成结论，是幸存者偏差的典型形态。

**影响**：这是"以为自己找到了"的镜像版本——以为自己找到了"没找到"背后的意义。

它会给出一个虚假的画像：这个账户是"安全的"，从而可能让调查者停止追查其他账户（"既然他防护做得好，应该不是他"）。

一个被虚假的心理画像引导的调查，方向性地错了，而且很难自我纠正。

**核查**：**把"未解出"表述为一个有范围、有前提的否定性结论**，并明确列出未覆盖的范围：

> "在 `<N>` 条候选（来自明文残留 `A`、上下文线索 `B`）与 `<X>` 小时内 `<Y>` 算力的条件下，未破解账户 `<account>` 的 NTLM 哈希。
> **本次未覆盖的范围**：其他账户的复用口令、网络抓包中的 NetNTLMv2 材料、`MSSQL$SVC` 等机器账户（已排除）、`/etc/shadow` 的 crypt 格式（未涉及）。
> **该结论不表明该账户不活跃，也不表明其口令强度。**"

**反向的错误同样要避免**：因为"解出了一个口令"就断言"该账户防护薄弱"——**这也超出了证据能支撑的范围**。

正确的表述是"该账户的口令可被字典攻击破解，说明其口令构成要素存在缺陷"，至于成因（是否复用了别处的口令、是否是他人代设）需要另外的证据。

<a id="section-30"></a>

#### 陷阱 12：把恢复结果与第三方服务的风险处置混在一起做

**现象**：破解后，发现该口令在其他平台可复用，于是自行联系该平台或通知相关方，要求其改密。

**原因**：这看起来是负责任的风险提示动作，动机良好。

但取证方的职责边界是"检验并报告"，处置决策属于数据控制方。

而且从取证角度看，**联系第三方会引入新变量**：你无法掌握对方的处置流程与时间点，而一旦发生纠纷，"你通知过了"这句话本身会成为一条需要解释的记录。

**影响**：一是越界——处置决定不是取证方的职权。

二是如果联系动作本身被记录为"取证方参与了后续处置"，会模糊取证与处置的界限，这在争议程序里是会被追问的点。

**核查**：**在报告里提出风险，由委托方决策并执行**。案例第 3 条结论要点正是这个处理方式：把"该账户口令可能复用至第三方服务"写进报告的合规说明，供委托方通知相关方自行改密，由委托方负责，取证方不主动联系。

**同一原则适用于其他附带发现**：属于范围外的凭据材料（其他账户、其他设备）**必须报告而不是丢弃**，只是报告格式受最小化约束（见红线三），且**处置动作交由委托方**。

<a id="section-31"></a>

## 五、案例示例

<a id="section-32"></a>

### 5.1 明文口令提示 + 4 条候选：账户同一性认定闭环

**场景**

查获一台 Windows 11 办公笔记本（`DigiForensics.dd`，512 GB）。委托方需要证明「该设备上登录过的账户 `zhangsan` 与某勒索事件中泄露的数据源是同一账户」。注意：本案的证明目标是「账户同一性」，不是「数据内容」——这个定位直接决定了后面该不该做爆破。

这条路径值得先走，是因为账户同一性只需要证明「哈希对应这个账户的口令」，不需要知道口令是什么，更不需要用它登录任何地方。

**处置过程**

第 1 步，授权确认（**这一步先于所有技术动作**）：

```bash
# 记录四项，并在检材上留下可复核的凭据
printf 'authorization_no=%s\
image_sha256=%s\
purpose=%s\
usage_limit=%s\
' \
  '<授权书编号>' "$(sha256sum /evidence/DigiForensics.dd | cut -d' ' -f1)" \
  '账户同一性认定' '不得用于登录；禁止连接任何远程服务' \
  > /evidence/authorization.txt
```

第 2 步，提取哈希并做 RID 判定：

```bash
icat -o 2048 /evidence/DigiForensics.dd <sam-inode> > /evidence/SAM
icat -o 2048 /evidence/DigiForensics.dd <sec-inode> > /evidence/SECURITY
secretsdump.py -n 0x102 /evidence/SAM
# 输出格式仍是 username:rid:lmhash:nthash:::
# zhangsan:1001:aad3b435b51404eeaad3b435b51404ee:<NTLM-hash-已脱敏>:::
# MSSQL$SVC:1002:aad3b435b51404eeaad3b435b51404ee:...:::   ← RID ≥ 1000 的机器账户，排除
```

落在 RID ≥ 1000 区间的需结合对象类型与名称再判断：`zhangsan` 这类域用户 RID 通常在 1000 以上、对应真实的人；而 `WIN-DIGI-01$`、`MSSQL$SVC` 这类名称以 `$` 结尾的计算机账户或服务账户 RID 同样落在该区间，其口令由系统生成、恢复它没有意义。这个判断放在第一步，可以直接砍掉后续一大类无意义的哈希。

第 3 步，**先做非爆破分析——这是本案效率的全部来源**：

```bash
# 在镜像中搜索用户名相关的明文线索
strings -a -t x /evidence/DigiForensics.dd | grep -i 'zhangsan'
# 偏移 0x3f21a800  /Users/zhangsan/Documents/密码提示.txt
icat -o 2048 /evidence/DigiForensics.dd <inode> > /evidence/hint.txt
cat /evidence/hint.txt
# 财务系统  <已脱敏>
```

同时发现 LSA Secret 条目：

```bash
secretsdump.py -n 0x0f /evidence/SECURITY | grep -i 'FINANCE'
# FINANCE_LEGACY  <脱敏>
```

第 4 步，**建立小候选集（不是全量字典）**——本案仅 4 条：

```bash
cat > /evidence/candidates.txt <<'EOF'
<已脱敏-候选1>
<已脱敏-候选2>
<已脱敏-候选3>
<已脱敏-候选4>
EOF
wc -l /evidence/candidates.txt
# 4 candidates
```

第 5 步，字典攻击：

```bash
hashcat -m 1000 -a 0 /evidence/hash.txt /evidence/candidates.txt \
  -r /usr/share/hashcat/rules/best64.rule --potfile /evidence/potfile.txt
# Status: 1/1 | Recovered: 1/1 | Time: 12.00s
```

第 6 步，**实际验证（决定性步骤）**：用解出的口令登录**镜像内的 SQL Server 备份恢复实例**，只读执行。

```bash
sqlcmd -S localhost -U zhangsan -P '<已脱敏>'
# 1> SELECT TOP 5 name FROM sys.tables;
# 1> GO
#   name
#   ------ ----------
#   t_user
#   t_order
#   ...  ← 成功返回业务表名
```

**注意这一步验证的是什么**：验证的是「该哈希确实对应这个账户的口令」，**全部发生在本地恢复实例上，不涉及任何在线服务。**

第 7 步，交叉印证：

```bash
python3 dpapi.py -t credman -k /evidence/SYSTEM -s /evidence/SOFTWARE \
  -p '<已脱敏>' -o /evidence/pp
python3 impacket-secretsdump -credman /evidence/pp | grep FINANCE_LEGACY
# FINANCE_LEGACY: <已脱敏>      ← 同一口令，第二条独立证据
```

第 8 步，固定证据：

```bash
printf 'sam_offset=0x%x\
hint_file_offset=0x3f21a800\
potfile=%s\
verify_sql=%s\
' \
  <SAM偏移> /evidence/potfile.txt 'SELECT TOP 5 name FROM sys.tables;' \
  > /evidence/evidence-index.txt
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 该设备存在账户 `zhangsan`（RID 1001） | SAM hive 记录 | 强 |
| 该账户登录口令为 X | 哈希字典命中 + 只读 SQL 验证成功 | **强（唯一决定性判据）** |
| 同一口令亦用于 LSA Secret | `FINANCE_LEGACY` 独立解出 | 强（双源一致） |
| 该账户与勒索事件数据源同一 | 上述结论 + 委托方侧佐证 | 强 |

**不能证明的**：**账户同一性不等于操作人同一性**——共用账户、凭据共享、远程登录都会打破这个等式。

本次**未确认是谁在何时使用了该口令**，这需要登录会话记录或服务端日志。

**未验证该口令在其他服务上是否复用**——该判断交由委托方通知相关方，**取证方不主动联系第三方**。

**误判对照**

本案最容易犯的错误是**跳过第 3 步，直接上 8000 万词大型字典**。

**为什么这个做法在本案里是纯粹的浪费**：镜像里已经存在一个明文 `密码提示.txt`，它把候选集缩到了 4 条。

4 条候选在单核 CPU 上 12 秒就能验完，而全量字典要跑数天算力——两者的成功率完全相同，因为真正的口令就在那 4 条里。

**正确判据有三条**：

1. **必须先做非爆破分析**。候选集的来源优先级是：镜像内明文线索 > 组织常见口令策略 > 使用习惯推断 > 全量字典。**前三种都是秒级成本，只有最后一种是天级成本。**
2. **必须做 RID 判定**。结合对象类型与名称识别出的机器账户（`WIN-DIGI-01$`、`MSSQL$SVC` 这类名称以 `$` 结尾的计算机账户与服务账户）直接排除——**恢复机器账户口令既无价值，也无授权依据**。注意 RID ≥ 1000 只是新建对象的默认区间，域用户 RID 同样落在其中，不能仅凭 RID 归为机器账户。
3. **必须做实际验证，而不能止于哈希命中**。哈希命中只说明「找到了一个能匹配该哈希的字符串」；用它在本地恢复实例上成功执行查询，才能证明「该哈希确实对应这个账户的口令」。

**按错误判据走的代价**：跳过明文分析直接上全量字典，除了浪费数天算力与电费，更糟的是当委托方事后问「为什么用了这么久」时，报告里会写上「采用字典攻击恢复口令」——这句话会让人误以为本案依赖了暴力破解，而实际上根本没有那个必要。

方法论上的低效，会在报告里被读成能力边界或合规瑕疵。

<a id="section-33"></a>

### 5.2 最小化与脱敏：完整口令为何不能进报告正文

**场景**

5.1 的结论已坐实。委托方拿到报告后提出一个看似合理的请求：**「把口令直接写在报告里，我们内部好核对。」**

**处置过程**

按授权范围与最小化双重约束处理：

```bash
# 报告正文：只写方法与验证，不写值
cat >> /evidence/report-section.md <<'EOF'
账户 zhangsan（RID 1001）的 NTLM 哈希位于 SAM hive 偏移 0x8a3f2000，
已通过字典攻击（候选集 4 条，来自镜像内明文线索）恢复，
并在镜像内 SQL Server 备份恢复实例上以只读查询
（SELECT TOP 5 name FROM sys.tables）实际验证通过。
完整口令见受控附件 A-2（单独封存，访问需二次审批）。
EOF

# 受控附件：口令值单独封存，与报告正文分离
printf 'A-2 分类: 高度敏感 / 访问需二次审批 / 禁止复制粘贴至即时通讯\
' \
  > /evidence/A-2-header.txt
```

```bash
# 同时写入合规说明页
cat >> /evidence/report-section.md <<'EOF'
附：《恢复方法合规说明》
- 授权书编号、检材 SHA-256、恢复目的（账户同一性认定）
- 为何选择字典攻击而非暴力破解：镜像内存在明文口令提示文件，
  候选集仅 4 条，穷举无必要亦无授权依据
- 风险提示：本账户口令可能复用至第三方服务，
  建议委托方通知相关方自行改密（由委托方负责，取证方不主动联系）
- 全程未使用该口令登录任何在线服务
EOF
```

**结论**

- 报告正文**不出现完整口令**。正文的证明力来自「哈希偏移 + 候选集来源 + 实际验证 SQL 与返回结果」这三项，**而不是来自口令值本身**。
- 完整口令作为**受控附件单独封存**，访问需二次审批。
- 本案**已向委托方提示口令复用风险**，但**改密动作由委托方负责**，取证方不主动联系任何第三方。
- **不能证明的**：**不能证明该口令在其他服务上是否确实被复用**——这需要各服务方配合，超出本案检材范围。

**误判对照**

错误做法是**直接把完整口令写进报告正文**，理由通常很朴素：「委托方要的就是这个值」。

**为什么这是错的**：报告正文的流转范围**远大于取证工作站**——它会经过委托方法务、业务部门，可能在庭审中出示，可能被复制进邮件与即时通讯。

**口令在工作站上是受控的，在报告流转链中就不是了。**

更关键的是，**本案并不需要这个值就能成立结论**：账户同一性靠的是「哈希 + 实际验证」，不是「看到了口令文本」。

**正确判据有三条**：

1. 判断标准是「这份报告会交给谁看」，而不是「委托方现在想看什么」。需要写入正文的，是**方法与验证过程**；需要封存的，是**敏感值**。
2. **报告正文必须有完整的可复核性**。哈希偏移、候选集来源与规模、验证用的 SQL 与返回结果——这三项足以让任何复核人独立重现结论，且不含任何敏感值。做不到这一点，才说明报告偷懒用值代替了证据。
3. **复用风险要提示，但不越界处置**。写「可能复用至第三方，建议通知相关方改密」是提示；**主动联系第三方或代为改密，则越过了授权边界**。

**按错误判据走的代价**：口令进入报告正文后，**它的暴露面就等于报告的接收方数量**。

一旦该账号在第三方服务出现异常，**没有任何记录能说明这个值是从哪里流出去的**，责任无法归因。

而这个错误在写入的当时毫无成本——**它属于成本最低、后果最重的一类取证错误。**

<a id="section-34"></a>

### 5.3 反例：RID 1000+ 机器账户与范围外账号的排除

**场景**

从 SAM 中导出了 14 个账号，其中包含 `MSSQL$SVC`（RID 1002）等机器账户，以及一个 `IT-admin` 域账号。若把它们一并纳入恢复计划，会同时踩到授权边界与无效劳动两个坑。

**处置过程**

按 RID 与归属双重判定分类：

```bash
secretsdump.py -n 0x102 /evidence/SAM | tee /evidence/accounts.txt
# zhangsan:1001:<NTLM-hash-已脱敏>:::
# MSSQL$SVC:1002:...:::
# WIN-DIGI-01$:1000:...:::        ← RID 1000 是分配区间的起点，不是内置账户；
#                                    它是机器账户（名称含 $ 美元符号），靠对象类型排除
```

```bash
# 逐个判定并记录排除理由，而不是简单不列
cat > /evidence/account-scope.txt <<'EOF'
zhangsan    RID 1001  普通用户   纳入（授权范围内，恢复目的直接相关）
MSSQL$SVC   RID 1002  机器账户   排除：服务账户口令由系统生成，恢复无价值
WIN-DIGI-01$ RID 1000 机器账户   排除：名称含 $ 美元符号、objectClass=computer，且机器账户不用于交互式登录
IT-admin    RID 1100 域账号     排除：非本案授权范围，仅作范围外发现上报
EOF
```

**结论**

- 本案实际纳入恢复的**只有 `zhangsan` 一个**，其余 13 个均记录了**明确的排除理由**。
- `IT-admin` 属**范围外发现**，**必须上报而非丢弃**，上报格式为「发现归属 `IT-admin` 的域账号条目，未还原、未验证」。
- **不能证明的**：**机器账户被排除 ≠ 这些账户未被使用**。

机器账户可被用于服务间认证，`IT-admin` 可能正是本案的关键人物。

排除的依据是「不属于本案证明目标」，不是「不重要」。

- **未覆盖范围**：本次未取得域控侧日志，**因此无法判断是否存在域账号被盗用的迹象**。

**误判对照**

两种错误方向：一是**看到 14 个哈希就全部纳入恢复**，二是**把机器账户直接删掉、不留任何记录**。

**为什么两种都不可取**：第一种会**把算力浪费在机器账户上**（机器账户口令是系统随机生成的高强度值，字典攻击几乎不可能命中），更严重的是**扩大了恢复范围，超出授权书载明的目的**。

第二种则制造了**记录空白**——三个月后复核时，报告里只有「排除了某些账户」而无理由，看起来像分析员漏掉了它们。

**正确判据有三条**：

1. RID ≥ 1000 排除的是「交互式登录价值」，不是「账户存在性」。机器账户必须**记录排除理由**，不能静默删除——`RID 1000`（`WIN-DIGI-01$` 这类机器账户）尤其容易被误当作普通用户。
   > **注意 RID 1000 的性质**：它**不是**内置账户，而是 RID 分配区间的起点。Windows 内置管理员是 **RID 500**（`S-1-5-21-<domain>-500`），内置来宾是 501。把 1000 称作"内置"会导致排除理由写错。机器账户靠**名称以 `$` 结尾**与 `objectClass=computer` 识别，**不能靠 RID 认出**——它恰好落在普通分配区间内。
2. **授权范围决定恢复范围**。`IT-admin` 是域账号，恢复其口令既超出本案证明目标，也超出授权书载明的范围。正确处理是作为范围外发现登记。
3. **排除记录本身是交付物的一部分**。`account-scope.txt` 这份清单让复核人能确认「14 个账号为何只恢复 1 个」，**它证明的是分析过程的完备性**。

**按错误判据走的代价**：无差别地全量恢复，一旦授权书被审查，会被认定为**超出授权范围的凭据恢复**——这是比技术失误严重得多的问题。

而静默删除排除记录，则在复核阶段无法自证清白，**委托方只能选择不采信整份报告**。

**阴性发现的写法**：正确表述是「在本案 SAM 导出的 14 个账号中，仅 `zhangsan`（RID 1001）属于授权范围内且与证明目标直接相关；其余 13 个已按 RID 与归属逐一记录排除理由」。

**必须同时列出未覆盖范围**（域控侧日志、其他设备上的同账号活动），否则这份清单会被读成「该机只有 14 个账号活动」。

<a id="section-35"></a>

## 六、扩展阅读方向

下面四组方向按"你在本篇之后会撞到的问题"组织。


**第一组：前置基础——先算清代价，再谈方案**

本篇的核心判断是"值不值得攻"，而这个判断需要两个基础能力。

- [哈希与完整性校验](../../fundamentals/fundamentals-concepts/fundamentals-concepts-hashes-and-integrity-verification.md) —— 本篇的"验证"步骤依赖的正是哈希知识。**同一套概念在取证里有两个角色**：验证检材是否被改动，和验证候选口令是否正确。这篇讲清了角色边界，也讲清了为什么"算出一个碰撞"不等于"拿到了口令"。
- [证据保管链与委托证明](../../fundamentals/fundamentals-chain/fundamentals-chain-chain-of-custody-and-authorization.md) —— 红线一要的可执行形式。**把授权书与检材编号绑定归档、开工前先记录**，这些动作在本篇步骤 1 里不是形式，而是这个链接的落地方式。
- [取证技能树](../../fundamentals/fundamentals-process/fundamentals-process-forensics-learning-path.md) —— 本篇要求的前置能力（文件格式识别、哈希提取、算力估算、时间记录）在这张树上的位置，以及缺哪一块该先补哪一块。缺"文件格式识别"直接上手算力，是本领域不必要的资源消耗。

**第二组：相邻议题——本领域的三条死路**

这三件事在网上流传极广，在取证语境里全是陷阱。

看清它们的失效原因，比多学一个工具更有用。

- [BitLocker 全卷加密取证](../crypto-volume/crypto-volume-bitlocker.md) —— **全卷加密不走爆破这条路**。BitLocker 的安全目标是"仅授权方可以恢复"，恢复密码与启动密钥是明文留存的，直接搜比暴力破解快几个数量级。先判断是"卷加密"还是"文件口令"，决定了整个处置方向。
- [EFS 文件系统加密取证](../crypto-volume/crypto-volume-efs.md) —— DPAPI 有**比爆破更短的路**：用户 profile 里的 master key，用已知密码即可解开。本篇的优先级表在 EFS 场景下要改写——"同机复用"之上还有"直接取私钥"这一层。
- [VeraCrypt 加密卷取证](../crypto-volume/crypto-volume-veracrypt.md) —— VeraCrypt 的设计目标就是"忘了密码则数据永久丢失"。本篇的方法论在这里适用性最弱，那篇明确列出了三条现实路径（找口令、找明文副本、找实现缺陷），**并解释了为什么"强行爆破"在这里不是一个理性选项**。读它是为了正确评估可行性，不是为了提高成功率。

**第三组：工具与规范——可复现性与法庭可采性**

- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md) —— 本篇红线一的制度依据，也是"在什么条件下可以对委托范围外的对象动手"的答案。在争议程序里，授权书的字句范围往往比技术判断更能决定结论。
- [时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md) —— 多机分布式恢复时，**各节点的时钟不同步会让恢复时间线失去参考价值**。分布式任务调度那部分工作必须先固定时间基准，否则事后无法说明"哪台机器什么时候算出了什么"。
- [远程工具凭据解密](crypto-app-remote-tool-credential-preservation.md) 与 [浏览器密码库与 Token 解密](crypto-app-browser-passwords-and-tokens.md) —— **本篇的输入来自那两篇**。任何Desk侧加盐单向哈希（`pwd_hash`、`access_pin_hash`）在那边被判定为"单向不还原"之后，是否进入本篇的离线验证，取决于红线一的授权范围与红线二的优先级判断。**这是本篇方法论最典型的应用场景。**

**第四组：判据与反例——如何证明"打不开"**

本领域较多产出的是负面结论，而负面结论的可辩护性要求最高。

- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— **一个关键前提的检验**：如果对方有能力改动检材，那"提取到的哈希就是数据库里存的那个"这件事本身就需要独立验证。哈希提取自 `SAM` hive 这一环节本身就是取证的一个争议点。**读它是为了知道自己的前提有多脆弱。**
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 本篇"提取 → 选择 → 执行 → 验证"四阶段的上游依据，以及"为什么验证不能跳过"在方法论层面的论证。
- [取证概念与分类](../../fundamentals/fundamentals-concepts/fundamentals-concepts-digital-forensics-concepts.md) —— 本篇讨论的所有对象——哈希、密文、密钥材料——在证据分类里各自属于哪一类、对应什么样的可采性要求。搞清楚"我手上的东西是什么类型"，比"我要用它做什么"更基础。

**一句话收尾这四组**：前置基础那组决定你会不会白烧算力；相邻议题那组决定你会不会把"爆破"当成唯一路径（卷加密、EFS、VeraCrypt 三种场景里，爆破分别是错的、次优的、和不该做的）；工具与规范那组决定你的方法论能不能在争议程序里站住（**闭源工具的不可复现性是真实的弱点**）；判据与反例那组决定你写下"打不开"这句话时，是不是附带了一个可辩护的范围。

本篇产出的是"我做了什么、花了多少算力、怎么验证的"，不是"我拿到了口令"——这两句话在法庭上的分量差一个数量级。
<a id="section-36"></a>

## 七、命令速查

```bash
# ===== 0. 环境自检 =====
hashcat -I                                # 列出可用计算设备
hashcat --example-hashes | less          # 权威的模式号/格式对照（务必先查）
john --list=formats | less               # JtR 支持的格式
hashcat --version

# ===== 1. 哈希提取（示例检材）=====
reged -x DigiForensics.dd "/WINDOWS/system32/config/SAM"     /tmp/SAM
reged -x DigiForensics.dd "/WINDOWS/system32/config/SECURITY" /tmp/SECURITY
python3 secretsdump.py -sam /tmp/SAM -security /tmp/SECURITY -nthashes > ntlm.txt
sudo cat /mnt/image/etc/shadow            # Linux 的 crypt 格式口令

# ===== 2. 加密文件 → 哈希 =====
cd /usr/share/john/run
python3 pdf2john.py    evidence.pdf   > evidence_pdf.hash
python3 office2john.py evidence.xlsx  > evidence_xlsx.hash
python3 7z2john.py     evidence.7z    > evidence_7z.hash
python3 keepass2john.py vault.kdbx    > evidence_kdbx.hash

# ===== 3. 攻击 =====
# 字典
hashcat -m 1000 -a 0 hash.txt wordlist.txt
# 字典 + 规则
hashcat -m 1000 -a 0 hash.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
# 掩码（8 位数字）
hashcat -m 1000 -a 3 hash.txt ?d?d?d?d?d?d?d?d
# 混合：候选词 + 4 位数字
hashcat -m 1000 -a 6 hash.txt candidates.txt ?d?d?d?d
# John the Ripper（CPU）
john --format=NT hash.txt --wordlist=wordlist.txt --rules

# ===== 4. 结果管理 =====
hashcat -m 1000 hash.txt --show                      # 查看已解出
hashcat -m 1000 hash.txt --left                      # 查看未解出
hashcat -m 1000 -a 0 hash.txt wordlist.txt --session=case01
hashcat --session=case01 --restore                  # 断点续跑
hashcat --status                                     # 另终端观察运行状态
hashcat -m 1000 -a 0 hash.txt wordlist.txt --potfile-path=./ntlm.pot

# ===== 5. 实际验证（不可跳过）=====
7z t -p'<解出的口令>' evidence.zip && echo VERIFIED
mysql --skip-column-names -h <host> -u <user> -p'<解出的口令>' -e "SELECT VERSION();"

# ===== 6. 常用模式号速查（以 --example-hashes 为准）=====
#   0     MD5              100   SHA-1            1400  SHA-256
#   1700  SHA-512          1000  NTLM             124   Django (SHA-1)
#   10000 Django PBKDF2-SHA256        2100  DCC2 / mscash2
#   2500  WPA-EAPOL-PBKDF2 (.hccapx, 旧)   22000 WPA-PBKDF2-PMKID+EAPOL (.hc22000, 新)
#   3200  bcrypt ($2*$)    5500  NetNTLMv1        5600  NetNTLMv2
#   7500  Kerberos AS-REQ  13100 Kerberos TGS-REP (etype 23)
#   16500 JWT              8900  scrypt           22100 BitLocker
#   注：模式号随 hashcat 版本增删，写入报告前请用 --example-hashes 复核
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 加密取证 — Passware Kit 与通用密码恢复方法论」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《Passware Kit 与通用密码恢复方法论》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-mem.raw`、`DigiForensics-masterkey.bin` 均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
