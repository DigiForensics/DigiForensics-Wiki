---
title: "应用私有数据与 SharedPreferences"
slug: "mobile-android-sharedpreferences"
canonical: "https://www.digiforensics.cn/wiki/mobile-android-sharedpreferences"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:49+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "mobile"
space: "移动取证"
node_path: ["Android"]
---

# 应用私有数据与 SharedPreferences

<a id="section-1"></a>

## 一、概述

应用私有目录是移动取证里**数据密度最高、体积最小、解析难度最低**的那一块。

物理镜像动辄上百 GB，一个应用私有目录可能只有几 MB。账号标识、登录状态、配置项、本地缓存、密钥痕迹，全挤在这几 MB 里。

它也是每个案件里最先被打开、也最先出结论的目录。

其中 `shared_prefs/` 尤其特殊：**明文 XML**，不需要任何解密工具，文本编辑器直接读。用户 ID、服务器地址、上次登录时间、搜索历史、已保存的账号摘要都在这里。

**没有这套读法会发生什么**：结论会从「应用记录了什么」退化成「应用目录里有若干文件」。

同一个应用、同一个版本，目录里躺着七八个子目录。挑哪个、先看什么、哪个可以丢，直接决定报告有没有实际内容。

更隐蔽的失败是**看起来有结论，其实是错的**。只读 `app.db` 而漏了 `-wal`，数据库会安静地退回上一次 checkpoint，最近几天的记录凭空消失，不报任何错（见 [陷阱 1](#section-14)）。

它在流程里的位置是**分析环节的最前段**。输入是 [Android 数据存储总览](mobile-android-android-data-storage-overview.md) 已经提取出来的应用私有目录，输出是可供时间线与关联分析的明文配置和数据库路径。

上游依赖提取工艺与完整性校验（流式导出、哈希固定、`tr -d '\r'` 这类批量细节见 [陷阱 9](#section-24)）。下游支撑三条线：

- **账号关联**：用 prefs 里的账号标识串并多应用
- **加固识别**：`lib/` 里的 so 决定静态分析能不能看到真实逻辑，见 [APK 逆向与 Manifest 分析](mobile-android-apk-manifest.md)
- **动态分析的路线判断**：`no_backup/` 里的密钥材料决定 [Frida 动态 Hook](mobile-android-frida-dynamic-hooking.md) 要 hook 什么

**涉及的证据形态**（具体到文件名与结构）：

| 形态 | 具体位置 | 结构特征 |
|---|---|---|
| 偏好配置 | `shared_prefs/<name>.xml` | 根标签 `<map>`，键在 `name` 属性上，值类型由元素标签决定 |
| 旧版偏好 | `shared_prefs/<name>.xml.bak` | **上一个完整版本**，可能比主文件更新鲜 |
| 加密偏好 | `shared_prefs/encrypted_shared_prefs/` | `androidx.security` 写入的密文，无 XML 声明 |
| 业务库 | `databases/app.db` + `-wal` + `-shm` | **三件套必须同在**，漏 WAL 丢最近写入 |
| 任意文件 | `files/`、`cache/`、`code_cache/` | `cache/` 可重建但含"访问过"的独立旁证 |
| 密钥材料 | `no_backup/*.key` | 高熵二进制、无文件头，取证只固定哈希 |
| 加固 so | `lib/<abi>/*.so` 与 APK 内同名目录 | 库名含 `jiagu`/`packer` 等即加固信号 |
| 外部目录 | `/sdcard/Android/data/` 与 `/sdcard/Android/media/` | 前者卸载即删，**后者卸载保留**，是卸载取证唯一入口 |

这个应用登录过哪些账号、上次活跃在什么时候、连过哪些服务器地址、搜索过什么关键词、是否被加固、卸载后还留下什么。

聊天内容与文件传输记录在加密库里能不能读出来（取决于加固与密钥材料，见 [2.3](#section-5)）；应用服务端存了什么；`cache/` 里的内容是不是用户真实看过——它只证明访问，不证明使用。

本篇给的是「从文件里能读出什么」，不是「用户做了什么」。

**本文不做的事**：不做应用运行时分析，不提取任何凭据的明文用途，不尝试在线使用检材内的会话令牌。遇到加密库时只做三件事：识别、固定哈希、标注解密条件。

**读者前提**：Linux 目录结构、XML 基础、ADB 基本操作，以及一个可执行的 Python 环境（本篇的解析脚本只用标准库）。

读 [二、核心原理](#section-2) 之前，先确认设备侧已经完成目录级提取并做过哈希。本篇的分析动作全部建立在「目录完整」这个前提上，前提不成立时本章所有读法都不适用。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 应用私有目录的七个子目录

```
/data/data/com.digiforensics.sample/        （等价于 /data/user/0/com.digiforensics.sample/）
├── shared_prefs/     ← ★ XML 键值配置，明文，首要目标
├── databases/        ← ★ SQLite 数据库 + -wal / -shm
├── files/            ← 任意文件（图片、文档、下载、自定义格式）
├── cache/            ← 临时缓存，可安全丢弃但对判断"访问过"有价值
├── no_backup/        ← 应用声明的"不参与备份"数据
├── lib/              ← ★ 应用自带 so 库（可能是加固壳）
└── code_cache/       ← 优化后的 DEX（Android 11+）
```

**优先级**：`shared_prefs/` 与 `databases/` 并列第一（明文配置与业务数据密度最高）；`files/` 与 `lib/` 次之（导出文件与**加固识别**，见 [03](mobile-android-apk-manifest.md)）；`no_backup/` 第三（**部分加密密钥材料、临时 DB 在此**）；`cache/` 与 `code_cache/` 最后（前者能证明"曾访问过某功能"，后者含混淆后的类结构）。

<a id="section-4"></a>

### 2.2 SharedPreferences 的文件格式
每个 `shared_prefs/<prefs_name>.xml` 对应一个偏好设置文件（对应代码里的 `getSharedPreferences(name, mode)`）。格式是标准 Android XML：

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="user_id">8827341</string>
    <boolean name="is_logged_in" value="true" />
    <int name="login_count" value="17" />
    <long name="last_login_time" value="1717213492000" />
    <float name="upload_quality" value="0.75" />
    <string name="last_search">优盤清倉</string>
</map>
```

**解析要点（这几条决定提取准不准）**：根标签是 **`<map>`**，不是 `<preferences>`，也不是 `PreferenceScreen`。**键在 `name` 属性上，不在元素名上**，所有键值都是同一层级的子元素。**值类型由元素标签决定**：`string` 是文本，`int` / `long` 是数值，`float` 是浮点，`boolean` 写成 `value="true"`。

`long` 时间戳几乎都是**毫秒级**，而且**必须 64 位解析**。`1717213492000` 用 32 位会溢出成负数。

还有三条容易翻车的：

- **① `.bak` 文件**：写入中断会留下 `<name>.xml.bak`，它是上一个完整版本，**内容可能比当前文件更新鲜**
- ② `encrypted_shared_prefs/`：Android 7+ 的 `androidx.security` 库使用，**内容是密文，不能按普通 XML 解析**
- **③ 重复键**：同名键可能重复出现（写入异常，或从 `.bak` 恢复所致），**按出现顺序全部读取并记录次数，不要只取第一个**

> **`.bak` 的实战价值经常被忽略。** Android 写 SharedPreferences 是「写临时文件 → 改名覆盖」，异常中断（应用被杀、空间不足）会留下 `.bak`。用户已经「退出登录」（当前文件 `is_logged_in=false`），`.bak` 里还留着 `true` 和旧账号。**两个文件的时间戳对比本身就是一条时间线证据。**

```bash
# 提取与初筛（shared_prefs 全是明文 XML，可直接 grep）
adb shell su -c "tar -cf - -C /data/data/com.digiforensics.sample shared_prefs" > prefs.tar
tar -xvf prefs.tar

# 全文搜索敏感关键词（一次性扫出所有应用配置）
grep -ril -E 'password|passwd|token|secret|api_key|session|cookie|auth' extracted/ \
  | tee suspicious-prefs.txt
```

<a id="section-5"></a>

### 2.3 `lib/` 目录：加固识别的第一现场

```
/data/data/com.digiforensics.sample/lib/arm64-v8a/
├── libappcore.so
├── libnative-lib.so
└── libjiagu.so          ← 名称含"jiagu/加固/bang"等即强加固信号
```

`/data/app/` 下安装的 APK 解包后也有 `lib/<abi>/`，两处应合并检查。

这套结构要回答的问题是：这个应用运行时到底加载了哪些 native 代码。

商业 App 里，加固库的存在意味着静态分析只能看到壳，解密 key 通常在 so 运行时初始化。这直接决定 [05 即时通讯取证](mobile-android-instant-messaging-forensics.md) 中「能否拿到数据库密钥」这条路径的成本。见 [03](mobile-android-apk-manifest.md) 的加固识别与 [04](mobile-android-frida-dynamic-hooking.md) 的动态分析。

```bash
PKG=com.digiforensics.sample
adb shell su -c "find /data/data/$PKG/lib /data/app/*/$PKG*/lib -name '*.so' 2>/dev/null" \
  | tee so-list.txt
file extracted/lib/arm64-v8a/*.so          # 确认架构与是否被剥符号
```

<a id="section-6"></a>

### 2.4 外部存储与分区存储的变化

| Android 版本 | 存储模型 | 取证影响 |
|---|---|---|
| ≤ 9（Pie） | 传统全权限，任一应用读写整个 `/sdcard` | 第三方应用数据散落在 `/sdcard/<App名>/` |
| **10（Q）** | **分区存储**：应用只能访问自己的专属目录 + 媒体库 | 旧路径大量失效 |
| 11–12 | 分区存储 + 权限收紧 | 更多数据留在应用私有目录 |
| 13–15 | 作用域化更严，`READ_MEDIA_*` 细分 | 内外部差异进一步扩大 |

**Android 10+ 的实际目录形态**（≤9 时代数据散落在 `/sdcard/<App名>/`，分区存储后这些旧路径大量失效）：

| 路径 | 内容 | 备注 |
|---|---|---|
| `/sdcard/Android/data/<包名>/` | 应用专属外部目录 | 卸载应用时**会被一并删除**（取证价值高但易灭失） |
| `/sdcard/Android/media/<包名>/` | **Android 11+ 的媒体专属目录** | 卸载后**保留**，是卸载应用的取证入口 |
| `/sdcard/Download/` | 下载目录 | **安装包、转账凭证导出常在此** |
| `/sdcard/DCIM/`、`Pictures/`、`Movies/`、`Documents/`、`Android/obb/<包名>/` | 媒体库（`MediaStore` 索引源）与扩展资源包 | Android 10+ 需通过 MediaStore 访问 |

> **两个高价值推论**：① 已卸载应用的数据线索主要在 `/sdcard/Android/media/<包名>/`——`Android/data` 随卸载清除但 `Android/media` 保留（Android 11+ 明确如此），这是"卸载后取证"的唯一常规入口。② `/sdcard/Download/` 是安装包与导出文件的高发地，赌博、诈骗类案件的 APK 残留、转账截图导出常在此（见 [01](mobile-android-android-data-storage-overview.md) 案例）。

```bash
adb shell su -c "ls -la /sdcard/" | tee sdcard-root.txt
adb shell su -c "du -sh /sdcard/Android/data/* /sdcard/Android/media/* 2>/dev/null" | sort -h | tail -20
adb pull /sdcard/Download/ extracted/Download/
```

---

<a id="section-7"></a>

## 三、操作步骤

<a id="section-8"></a>

### 第 1–2 步：定位并流式导出

```bash
PKG=com.digiforensics.sample
adb shell pm path $PKG                            # APK 位置（/data/app/...）
adb shell su -c "du -sh /data/data/$PKG"           # 体积，决定提取策略
adb shell su -c "tar -cf - -C /data/data $PKG" > app.tar
sha256sum app.tar | tee app.tar.sha256             # tar 包本身先哈希固定
tar -tf app.tar | head -60 && tar -xf app.tar     # 先列后拆，确认包完整
find extracted -type f -exec sha256sum {} \; > hashes-app.txt
```

<a id="section-9"></a>

### 第 3 步：优先处理 `shared_prefs/`

```bash
ls -l extracted/shared_prefs/
find extracted/shared_prefs -name '*.bak' -ls       # 别漏 .bak
python3 parse_prefs.py extracted/shared_prefs prefs-report.csv
column -s, -t prefs-report.csv | head -40
```

**可直接运行的 Python 脚本**（批量解析并汇总 SharedPreferences）：

```python
#!/usr/bin/env python3
# 批量解析 shared_prefs/*.xml 汇总为 CSV。Python 3.8+，仅标准库
# 用法: python3 parse_prefs.py <shared_prefs目录> <输出CSV>
import csv, datetime, os, sys
import xml.etree.ElementTree as ET

SENSITIVE = ("password", "passwd", "pwd", "token", "secret", "key",
             "session", "cookie", "auth", "sign", "credential", "salt")

def human_time(v):
    """毫秒/秒时间戳 → 可读时间；明显不是时间戳则原样返回。"""
    try:
        n = int(v)
    except (TypeError, ValueError):
        return v
    if 1_000_000_000 < n < 4_000_000_000:            # 秒级
        n *= 1000
    if 946_684_800_000 < n < 4_102_444_800_000:       # 2000 ~ 2100
        return datetime.datetime.utcfromtimestamp(
            n / 1000).strftime("%Y-%m-%d %H:%M:%S")
    return v

def parse_file(path):
    """返回 [(key, type, value, flag), ...]；解析失败返回空表。"""
    rows = []
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as e:
        print(f"[!] 解析失败 {path}: {e}", file=sys.stderr)
        return rows
    for el in root:                                   # 根标签通常是 <map>
        key = el.get("name", "")
        value = el.get("value")
        if value is None:
            value = (el.text or "").strip()
        flag = "SENSITIVE" if any(s in key.lower() for s in SENSITIVE) else ""
        if el.tag == "long" and not flag:
            value = human_time(value)                 # 疑似时间戳则转换
        rows.append((key, el.tag, value, flag))
    return rows

src, out = sys.argv[1], sys.argv[2]
total = sens = 0
with open(out, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["prefs_file", "key", "type", "value", "flag"])
    for fn in sorted(os.listdir(src)):
        if not fn.endswith((".xml", ".xml.bak")):
            continue
        for key, vtype, value, flag in parse_file(os.path.join(src, fn)):
            w.writerow([fn, key, vtype, value, flag])
            total += 1
            sens += 1 if flag else 0
print(f"共 {total} 个键值，其中敏感键 {sens} 个 → {out}")
```

<a id="section-10"></a>

### 第 4 步：`databases/` 正确提取（不要漏 WAL）

```bash
ls -l extracted/databases/                          # app.db / app.db-wal / app.db-shm
adb shell su -c "tar -cf - -C /data/data/com.digiforensics.sample databases" > db.tar
tar -xvf db.tar
sqlite3 extracted/databases/app.db "PRAGMA integrity_check;"
sqlite3 extracted/databases/app.db ".tables"
```

> **`-wal` / `-shm` 漏掉的后果**：数据库会"退回"到上次 checkpoint 的状态，**最近写入的数据全部消失**。这会让人误判"数据被删了"，是移动取证里常见的误判之一。详见 [09-SQLite-WAL取证](../mobile-database/mobile-database-sqlite-wal.md)。

<a id="section-11"></a>

### 第 5–7 步：外部存储、跨应用搜索与验证

```bash
adb pull /sdcard/Android/data/com.digiforensics.sample/  extracted/ext-data/
adb pull /sdcard/Android/media/com.digiforensics.sample/ extracted/ext-media/  # 卸载后仍保留
adb pull /sdcard/Download/  extracted/Download/
find extracted -type f -exec sha256sum {} \; > hashes-ext.txt

# 跨应用：一次性抓出所有应用的 shared_prefs
mkdir -p all-prefs
for d in $(adb shell su -c "ls /data/data/" | tr -d '\r'); do   # tr -d '\r' 必须加
  adb shell su -c "tar -cf - -C /data/data/$d shared_prefs 2>/dev/null" \
    | tar -xf - -C all-prefs 2>/dev/null
done
grep -ril -E 'password|token|secret|api_key|session' all-prefs/ | head -40

# 验证：设备端与本地哈希一致 + 库完整 + prefs 时间线
adb shell su -c "md5sum /data/data/com.digiforensics.sample/databases/app.db"
md5sum extracted/databases/app.db
sqlite3 extracted/databases/app.db "PRAGMA integrity_check;"     # 期望 ok
find extracted/shared_prefs -type f -printf '%T@ %p\
' | sort -n
```

---
<a id="section-12"></a>

## 四、常见陷阱

应用私有目录是「用文本编辑器就能读」的部分。

正因为门槛低，这一章的陷阱几乎全部来自**偷懒式的省事动作**：只拉一个文件、只读主文件、凭记忆拼路径、用 32 位整数存时间戳。

每一个都会安静地产出一份看似合理的错误结论。

<a id="section-13"></a>

### 4.1 数据库与 WAL

<a id="section-14"></a>

#### 陷阱 1：只拉 `app.db`，丢掉 `-wal` / `-shm`

**现象**：只提取了 `databases/app.db` 一个文件，`sqlite3` 打开正常、`.tables` 能列出表名、记录数也读得出来，于是报告写「该应用数据库中未发现 X 记录」。

**原因**：应用在 Android 上普遍使用 **WAL（预写日志）模式**——新的写入先追加到 `app.db-wal` 文件里，事务提交后并不立刻写回主库文件，而是等到 checkpoint 触发时才批量合并。进程被系统杀掉、应用崩溃、或者数据量没到阈值，`-wal` 里的内容就一直留在那里。单独打开 `app.db` 时，SQLite 读到的就是这个数据库上一次 checkpoint 时的快照，结构完整、校验通过、唯独缺了最近这一段。**它不报错、不警告、也不提示「我看到的不是全部」**——查询结果看起来完全正常，只是少了最近几天的记录。

**影响**：**这是「以为自己找到了，其实漏了」的典型形态。**

最常见的表现是「数据库里最后一条记录停在案发前一周」，分析人员据此得出「用户在该时段未使用本应用」。而这批记录就躺在提取目录旁边的 `-wal` 文件里。

这类误判**难以通过复检发现**：若复检时不重新核对 `-wal` / `-shm`，常规复检会沿用同一份不完整快照。报告里的「未发现」本身没错，只是「发现」的对象是个不完整的快照。

**核查**：`databases/` 必须整目录打包，三个文件同在。`-shm` 是共享内存索引文件，一般可以由 SQLite 重建，但**一并提取成本低**：

```bash
PKG=com.digiforensics.sample
# ① 目录级导出，-wal / -shm 天然包含在内
adb shell su -c "tar -cf - -C /data/data/$PKG databases" > db.tar
tar -xf db.tar -C extracted/

# ② 提取完成后先确认 journal_mode 与三件套齐备
ls -l extracted/databases/app.db*
sqlite3 extracted/databases/app.db "PRAGMA journal_mode;"
# 期望 wal

# ③ 关键：让 SQLite 自己把 WAL 合并进主库，合并前后分别查一次做差分
sqlite3 extracted/databases/app.db "SELECT count(*) FROM <业务表>;"   # 合并前
sqlite3 extracted/databases/app.db "PRAGMA wal_checkpoint(TRUNCATE);"  # 显式合并
sqlite3 extracted/databases/app.db "SELECT count(*) FROM <业务表>;"   # 合并后
```

两次 count 的差值就是「差点漏掉的记录量」，这个数字要写进报告——它是证明提取完整性的直接证据。注意：合并操作会改写副本，绝不能在设备侧或原始检材上做，只能在提取出的副本上做。 若设备侧已用 `PRAGMA wal_checkpoint` 之类的命令处理过，那是写操作——见陷阱 10。

<a id="section-15"></a>

#### 陷阱 2：把 `cache/` 当垃圾，删掉之前没做哈希

**现象**：整理提取目录时看到 `cache/` 占了 1.2 MB，直接 `rm -rf`，或者在传输时用 `tar --exclude` 排除掉。

**原因**：`cache/` 里的内容**在技术上确实可被应用重新生成**——但这不代表它没有取证价值。它记录的是这个应用最近访问过哪些资源、请求过哪些 URL、生成了哪些缩略图与临时文件。对一个被用来浏览违禁内容的应用，`cache/` 里的 WebView 缓存条目、下载失败的临时文件、缩略图残片，**往往是「访问过」的独立证据来源**，且与应用自己维护的数据库完全无关。它的价值不在内容本身，在「存在性」——文件的存在与修改时间本身就是一条时间线证据。

**影响**：**删除不可逆。**

提取后删掉，报告里就再也引用不了这批证据。委托方后续提出补充要求时，检材上可能已经因为应用再次运行而覆盖了这批缓存，无法回溯。

更实质的问题是举证能力。一条「该设备访问过 X」的结论如果只有一个数据来源（应用自己的数据库），被告方可以质疑「数据库是应用自己写的、可以改」。缓存文件的 mtime 由系统维护，不受应用控制，这是能独立支撑同一结论的旁证。

**核查**：**先全量哈希固定，再决定是否深入分析**。`cache/` 与 `code_cache/` 都属于「可重建但不可再生」的时间线证据：

```bash
# ① 固定优先：全目录哈希清单先落地
find extracted -type f -exec sha256sum {} \; > hashes-all.txt
wc -l hashes-all.txt

# ② 按修改时间排序，最新访问的排前面
find extracted/cache -type f -printf '%T@ %p\
' | sort -rn | head -50

# ③ 挑有价值的目标：WebView 缓存、未完成下载、缩略图
ls -la extracted/cache/webview/ 2>/dev/null
find extracted/cache -name '*.tmp' -o -name '*.part' -o -name '*.download'
```

报告里应把 `cache/` 的时间戳作为独立证据类型列出，并明确它的证据性质是「系统维护的时间戳 + 应用可重建内容」，与数据库记录互为佐证。

<a id="section-16"></a>

### 4.2 SharedPreferences 解析

<a id="section-17"></a>

#### 陷阱 3：只读主文件，丢掉 `.bak` 里更新鲜的旧配置

**现象**：解析 `shared_prefs/` 目录下所有 `*.xml`，输出一份键值表，然后据此写「该设备仅登录过账号 X」。

**原因**：Android 写 SharedPreferences 的机制是**「写临时文件 → 原子改名覆盖」**，而**被中断时会留下 `<name>.xml.bak`**。`.bak` 是**上一个完整版本**——它不是「更旧的备份」，而是**最近一次成功写入之前的那个状态**。用户已经退出登录（主文件 `is_logged_in=false`）或已切换账号时，`.bak` 里往往还留着 `true` 和旧账号的完整配置。**只读主文件的情况下，这条信息完全不存在。** 而且 `.bak` 与主文件的 mtime 差值本身就是一条时间线证据：两次写入之间发生了什么、用户是否做过退出登录或换号操作，全在这个时间差里。

**影响**：**漏掉的是「换号」这个行为本身。**

在账号关联类案件里，「同一设备先后使用过两个账号」是串并案件的关键线索。只读主文件会得出「只有一个账号」，这个错误结论会让整个串并方向跑偏。

更隐蔽的是它看起来完全正常。主文件是完整可解析的 XML，键值表没有异常，分析人员没有任何理由怀疑自己漏了东西。

**核查**：`.bak` 与主文件成对提取、成对分析，mtime 差值作为一项发现记录：

```bash
# ① 先列出所有 .bak —— 这一步经常被跳过
find extracted/shared_prefs -name '*.xml.bak' -ls

# ② 关键：成对对比 mtime，时间差是「换号时间」的上下界
stat -c '%n  mtime=%y' extracted/shared_prefs/account_prefs.xml \
                      extracted/shared_prefs/account_prefs.xml.bak

# ③ 内容差分：只关注两个文件里值不同的键
diff <(grep -o 'name="[^"]*"' extracted/shared_prefs/account_prefs.xml) \
     <(grep -o 'name="[^"]*"' extracted/shared_prefs/account_prefs.xml.bak)
```

解析脚本要同时处理 `.xml` 与 `.xml.bak` 两种后缀（`os.listdir` 的过滤条件里要写 `(".xml", ".xml.bak")`），并把文件名一并写进输出表，这样 CSV 里能一眼看出哪个值来自哪个版本。报告里这类发现的标准表述是：「`.bak`（时间 A）保留账号 X，主文件（时间 B）为账号 Y，可判定该设备在 A–B 期间内发生过一次账号切换」——不要写成「曾使用过两个账号」这么笼统的话，中间的时间信息是有价值的。

<a id="section-18"></a>

#### 陷阱 4：把 `shared_prefs` 当二进制，`file` 报 unknown 就放弃

**现象**：拿到一个 `.xml` 偏好文件，`file` 命令输出 `XML 1.0 document`，但某些工具报 `unknown` 或数据乱码，于是判断「配置已加密，无法解析」并跳过。

**原因**：`shared_prefs/` 下绝大多数文件就是标准 Android XML 文本——根标签是 `<map>`，键在 `name` 属性上，用文本编辑器直接打开就能读。**能读，但读不出来**通常是另外三种原因：① 文档声明是 UTF-8 但内容含非法字节，用错误编码打开导致乱码；② 文件**在写入过程中被截断**（空间不足时），尾部残缺，宽松解析器能读出一部分、严格解析器直接报 `ParseError`；③ 它根本不是 `shared_prefs` 文件，而是同目录下的二进制数据被错认成 XML。**「解析失败」是结果，不是「文件已加密」的证据**——这两者的处置方式完全不同。

**影响**：把「解析不了」写成「已加密」，是一个虚假的技术判断，而且会被写进报告。

委托方一旦按「已加密、无法获取」接受结论，而实际只是解析器选型问题，这批数据就白丢了。复核时若换工具解析成功，整份报告的技术判断部分都会受到质疑。

**核查**：**先看文件头，判断是截断、编码问题，还是真的非文本**：

```bash
f=extracted/shared_prefs/account_prefs.xml
file "$f" ; head -c 200 "$f" | xxd | head -5      # 看真实字节，不是看 file 的结论
# 正常 SharedPreferences 开头一定是 <?xml version='1.0' encoding='utf-8' standalone='yes' ?>

# 截断检查：尾部是否完整闭合
tail -c 60 "$f"                                  # 正常应以 </map> 结尾

# 明确解析失败原因，别把 ParseError 当成加密
python3 -c "import xml.etree.ElementTree as ET; ET.parse('$f')" 2>&1 | tail -2
```

报 `ParseError` 时报告要写「文件内容不完整，尾部残缺」并给出缺失比例，不要写「加密」。 判断真加密的依据是**文件头没有 XML 声明、或整体呈高熵随机字节**——`encrypted_shared_prefs/` 才是那种情况（见陷阱 5）。

<a id="section-19"></a>

#### 陷阱 5：对 `encrypted_shared_prefs/` 强行按 XML 解析

**现象**：`shared_prefs/` 里有一个子目录 `encrypted_shared_prefs/`，里面的 `.xml` 用任何工具都读不出内容，分析人员反复尝试各种编码和解析器，浪费大量时间，最后在报告里写「该配置已加密，无法获取」。

**原因**：Android 7+ 起 `androidx.security` 库提供 `EncryptedSharedPreferences` API，它把 SharedPreferences 整体加密后写入 `encrypted_shared_prefs/` 目录。这与「主目录里的明文 XML」是**两套完全不同的存储**——同一个应用可能同时拥有两套，账号偏好在明文目录、凭据材料在加密目录。你无法通过任何解析技巧读出内容，因为那里存的是密文。 它的密钥不在文件里，而是由应用在 `/data/misc/keystore/` 中经硬件密钥保护的材料派生。用 `strings`、`xxd`、换编码、暴力试密钥都不会成功——**这条路在原理上就是走不通的**。

**影响**：时间成本（反复尝试无效手段往往耗掉几小时）之外，更实际的问题是**报告表述失真**。

「已加密，无法获取」听起来像一个客观的技术结论，但它掩盖了两件更重要的事：

**① 存在一个加密目录本身就是一条信息。** 说明该应用使用了加密存储库，属技术画像的一部分。

**② 报告没有交代是否尝试了合规的解密路径**，以及这条路径需要什么前置条件。

委托方看到「无法获取」就结束了。而实际上还有一条需要授权才能走的路。

**核查**：认出目录性质，把问题转化为「需要什么」，而不是「做不到」：

```bash
ls -la extracted/shared_prefs/encrypted_shared_prefs/
# 确认：文件存在、文件头无 XML 声明、体量明显大于同规模明文 prefs
head -c 32 extracted/shared_prefs/encrypted_shared_prefs/*_preferences.xml | xxd

# 关键材料在 keystore，需要单独提取
adb shell su -c "ls -la /data/misc/keystore/" | tee keystore-listing.txt
```

**报告表述模板**：「`encrypted_shared_prefs/` 下存在 N 个加密偏好文件（`androidx.security` 加密存储库写入），内容为密文，本次未解密。其密钥材料位于 `/data/misc/keystore/`，受 TEE 保护，已提取目录结构但未尝试在线使用凭据。解密需要 [取得对应授权] + [具备硬件密钥派生条件]，详见第 04 篇。」**把「能做但需要条件」与「做不到」严格区分开**——这是这类阴性发现唯一正确的表述方式。

<a id="section-20"></a>

#### 陷阱 6：用 32 位整型解析 `long` 毫秒时间戳

**现象**：解析 SharedPreferences 时，`last_login_time` 的值 `1717213492000` 被解析成 `-146685256`，或者被识别为「明显不是时间戳」而原样输出，报告里登录时间一栏是空的或错的。

**原因**：Android 应用写时间戳的惯例是**毫秒级、且以 `long` 类型存储**（64 位有符号）。而 32 位有符号整型的上限是 2147483647（对应 2038 年 1 月 19 日），**当前任何真实毫秒时间戳都远超这个值**。用 32 位解析会溢出成负数，**而负数在很多脚本里被当作「不是时间戳」直接跳过**——数据被静默丢弃，输出表里那一行是空的。另一个方向的问题是**秒与毫秒不分**：同一个 `<long>` 里，有的应用写毫秒、有的写秒，还有的写的是纳秒或微秒，量级差 1000 到 1000 倍，混用会让时间线整体偏移数年。

**影响**：**这是四段式改写里容易被忽略的「静默数据丢失」。** 它不报错，只是让某些时间字段变成空值或荒谬的数值——**如果这些字段恰好是案件的关键时间点**（登录时间、最后活跃时间、订单提交时间），时间线就会缺掉最关键的一个锚点。而「字段为空」在报告里很容易被解释成「应用未记录该信息」。

**核查**：用 64 位解析 + 显式做量级判定，量级不确定时不猜：

```python
def human_time(v):
    """毫秒/秒时间戳 → 可读时间。量级不在合理区间的原样返回，不猜。"""
    try:
        n = int(v)
    except (TypeError, ValueError):
        return v
    if 1_000_000_000 < n < 4_000_000_000:            # 秒级
        n *= 1000
    if 946_684_800_000 < n < 4_102_444_800_000:       # 2000 ~ 2100 年，毫秒级
        return datetime.datetime.utcfromtimestamp(
            n / 1000, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S (UTC)")
    return v                                        # 不在区间 → 原样返回 + 标记
```

**三点纪律**：① Python 用 `int`（任意精度），C/C++ 用 `int64_t`，JavaScript 注意超过 2^53 会丢精度；**② 转换时显式指定时区**，`utcfromtimestamp` 得到的是 UTC，**必须显式加偏移量才能和设备本地时间对齐**；③ 落在合理区间外时原样保留并标注「量级待确认」，不要强行转换——一个显示 `1717213492`（秒级）还是 `1717213492000`（毫秒级）的时间戳，**两者相差 56 年，猜错就是全盘皆错**。

<a id="section-21"></a>

### 4.3 外部存储与目录覆盖

<a id="section-22"></a>

#### 陷阱 7：凭 Android 9 时代的目录知识拼路径

**现象**：在 Android 13 设备上按经验拼出 `/sdcard/Tencent/MicroMsg/` 去 `adb pull`，报 `No such file or directory`，于是判定「该设备没有微信数据」。

**原因**：Android 10 引入**分区存储（Scoped Storage）**之后，外部目录的形态发生了根本性变化：应用不再能随意在 `/sdcard/` 根下创建任意目录，自身的文件被限制在专属目录 `/sdcard/Android/data/<包名>/` 与 `/sdcard/Android/media/<包名>/` 之内，其余位置需通过媒体库与 SAF 接口访问。结果是大量在 Android 9 及更早版本上位于 `/sdcard/<App名>/` 的数据在新系统上根本不存在这个路径。同时 Android 11+ 又有新的变化：应用外部目录的可见性被进一步限制，没有存储权限的进程（以及部分工具）看不到 `/sdcard/Android/` 下的内容。用旧路径知识操作新系统，得到的每一个 "No such file" 都会被误读成「数据不存在」。

**影响**：「No such file or directory」是关于路径的结论，不是关于内容的结论。

实际操作中它极易被直接翻译成「该应用未在此设备上留下外部数据」。这个翻译没有任何依据。

凡是用拼出来的路径做的 `pull`，失败结果都不能作为阴性证据。

同一批路径「碰巧存在」的场合同样危险：路径存在但内容是空目录，与路径不存在在终端上表现不同，误判形式却一样。

**核查**：**先枚举实际存在的目录，再决定取什么**。不要凭记忆拼任何一个路径：

```bash
# ① 先看外部存储根目录实际有什么
adb shell su -c "ls -la /sdcard/" | tee sdcard-root.txt

# ② 按体量排序，快速定位高价值目录（卸载残留、图片视频、下载）
adb shell su -c "du -sh /sdcard/Android/data/* /sdcard/Android/media/* 2>/dev/null" \
  | sort -h | tail -20

# ③ 下载目录是安装包与导出文件的高发地，单独确认
adb shell su -c "ls -la /sdcard/Download/"

# ④ 用包名做通配，而不是用中文 App 名
adb shell su -c "ls -d /sdcard/*/ | grep -i digiforensics"
```

报告里凡涉及「外部目录未发现 X」，必须附上第 ① 步的 `sdcard-root.txt` 与第 ② 步的枚举结果作为依据。 只有一个 "No such file" 的记录，**不构成阴性发现的支撑**。

<a id="section-23"></a>

#### 陷阱 8：只查 `Android/data/`，漏掉卸载后才保留的 `Android/media/`

**现象**：一台设备上装过目标应用但现已卸载，报告依据「`/sdcard/Android/data/<包名>/` 已被清除，无残留数据」写下结论。

**原因**：这是两个语义相近、行为却完全不同的目录：`Android/data/<包名>/` 在应用卸载时会被系统一并清除，所以它对已卸载应用**没有取证价值**；`Android/media/<包名>/` 是 Android 11 引入的媒体专属目录，应用卸载后内容会被保留。这意味着「卸载后取证」的唯一常规入口就是 `Android/media/`。 而 `Android/media/` 里的内容通常是**媒体文件**——聊天导出的图片、视频、语音、截图、转账凭证图片，是相当高价值的证据。只看 `data/` 就下「无残留」的结论，等于用错了目录就否定了整条取证路径。

**影响**：这个漏检会直接导致「已卸载应用无任何数据」的错误定性。

在「装了又删」的规避行为类案件里，卸载本身就是可疑行为，而卸载后残留是唯一的行为痕迹。

漏查 `Android/media/` 意味着这类案件直接查不下去。报告上那句「无残留」会让委托方相信设备已经清理干净。

**核查**：两个目录成对提取、成对判断，并把「目录不存在」和「目录存在但为空」区分开：

```bash
PKG=com.digiforensics.sample
# ① 成对检查，两个都要看
adb shell su -c "ls -la /sdcard/Android/data/$PKG/ 2>&1" | tee ext-data.txt
adb shell su -c "ls -la /sdcard/Android/media/$PKG/ 2>&1" | tee ext-media.txt

# ② media 里有内容就整体提取（含子目录里的缩略图与临时文件）
adb pull /sdcard/Android/media/$PKG/ extracted/ext-media/

# ③ 与包管理器台账交叉：如果 pm 里没有这个包但 media 里有内容，
#    这就是「装过又删」的痕迹，时间以文件 mtime 为准
adb shell pm list packages | grep -c $PKG
find extracted/ext-media -type f -printf '%T@ %p\
' | sort -rn | head -20
```

**报告表述模板**：「目标包名在 `pm list packages` 中**不存在**（已卸载），但 `/sdcard/Android/media/<包名>/` 下保留 N 个文件，mtime 集中在 [时间区间]，内容为 [类型描述]。据此认定该设备曾安装并使用过该应用，卸载行为未清除媒体目录内容。」这个结论的强度来自两个独立来源的组合——台账说卸载了，文件系统说东西还在，两者同时成立才是「卸载未清干净」的确证。

<a id="section-24"></a>

#### 陷阱 9：批量循环时忘了 `tr -d '\r'`，路径全线失效

**现象**：写了个循环批量抓取所有应用的 `shared_prefs`：

```bash
for d in $(adb shell su -c "ls /data/data/"); do
  adb shell su -c "tar -cf - -C /data/data/$d shared_prefs" | tar -xf - -C all-prefs 2>/dev/null
done
```

循环跑完，`all-prefs/` 里几乎是空的，stderr 全被 `2>/dev/null` 吞掉了。

**原因**：`adb shell` 走的是 ADB 协议的 shell 通道，它返回的输出行尾带 `CR`（回车，Windows 风格换行）。`$( )` 命令替换**不会自动去掉它**，于是循环变量里实际是 `com.digiforensics.sample\r`。这个带 `\r` 的路径被 `tar` 用作 `-C` 的目标目录时，**路径不存在**，`tar` 报错退出——而 `2>/dev/null` 把这个报错完全吞掉了。结果就是：命令全部失败，输出目录全空，整个过程没有一行错误信息。 这个陷阱的恶劣之处在于它**静默成功**：`for` 循环正常结束、退出码为 0（因为管道末尾的 `tar -x` 读到了空输入也算成功），**任何基于退出码的检查都会认为提取成功**。

**影响**：**全库级批量提取的整体性失效。**

整个批处理可能只拿到一两个应用的数据，报告上写的却是「已批量提取全部 187 个应用的 shared_prefs」。

这是覆盖范围虚报中较难自查的一种，因为它发生在自动化环节。人工抽查一两个包都会发现正常，**只有逐个核对完整清单才会暴露**。

更麻烦的是静默失败会让人怀疑「是不是这些应用真的没有配置」，从而得出错误的行为画像。

**核查**：三个必做动作：去 `\r`、不吞错误、事后核对数量。

```bash
# ① tr -d '\r' 去掉 Windows 行尾（必须）
# ② 循环里先筛出「确实存在 shared_prefs 子目录」的包，跳过 base.apk 等非目录项
# ③ 计数与设备侧对齐
adb shell su -c "ls /data/data/" | tr -d '\r' > packages-raw.txt
grep -c . packages-raw.txt                                   # 设备侧包总数

mkdir -p all-prefs
: > prefs-extract-log.txt
while read -r d; do
  [ -z "$d" ] && continue
  adb shell su -c "[ -d /data/data/$d/shared_prefs ] && echo yes" 2>/dev/null \
    | tr -d '\r' | grep -q yes || { echo "SKIP $d (无 shared_prefs)" >> prefs-extract-log.txt; continue; }
  adb shell su -c "tar -cf - -C /data/data/$d shared_prefs" 2>>prefs-extract-log.txt \
    | tar -xf - -C all-prefs 2>>prefs-extract-log.txt \
    && echo "OK $d" >> prefs-extract-log.txt \
    || echo "FAIL $d" >> prefs-extract-log.txt        # 失败要留痕，不要静默
done < packages-raw.txt

# ④ 事后核对：成功的包数 + 产出的 prefs 文件数，双向对齐
grep -c '^OK' prefs-extract-log.txt
find all-prefs -name '*.xml*' | wc -l
```

**第 ④ 步不能省。** 「产出文件数」与「有 shared_prefs 的包数」应当大致匹配，**两者的差值就是需要逐条解释的缺口**。报告里要列出失败/跳过的包清单，而不是笼统写「批量提取完成」。

<a id="section-25"></a>

### 4.4 状态变更与结论表述

<a id="section-26"></a>

#### 陷阱 10：★ 为「看看到底有什么」而触发应用或修改权限

**现象**：为了确认某应用是否安装、是否运行过，在检材上执行了 `pm clear`、修改了文件权限、`settings put` 改了什么开关，或者干脆打开应用让它自己跑一遍看会生成什么数据。

**原因**：`pm clear` 会**清空该应用的全部数据**——`shared_prefs`、`databases`、`files`、`cache` 一次性消失，这是**完全不可逆**的。其他写操作的影响也各有其形态：改权限位（`chmod`）本身留下了权限变化痕迹，分析时文件属主与权限会与原始状态不符；`settings put` 改变的是系统配置，会在设置数据库与系统日志里留痕；**打开应用则更复杂**——应用启动后会读取配置、可能立即执行一次数据同步或缓存刷新，这会改写 `cache/`、更新数据库、可能触发一次 `shared_prefs` 写入，**而这些改写覆盖掉的正是取证价值最高的部分**。**「看一眼」这个动作在写设备上从来不是中性的。**

**影响**：**不可逆，而且会静默毁掉证据。**

最严重的场景是 `pm clear` 之后才发现委托方要的正是那批数据。检材已经无法恢复到该状态。

其次是「打开应用看会怎样」导致的基线被自己污染：后续所有分析都基于一个被自己改动过的状态，而报告无法回答「这个状态是原始的，还是我造成的」。

**这一条在复核时是致命的。** 委托方只需问一句「提取期间是否运行过该应用」，答案就会让整批证据的可靠性受疑。

**核查**：**只读原则没有例外，「确认」不是理由**。所有判断用只读手段完成：

```bash
# ✗ 绝对不要：清数据、改权限、改设置、启动应用
# ✓ 只读替代
adb shell pm path $PKG                      # 替代启动应用：确认安装
adb shell su -c "stat -c '%a %U %G %y' /data/data/$PKG/shared_prefs"   # 替代 chmod：看权限
adb shell su -c "ls -lZ /data/data/$PKG"   # 替代 settings：看实际状态
adb shell dumpsys package $PKG | head -60   # 替代安装运行：看组件与状态
```

若确实需要判断应用运行态，优先用系统留下的运行痕迹：`/data/system/` 下的最近任务记录、`logcat` 历史、应用的 `cache/` 目录 mtime、数据库里的 `last_active` 字段——这些是「它自己写下的证据」，比你去运行它更有说服力。若已发生不可避免的写操作，必须在报告的「检材状态变更说明」里逐条列出动作、时间、影响范围，并说明后续分析结论的证据强度是否受影响。

<a id="section-27"></a>

#### 陷阱 11：漏掉 `no_backup/` 与 `lib/`，尤其是加固识别

**现象**：提取完七个子目录后按「优先级」只深入了 `shared_prefs/` 和 `databases/`，`no_backup/` 180 KB 和 `lib/` 8 KB 被归入「不重要，未深入」。

**原因**：这两个小目录承载着**决定后续分析路径能否走通的关键事实**。`no_backup/` 是应用声明「不参与备份」的数据区，**加密类应用会把会话密钥材料、部分临时数据库放这里**——它是「这批数据为什么打不开」这个问题的答案所在。`lib/` 里的 `.so` 决定**这个应用是否被加固**，进而决定静态分析能不能看到真实的业务逻辑、数据库密钥能不能从代码里读出来。两者的体量都很小（几十到几百 KB），而它们回答的是「接下来该怎么办」这种方向性问题。 用体量判断重要性，在这个场景下恰好是反的。

**影响**：**不是「漏了数据」，是「漏了路线图」。**

报告写「`no_backup/` 与 `lib/` 体量小，未深入分析」时，读者会合理地认为这不影响结论。实际上它直接决定了「该应用的加密配置能否解开」这个尚未回答的问题。

委托方据此决定是否申请进一步授权（可能涉及硬件密钥材料提取），而这个决定是基于一个未经检查的假设做出的。

更实际的风险是：加固应用如果被当成普通应用处理，后续所有静态分析都可能只看到壳，分析结论建立在错误的代码结构上。

**核查**：**小目录先做清单级检查，成本极低、决定后续路径**：

```bash
PKG=com.digiforensics.sample
# ① no_backup/：先看体量构成，识别密钥材料
find extracted/no_backup -type f -printf '%s %p\
' | sort -rn | head -20
file extracted/no_backup/* 2>/dev/null
# 高熵随机字节 + 无文件头 → 疑似密钥材料，不要试图解析，直接固定哈希

# ② lib/：加固识别
find extracted/lib /data/app/*/$PKG*/lib -name '*.so' 2>/dev/null | tee so-list.txt
file extracted/lib/arm64-v8a/*.so
# 关注：库名是否含 jiagu / packer / bang / shell / protect
#      文件是否有符号表（stripped）、导出符号里是否有 JNI_OnLoad
nm -D extracted/lib/arm64-v8a/*.so 2>/dev/null | grep -iE 'load|decrypt|init' | head -20

# ③ APK 内也有一份 lib/，两处要合并判断
unzip -l /path/to/base.apk | grep '\.so$'
```

**报告表述模板**：「`no_backup/`（180 KB）中识别出 2 个高熵二进制文件（`session.key`、`db.key`），已固定哈希未尝试解析；其解密依赖 `/data/misc/keystore/` 下材料。`lib/` 下存在 `libxxxpacker.so`（1.9 MB，符号表已剥离），**判定该应用经过加固**，静态分析仅可见壳代码，业务逻辑与数据库密钥需通过动态手段获取，路径见第 04 篇。」这两句话把「未深入」升级成了「已判定 + 下一步路径明确」，是同一个未完成动作的两种完全不同价值的交付方式。
<a id="section-28"></a>

## 五、案例示例

<a id="section-29"></a>

### 5.1 search_history.xml 与 app.db 的搜索行为双源印证

**场景**

查获一台已 root 的 Android 12 手机，委托方要求查明嫌疑人是否在目标应用上"搜索并保存过某违禁商品关键词"。目标应用包名 `com.digiforensics.sample`，私有目录 148 MB。

委托方的问题指向「搜索行为」，而搜索行为在这类应用里有**两套独立的存储**：配置层的 `SharedPreferences` 与业务层的 SQLite。

只查一层都可能得出片面结论。配置层可能被清理，业务层可能延迟写入。

**处置过程**

第一步，定位与清点：

```bash
$ PKG=com.digiforensics.sample
$ adb shell pm path $PKG
package:/data/app/~~Hk2==/com.digiforensics.sample-1a2b3c==/base.apk
$ adb shell su -c "du -sh /data/data/$PKG"
148M
```

提取时**必须整体打包，不能逐文件 pull**。逐文件会破坏 `.bak` 与 WAL/SHM 的配套关系：

```bash
$ adb shell su -c "tar -cf - -C /data/data $PKG" > app.tar
$ sha256sum app.tar
$ tar -tf app.tar | wc -l
4127
$ tar -xf app.tar

$ du -sh extracted/*/ | sort -h
96M  databases/
38M  files/
1.2M cache/
412K shared_prefs/
180K no_backup/
8.0K lib/
```

`databases/` 96 MB 远大于 `shared_prefs/` 412 KB —— 这个比例提示业务数据为主，配置为辅。

第二步，清点 `shared_prefs` 并**主动寻找备份文件**：

```bash
$ ls extracted/shared_prefs/ | wc -l
34
$ find extracted/shared_prefs -name '*.bak' -ls
-rw------- 1 root root 2048 2024-07-11 23:07:14 .../account_prefs.xml.bak
```

**34 个 XML 中有 1 个 `.bak`。** 这个发现决定了 5.2 的整个走向。

第三步，解析 SharedPreferences 并做敏感键分类：

```bash
$ python3 parse_prefs.py extracted/shared_prefs prefs-report.csv
共 386 个键值，其中敏感键 21 个
$ grep -E 'SENSITIVE|search|keyword' prefs-report.csv | head -12
```

| 文件 | key | type | value | 说明 |
|---|---|---|---|---|
| `app_prefs.xml` | `user_nick` | string | `2024数码小王` | 账号昵称 |
| `app_prefs.xml` | `last_login_time` | long | 2024-08-15 21:33:07 | 已转可读时间 |
| `search_history.xml` | `kw_0` | string | `优盤清倉 尾货` | 搜索历史 |
| `search_history.xml` | `kw_1` | string | `ugg` | |
| `search_history.xml` | `kw_2` | string | `ugg 限量 联名` | 已下架商品 |
| `account_prefs.xml` | `session_token` | string | `A7F2****`（32 位） | **SENSITIVE** |
| `account_prefs.xml` | `is_logged_in` | boolean | `true` | |

`session_token` 属敏感凭据，按脱敏原则记录，完整值只存受控存储。

第四步，与业务层交叉 —— 这是本案的核心验证：

```bash
$ sqlite3 extracted/databases/app.db \
  "SELECT datetime(t/1000,'unixepoch','+8 hours') AS ts, keyword FROM search_log
   WHERE keyword LIKE '%ugg%' ORDER BY t LIMIT 10;"
2024-08-15 21:29:51  ugg
2024-08-15 21:31:08  ugg 限量 联名
2024-08-15 21:33:07  优盤清倉 尾货
```

三个时间点（21:29:51 / 21:31:08 / 21:33:07）与 `search_history.xml` 的 `kw_0`/`kw_1`/`kw_2` 内容完全对应，而且 `kw_0` 的时间与 `last_login_time`（21:33:07）落在同一秒。

第五步，检查数据库完整性与日志模式：

```bash
$ sqlite3 extracted/databases/app.db "PRAGMA integrity_check;"
ok
$ sqlite3 extracted/databases/app.db "PRAGMA journal_mode;"
wal
$ ls -l extracted/databases/app.db*
-rw-r--r-- 1 root root 98765432 app.db
-rw-r--r-- 1 root root  4194304 app.db-wal
-rw-r--r-- 1 root root     32768 app.db-shm
```

三个文件齐备 + `integrity_check = ok` —— 结论建立在完整数据上，未受未合并 WAL 的影响。

第六步，固定提取件哈希。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 该机在目标应用上搜索过 3 个指定关键词 | `search_history.xml` + `app.db.search_log` 双源内容与时间一致 | 强 |
| 全部搜索集中在 2024-08-15 21:29:51 – 21:33:07（4 分 16 秒） | 两个来源的时间戳序列 | 强 |
| 支持"一次连续操作"而非零散浏览 | 4 分钟内 3 次搜索 + `last_login_time` 落在同一窗口 | 中（连续性推断） |
| 提取件完整，分析基础可靠 | `app.tar` 哈希 + `integrity_check=ok` + WAL/SHM 齐备 | 强 |
| **是否实际下单** | — | **不在本报告范围**（需订单数据） |

**能证明的**：搜索行为的事实、关键词内容、时间精度到秒、且两套独立存储互相印证。

**不能证明的**：
- **不能证明搜索由机主本人操作。** 设备未配置生物识别锁的日志记录
- **不能证明搜索目的**。搜索行为本身中性
- **不能证明商品被购买**。`search_log` 无订单信息
- **不能证明关键词被"保存"**。`search_history.xml` 是应用自动维护的缓存，保存行为是应用逻辑而非用户显式操作

**未覆盖范围**：`no_backup/` 的 180 KB（疑为会话密钥材料）、`cache/` 1.2 MB（可能含渲染态数据）、`files/` 38 MB 的内容语义、已删除的搜索记录（WAL 之外的 freelist）、以及服务端侧的搜索日志。

**误判对照**

这个案例的误判点集中在**时间戳处理**上。看起来是小事，错了会让整条时间线失效。

**其一，忘记时区换算。**

SQLite 的 `datetime(t/1000,'unixepoch')` 返回 **UTC**，设备时区是 UTC+8。不换算的话，三个时间点会变成 `13:29:51 / 13:31:08 / 13:33:07`，与 `last_login_time`（21:33:07，SharedPreferences 里的 `long` 是毫秒本地时间）差 8 小时。

判据是**两个独立来源的时间戳在同一秒上收敛**：

| 检查 | 换算正确 | 换算错误 |
|---|---|---|
| `search_log` 末条 vs `last_login_time` | 21:33:07 = 21:33:07 | 13:33:07 ≠ 21:33:07 |
| 时间线合理性 | 4 分钟窗口 | 4 分钟窗口（但与登录时间矛盾） |
| 与其他日志（如 WiFi 关联时间）对齐 | 对齐 | 差 8 小时 |

判据的通用形式：凡是从两个不同系统取到的时间戳，必须验证它们能否收敛到同一事件。若差值恰好是时区整数倍（8、9、-5），基本可确定是时区问题。 本案正是靠 `last_login_time` 这个来自另一存储层的锚点发现的。

其二，只查 `databases/` 不查 `shared_prefs/`。

业务层 SQLite 通常记录完整的搜索日志，但配置层的 `search_history.xml` 有独立的生命周期 —— 它可能在应用更新时被重置、可能在用户清理缓存时被删除、也可能在业务库写入失败时成为唯一记录。

反之，只查 `shared_prefs/` 也有同样的单向风险：`kw_0`/`kw_1`/`kw_2` 是应用维护的关键词缓存，条数有限（本次仅 3 条），而业务库可能有更多。

判据是**两个来源都要查，且必须做交叉表**：

| 情形 | `search_history.xml` | `app.db.search_log` | 判读 |
|---|---|---|---|
| 两者都有，内容一致 | ✅ 本案 | ✅ | 强：双源印证 |
| 只有 SharedPreferences 有 | ✅ | ❌ | 配置层为唯一来源，强度降为中 |
| 只有业务库有 | ❌ | ✅ | 配置层已被清理，需说明清理时点未知 |
| 两者都有但内容不符 | ✅ | ✅ | **异常：可能存在未同步、伪造或分账号存储，需深查** |

**本案的正确做法是逐条建交叉表**（不是只比条数），确认 `kw_0`↔`21:33:07`、`kw_1`↔`21:29:51`、`kw_2`↔`21:31:08` 一一对应。**条数相等不等于内容对应。**

其三，把 `search_history.xml` 说成「用户保存的搜索记录」。

判据在这个文件的**产生方式**：`SharedPreferences` 是应用的配置存储，`search_history.xml` 里的 `kw_N` 是**应用按自己的策略写入的缓存**（例如最多保留 N 条、超期清理）。

「用户保存」是关于用户意图的断言，需要用户显式操作作为证据。本案没有任何这类证据。

按错误判据走的代价：委托方据此认为「嫌疑人主动收藏了违禁商品关键词」，把性质从「浏览行为」提升到「预备行为」。**在法律层面这是两个完全不同的定性。**

**第四个实操细节**：`SharedPreferences` 写入采用「写 `.bak` → 写主文件 → 删 `.bak`」的三步流程。**若在第三步前进程被杀，`.bak` 会留存。**

这既是 5.2 的线索来源，也意味着**每次正常写入都会短暂产生 `.bak`**。

判据是 `.bak` 的 mtime 与主文件的 mtime 差值：正常写入的差值通常在秒级。本案差了 35 天 11 小时，说明那个 `.bak` 是**一次异常中断或跨版本升级的残留**。这个差值本身就是判断 `.bak` 性质的关键指标。

<a id="section-30"></a>

### 5.2 account_prefs.xml.bak 揭示的账号切换

**场景**

承接 5.1。委托方审阅 `prefs-report.csv` 时提出一个具体问题：`user_nick` 显示的是「2024数码小王」，而员工名册上该设备登记的账号是「优选好物」。要求确认这台设备上是否登录过其他账号。

这个问题看似简单，其实是本篇的核心：主文件只反映当前状态，`.bak` 才反映历史状态。

**处置过程**

第一步，比较主文件与 `.bak` 的时间戳：

```bash
$ stat -c '%n  mtime=%y  size=%s' \
    extracted/shared_prefs/account_prefs.xml \
    extracted/shared_prefs/account_prefs.xml.bak
account_prefs.xml       mtime=2024-08-16 10:41:52  size=1842
account_prefs.xml.bak   mtime=2024-07-11 23:07:14  size=2048
```

**差值 35 天 11 小时 34 分 38 秒。** 远大于正常写入的秒级差值（见 5.1 误判对照第四条），说明这个 `.bak` 不是一次普通写入的中间态。

第二步，并排读取两份文件的账号字段：

```bash
$ grep -E 'user_nick|session_token|is_logged_in' \
    extracted/shared_prefs/account_prefs.xml.bak | sed -E 's/(>[A-F0-9]{4})[A-F0-9]{20,}/\1****/'
<string name="user_nick">2024数码小王</string>
<string name="session_token">A7F2****</string>
<boolean name="is_logged_in" value="true" />

$ grep -E 'user_nick|session_token|is_logged_in' \
    extracted/shared_prefs/account_prefs.xml | sed -E 's/(>[A-F0-9]{4})[A-F0-9]{20,}/\1****/'
<string name="user_nick">优选好物</string>
<string name="session_token">B91E****</string>
<boolean name="is_logged_in" value="true" />
```

两个不同的账号、两个不同的 session token、`is_logged_in` 均为 `true`。

第三步，确认这不是解析错误 —— 逐行对比两份文件的结构：

```bash
$ python3 - <<'PY'
import xml.etree.ElementTree as ET
for f in ('account_prefs.xml.bak', 'account_prefs.xml'):
    p = '/Users/foren/work/extracted/shared_prefs/' + f
    t = ET.parse(p); r = t.getroot()
    print('%-24s %d 个键，根节点 %s' % (f, len(list(r)), r.tag))
    for c in r:
        v = c.get('value') if c.get('value') is not None else (c.text or '')
        if len(v) > 12:
            v = v[:4] + '****'
        print('    %-22s %-8s %s' % (c.get('name'), c.get('type') or 'string', v))
PY
account_prefs.xml.bak   11 个键，根节点 map
    user_nick              string   2024数码小王
    session_token          string   A7F2****
    is_logged_in           boolean  true
    device_id              string   7f3a9c2e****
    last_sync_time         long     1720699634
    ...
account_prefs.xml        11 个键，根节点 map
    user_nick              string   优选好物
    session_token          string   B91E****
    is_logged_in           boolean  true
    device_id              string   7f3a9c2e****
    last_sync_time         long     1723760512
    ...
```

`device_id` 两次相同（`7f3a9c2e****`），`last_sync_time` 从 `1720699634`（2024-07-11）变为 `1723760512`（2024-08-16）。

**同一设备、同一 token 体系，账号换了。** 这排除了「两份文件来自不同设备」的可能。

第四步，换算 `last_sync_time` 并与 `.bak` 的 mtime 对齐：

```bash
$ python3 -c "
import datetime
for t in (1720699634, 1723760512):
    print(t, datetime.datetime.utcfromtimestamp(t + 8*3600).strftime('%Y-%m-%d %H:%M:%S'))
"
1720699634 2024-07-11 23:07:14
1723760512 2024-08-16 10:41:52
```

两个 `last_sync_time`（UTC+8 换算后）与两个文件的 mtime 完全一致。 `.bak` 里记录的是它自己那个时刻的同步时间，主文件里是新账号的同步时间。

这证明两份文件各自独立、内部自洽，不是解析错位造成的。

第五步，在数据库里找账号切换的独立佐证：

```bash
$ sqlite3 extracted/databases/app.db \
  "SELECT datetime(t/1000,'unixepoch','+8 hours'), event, detail FROM user_event
   WHERE event LIKE '%login%' OR event LIKE '%switch%' ORDER BY t LIMIT 12;"
2024-07-11 23:06:58  login_success     nick=2024数码小王
2024-08-16 10:40:44  logout           nick=2024数码小王
2024-08-16 10:41:52  login_success     nick=优选好物
```

`user_event` 表给出完整序列：7 月 11 日以"2024数码小王"登录 → 8 月 16 日 10:40:44 登出 → 10:41:52 以"优选好物"登录。

第六步，扫描其他文件里是否还有更多账号痕迹：

```bash
$ grep -rlE '2024数码小王|优选好物' extracted/ 2>/dev/null
extracted/shared_prefs/account_prefs.xml
extracted/shared_prefs/account_prefs.xml.bak
extracted/databases/app.db
extracted/files/cache/account_cache.json
$ python3 -c "
import json
d = json.load(open('extracted/files/cache/account_cache.json', encoding='utf-8'))
print('缓存中账号数:', len(d.get('accounts', [])))
for a in d.get('accounts', []):
    print('  %-14s last=%s' % (a['nick'], a['lastActive']))
"
缓存中账号数: 2
  2024数码小王    last=2024-07-11T23:07:14
  优选好物        last=2024-08-16T10:41:52
```

四个独立来源（两个 XML、一个 SQLite、一个 JSON 缓存）都记录了两个账号，且时间戳互相一致。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 该设备上先后登录过两个账号 | `.bak` + 主文件 + `user_event` + `account_cache.json` 四源 | 强 |
| 账号 A「2024数码小王」活跃于 2024-07-11 23:07:14 前 | 四源的 `last` / `last_sync_time` / mtime 一致 | 强 |
| 账号 B「优选好物」自 2024-08-16 10:41:52 起使用 | 同上 | 强 |
| 切换过程为「登出 → 登录」，非直接覆盖 | `user_event` 的 `logout`(10:40:44) → `login_success`(10:41:52) | 强 |
| 两次登录均在同一设备上 | `device_id = 7f3a9c2e****` 两份相同 | 强 |
| **切换由何人操作** | — | **无证据（无生物识别/登录类型记录）** |

**能证明的**：两账号的存在与各自的时间边界、切换的时序、同设备性。**四源独立印证。**

**不能证明的**：
- **不能证明是同一个人切换的。** 两种账号都无实名认证信息
- **不能证明账号 A 属于谁。** 昵称非实名标识
- **不能证明 5.1 中的搜索行为发生在哪个账号下** —— `search_log` 表**没有用户字段**！这是本案一个重要缺口

**未覆盖范围**：`session_token` 的有效期与服务端状态（需服务端配合）、账号 B 的后续使用情况（数据截至 8-16）、设备是否还有其他未写入 XML 的账号（如仅服务端登录）、以及切换是否经由第三方设备。

**误判对照**

这个案例的误判点密度较高，**而且四个都在「看起来已经查得很细」的地方**。

**其一，只读主文件，把账号切换完全漏掉。**

这是本案例最直接的误判。`account_prefs.xml` 只有当前状态，**`.bak` 里才有上一个账号的完整信息。**

分析流程若只按 `ls *.xml` 遍历（这是最常见的做法），`account_prefs.xml.bak` 会被直接跳过。委托方的问题「是否登录过其他账号」会得到「未发现其他账号」的回答。而另一个账号的昵称、token、`device_id` 就躺在同一个目录里。

判据是**遍历必须包含备份与临时文件**：

| 文件模式 | 语义 | 是否必须遍历 |
|---|---|---|
| `*.xml` | 当前配置 | 必须 |
| `*.xml.bak` | **上次写入的上一版本** | **必须** |
| `*.xml.tmp` / `*.new` | 写入中断的中间态 | 必须 |
| `*.bak.*` | 备份的备份 | 建议 |
| 隐藏文件 | 少见但存在 | 建议 |

`find extracted/shared_prefs -type f | wc -l` 应得到 **35**（34 个 `.xml` + 1 个 `.bak`）。若只 `ls *.xml` 得到 34，说明漏了一个。 判据是**总数必须与目录项计数一致**。

其二，把 `.bak` 的 mtime 当成「账号切换时间」。

`.bak` 的 mtime（`2024-07-11 23:07:14`）是**它自己那次写入的时间**，也就是账号 A 的活跃时刻，**不是切换发生的时刻**。真正的切换时刻是 `2024-08-16 10:41:52`。

判据是**区分三个时间概念**：

| 时间概念 | 本案取值 | 来源 |
|---|---|---|
| 账号 A 的活跃时刻 | 2024-07-11 23:07:14 | `.bak` 的 mtime / `last_sync_time` |
| 账号切换时刻 | 2024-08-16 10:41:52 | 主文件 mtime / `user_event.login_success` |
| 账号 A 的登出时刻 | 2024-08-16 10:40:44 | **只有 `user_event` 有** |

**第三个时间（登出时刻）在任何 XML 里都不存在**，只有业务库的事件表记录了它。

这说明**要还原「切换」这个动作本身，必须查业务库**。只看配置文件只能得到「前后两个状态」，得不到「切换过程」。

其三，把两个 session token 的差异读成「两个 token 都曾有效」。

`session_token` 是应用自己的凭据机制，**它在设备上的存在不等于它在服务端有效**。判据分两层：

| 层面 | 本次可得 | 需要的额外证据 |
|---|---|---|
| token 存在于设备 | ✅ 两份文件 | — |
| token 曾被服务端接受 | ❌ 未验证 | 服务端会话记录 |

**验证 token 有效性的唯一方式是服务端数据。** 本案未取得，也不应在未授权情况下尝试使用这些 token 登录。

报告里正确写法是「设备上留存两个不同的 session token（已脱敏），其服务端有效性未验证」。

**其四，把账号切换与 5.1 的搜索行为强行关联。**

这是最需要警惕的一个误判，因为它看起来能把两个案例串成一个完整故事。判据是**检查 `search_log` 表有没有用户字段**：

```bash
$ sqlite3 extracted/databases/app.db "PRAGMA table_info(search_log);"
cid  name       type
0    id         INTEGER
1    t          INTEGER
2    keyword    TEXT
3    source     TEXT
# 无 user_id / account / nick 字段
```

**`search_log` 表没有用户字段。** 5.1 的三条搜索记录发生在 `2024-08-15 21:29–21:33`，按时间推断应归属账号 B（8-16 之前仍是账号 A 时期？**不对** —— 8-15 早于 8-16 的切换，所以应归属账号 A「2024数码小王」）。

**但这是推断，不是证据。** 正确表述：「三条搜索记录发生于 2024-08-15 21:29:51–21:33:07，按时间推断处于账号 A「2024数码小王」的活跃期（账号 A 活跃至 2024-07-11 后于 2024-08-16 登出，中间 35 天的账号状态无事件记录）。该归属为时间推断，`search_log` 表无用户字段，不能确证。」

按错误判据走的代价：报告写「账号 2024数码小王 搜索了违禁关键词」，而实际上时间线只能推断、无法确证，且中间 35 天的账号状态完全空白。**这段时间里设备可能被任何人使用过。**

**第五个实操细节**：`.bak` 文件的 `size=2048` 大于主文件的 `size=1842`。这是正常的 —— `.bak` 保留了更多键（本次 11 个键相同，但键值长度不同）。

判据是解析 `.bak` 时要用与主文件相同的解析器，不能假设两者结构一致。本次用同一份 `parse_prefs.py` 处理两份文件，输出结构对齐，比对才有效。

<a id="section-31"></a>

## 六、扩展阅读方向

本篇停在「应用私有目录里能读出什么」。

下面几组文章接住它留下的四类缺口，按**你接下来会撞上的问题**分组。

先补数据库能力：同一个应用里 XML 只能回答一半问题

- [SQLite 基础与结构](../mobile-database/mobile-database-sqlite.md) —— `databases/app.db` 是二进制单文件，B-tree 页、schema 表、freelist 的读法与 XML 完全不同。读完这篇你会知道为什么 `PRAGMA integrity_check` 通过不代表数据没丢。
- [SQLite WAL 取证](../mobile-database/mobile-database-sqlite-wal.md) —— **本篇陷阱 1 的完整解法**。`app.db-wal` 的 checkpoint 机制、合并前后差分、删库残留如何在 `-wal` 里被找回来。
- [SQLite 数据库取证通用方法](../mobile-database/mobile-database-database-forensics-methods.md) —— 多库场景的通用核查清单与阴性发现表述模板。陷阱 10 的报告写法可以照抄。

**加固与动态分析：读不出数据库时的下一步**

- [APK 逆向与 Manifest 分析](mobile-android-apk-manifest.md) —— `lib/` 里的 so 判定加固之后，静态分析这条路要走多远。`allowBackup`、导出组件、网络安全配置的读法也在这一篇。
- [Frida 动态 Hook](mobile-android-frida-dynamic-hooking.md) —— `no_backup/` 里的密钥材料指向的就是这条路径。但先读前一篇：动态 hook 的前提是知道该 hook 什么，而那来自静态分析。
- [数据库与配置文件加密](../../crypto/crypto-app/crypto-app-database-configuration-decryption.md) —— `encrypted_shared_prefs/` 与各类加密库在 PC 侧的对应物，以及密钥材料的一般性识别方法。
- [远程工具凭据解密](../../crypto/crypto-app/crypto-app-remote-tool-credential-preservation.md) —— 当应用里的会话令牌是离线分析对象时，凭据处理的授权与脱敏要求。

**存储模型与外部目录：路径为什么不能凭记忆拼**

- [Android 数据存储总览](mobile-android-android-data-storage-overview.md) —— FBE 的 CE/DE 分层、`/data/user_de/` 为什么常被漏掉、分区表与动态分区。**本篇所有 CE 层数据的存在性前提都在这里。**
- [iOS 备份与沙盒提取](../mobile-ios/mobile-ios-ios-backup-and-sandbox-extraction.md) —— Android 侧的完整对应物。两边的路径哲学、提取前提、覆盖范围都不一样，对照看能看清哪些是平台通病、哪些是 Android 特有。
- [FAT 系列结构](../../filesystem/filesystem-mobile-fs/filesystem-mobile-fs-fat.md) —— 外置 SD 卡仍是 FAT32/fatplus 时，媒体文件的块级恢复路径。

**时间与结论：这一批文件能不能支撑时间线**

- [时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md) —— 时间戳换算那一篇里 `last_login_time` 这类毫秒 `long` 的归一方法，是陷阱 6 那个「猜错差 56 年」的正解。
- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— **`.bak` 的 mtime 差值到底能证明什么**。应用改自己的 XML 时间戳是可行的，本篇把它当作时间线证据时需要知道这条边界。
- [时间线重建](../../computer/computer-log/computer-log-linux-timeline-reconstruction.md) —— 多个应用的时间戳如何合并成一条可辩护的顺序。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 只读原则的出处。陷阱 10 那个 `pm clear` 之所以不可逆，是因为它没有任何补救路径。
<a id="section-32"></a>

## 七、命令速查

```bash
# ===== 环境与定位 =====
PKG=com.digiforensics.sample
adb devices -l
adb shell pm path $PKG
adb shell su -c "du -sh /data/data/$PKG"

# ===== 提取（推荐 tar 流式导出，可哈希为单一容器）=====
adb shell su -c "tar -cf - -C /data/data $PKG" > app.tar
sha256sum app.tar && tar -tf app.tar | head -60      # 先列不拆
tar -xf app.tar
find extracted -type f -exec sha256sum {} \; > hashes.txt
adb pull /data/data/$PKG/shared_prefs extracted/    # 也可分目录 pull
adb pull /data/data/$PKG/databases    extracted/    # ★ 整个目录，别只拉 .db
adb shell "run-as $PKG" ls -la                     # debuggable 应用免 root

# ===== SharedPreferences =====
ls -l extracted/shared_prefs/
find extracted/shared_prefs -name '*.bak' -ls        # 别漏 .bak
python3 parse_prefs.py extracted/shared_prefs prefs-report.csv
grep -E 'SENSITIVE|search' prefs-report.csv
grep -ril -E 'password|token|secret|api_key|session' extracted/

# ===== so 库（加固识别）与外部存储 =====
adb shell su -c "find /data/data/$PKG/lib -name '*.so' 2>/dev/null"
adb shell su -c "du -sh /sdcard/Android/data/* /sdcard/Android/media/* 2>/dev/null" | sort -h | tail -20
adb pull /sdcard/Android/media/com.digiforensics.sample/ extracted/   # 卸载后仍保留
adb pull /sdcard/Download/  extracted/

# ===== 数据库验证与时间戳 =====
ls -l extracted/databases/                # 必须有 .db / .db-wal / .db-shm
sqlite3 extracted/databases/app.db "PRAGMA integrity_check;"
sqlite3 extracted/databases/app.db "PRAGMA journal_mode;"
sqlite3 extracted/databases/app.db ".tables"
find extracted/shared_prefs -type f -printf '%T@ %p\
' | sort -n
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 移动与数据库取证 — 应用私有数据与 SharedPreferences」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《应用私有数据与 SharedPreferences》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.vc` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
