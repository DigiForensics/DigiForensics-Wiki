---
title: "Frida 动态 Hook"
slug: "mobile-android-frida-dynamic-hooking"
canonical: "https://www.digiforensics.cn/wiki/mobile-android-frida-dynamic-hooking"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:50+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "mobile"
space: "移动取证"
node_path: ["Android"]
---

# Frida 动态 Hook

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/mobile-android-frida-dynamic-hooking)

<a id="section-1"></a>

## 一、概述

Frida 可在运行时拦截函数调用、观察参数与返回值，并读取进程内存。它适用于静态分析难以确认的运行时密钥派生过程，以及加固应用在运行时释放的代码。

分析前先定位目标函数，确认参数含义，再用调用记录和实际解密结果验证观察到的数据。

上游是 [APK 逆向与 Manifest 分析](mobile-android-apk-manifest.md) 的加固判定 —— **没有那个结论，动态分析就是盲试**。

下游是 [即时通讯取证](mobile-android-instant-messaging-forensics.md) 里加密数据库的解密，以及 [进程与注入检测](../../memory/memory-analyze/memory-analyze-process-and-injection-detection.md) 里对本篇操作痕迹的识别。

动态注入会改变目标进程的运行状态。应记录工具版本、脚本内容、操作时间及产生的文件，并区分原有证据与分析操作留下的痕迹。

使用前需确认以下条件：

- **「Frida 能破解所有加密」** —— 它只能观察运行时行为。密钥在 TEE 内生成就看不到，`StrongBox` 保护的密钥同样不可读。
- **「有 Frida 就不用静态分析了」** —— **必须先做完备的静态分析**，否则你不知道该 hook 哪个函数、参数是什么含义。
- **「Hook 成功就等于取到了数据」** —— 拿到 key 还要实际解密成功、并能解析出表结构，才算验证通过（见 [第 5 步](#section-11)）。

**涉及的证据形态**：

| 形态 | 具体内容 | 说明 |
|---|---|---|
| 设备端服务 | `/data/local/tmp/frida-server`，端口 `27042` | rooted 设备常以高权限 frida-server 运行；亦有 Gadget 等非 root 集成路径。权限和注入方式取决于设备、目标进程及部署方案；工具本身要哈希记录 |
| 通道 | `adb forward` 的 USB 转发，或 TCP/IP | **TCP 会把 27042 暴露在网络上**，任何人可完全控制目标进程 |
| 脚本 | `.js` 脚本、`frida-trace` 的自动生成的桩 | **脚本本身可能含敏感值，产出日志按证据材料管理** |
| 运行时观察 | `sqlite3_key`、`open`、`exec` 的调用序列 | 目标是**证明某个值从哪个调用点来**，不是刷屏 |
| 落盘产物 | hook 抓到的密钥、解密后的库 | **只在副本上操作**，绝不在检材上解密 |
| 环境痕迹 | `/data/local/tmp/`、`/proc` 下的注入映射、进程内存布局 | 本篇操作自己留下的，**报告必须主动交代** |

调用记录用于核查数据库打开过程、密钥来源、目标代码的执行情况，以及加固代码的释放时机。

Hook 脚本可以改变返回值，因此观察结果需要交叉验证。进程内的调用记录也不能直接归因于某个用户；密钥是否被上传，需结合网络记录判断。

报告应注明观察条件、脚本是否修改参数或返回值，以及支持用户行为归因的独立证据。

**本文不做的事**：不做脱壳、不做破解保护机制、不修改检材上的原始 APK。`frida-gadget` 方案需要重打包重签名，只应在委托方明确同意制作分析副本时使用，绝不替换原始 APK。

抓到密钥后的用途是**离线解密检材副本**。任何在线使用检材内凭据的行为都超出取证范围。

**读者前提**：[APK 逆向与 Manifest 分析](mobile-android-apk-manifest.md) 的加固判定结论、Java/Native 运行时概念、以及进程与内存的基本模型。

**如果没有静态分析的基础，建议不要直接开始写脚本** —— [第 1 步](#section-8) 那一节就是为此存在的。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 架构：两端 + 一条通道

```
主机端（分析机）：frida CLI(REPL) / frida-ps / frida-trace / frida-kill / frida-tools + Python 绑定
        │  ① USB（ADB 转发，默认）  或  ② TCP/IP        默认端口 frida-server: 27042
        ▼
设备端（检材）：frida-server（常驻，需 root） / frida-gadget（内嵌 APK，免 root）
               与目标进程同 UID，注入后调用拦截生效
```

**frida-server** 是设备端常驻服务，**必须 root**，是取证默认首选。

**frida-gadget** 免 root，但**必须重打包并重签名 APK**，只在委托方明确同意制作分析副本时使用。

**任何情况下都不要替换原始 APK** —— gadget 方案改变检材本身，在正式案件中会破坏证据完整性。

**通道选择**：`adb forward tcp:27042 tcp:27042` 后用 `frida -U`（USB，推荐）；远程时设备端 `frida-server -l 0.0.0.0:27042`、主机端 `frida-ps -H 192.168.1.50:27042 -ai`。

> 网络方式会把 27042 端口暴露在网络上，任何人都能连接并完全控制目标进程。 在受限网络环境的现场作业中，**优先用 USB 转发**；如必须用网络，做完立即 `frida-kill` 关闭服务并记录操作时间。

<a id="section-4"></a>

### 2.2 三种 Hook 机制

| 机制 | 作用对象 | 典型用途 |
|---|---|---|
| **`Java.perform`** + `Java.use` | **Java/Kotlin 层**方法 | 读数据库初始化参数、拦截加解密调用 |
| **`Interceptor.attach`** | **任意 native 函数**（含 libc、JNI） | 读 `sqlite3_key`、拦截 `open`、看 native 算法 |
| `Module.findExportByName` + `NativeFunction` | 按地址直接调用 native 函数 | 主动调用函数验证行为 |

**两条规则**（详细示例见 [第 3–4 步：Hook 的四种典型用法](#section-10)）：

```javascript
Java.perform(function () {                       // ① 必须在 Java 线程内执行
    var DB = Java.use("android.database.sqlite.SQLiteDatabase");
    DB.openOrCreateDatabase.overload(             // ② 必须写 overload 精确指定重载
        "java.io.File", "int", "android.database.sqlite.SQLiteCursorFactory"
    ).implementation = function (file, flags, factory) {
        console.log(file.getAbsolutePath());
        return this.openOrCreateDatabase(file, flags, factory);  // ③ 必须回调原实现
    };
});
```

> **不写 `overload`** 会报 "more than one overload"。**不回调原实现**会导致应用崩溃或功能异常——**在检材上这意味着状态被破坏**，是动态分析中最容易造成证据污染的操作。

<a id="section-5"></a>

### 2.3 版本差异：`-f` 的行为变化

旧版（< 12）`frida -f <包名>` 启动后**处于暂停态**，需在 REPL 里输入 `%resume`；新版（≥ 12）`-f` 启动后**自动恢复执行**，旧的 `--no-pause` 参数**已废弃**。

> **常见错误**：把旧教程里的 `--no-pause` 抄进新版本命令行，frida 直接退出。先 `frida --version`，再看版本对应的用法。

<a id="section-6"></a>

### 2.4 反 Frida 检测的常见手法

这一节列出检测类型与可观察痕迹，目的是**识别检材的对抗性**，不是提供规避手段。

| 检测类型 | 实现方式 | 观察点 |
|---|---|---|
| **字符串扫描** | 读自身内存/已加载库，搜 `frida`、`gum-js-loop`、`gmain` 等符号 | so 列表中出现 `frida-agent` |
| **端口探测** | 遍历 `/proc/net/tcp`，查 `27042`（hex `0x69AA`）是否 LISTEN | `ss -ltnp \| grep 27042` |
| **进程名扫描** | 遍历 `/proc/*/cmdline`，查含 `frida` 的进程 | `ps -A \| grep frida` |
| **D-Bus 检测** | 注册 frida 所用的 D-Bus 总线名，注册成功即判定被注入 | 日志无异常但行为变化 |
| **完整性校验 / 调试器检测** | 校验自身文件 hash、检查 `/proc/self/maps` 异常条目；检查 `TracerPid`、`ptrace` 自身状态 | 匿名可执行段数量异常；常规调试检测常与 Frida 同时出现 |

**取证中的两类用途**：

① **识别检材的对抗性。** 若应用有明确的 Frida 检测，说明开发者有对抗意识，**其保护强度评估应相应提高**，报告也应说明这一发现。

② **降低动态分析的可用性。** 检测存在时，**优先考虑旁路方案**（直接 dump 进程内存、读取已落盘的中间文件、静态分析），而不是硬碰。

> **不提供绕过反检测的具体代码。** 理由有二：① 这类技术对商用 App 的保护机制构成规避手段，超出取证分析的必要范围；② 更重要的是，多数案件并不需要走这条路 —— 落盘的数据直接按分区取走即可，取证路径见 [第 01 篇](mobile-android-android-data-storage-overview.md)。

---

<a id="section-7"></a>

## 三、操作步骤

<a id="section-8"></a>

### 第 1 步：静态分析先行（本步不能跳）

```bash
# 先做完整的 APK 静态分析（见 03 篇），再明确三件事才动手：
#  1. 目标：我要拿什么？（数据库密码 / 解密后的字节 / 接口参数）
#  2. 位置：它可能在哪里产生？（Java 层？JNI？native 库中的某函数？）
#  3. 验证：拿到后如何证明它是真密钥？（实际解密成功 + 表结构可读）
aapt dump badging base.apk ; apktool d -f -o app-decoded base.apk
jadx -d app-jadx base.apk --no-res
grep -rn "openOrCreateDatabase\|SQLiteOpenHelper" app-jadx/sources/
grep -rn "SecretKeySpec\|Cipher.getInstance" app-jadx/sources/
unzip -l base.apk | grep '\.so$' | awk '{print $NF}'   # 确认有无加固
```

<a id="section-9"></a>

### 第 2 步：准备设备端

```bash
adb shell su -c "id"                # 前提：检材已 root（授权文件见 01 篇）
# 推送并启动 frida-server（版本必须与主机端 frida 完全一致，否则握手失败）
adb push frida-server-16.x.x-android-arm64 /data/local/tmp/frida-server
adb shell su -c "chmod 755 /data/local/tmp/frida-server"
adb shell su -c "/data/local/tmp/frida-server -D &"   # 后台常驻
adb shell su -c "ps -A | grep frida"
adb forward tcp:27042 tcp:27042     # USB 转发，避免暴露网络端口
frida-ps -U | head -20              # 能列出进程 = 通道建立成功
```

> **版本必须一致**：主机端 `frida --version` 与设备端 `frida-server --version` 不同会直接握手失败。这是「连不上」最常见的原因。

<a id="section-10"></a>

### 第 3–4 步：摸清进程，Hook 的四种典型用法

用法 A：`frida-trace` 批量生成调用日志（最快定位）

```bash
frida-ps -U -ai | grep -i sample        # 列出应用（-a 应用 / -i 已安装标识）
frida-trace -U -f com.digiforensics.sample -p "*sqlite3*" -i          # 所有 sqlite3 native 调用
frida-trace -U -f com.digiforensics.sample -j "openOrCreateDatabase"   # Java 层数据库打开
frida-trace -U -f com.digiforensics.sample -i "*!open*"                # libc open：能看到打开的文件路径
```

输出落在 `./__handlers__/` 目录下，是纯文本调用日志，**可作为证据材料**。

用法 B：`Java.use` 拦截 Java 层调用

```javascript
// hook-crypto.js —— 在已授权检材上确认加解密的调用时序
// 用法: frida -U -f com.digiforensics.sample -l hook-crypto.js
Java.perform(function () {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload("[B").implementation = function (input) {
        var out = this.doFinal(input);            // ★ 必须回调原实现
        // 只记录长度与时序，不在日志中回显明文，避免敏感数据扩散
        console.log("[doFinal] in=" + input.length + "B out=" + out.length + "B");
        return out;
    };
});
```

> **`overload` 为什么必需**：Java 方法可重载，Frida 必须按参数列表精确指定要 Hook 的那一个。不写 `overload` 会报 "more than one overload"。同时注意：Hook 函数必须显式回调原实现，否则应用会崩溃或行为异常——这在检材上意味着状态被破坏。

**用法 C：拦截 native 函数**

```javascript
// hook-sqlite.js —— 观察数据库打开时传入的 key
// 用法: frida -U -n "样本应用" -l hook-sqlite.js
var sqlite3 = Module.findExportByName(null, "sqlite3_key");  // SQLCipher 才有
if (sqlite3) {
    Interceptor.attach(sqlite3, {
        onEnter: function (args) {            // args[1] 指向 key 字节，args[2] 为长度
            var len = args[2].toInt32();
            if (len > 0 && len < 128) {
                console.log("[sqlite3_key] len=" + len + " key=" +
                    hexdump(Memory.readByteArray(args[1], len), {ansi: false}));
            }
        }
    });
} else { console.log("[!] 未找到 sqlite3_key —— 该库可能使用应用自加密"); }
```

**用法 D：读取内存中的字符串（探索性）**——`Process.enumerateRangesSync({protection:'r--'})` 遍历可读内存区，`Memory.readUtf8String(r.base, Math.min(r.size, 4096))` 读内容后用正则筛出 `api.`/`token`/`secret`/`http(s)://` 等模式，跨页读失败是正常的，用 try/catch 吞掉即可。

<a id="section-11"></a>

### 第 5 步：验证与现场清理

```bash
# 真正的验证在主机侧做：拿 key 去解密副本（★ 永远在副本上操作）
cp app.db app-copy.db && sha256sum app.db app-copy.db
sqlite3 app-copy.db "PRAGMA key='<取得的key>';"
sqlite3 app-copy.db ".tables"              # 能列出表 = 密钥正确 ✓
sqlite3 app-copy.db "PRAGMA integrity_check;"
frida-kill -U                              # 作业结束立即停止服务
# 复核检材未变：设备上未必自带 md5sum（toybox/busybox 差异），缺失时先 tar 回本地再算
adb shell su -c "md5sum /data/data/com.digiforensics.sample/databases/app.db"
sha256sum app.db                           # 与提取时的哈希比对
```

**必须记录的操作日志**（写入证据链）：**分析时间**（起止精确到分）、**工具版本**（两端 frida 版本号与 `frida-server` 二进制哈希）、**分析对象**（包名、APK 哈希、数据目录路径）、**操作类型**（spawn / attach / 注入的脚本——脚本本身也是证据）、**影响面**（是否重启应用、是否修改文件、是否退出登录）、**取得结果**（调用序列、参数、密钥值；**是否写入报告需评估**）。

> 验证标准是「能读出表结构且 `integrity_check` 返回 ok」，不是「长度对得上」或「看起来像十六进制串」—— 一个 16 字节的随机串有极小概率通过格式检查，但不可能通过实际解密。

---
<a id="section-12"></a>

## 四、常见陷阱

动态分析是本分类中需要在检材或检材副本上执行动作的分析环节。

前面几篇的陷阱多发生在读与解析。这一篇的陷阱集中在**做与不留痕** —— hook 崩了应用、网络端口没关、密钥拿到了却没验证、日志里全是明文。

这一章的每一条都要考虑一个共同前提：动态分析的所有动作都会在检材上留下痕迹，且其中一部分不可回退。

<a id="section-13"></a>

### 4.1 环境与连接

<a id="section-14"></a>

#### 陷阱 1：两端 Frida 版本不一致，反复排查「连不上」

**现象**：`frida-server` 推上设备、起了进程、`adb forward` 也做了，`frida-ps -U` 报连接失败或握手错误。反复换端口、重启 adb、检查 USB 调试授权，全部无效。

**原因**：**Frida 的主机端与设备端必须版本完全一致**，两个数字都要对得上（`16.2.1` 与 `16.2.1`）。小版本不同也会直接握手失败，而这个失败的表现是「连接被拒」或「协议错误」——与「设备没 root」「USB 调试没授权」「端口被占用」在错误信息上非常相似。分析者的注意力会自然地落在更「物理」的因素上（权限、线缆、端口），因为它们更容易验证，而版本号这个纯粹的软件匹配问题**不在任何一条错误信息的字面里**。另外两端的架构也必须匹配（`android-arm64` 的 server 不能推到 x86 模拟器或 armeabi 设备上），这一点同样不会在错误信息里明说。

**影响**：**时间成本**之外，真正的问题是它会引发**一系列「试探性操作」**。

为了排除各种可能，分析者会不断重启 adb、反复 push、改端口、试 `frida-ps -H`。

**其中有些操作会在检材上留下痕迹**（重启服务、推送文件、进程反复起停），**有些则可能触发应用的异常行为**。

最后通道终于通了，但检材的状态已经不是刚拿到时的样子了，而这一段反复折腾的过程往往没有被记录进操作日志。

**核查**：版本与架构在推之前就核对，并把核对结果写进工作记录：

```bash
# ① 两端版本号，必须逐字符相同
frida --version
adb shell su -c "/data/local/tmp/frida-server --version"
# 16.2.1  ==  16.2.1  ✓

# ② 架构必须匹配设备实际架构
adb shell getprop ro.product.cpu.abi
# arm64-v8a → 对应 frida-server-*-android-arm64

# ③ 二进制哈希固定（工具也是证据，见陷阱 10）
sha256sum frida-server-16.2.1-android-arm64 | tee frida-server.sha256

# ④ 推送后先验证进程真的起来了，再建立转发
adb shell su -c "chmod 755 /data/local/tmp/frida-server"
adb shell su -c "/data/local/tmp/frida-server -D &"
adb shell su -c "ps -A | grep frida"
adb forward --remove tcp:27042 2>/dev/null ; adb forward tcp:27042 tcp:27042
frida-ps -U | head -5            # 能列出进程才算通道建立
```

排查顺序固定为：版本 → 架构 → root 权限 → 端口占用 → USB 调试授权。 先做前两项，因为它们最确定、验证成本最低，且**排除方式是把两个版本号并排打出来看一眼**。

<a id="section-15"></a>

#### 陷阱 2：★ 把 `frida-server` 用 `-l 0.0.0.0:27042` 监听网络，作业结束未关闭

**现象**：现场没有 USB 线（设备在现场封存中、线在包里但不便连接），于是用 `frida-server -l 0.0.0.0:27042` 起了网络监听，作业做完只把分析机断开，没有执行 `frida-kill`，设备上的服务继续运行。

**原因**：27042 一旦监听在 `0.0.0.0` 上，同一网络内任何设备都能连接它，并对目标进程获得完全控制能力——包括读取全部内存、Hook 任意函数、修改返回值、调用任意 native 函数。**而这不需要任何凭据**。它不在界面上、不弹通知、不写日志，安卓的省电策略也不会因为它没有 wakelock 压力而轻易杀掉它。从取证角度看还有一个后果：检材状态在分析结束后仍处于「被工具完全控制」的状态，且持续到有人手动关掉为止。

**影响**：这是一个把检材置于不受控状态的风险，且持续时间不可控。

后果分两类。

**① 安全类。** 网络内他人可读取检材内全部数据 —— 这批数据的性质可能正是案件涉及的高敏感信息，甚至篡改或植入内容。

**② 证据类。** 如果在此期间有人对检材做了操作，检材状态的变化会算在谁头上？ 取证人员留下的、持续开放的攻击面，在移交或暂存环节是完全无法解释的。

委托方要求「设备保持原状」时，这个状态变化本身就是违约。

**核查**：优先 USB 转发；必须用网络时，把「关闭动作」作为作业的强制收尾项并记录时间：

```bash
# 首选：USB 转发，端口只在本机监听
adb forward tcp:27042 tcp:27042          # 只在主机侧建立，不在网络上开端口
frida-ps -U

# 确需网络时：绑定到具体网卡地址，不绑 0.0.0.0
adb shell su -c "/data/local/tmp/frida-server -l 192.168.1.50:27042 -D &"
# 作业结束，立即关闭并记录
frida-kill -H 192.168.1.50:27042
adb shell su -c "ps -A | grep frida"    # 确认已无进程（输出为空才算干净）

# 记录：起止时间、监听地址、关闭时间、关闭验证结果
```

**若现场条件不支持 USB 而必须走网络**：① 在检查笔录中记录该判断的依据；② 明确使用时段并尽量缩短；③ **作业结束必须验证进程已消失**，并把「起止时间 + 关闭验证」写进操作日志；④ 向委托方说明这段时间内检材的网络暴露状态。「关掉」这个动作要有验证结果，不能只写「已关闭」。

<a id="section-16"></a>

### 4.2 Hook 正确性与检材污染

<a id="section-17"></a>

#### 陷阱 3：Hook 忘记回调原实现，应用崩溃

**现象**：Hook 上了 `Cipher.doFinal`，日志正常打出来，但应用随后闪退。再看日志，发现 Hook 函数里只有 `console.log`，没有 `return this.doFinal(input)`。

**原因**：Frida 的 `implementation` 赋值**完全替换**了原方法。不写回返回值，Java 层拿到的是 `null`（或默认构造的对象），而这与原实现返回的密文/明文字节数组在类型上勉强兼容、语义上完全错误——于是应用在下一行代码里拿到一个空数组，继续执行到某个深度才抛出异常。这个延迟崩溃的现象会让人误以为是「应用本身有问题」或「设备不稳定」，而真实原因是自己少写了一行。 另一类情况更隐蔽：Hook 的是 `native` 函数时，`Interceptor.attach` 不会自动调用原实现，而如果分析者在 `onEnter` 里修改了参数值而不恢复，就会改变应用的真实行为。

**影响**：**在检材上崩溃的后果，比在普通设备上严重得多。**

一是**应用崩溃可能伴随数据写入被打断**。崩溃发生在应用写数据库途中，会留下 WAL 不一致、临时文件、`.bak` 残留。

二是**「崩溃」本身可能被解读为检材的异常状态**，尤其当同一应用之前被记录为正常运行过。

三是**反复崩溃可能触发应用的崩溃计数与自保护逻辑**（部分应用检测到反复崩溃会清空本地数据或触发账号风控），**这一下损失的是委托方要的数据**。

报告里这段过程如果没写清，检材状态变化就成了一个无法解释的缺口。

**核查**：**Hook 的三条纪律，逐条对应三种破坏形态**：

```javascript
Java.perform(function () {
    var Cipher = Java.use("javax.crypto.Cipher");
    // ① 必须用 overload 精确指定重载，否则报 "more than one overload"
    Cipher.doFinal.overload("[B").implementation = function (input) {
        var out = this.doFinal(input);        // ② ★ 必须回调原实现
        // ③ 只记录长度与时序，不在日志中回显明文（见陷阱 9）
        console.log("[doFinal] in=" + input.length + "B out=" + out.length + "B");
        return out;                            // 返回值必须原样传回
    };
});
```

```javascript
// native 侧：只读不改是最安全的形态
var f = Module.findExportByName(null, "sqlite3_key");
if (f) {
    Interceptor.attach(f, {
        onEnter: function (args) {
            var len = args[2].toInt32();
            if (len > 0 && len < 128) {
                // 只读不写：args 不可写，修改需 Interceptor.replace，代价高且危险
                console.log("[sqlite3_key] len=" + len);
            }
        }                                  // 不设 onLeave / 不改返回值 = 不影响原行为
    });
}
```

先跑一个只读、不改返回值的最小 Hook 验证通道与目标是否正确，确认没问题再加参数打印。

如果需要修改返回值或参数（`Interceptor.replace`），那已经超出了「观察」的范畴 —— 这类操作会改变应用行为，报告里必须作为独立的实验步骤记录，且不得用于会产生法律后果的事实认定。

<a id="section-18"></a>

#### 陷阱 4：没做静态分析就「满屏 Hook」，产出的日志无法解释

**现象**：打开 `frida-trace` 挂上几十个通配规则（`*open*`、`*read*`、`*crypto*`、`*key*`），跑一遍，拿到几千行日志，然后发现**没法用**——不知道哪个调用是关键、参数含义不明、也不知道拿到的值到底是什么。

**原因**：没有静态定位时，Hook 日志只有调用事实、没有语义。 你会看到 `open` 被调用了几百次，但哪个是数据库文件？看到某个函数收了 16 字节，那是密钥、IV、还是随机数？判断「这个值是什么」需要的信息（这个类在业务里的角色、这个参数在其他调用点的取值、这个返回值被谁消费）恰恰是静态分析能提供而 Hook 提供的。 反过来，Hook 能提供而静态不能提供的只有「实际执行时传了什么」——两者提供的是互补信息，把 Hook 当成静态的替代，等于放弃了语义只留下了数值。

**影响**：**这是产出无法使用的成果，然后花大量时间去解释它。**

更实际的问题是**它极易导致「误取」**：在几千行日志里找到一个看起来像密钥的 16 字节串，据此去解密，**解不开**。

而此时无法判断是「这个值不是密钥」还是「取密钥的方式错了」—— **这个二义性让整个方向卡住。**

大量时间投入换来一个不可用结论，且检材已经被反复启动过多次（见陷阱 3 的风险）。

**核查**：**静态先行，动手前必须先写清三件事**：

```bash
# 第 1 步：静态分析，定位到具体类与具体方法
aapt dump badging base.apk ; apktool d -f -o app-decoded base.apk
jadx -d app-jadx base.apk --no-res
grep -rn "openOrCreateDatabase\|SQLiteOpenHelper" app-jadx/sources/
grep -rn "SecretKeySpec\|Cipher.getInstance" app-jadx/sources/
unzip -l base.apk | grep '\.so$' | awk '{print $NF}'   # 有加固则静态到此为止

# 第 2 步：Hook 前写下三件事（写不出来就说明还没准备好）
#   目标：要拿什么？（数据库口令 / 解密后的字节 / 接口参数）
#   位置：它可能在哪里产生？（Java 层某类 / JNI 某 so 的某导出符号）
#   验证：拿到后如何证明它是真值？（实际解密成功 + 表结构可枚举）
```

**执行时按「窄到宽」的顺序，而不是一上来就宽**：

```bash
# ① 最窄：已知类名与方法名，直接 Hook（静态已定位时的首选）
frida-trace -U -f com.digiforensics.sample -j "openOrCreateDatabase" 2>&1 | head -20

# ② 中等：通配符摸调用面，确认「加密发生在哪一层」
frida-trace -U -f com.digiforensics.sample -j "*encrypt*" 2>&1 | head -30
# /system/lib64/libfoo.so: libfoo.so!Java_com_foo_Crypto_encrypt
# ← 关键发现：业务层自带加密封装，而非直接用平台 API

# ③ 宽：全量 sqlite3 native 调用（用于确认是否走标准接口）
frida-trace -U -f com.digiforensics.sample -i "*sqlite3*" 2>&1 | head -30
```

每扩大一层之前，先问「上一层的产出是否已经够回答我要的问题」。

够就停下 —— **这既是效率要求，也是减少检材上动作次数的要求**。

<a id="section-19"></a>

#### 陷阱 5：拿到疑似密钥就直接当结论，不做实际解密验证

**现象**：Hook 到了 `sqlite3_key`，日志里打出 16 字节，报告写「已取得数据库密钥」。委托方据此认为数据已可获取。

**原因**：「拿到一个长度合适的字节串」与「它是正确的密钥」之间隔着一整套验证。 十六进制串长得像密钥是最不可靠的判断依据——一个 16 字节的随机串（IV、随机数种子、加密后的数据块）在外观上与 AES-128 密钥毫无区别。而即使「是密钥」，也可能是加密前的中间值、密钥的哈希、或者用于别的算法的密钥。真正的验证只有一个：拿它去实际打开数据库副本，能枚举出表结构，且 `PRAGMA integrity_check` 返回 `ok`。**这两条都过了，才说明它确实是这个库的密钥。**

**影响**：**「取得密钥」是一个会被直接引用的成果性表述**，它隐含「数据已可获取」的推论。

委托方据此安排后续动作（让技术方解密、通知当事人、或基于内容做处置），**而实际数据一个字都读不出来**。

更严重的情形是拿着一个错误密钥反复尝试 —— 对 SQLCipher 类库来说，错误的 key 会消耗掉内部的校验状态，多次失败后库可能被标记为不可用。

而且在报告层面，「已取得密钥」与「已解密获取数据」是两件事，混用会让报告的技术叙述与实际产出不匹配。

**核查**：**验证是取得动作的一部分，不是可选项**。判定标准是「能读出表结构 + integrity_check 为 ok」，不是「长度对得上」或「看起来像十六进制」：

```bash
# ★ 永远在副本上验证，绝不在原始检材或原始提取件上
cp app.db app-copy.db
sha256sum app.db app-copy.db            # 先证明副本与原件一致

# 实际解密验证：能列出表 = key 有效
sqlite3 app-copy.db "PRAGMA key='<取得的key>';"
sqlite3 app-copy.db ".tables"           # 列出 message / pay_record / user_profile ✓
sqlite3 app-copy.db "PRAGMA integrity_check;"   # ok ← 结构完好 ✓

# 副本是否被改动过，也要能说清
sha256sum app-copy.db                   # 此时哈希已变（解密会写），原件哈希才是基准
```

**报告表述模板**：

> **数据库解密验证**：在提取件副本 `app-copy.db` 上以 Hook 取得的口令执行 `PRAGMA key`，成功枚举出 3 张业务表（`message`、`pay_record`、`user_profile`），`PRAGMA integrity_check` 返回 `ok`。据此确认该口令为 `app.db` 的有效密钥，数据库内容可读。
> **数据获取状态**：本次分析的目标是判定库中是否存储支付凭证信息。上述验证确认了「库可解密」，但「是否含支付凭证」需在解密后的表内容中检索，本次未执行该步，故不做该项结论。

注意最后一句——「拿到密钥」和「完成委托要求」是两件事，报告必须把这条界线画清楚。

<a id="section-20"></a>

#### 陷阱 6：能列出表名就断言「不是 SQLCipher」

**现象**：`sqlite3 app-copy.db "PRAGMA key='xxx'"` 之后 `.tables` 正常列出了表名，报告写「该数据库未使用 SQLCipher 加密，是普通 SQLite 库」。

**原因**：「用一个参数就能打开」与「使用了哪种加密实现」是两个不同层面的事实。 判定加密实现需要看**独立的形态特征**：**① 文件头**——未加密的 SQLite 文件以 `SQLite format 3\0`（16 字节魔数）开头，而 SQLCipher 类库在应用密钥后会把头部**改写为随机 salt**，魔数因此消失，文件头看起来是随机字节；**② 动态库加载**——进程内是否加载了 `libsqlcipher.so` 这类库；**③ 库内痕迹**——是否存在 `PRAGMA key` / `rekey` 的调用痕迹（如应用侧代码、WAL 文件的差异）。「这次能用某个参数打开」只证明了这个参数对这次打开有效，别的实现方式（比如自实现的字段级加密、把整个文件当 blob 存在另一个库里、或 key 恰好等于文件头前缀）也能产生同样的现象。

**影响**：**这是一条会传播的技术判断。**

报告写「未使用 SQLCipher」，会直接影响后续动作：委托方或技术方据此判断「那数据为什么读不出来」，进而把方向引向「数据库损坏」「数据未落盘」等错误解释。

而实际上加密实现的存在，恰恰是「数据读不出来」的最常见原因。

把「能打开一次」当成「没加密」，会系统性地把问题引向错误方向，并可能让真正的解密路径永远不被尝试。

**核查**：加密实现类型要多形态交叉判定，且报告里把「本次观察到什么」与「据此不能推出什么」同时写清：

```bash
# ① 文件头魔数：16 字节，非 "SQLite format 3\0" 即头被改写
head -c 16 app.db | xxd
# 53514c69 74652066 6f726d61 74203300  → "SQLite format 3\0" 未加密特征
# （其他随机内容 → 头部被改写，疑似文件级加密）
python3 -c "
import binascii
h=open('app.db','rb').read(16)
print('magic ok' if h==b'SQLite format 3\x00' else 'magic 异常（头部可能被改写）')
print(binascii.hexlify(h).decode())"

# ② 进程内是否加载了加密库（Hook 或 /proc/<pid>/maps）
adb shell su -c "grep -i sqlcipher /proc/\$(pidof com.digiforensics.sample)/maps"

# ③ 文件熵值：全文件均匀高熵 → 强加密；局部高熵 → 可能仅部分字段加密
python3 -c "
import math,collections
d=open('app.db','rb').read()
c=collections.Counter(d); n=len(d)
print('熵=%.3f' % (-sum(v/n*math.log2(v/n) for v in c.values())))"

# ④ 应用侧是否执行过 PRAGMA key / rekey
grep -rn "PRAGMA key\|rekey\|sqlcipher" app-decoded/smali/ app-jadx/sources/ 2>/dev/null | head
```

**报告表述模板**：

> **加密形态判定**：本次 Hook 观测到应用在打开 `app.db` 时传入 16 字节口令（SHA-256 摘要 `a1b2…`，`openDatabase` 的 `params` 参数，非明文回显），**传入该口令后数据库可打开且表结构可枚举**。
> **文件头**：`app.db` 前 16 字节为 `53514c69…`（`SQLite format 3\0`），**未呈现 SQLCipher 的头部改写特征**。
> **动态库**：目标进程 maps 中**未见** `libsqlcipher.so`。
> **据此判定**：本次未发现标准 SQLCipher 加密实现。**但「可打开」与「未加密」不是同一结论**——该应用可能使用自实现的字段级加密、将密文存于另一字段，或口令恰好等于头部内容。本条结论限于「未发现标准 SQLCipher 特征」，不排除其他加密实现。

<a id="section-21"></a>

#### 陷阱 7：★ 用 `frida-gadget` 重打包替换检材上的原始 APK

**现象**：为了让免 root 的设备也能动态分析，把 `frida-gadget` 库塞进 APK 目录、重新打包签名、卸载原应用后安装改造版。

**原因**：重签名必然改变 APK 的签名证书，而签名证书是这批 APK 身份认定的依据。 而且这个操作还连锁触发了几件事：卸载原应用会清空 `/data/data/<包名>/` 全部私有数据（包括 `databases/`、`shared_prefs/`）；重打包后的 APK 文件名、目录名（`/data/app/~~xxxx==/`）、体积、mtime 全部不同；而目标应用如果本来就有自校验（`PackageManager` 比对自身签名）或加固自校验，**运行时会直接崩溃**。分析者以为只是「加了个库」，实际上换掉了证据本体。 更根本的是：这个动作与「在检材上做实验」在性质上是一样的——它把证据对象替换成了一个被改造过的替代品。

**影响**：**不可逆，且可能直接摧毁委托要求的核心数据。**

卸载重装之后，**原来那份 `app.db` 已经不存在了**，而它的价值恰恰是解密目标本身。即使后来拿到了密钥，也没有可解密的库了。

如果原 APK 已经被移动出设备（为了「保护」它而做的搬运），那么签名比对、版本比对、与其他变体包的关联分析全部无法进行 —— 第 03 篇里那套「同签名批量打包」的认定方法在这批文件被替换后就不再适用。

这一条是不可逆的破坏，而破坏的对象是唯一的原始证据。

**核查**：gadget 方案只用于分析副本，检材上的原始 APK 永不动：

```bash
# ✓ 首选：frida-server，不改动检材的 APK
adb push frida-server-16.2.1-android-arm64 /data/local/tmp/frida-server
adb shell su -c "chmod 755 /data/local/tmp/frida-server"
adb shell su -c "/data/local/tmp/frida-server -D &"

# ✓ gadget 方案：仅当委托方明确同意制作分析副本时使用，
#   且全过程在副本目录内进行，检材目录不参与
mkdir -p gadget-work
cp DigiForensics.apk gadget-work/DigiForensics-gadget.apk
# （打包、签名、仅在副本上安装；检材上的原始 APK 保持原位）
# 安装到副本前必须记录：原 APK 哈希、当前安装的是原版还是改造版
```

**如果确实需要在免 root 设备上做动态分析**：① 取得委托方对「制作分析副本」的明确书面同意；② 在报告中单列说明「本节结论来自分析副本，副本经重签名，其签名与检材原件不同」；③ 所有只能从原始 APK 得到的结论（签名主体、版本、资源内容）必须回到检材原件上做；④ 作业完成后恢复原始安装状态并验证哈希。

这四条里第 ③ 条是底线 —— 原件的结论不能由副本的结论替代。

<a id="section-22"></a>

### 4.3 密钥暴露与工具可信度

<a id="section-23"></a>

#### 陷阱 8：`frida-server` 二进制不固定哈希，无法证明工具未被篡改

**现象**：从某个非官方渠道下载了 `frida-server` 二进制，推到设备上运行了，Hook 也成功了，报告记录了版本号但没记哈希。

**原因**：**版本号是一个自述信息，不是可验证的身份。** 版本号相同的东西可以有很多份内容不同的文件——**而这正是工具供应链的真实风险**。在一个取证流程里，运行在检材与目标进程之间的那个二进制，拥有对目标进程的完全控制能力：它能读全部内存、Hook 任意函数、修改返回值。如果这个二进制的内容不能被证明，那么通过它取得的所有数据都无法证明来源。 记录版本号只回答了「它自称是什么」，记录哈希才回答了「它是哪些字节」——**后者才是可复核的。**

**影响**：这是举证能力上的空洞，而它的位置在整条证据链的最前端。

复核方完全可以问一句：「你用来读取数据的这个工具，能否证明它没有被改动过？」没有哈希，这个问题无法回答。

**更麻烦的是它会沿着链路反向传播** —— 通过这个工具取得的一切（调用序列、参数、密钥）都会被归入「来源不可验证」。

**而记录这个工具的哈希，代价只是一行命令。**

**核查**：工具哈希与其他工具一样先行固定，并与其他环境事实一起记录：

```bash
# ① 工具本身也是证据，第一时间固定
sha256sum frida-server-16.2.1-android-arm64 | tee frida-server.sha256
frida --version | tee frida-host-version.txt

# ② 推送后核对设备侧一致性
adb shell su -c "sha256sum /data/local/tmp/frida-server"
# 与主机侧哈希一致 ✓

# ③ 版本号与哈希一并写进操作日志
#    主机端：frida 16.2.1
#    设备端：frida-server 16.2.1，SHA-256 a1b2c3d4…
#    分析对象：com.digiforensics.sample，APK SHA-256 e5f6…，app.db SHA-256 …
#    操作类型：spawn（frida -f）+ 注入脚本 hook-db.js（脚本 SHA-256 …）
#    脚本本身也是证据，一并固定
sha256sum hook-db.js hook-sqlite.js 2>/dev/null

# ④ 作业收尾：清理并验证
frida-kill -U
adb shell rm -f /data/local/tmp/frida-server
adb shell su -c "ps -A | grep frida"    # 确认为空
```

操作日志至少要覆盖六项：分析时间（起止到分）、两端工具版本与 `frida-server` 二进制哈希、分析对象（包名 / APK 哈希 / 数据目录路径）、操作类型（spawn 还是 attach，注入的脚本及其哈希）、影响面（是否重启应用、是否修改文件、是否退出登录）、取得结果（调用序列、参数、密钥值——是否写入报告需评估**）。**

<a id="section-24"></a>

#### 陷阱 9：在 Hook 日志里打印完整明文敏感数据

**现象**：为了「确认内容」，脚本里 `console.log` 打出解出的明文全文——聊天内容、身份证号、银行卡号、甚至密码。日志文件随手存到工作目录。

**原因**：Hook 日志是**分析过程最顺手、也最容易被过度记录的产物**。它落在主机的工作目录里，没有加密、没有权限控制、会随项目打包带走、可能进入最终报告的附件，而**内容是检材里最敏感的那部分**。这个动作看起来只是「打印出来看看」，但它把一次可控的、局部的暴露，变成了一个持久的、可能被复制传播的副本。更现实的是，**一旦明文被打印，报告撰写阶段就很难避免地会引用它**——因为它就摆在日志里，而且「这就是证据内容」是一个很自然的写法。这就是敏感信息从「受控的检材」扩散到「不受控的文档」的那个时刻。

**影响**：**这不只是合规问题，可能造成实质损害。**

日志外泄的后果包括：

**① 无关人员接触到第三方隐私。** 聊天记录里往往涉及大量与案件无关的第三方个人信息，而这些人在案件中没有任何知情地位。

**② 证据材料的处置失控。** 按最小化与脱敏原则，报告与附件应只包含支撑结论所必需的内容，而整段明文日志远超这个范围。

③ 在特定案件类型中，日志本身可能成为新的涉案材料（如涉及未成年人、涉及他人隐私数据），处置不当会引发独立的责任。

**核查**：**日志只记「够验证」的信息，不记「内容本身」**：

```javascript
// 最小暴露：长度、时序、摘要
Java.perform(function () {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload("[B").implementation = function (input) {
        var out = this.doFinal(input);
        // ✓ 只记录长度与方向，不回显明文
        console.log("[doFinal] in=" + input.length + "B out=" + out.length + "B");
        return out;
    };
});
```

```javascript
// 密钥类参数：记录长度与 SHA-256 摘要（逐字节转 hex，byte[] 直接 toString 得 [B@1a2b3c）
var MessageDigest = Java.use("java.security.MessageDigest");
function sha256hex(s) {
    var bytes = MessageDigest.getInstance("SHA-256").digest(s.getBytes("UTF-8"));
    var hex = "";
    for (var i = 0; i < bytes.length; i++) {
        var b = bytes[i] & 0xff;
        hex += (b < 16 ? "0" : "") + b.toString(16);
    }
    return hex;
}
console.log("[db] keySHA256=" + sha256hex(params));   // 摘要可复算、可比对，不暴露原文
```

**当内容本身是结论所必需时**（比如必须证明「该表含支付凭证字段」）：在解密后的副本上做检索，把结果作为结论写进报告，而完整的原始内容留在受控的提取件里不进报告。

**报告引用数据时应做必要性与比例性判断** —— 展示 3 条代表性记录足以支撑结论时，就不要贴 300 条。

**日志文件本身也要按证据材料对待**：固定哈希、限制访问、不随项目目录整体打包外发。作业结束时明确记录「日志已生成，含 N 条记录，其中涉及敏感内容 M 处，已按最小化原则处理」。

<a id="section-25"></a>

### 4.4 结论表述

<a id="section-26"></a>

#### 陷阱 10：报告里写「已解密数据库」，但没有写清解密的对象与范围

**现象**：报告结论部分写「已解密目标数据库并获取全部数据」，而实际只打开了一个 `app.db`，应用私有目录里还有另外三个库文件、还有 `DigiForensics-user_profile.db` 与 `DigiForensics-log.db` 未处理。

**原因**：「已解密数据库」这句话在中文里没有量化边界，读者会自然理解为「这批数据都拿到了」。而「解密成功」是一个逐库成立的事实——一个库解开不代表其他库也解开了，因为每个库可能用不同的口令或不同的实现（甚至有些库根本没加密）。同时「获取全部数据」里的「全部」也需要界定：**是全部表、全部记录、全部字段，还是全部库？** 这些在实施时通常只做了其中一项，但表述时用了最宽的那一项。

**影响**：这是一个覆盖范围虚报的问题，且它出现在结论部分 —— 报告里最容易被单独摘录的部分。

委托方可能据此认为「所有数据都已拿到」，从而不再追加委托。而实际上有未解密的库。

**若那些未解密的库里恰好有最关键的数据**（比如另一个库存着交易流水，而解开的只是用户设置），**漏检就直接影响案件定性**。

反过来，若委托方按「全部已获取」对外答复当事人，后续发现数据不全，会造成更严重的信任问题。

**核查**：把解密结果做成一张逐库清单，覆盖范围由清单定义，而不是由一句话定义：

```bash
# 枚举所有数据库文件，含未加密的
find extracted/databases -type f \( -name '*.db' -o -name '*.sqlite' -o -name '*.db3' \) | tee all-dbs.txt
# 逐个判定：文件头魔数 + 尝试打开 + 表枚举
while read -r f; do
  echo "=== $f  $(stat -c%s "$f")B"
  cp "$f" /tmp/t.db
  sqlite3 /tmp/t.db ".tables" 2>/dev/null | head -3
  rm -f /tmp/t.db
done < all-dbs.txt
```

**报告写成清单**：

> **数据库解密状态**
>
> | 文件 | 大小 | 加密状态 | 状态依据 | 处理结果 |
> |---|---|---|---|---|
> | `app.db` | 96 MB | 加密（口令传入） | Hook 观测 + 头部魔数 | **已解密**，枚举 3 张表，integrity_check = ok |
> | `DigiForensics-user_profile.db` | 2.1 MB | 加密（口令与 app.db 不同） | 头部魔数异常 | **已解密**，2 张表 |
> | `DigiForensics-log.db` | 412 MB | 加密 | 头部魔数异常 | **未解密**：本次 Hook 期间应用未打开该库，未取得其口令 |
> | `DigiForensics-cache.db` | 88 KB | 未加密 | 头部魔数为 `SQLite format 3\0` | 直接读取，1 张表（缓存索引，无业务内容） |
>
> 共 4 个库文件，已解密 3 个，未解密 1 个（`DigiForensics-log.db`，412 MB）。未解密原因：应用在本次分析时段未访问该库。
> **后续可尝试路径**：启动应用并触发相关功能以观测该库的打开调用；或从静态代码分析该库的初始化位置。本报告不对 `DigiForensics-log.db` 内容作任何判断。

**这个清单的三个作用**：① 它把「未完成」显式列出来，而不是藏起来；② 它把每个结论的「依据」一栏填满，读者能判断每个判断的强度；③ 它让「未解密」成为一项明确的待办，而不是一个遗漏。

<a id="section-27"></a>

#### 陷阱 11：把「Hook 成功」等同于「数据已取得且可信」

**现象**：`frida-ps -U` 列出了进程、Hook 日志打出了调用、应用没有崩溃，于是报告写「动态分析完成，已获取所需数据」。

**原因**：「Hook 成功」证明的只是「注入与拦截机制工作正常」，与「取到了想要的东西」之间隔着好几道验证。 具体要问：① **Hook 的目标是那个产生密钥的调用点吗**——Hook 到了 `sqlite3_key` 不代表那是业务密钥的来源，也可能是某个不相关的打开；② **日志里出现的是执行时序还是仅一次偶然调用**——有些库只在特定操作下才打开，Hook 挂上后应用启动期间没走到那个分支，就什么都没有；③ **取得的是密钥还是密钥的中间形态**（哈希、加密后的形式）；④ **拿到之后有没有实际用**。这四个问题任何一个没回答，「已获取数据」都是超出证据的表述。

**影响**：「动态分析完成」是一个流程性的成就表述，它在报告里的作用是让委托方认为这一环已经闭合。

实际上如果 Hook 目标选错、或者取到的值不是所需，整个动态分析环节并未达成目的 —— **但报告的语气让委托方认为可以结案了。**

**这在项目节奏上的代价是实质的**：委托方基于「已完成」的判断把设备归还、把检材移交给下一环节，而后再想补做需要重新协调。

**核查**：**把「机制可用」与「目标达成」分成两件事分别记录**，并逐项列出取得内容的可解释性：

> **动态分析执行记录**
>
> | 项 | 内容 | 状态 |
> |---|---|---|
> | 通道建立 | 主机 frida 16.2.1 / 设备 frida-server 16.2.1（SHA-256 `a1b2…`），USB 转发 | **已完成** |
> | 目标进程附加 | `com.digiforensics.sample`，spawn 方式 | **已完成** |
> | 目标函数定位 | 静态定位 `com.digiforensics.sample.crypto.Digest.decrypt`；`frida-trace` 摸调用面确认业务层自封装（`libfoo.so!Java_com_foo_Crypto_encrypt`） | **已完成** |
> | 参数语义确认 | `sqlite3_key` 的 `args[1]/args[2]` 为口令字节与长度；`openDatabase` 的 `params` 参数为口令字符串 | **已完成** |
> | 取得内容 | 16 字节口令，SHA-256 `a1b2c3d4…`（**明文未写入报告**） | **已取得** |
> | 内容验证 | 副本解密成功，3 张表可枚举，integrity_check = ok | **已验证** |
> | 委托目标 | 判定 `pay_record` 表是否含支付凭证信息 | **未完成**：本次仅完成密钥取得与库解密，**未对表内容做字段级检索** |
>
> **机制层面：已完成并验证。委托目标层面：未完成。**
> **可解释性说明**：所取得口令值经实际解密验证，**其正确性由「副本可打开且结构完整」证明**，非由长度或格式推定。该值来源于 `openDatabase` 的 `params` 参数（`args` 不适用），且在同一调用点连续三次观测到相同值。

**最后一句是「可解释性」的最小标准**：动态分析拿到的每个值，都必须能说清「它在哪个调用点、参数是什么、为什么等于这个值」。 说不出这三样的值，不进报告。
<a id="section-28"></a>

## 五、案例示例

> **授权前提**：以下案例基于**委托方书面授权**进行动态分析，授权范围明确包含「在已 root 隔离测试设备上加载目标应用并观察其运行时行为」。**未取得该授权时，本章所述路径均不可执行** —— 技术可行不等于可以执行。

<a id="section-29"></a>

### 5.1 加固应用数据库密钥的运行时定位与支付记录提取

**场景**

查获一台已 root 的 Android 12 手机，检材为一个加固应用（包名 `com.digiforensics.sample`），其本地数据库 `app.db` 已被确认存在且体积正常。

委托方要求查明库中是否存储了用户的支付凭证信息。**已取得委托方书面授权进行动态分析。**

这条路径的必要性在前一步已经论证：静态分析因加固而失败，**这不是「没做」，是「加固使其不可做」** —— 这个判断本身就是结论的一部分。

**处置过程**

第一步，静态分析先行，**目的是确定 Hook 目标**：

```bash
$ unzip -l base.apk | grep -E '\.so$|assets/|\.dex$'
  312K  lib/arm64-v8a/libjiagu.so
  1.4M  classes.dex
$ aapt dump xmltree base.apk AndroidManifest.xml | grep -A3 'E: application'
A: android:name(0x01010003)="com.digiforensics.shell.StubApplication"
$ jadx -d app-jadx base.apk --no-res 2>&1 | tail -2
$ grep -rn "Cipher.getInstance\|SecretKeySpec" app-jadx/sources/ | wc -l
2
```

**只有壳里的 2 处，业务加解密逻辑完全不可见。** 静态到此为止。

第二步，动态定位 —— 先 trace 摸调用面，不要一上来就写 hook：

```bash
$ frida --version
16.2.1
$ adb push frida-server-16.2.1-android-arm64 /data/local/tmp/frida-server
$ adb shell su -c "chmod 755 /data/local/tmp/frida-server"
$ sha256sum frida-server-16.2.1-android-arm64     # 工具哈希入证据目录
$ adb shell su -c "/data/local/tmp/frida-server -D &"
$ adb forward tcp:27042 tcp:27042
$ frida-ps -U | head -3
```

> **版本必须严格一致**：frida 主机端 16.2.1 对应 frida-server 16.2.1。**版本不匹配会在连接时立即报错**，用 `frida --version` 逐字符比对即可排除。

第三步，用 `frida-trace` 快速确认数据库打开路径：

```bash
$ frida-trace -U -f com.digiforensics.sample -i "*sqlite3*" 2>&1 | head -30
[+] attach
[open] /data/user/0/com.digiforensics.sample/databases/app.db
[open] flags=66
[exec] SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'
[table] message
[table] user_profile
[table] pay_record
```

`pay_record` 表存在，`flags=66`（`0x42` = `OPEN_READWRITE|CREATE`）。

第四步，**判定加密实现类型 —— 这一步不能跳**：

```bash
# 4.1 文件头魔数：SQLCipher 会在偏移 0 写入随机 salt，魔数不再是 SQLite 格式串
$ xxd -l 16 app.db
00000000: 3a 70 4b 0a d1 7f 3c 92  8e b4 6a 05 f1 22 3d 8a
# ← 首 16 字节不是 "SQLite format 3\0"（应为 3a 51 4c 69 74 65 20 66...）

# 4.2 是否加载了加密扩展
$ frida-trace -U -f com.digiforensics.sample -i "dlopen" 2>&1 | grep -iE 'sqlcipher|sqlite|crypto'
[dlopen] libsqlcipher.so
# ← 确认加载了 SQLCipher

# 4.3 是否有 PRAGMA key 执行痕迹
$ frida-trace -U -f com.digiforensics.sample -i "*exec*" 2>&1 | grep -i 'pragma'
[exec] PRAGMA key = "x'9f3a...'"
```

三项证据共同确认：数据库使用 SQLCipher 加密。 仅凭「表名能列出来」就说「不是加密库」是不严谨的 —— 那只说明本次传入的密钥有效。

第五步，定位密钥来源。**先看数据库打开路径上到底有没有 key 参数**：

```bash
$ frida-trace -U -f com.digiforensics.sample -j "*openOrCreateDatabase*" 2>&1 | head -20
onEnter: path=/data/user/0/.../app.db   hasKey=true   keyLen=32
# ★ 收到了 32 字节 key 参数
```

第六步，写 hook 脚本，**遵循最小暴露原则**：

```javascript
// hook-db.js —— 只记录 key 的 SHA-256 摘要，不落原始值
// 用法: frida -U -f com.digiforensics.sample -l hook-db.js
Java.perform(function () {
    var DB = Java.use("android.database.sqlite.SQLiteDatabase");
    DB.openDatabase.overload("java.io.File", "int",
        "android.database.sqlite.SQLiteCursorFactory",
        "java.lang.String", "android.database.sqlite.SQLiteHook",
        "android.database.sqlite.SQLiteConnectionParams"
    ).implementation = function (file, flags, factory, hook, params) {
        if (params) {
            var pw = params.getPassword();
            if (pw) {
                var key = pw.getBytes("UTF-8");
                var md = Java.use("java.security.MessageDigest").getInstance("SHA-256")
                    .digest(key);
                // byte[] 必须逐字节转 hex；直接 toString() 得到 [B@1a2b3c 这类对象标识
                var hex = "";
                for (var i = 0; i < md.length; i++) {
                    var b = md[i] & 0xff;
                    hex += (b < 16 ? "0" : "") + b.toString(16);
                }
                console.log("[db] path=" + file.getAbsolutePath() +
                            " keyLen=" + key.length +
                            " keySHA256=" + hex);
            }
        }
        return this.openDatabase(file, flags, factory, hook, params);
    };
});
```

第七步，**决定性验证步骤 —— 在副本上实际解密**：

```bash
$ frida -U -f com.digiforensics.sample -l hook-db.js 2>&1 | grep -E '^\[db\]'
[db] path=/data/user/0/com.digiforensics.sample/databases/app.db keyLen=32 keySHA256=a7f2...

$ cp app.db app-copy.db && sha256sum app.db app-copy.db
$ sqlite3 app-copy.db "PRAGMA key='x<key>';"
$ sqlite3 app-copy.db ".tables"
message  pay_record  user_profile
$ sqlite3 app-copy.db "PRAGMA integrity_check;"
ok
```

`.tables` 能列出 + `integrity_check = ok` —— 这才是「密钥正确且数据完整」的判据。 密钥的 SHA-256 看起来对不算验证。

第八步，提取并交叉验证：

```bash
$ sqlite3 -header -column app-copy.db \
  "SELECT id, datetime(create_time/1000,'unixepoch','+8 hours') AS t, amount, channel
   FROM pay_record ORDER BY create_time LIMIT 20;"
id   t                     amount   channel
101  2024-08-15 21:33:11   288.00   wechat
102  2024-08-16 10:40:55   1288.00  alipay
```

第九步，清理并验证检材未被改动：

```bash
$ frida-kill -U
$ sha256sum app.db
# 与提取时的哈希一致 → 证明只做内存注入、未改动检材文件 ✓
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 静态分析不可行的原因是加固存在 | 四项加固特征 + `jadx` 产物仅壳类 | 强（已实测） |
| `app.db` 使用 SQLCipher 加密 | 文件头魔数被改写 + `libsqlcipher.so` 加载 + `PRAGMA key` 痕迹 | 强（三源） |
| 数据库密钥在运行时可从 `openDatabase` 的 `params` 取得 | `hasKey=true keyLen=32` + hook 输出 | 强 |
| 数据库已成功解密且结构完整 | `.tables` 列出 3 表 + `integrity_check = ok` | 强 |
| 存在 2 条支付记录，金额 288.00 与 1288.00 | `pay_record` 表 | 强 |
| 第二笔支付在账号切换后 57 秒 | `pay_record`(10:40:55) vs `account_prefs.xml`(10:41:52) | 中（时间关系） |
| 检材未被改动 | 分析前后 `app.db` 哈希一致 | 强 |
| **`message` 表内容** | — | **未提取**（解密路径不同，本次 Hook 未覆盖） |

**能证明的**：加密实现的具体类型；密钥的运行时来源；解密后数据的内容与结构；检材完整性。

**不能证明的**：
- **不能证明支付已实际完成。** `pay_record` 是应用本地记录，可能在发起时写入而未成功
- **不能证明支付账户归属。** `channel=wechat/alipay` 只记录渠道名，无交易号
- **不能证明这两笔支付由机主操作**
- **不能从「解密成功」推出「数据未被服务端篡改」**

**未覆盖范围**：`message` 表的解密路径（可能用不同密钥）、服务端侧的订单状态、`user_profile` 的详细字段、密钥的生成与存储机制（是否每次会话派生）。

**误判对照**

这个案例的误判点集中在**「看起来成功了」的每一个节点上** —— 动态分析的错误往往不报错，只给出一个似是而非的成功信号。

其一，hook 脚本里 `byte[].toString()` 直接拼接。

这是本案需要优先处理的 Frida 坑。Java 层的 `byte[]` 在 Frida 中是 JS 数组，直接 `toString()` 得到的是 `[B@1a2b3c4d` 这样的对象标识，不是内容。

脚本会正常运行、不报错、输出一行看起来正常的日志 —— 但那个「keySHA256」是垃圾。

正确写法是**逐字节转 hex**（见脚本中 `for` 循环）。判据是**输出长度**：

| 写法 | 输出 | 判据 |
|---|---|---|
| `md.toString()` | `[B@a7f2c1d8` | 长度 ~12，非 64 字符 hex |
| `md.join("")` | `a7f2c1d8e9b4...`（有符号字节，>127 变负数） | 长度 32 但含负号/乱码 |
| 逐字节 `& 0xff` 转 hex | 64 字符纯 hex | ✅ |

判据的通用形式：hook 脚本的输出必须做形状校验（长度、字符集）。 Frida 不做类型检查，一个类型错误会以「看起来正常」的形态输出。

**其二，把「表名能列出来」当作「库不是加密的」。**

`frida-trace` 的输出里 `message`/`user_profile`/`pay_record` 三个表名清晰可见，看起来像明文库。判据是**表名可见 ≠ 明文**：

| 观察 | 实际含义 |
|---|---|
| `.tables` 能列出表名 | 传入的密钥**有效** |
| 文件头为 `SQLite format 3\0` | 才是明文库 |
| 文件头为随机字节 | SQLCipher（salt 覆盖了魔数） |
| `dlopen` 加载 `libsqlcipher.so` | 使用了加密扩展 |

本案 `xxd -l 16 app.db` 的首字节是 `3a 70 4b 0a` 而非 `3a 51 4c 69 74 65 20 66 6f 72 6d 61 74 20 33 00`。**只看表名会得出完全相反的结论。**

按错误判据走的代价：报告写「该数据库未加密，内容可直接读取」，委托方据此认为取证难度低、可能要求加快进度。而实际上解密是关键步骤，也是授权范围的核心。

其三，把「密钥 SHA-256 看起来对」当作解密成功。

拿到 `keySHA256=a7f2...` 之后，一个常见的错误是直接开始提取数据。**判据是必须做实际验证**：

| 验证方式 | 命令 | 通过标准 |
|---|---|---|
| 列结构 | `sqlite3 app-copy.db ".tables"` | 输出表名 |
| 完整性 | `sqlite3 app-copy.db "PRAGMA integrity_check;"` | `ok` |
| 可读性 | `SELECT * FROM <表> LIMIT 5` | 返回行而非错误 |

**三项全过才算解密成功。** 只做第一项不够 —— 部分错误的密钥会「看起来能打开」（SQLCipher 不会在密钥错误时报错，而是把密钥当作 salt 解读，返回空的或乱码的库）。`integrity_check` 返回 `ok` 是其中最硬的一道判据。

按错误判据走的代价：提取出一堆乱码或空值，写进报告后才发现。**而此时报告可能已经发出。**

**其四，把两笔支付的时间巧合当作因果关系。**

`pay_record` 第二笔在 `2024-08-16 10:40:55`，`account_prefs.xml` 的账号切换在 `10:41:52`，相差 57 秒。

这个时间接近很容易被写成「账号切换后立即发生支付」，暗示两件事相关。

判据是**57 秒的间隔本身不构成关联**。要主张因果，需要排除其他解释：

| 可能的解释 | 本案是否排除 |
|---|---|
| 切换账号后立即支付 | 可能 |
| **支付与应用重启动作是同一次操作的两面** | **更可能** —— 账号切换与支付常在同一次登录后连续完成 |
| 两次独立操作，恰好接近 | 可能 |
| 系统时钟漂移导致的时间错觉 | 未排除 |

**最值得写的替代解释是第二条**：`login_success` 之后应用通常会拉取账户状态、加载默认支付方式，若用户随后点击支付，间隔几十秒是**产品逻辑的自然结果**，不是「切换触发了支付」。

按错误判据走的代价：报告建立了一条「账号切换→支付」的因果叙事，委托方据此追查切换账号的人。而实际上这两件事可能都只是「登录后做了两件常规操作」。

**第五个实操细节**：`frida-trace` 与 `frida -l` 的定位方式不同 —— 前者按**符号名通配**（`-i "*sqlite3*"` 匹配已导出函数，`-j` 匹配 Java 方法），后者执行自定义脚本。

判据是先用 `frida-trace` 确认调用面存在，再写 `frida -l` 抓参数。 直接写 hook 而不先 trace，会在 `overload()` 选择器上反复试错（SQLiteOpenHelper 与 SQLiteDatabase 的方法签名不同，一个 hook 不到不代表没有）。

先摸调用面再写 hook，可减少在 `overload()` 选择器上的试错轮次。

<a id="section-30"></a>

### 5.2 Hook 污染检材的识别与回滚

**场景**

承接 5.1。分析方换了一台设备，想抓 `message` 表的解密参数。抓取过程中顺手在应用里点开了一个菜单，看着无害。结果 `app.db` 的哈希变了。

要处理的是动态分析自己的副作用。静态分析天生只读，动态分析不是 —— 每一次交互都可能改到被检环境。

**处置过程**

第一步，建立基线哈希。**这一步必须在任何动态操作之前完成**：

```bash
$ PKG=com.digiforensics.sample
$ adb shell su -c "md5sum /data/data/$PKG/databases/app.db"
7a3f...  /data/data/com.digiforensics.sample/databases/app.db
$ adb shell su -c "cp /data/data/$PKG/databases/app.db /sdcard/DigiForensics-app-base.db"
$ adb shell su -c "sha256sum /data/data/$PKG/databases/app.db/*.db | tee /sdcard/db-hashes-before.txt"
```

第二步，操作前后各做一次哈希。主库之外，WAL 和 SHM 也要算进去。

```bash
$ adb shell su -c "ls -l /data/data/$PKG/databases/"
-rw-r--r-- 1 root root  987654 2026-03-15 10:20:14 app.db
-rw-r--r-- 1 root root   65536 2026-03-15 10:20:14 app.db-wal
-rw-r--r-- 1 root root   32768 2026-03-15 10:20:14 app.db-shm
```

只哈希 `app.db` 不够。运行时的写入可能还留在 WAL 里，`-shm` 是共享内存索引。两者变了，都是检材被动过的证据。

第三步，在设备上做操作，然后立即比对：

```bash
# 分析方打开了应用内的"清理缓存"菜单项
$ adb shell su -c "sha256sum /data/data/$PKG/databases/app.db" \
    | diff - /sdcard/db-hashes-before.txt | head -4
- 3e8a7f...  /data/data/com.digiforensics.sample/databases/app.db
+ 91c4b2...  /data/data/com.digiforensics.sample/databases/app.db
```

主文件哈希变了，`-wal` 和 `-shm` 的 mtime 也跟着更新。检材被改动了，这没什么可犹豫的。

第四步要回答另一个问题：内容变了，还是只变了元数据？

```bash
$ adb shell su -c "cp /data/data/$PKG/databases/app.db /sdcard/DigiForensics-app-after.db"
$ adb pull /sdcard/DigiForensics-app-after.db
$ sqlite3 /work/DigiForensics-app-after.db "PRAGMA page_count; PRAGMA freelist_count;"
# page_count  从 241 变为 241   ← 页面总数未变
# freelist    从 3 变为 127    ← 空闲页激增
```

`page_count` 没动，`freelist_count` 从 3 涨到 127。 这是"大量行被删除"的典型形态：所谓"清理缓存"删掉了应用自己认为可清理的数据行。

第五步，评估损失范围：

```bash
$ sqlite3 /work/DigiForensics-app-after.db "PRAGMA integrity_check;"
ok
$ sqlite3 /work/DigiForensics-app-after.db ".tables"
message  pay_record  user_profile      # 表结构仍在
$ sqlite3 /work/DigiForensics-app-after.db "SELECT count(*) FROM pay_record;"
2                                        # 支付记录未丢
$ sqlite3 /work/DigiForensics-app-after.db "SELECT count(*) FROM message;"
0                                        # 消息表被清空
```

`message` 表清空了，0 行。`pay_record` 那 2 条还在。

第六步，从基线副本恢复，同时把恢复动作记下来。

```bash
$ adb shell su -c "cp /sdcard/DigiForensics-app-base.db /data/data/$PKG/databases/app.db"
$ adb shell su -c "rm -f /data/data/$PKG/databases/app.db-wal /data/data/$PKG/databases/app.db-shm"
$ adb shell su -c "sha256sum /data/data/$PKG/databases/app.db"
7a3f...  /data/data/com.digiforensics.sample/databases/app.db   ← 与基线一致 ✓
```

> **重要提醒**：法证意义上的恢复**不能抹除改动已经发生的事实**。它只是把设备状态退回基线。改动事件本身必须完整记录并向委托方报告，隐去这一点就构成了证据污染。

第七步，写事故记录：

```text
检材状态变动记录

时间：2026-03-15 10:24:17 - 10:26:03 (+08:00)
设备：DIGIFORENSICS-TEST-01（隔离测试机，非扣押设备）
对象：com.digiforensics.sample / databases/app.db

变动内容：
  app.db     SHA-256  3e8a7f…（变动前）→ 91c4b2…（变动后）
  app.db-wal 由 0 条事务记录 → 若干；变动后已删除
  app.db-shm 索引重建；变动后已删除
  数据层面：message 表由 214 行清空为 0 行；
            freelist_count 由 3 增至 127；
            pay_record（2 行）与 user_profile 未受影响

原因：分析人员误操作，在目标应用内点击了"清理缓存"功能入口。

已采取措施：
  1. 自 /sdcard/DigiForensics-app-base.db（操作前基线副本）恢复主文件
  2. 删除 WAL/SHM 并重新生成
  3. 恢复后哈希与基线一致

影响评估：
  本次变动发生在隔离测试机上，未涉及扣押设备。
  隔离机上的数据库副本来自扣押设备的只读提取件，
  该提取件本身未被触碰，哈希与提取时一致。
  因此扣押检材未受影响，本案结论不受影响。

遗留事项：
  隔离机上 message 表数据已丢失，无法在本机继续分析该表。
  后续如需分析该表，须从扣押检材重新提取，或申请
  更严格的操作规程（禁交互模式）。
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 动态操作确实改动了数据库 | 前后 SHA-256 不一致 | 强 |
| 改动性质为大量行删除 | `page_count` 不变 + `freelist_count` 3→127 | 强 |
| `message` 表被清空，`pay_record` 与 `user_profile` 未受影响 | 恢复后 `count(*)` 与表清单 | 强 |
| 设备已恢复至基线状态 | 恢复后 SHA-256 与基线一致 | 强 |
| **扣押检材未受影响** | 扣押提取件哈希与提取时一致，隔离机为独立副本 | 强 |
| 本次隔离机上的 `message` 表数据已不可恢复 | 表已清空，无其他副本 | 强 |

**能证明的**：改动的事实、性质与范围；恢复的有效性；扣押检材未受影响。

**不能证明的**：
- **不能证明"恢复"等于"未发生改动"。** 恢复只是状态归位，事件本身已记录在案
- **不能证明隔离机上没有其他未察觉的改动。** 本次只对 `databases/` 做了哈希，`files/`、`cache/`、`shared_prefs/` 未做全量比对

**未覆盖范围**：`files/`（38 MB）、`cache/`、`shared_prefs/` 的前后状态比对（本次只覆盖 databases）；分析期间是否有其他应用被触发；网络层是否有数据外发（未做流量采集）。

**误判对照**

这个案例的误判点很朴素，后果却不轻：只哈希主文件，忽略 WAL 和 SHM。

其一，只检查 `app.db` 的哈希，漏掉 `-wal` 与 `-shm`。

WAL 模式下事务数据先落 `-wal`，`-shm` 维护共享内存索引。运行时写入不一定立刻反映到主文件上，要等 checkpoint。

只查主文件哈希，会是两种结果之一：

| 情况 | 后果 |
|---|---|
| 主文件哈希也变了 | 能发现（本案的实际情况） |
| **主文件未变，WAL 变了** | **完全漏掉**，而数据库逻辑内容已经改变 |

判据很简单，三个文件必须一起哈希：

```bash
$ adb shell su -c "sha256sum /data/data/$PKG/databases/app.db*"
```

通配符 `app.db*` 一并覆盖 `app.db`、`app.db-wal`、`app.db-shm`。一个字符的差别，决定阴性结论成不成立。

**其二，把"恢复后哈希一致"当成"没发生过改动"。**

恢复成功确实把状态退回基线，但改变不了已经发生的事实。看的是取证记录是否完整：

| 记录项 | 本次做法 | 为什么必须 |
|---|---|---|
| 变动前哈希 | ✅ 记录 | 基线 |
| 变动后哈希 | ✅ 记录 | 证明变动 |
| 变动的时间范围 | ✅ 记录 | 界定影响面 |
| 变动的内容分析 | ✅ `page_count`/`freelist_count` | 量化损失 |
| 恢复动作 | ✅ 记录 | 说明补救 |
| **向委托方报告** | ✅ 写入事故记录 | **否则构成证据隐匿** |

按错误判据走，委托方会收到一份建立在"数据完整"前提上的报告，而这个前提已经不成立。若复核时发现检材被改动、分析方没说，毁掉的不只是这份报告，是整次委托的公信力。

**其三，把隔离机上的改动当作"不影响本案"。**

本案能判定"扣押检材未受影响"，靠的是一个必须显式验证的前提：隔离机上的数据是扣押检材的独立副本。三个条件同时成立才算数。

1. 隔离机上的 `app.db` 来自扣押检材的提取，且提取件本身未被触碰（哈希可比对）
2. 隔离机是独立设备，不是扣押设备本身
3. 分析工作全部在隔离机上进行

缺一个，"不影响本案"就不成立。本案报告把它写成独立的"影响评估"段落而不是一句附注，因为它是整段事故陈述能被接受的前提。

**第四个实操细节**：`frida -f` 的 spawn 模式和应用手动启动，都可能触发应用的初始化逻辑，里面就包括自动清理过期数据。本次是手动点击"清理缓存"，但有些应用启动时就会自己清一遍。看启动后的数据库 mtime 变化：

```bash
$ adb shell su -c "stat -c %y /data/data/$PKG/databases/app.db"
# 启动应用前
2026-03-15 10:20:14
$ adb shell am start -n com.digiforensics.sample/.MainActivity
$ sleep 5
$ adb shell su -c "stat -c %y /data/data/$PKG/databases/app.db"
# 启动应用后
2026-03-15 10:24:17    ← 变了
```

这个检查该在每次动态分析开始前做。成本 10 秒，能省掉一整类麻烦。

<a id="section-31"></a>

## 六、扩展阅读方向

动态分析只告诉你"程序在运行时说了什么"。要变成可交付的结论，中间还缺三段：它留下了什么痕迹、密钥拿到之后怎么处理、结论能写多强。下面几组文章分别接这三段。

**环境痕迹：本篇操作自己造成的改变**

- [进程与注入检测](../../memory/memory-analyze/memory-analyze-process-and-injection-detection.md) —— **反向使用本篇的技能**。内存镜像里的 `malfind` 异常、可疑可执行内存段、反射加载痕迹，就是 Hook 留下的东西；在别人的设备上识别同类痕迹，方法完全一样。
- [注入执行与免杀痕迹](../../memory/memory-analyze/memory-analyze-memory-injection-and-evasion.md) —— 注入痕迹的变体与误报来源。知道哪些是正常框架行为，能避免把系统组件判成恶意。
- [Linux 与 Android 内存取证](../../memory/memory-artifact/memory-artifact-linux-android.md) —— 若改走内存路线，Android 侧的采集与进程解析方式完全不同。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 检材状态变更的记录要求。本篇第 5 步的"现场清理"到底该做什么、记录到什么粒度，原则在这。

**密钥之后：拿到不等于能用**

- [数据库与配置文件加密](../../crypto/crypto-app/crypto-app-database-configuration-decryption.md) —— 识别出 `sqlite3_key` 之后，如何判断这个库到底是 SQLCipher、文件系统加密还是自定义方案。**"能列出表名"只证明本次密钥有效，不证明加密类型**，这个区分在这篇。
- [浏览器密码库与 Token 解密](../../crypto/crypto-app/crypto-app-browser-passwords-and-tokens.md) —— 会话令牌类材料的离线分析框架，以及脱敏要求。
- [SQLite 基础与结构](../mobile-database/mobile-database-sqlite.md) —— 解密之后才是正常的数据分析。如果解密失败，先回来核对是不是文件头被改写、是不是只解了主库没解 `-wal`。
- [SQLite WAL 取证](../mobile-database/mobile-database-sqlite-wal.md) —— 加密库的 WAL 处理与普通库不同，这条路径上很容易踩空。

**同一问题的其他平台解法**

- [iOS 系统痕迹与 DFU 恢复](../mobile-ios/mobile-ios-dfu.md) —— iOS 侧的对应议题。注入机制依赖越狱与开发者镜像，工具链独立，但"运行时才可见的信息"这个问题完全相同。
- [内存中的凭据与密钥](../../memory/memory-artifact/memory-artifact-memory-credentials-and-keys.md) —— 不注入、直接从内存里找。**当设备不允许加载工具时，这是替代路径。**

**判据与反例：这些结论不能照搬**

- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— 设备侧时间被改、文件时间戳批量归一、`debuggable` 标志被篡改的识别。本篇的操作会让时间线出现非业务变化，报告里必须把它与反取证痕迹分开叙述。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md) —— 动态分析在委托范围上的授权要求，以及"分析副本"与"原始检材"的界限。
- [取证概念与分类](../../fundamentals/fundamentals-concepts/fundamentals-concepts-digital-forensics-concepts.md) —— 派生产物（脚本、日志、解密副本）在证据体系里是什么位置。
<a id="section-32"></a>

## 七、命令速查

```bash
# ===== 环境（两端版本必须严格一致）=====
python3 -m pip install frida-tools && frida --version
adb push frida-server-<版本>-android-arm64 /data/local/tmp/frida-server
sha256sum frida-server-<版本>-android-arm64       # 记录工具哈希
adb shell su -c "chmod 755 /data/local/tmp/frida-server"
adb shell su -c "/data/local/tmp/frida-server -D &" ; adb forward tcp:27042 tcp:27042
frida-ps -U -ai | grep -i sample                   # 通道建立 ✓

# ===== 附加方式 =====
frida -U -n "样本应用" -q -e 'console.log(Process.id);'      # attach：不重启、状态保持
frida -U -f com.digiforensics.sample -q -e 'console.log(Process.enumerateModules().length);'
frida-kill -U                                       # 作业结束立即关闭
# 新版 -f 自动 resume；旧版需 %resume，--no-pause 已废弃

# ===== 快速定位（生成调用日志，落在 ./__handlers__/）=====
frida-trace -U -f com.digiforensics.sample -p "*sqlite3*" -i
frida-trace -U -f com.digiforensics.sample -j "*openOrCreateDatabase*"
frida-trace -U -f com.digiforensics.sample -i "*!open*"

# ===== 脚本化 Hook =====
frida -U -f com.digiforensics.sample -l hook-db.js
#   Java.perform(function(){...})         在 Java 线程执行
#   Java.use("类名")                       取类包装
#   .overload("参数类型", ...)             ★ 必须指定，否则重载报错
#   .implementation = function(a,b){ ...; return this.m(a,b); }   ★ 必须回调原实现
#   Module.findExportByName(null, "sqlite3_key") / Interceptor.attach(addr, {onEnter,onLeave})

# ===== 验证（不可省略，永远在副本上）=====
cp app.db app-copy.db && sha256sum app.db app-copy.db
sqlite3 app-copy.db "PRAGMA key='<取得的key>';" ; sqlite3 app-copy.db ".tables"
sqlite3 app-copy.db "PRAGMA integrity_check;"   # ok = 结构完好

# ===== 检材完整性复核（设备上未必自带 md5sum，缺失时先 tar 回本地再算）=====
frida-kill -U
adb shell su -c "md5sum /data/data/com.digiforensics.sample/databases/app.db"
# 备选: adb shell su -c "tar -cf - -C /data/data/$PKG/databases app.db" | tar -xO > app.db && md5sum app.db
# 记录：分析时间 / 工具版本与哈希 / 分析对象哈希 / 注入脚本 / 应用是否重启 / 取得结果
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 移动与数据库取证 — Frida 动态 Hook」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《Frida 动态 Hook》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.vc` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
