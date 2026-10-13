---
title: "APK 逆向与 Manifest 分析"
slug: "mobile-android-apk-manifest"
canonical: "https://www.digiforensics.cn/wiki/mobile-android-apk-manifest"
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

# APK 逆向与 Manifest 分析

<a id="section-1"></a>

## 一、概述

APK 是移动取证里**第一份也是最容易被跳过的证据**。

很多分析者拿到手机就直接翻 `/data/data/`，略过了两个更基础的问题：**这个应用到底是什么？**（包名、版本、签名证书、下载来源）**它在设备上能做什么？**（申请了哪些权限、哪些组件被导出、是否允许明文通信）

两个问题的答案都在 `AndroidManifest.xml` 里。而且不需要解密、不需要 root、不需要任何反编译工具 —— `aapt dump badging` 一条命令就能读出最关键的一批字段。

**跳过这一步会发生什么**：后面所有分析都建立在「这是一个赌博类 App」「这是一次正常的社交应用使用」这类未经核实的判断上。

包名对不上、版本比设备上装的旧、签名与官方不一致 —— **这三个事实任意一个成立，都可能改变定性方向**，而它们只在 APK 里写着。

加固与否还决定成本结构：判断不出加固，就无法决定接下来是静态读代码还是必须上动态。

**它在取证流程里的位置**：同时服务**采集**与**分析**两环，且**在分析环的最前面**。

采集环的用法是：APK 从设备侧取出后先做基本属性提取。这条路对未 root 设备同样成立（`pm path` 无需权限），因此它常常是唯一能在无 root 情况下取得的能力画像来源。

分析环的用法是：根据 Manifest 声明反推该看私有目录里的哪些文件（见 [应用私有数据](mobile-android-sharedpreferences.md)），以及根据加固判定决定是否进入 [Frida 动态 Hook](mobile-android-frida-dynamic-hooking.md)。

上游依赖 APK 的获取与固定（见 [第 1 步](#section-8)）。下游支撑三件事：**身份认定**（签名是密钥层面的唯一权威来源）、**能力画像**（权限组合与导出组件）、**证据解释**（为什么这个库打不开）。

**涉及的证据形态**（具体到文件名与结构）：

| 形态 | 具体位置 | 结构特征 |
|---|---|---|
| 包声明 | `AndroidManifest.xml` | **二进制 AXML**（字符串池 + 资源 ID），不能直接文本打开 |
| 业务代码 | `classes.dex` / `classes2.dex`… | Dalvik 字节码，多 dex 是现代应用的常态 |
| 签名 | `META-INF/MANIFEST.MF`、`*.SF`、`*.RSA` | v1 方案；v2/v3/v4 签名**不在 `META-INF` 里**，须用 `apksigner` 验证 |
| native 库 | `lib/{arm64-v8a,armeabi-v7a,x86}/` | **加固识别的主要依据**，库名与体积是信号 |
| 原始资源 | `assets/`、`resources.arsc` | 硬编码 API 地址、密钥、渠道号的常驻位置 |
| 安装台账 | `/data/system/packages.xml` 的包条目 | 与 APK 的 `package` 字段交叉验证对应关系 |
| 证书身份 | 签名证书的 SHA-256 指纹 | 同签名多包名 = 同一开发者或同一批打包工具 |

这是哪个应用、什么版本、由谁签名、从哪装的、申请了哪些权限、哪些组件可被外部调用、是否加固。**回答这些不需要解密任何数据。**

应用运行时拿到了什么数据（权限声明 ≠ 实际调用）；数据库里存了什么（加固与密钥在 `lib/` 里）；签名一致就代表同一开发者（证书可能是共享的）；`allowBackup=true` 在 Android 12 之后意味着能用 `adb backup`（该路径已废弃，覆盖面不可控，见 [Android 数据存储总览](mobile-android-android-data-storage-overview.md)）。

**本文不做的事**：不在检材上执行 APK、不做脱壳、不构造任何针对商业应用保护机制的绕过手段。

加固识别的结论到此为止：**判定「有壳」，然后说明下一步需要什么条件。**

**反取证视角下同样重要** —— 本篇的字段集也是识别「APK 被重打包替换」的判据清单，见 [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md)。

**读者前提**：ZIP 结构、XML 基础，以及对 Android 组件模型（Activity / Service / BroadcastReceiver / ContentProvider）有基本认识。命令行工具只需要 `aapt`（或 `aapt2`）与 `apktool`。

**开始之前有一件事必须先确认**：APK 是从检材上原样取下来的吗？

按 [第 1 步](#section-8) 固定哈希之后再看后面的内容。本篇所有结论都建立在「这份 APK 就是设备上那个」这个前提上，前提不成立时，权限画像与加固判定都会指向错误的对象。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 APK 的内部结构

APK 本质是一个 ZIP 包，但内部有一份编译后的二进制 XML（AXML）：

```
app.apk (ZIP)
├── AndroidManifest.xml    ← ★ 编译后的二进制 XML，需 aapt/aapt2 解析
├── classes.dex            ← ★ Dalvik 字节码（主代码）；classes2.dex… 为多 dex
├── lib/{arm64-v8a,armeabi-v7a,x86_64}/  ← native 库，按 ABI 分目录
├── assets/                ← 原始资源（不编译），可能含配置、密钥、字体
├── res/                   ← 编译后的资源（layout、drawable、values）
├── resources.arsc         ← 资源表（字符串、样式、ID 映射）
└── META-INF/              ← ★ 签名：MANIFEST.MF（全文件 SHA-1 清单）、*.SF、*.RSA/*.DSA/*.EC
```

| 组成 | 取证价值 | 关键点 |
|---|---|---|
| `AndroidManifest.xml` | ★★★★★ | **所有权限与组件的源头** |
| `META-INF/` | ★★★★★ | **签名证书是密钥层面身份的唯一权威来源** |
| `classes*.dex` | ★★★★ | 业务逻辑，jadx 反编译 |
| `lib/*.so` | ★★★ | **加固识别的主要依据** |
| `assets/` | ★★★ | 常含硬编码配置、密钥、渠道号 |
| `resources.arsc` / `res/` | ★★ | 硬编码字符串常在前者 |

> **一个实用的取证结论**：`resources.arsc` 与 `assets/` 中的**硬编码字符串**（API 地址、密钥、渠道号）常常是低成本线索——`strings` 扫一遍就能找到明文密钥或后台地址。

<a id="section-4"></a>

### 2.2 Manifest 的关键字段

`AndroidManifest.xml` 是 XML，但存的是**二进制 AXML 格式**（字符串池 + 资源 ID），不能直接用文本编辑器打开。

| 字段 | 取证意义 | 高价值判定 |
|---|---|---|
| `package` | 应用唯一标识 | 与 `packages.xml` 交叉验证包的对应关系 |
| `versionCode` / `versionName` | 版本 | 版本差异可能对应不同功能或漏洞修复 |
| `android:debuggable` | 是否调试包 | `true` = 测试包，正式发布应用应为 false |
| `android:allowBackup` | 是否允许备份 | `true` = 数据可被 `adb backup` 提取（Android 12 前） |
| `android:usesCleartextTraffic` | 允许明文 HTTP | **`true` = 存在流量被窃听风险** |
| `android:networkSecurityConfig` | 自定义网络安全配置 | **指向 XML 资源文件，指定是否信任用户 CA** |
| `android:usesPermission` / `exported` | 申请的权限 / 组件可被外部调用 | 见下方风险分级；`exported=true` 的组件可能被恶意 App 调用 |
| `android:sharedUserId` | 共享 UID | **多个应用共用 UID = 可互相读数据** |
| `requestLegacyExternalStorage` / `appComponentFactory` | 绕过分区存储 / 组件工厂 | 前者 Android 10 常用，后者**自定义即暗示加固或热修复框架** |

**`debuggable=true` 的取证意义**：正式上架的应用若为 `debuggable=true`，说明它是以**未剥离的调试配置发布的**。

这可以支持「该应用未按正式发布流程打包」的判断，在同一批 APK 中出现时可作为同源线索。仍需与签名、渠道号、安装来源交叉，仍是线索而非单独定案依据。

**`allowBackup=true` 的取证意义**：Android 12 之前 `adb backup` 可据此提取应用数据。虽已废弃，但**它是判断「该应用数据可被其他手段绕过提取」的指标**。

很多金融类应用会显式设为 `false`。反过来说，`true` 意味着开发者未做这层保护。

<a id="section-5"></a>

### 2.3 权限风险分级

| 等级 | 权限 | 取证价值 |
|---|---|---|
| **极高** | `READ_SMS`、`RECEIVE_SMS`、`SEND_SMS`、`READ_CALL_LOG`、`WRITE_CALL_LOG` | 短信与通话是核心证据来源，**能读就能伪造** |
| **高** | `ACCESS_FINE_LOCATION`、`ACCESS_COARSE_LOCATION`、`CAMERA`、`RECORD_AUDIO`、`READ_CONTACTS`、`READ_PHONE_STATE` | 位置、影像、录音、通讯录 |
| **中** | `READ_EXTERNAL_STORAGE`、`WRITE_EXTERNAL_STORAGE`、`READ_MEDIA_IMAGES`、`READ_PHONE_NUMBERS`、`GET_ACCOUNTS`、`READ_CALENDAR` | 媒体文档与身份关联 |
| **低** | `INTERNET`、`ACCESS_NETWORK_STATE`、`ACCESS_WIFI_STATE`、`VIBRATE`、`WAKE_LOCK` | 网络与硬件，几乎所有应用都有 |

**实战的读法**：不是「权限越多越可疑」，而是**看权限组合**。

例如一个短视频应用同时持有 `CAMERA` + `RECORD_AUDIO` + `READ_CONTACTS` + `ACCESS_FINE_LOCATION`，且全部在 `targetSdkVersion` 允许的范围内被授予 —— 这本身就是一个值得追问的事实。

> ⚠️ `targetSdkVersion` 决定了权限的实际约束强度。 Android 运行时权限模型（用户可手动关闭）对 `targetSdkVersion ≥ 23` 的应用生效；老应用则安装即全给。取证时需结合 `dumpsys package` 的实际授予状态，而不是只看 Manifest 声明。

<a id="section-6"></a>

### 2.4 加固识别

加固的核心思路是**把真正的 `Application` 类替换掉**，在启动最早阶段解密 DEX 内存，因此 `jadx` 看到的只是壳代码。

识别通常看六类信号：

- **so 库名**：`libjiagu*.so`、`libshell*.so`、`libDexHelper.so`、`libprotect*.so`
- **`Application` 类名**：指向 `StubApplication`、`ShellApplication` 等第三方壳包，且与包名无关
- **DEX 数量**：只有一个很小的 `classes.dex`，真实代码在 assets 的加密文件里
- **assets 加密文件**：`assets/jiagu_*.dat`、`assets/*.bin`，体积与业务量成正比
- 自定义 `appComponentFactory` 或非常规 multidex 实现
- **冷启动明显变慢**（加密解密开销）

`jadx` 结果中主类几乎无业务方法、只有大量 `native` 声明，是综合佐证。

前四项属强信号，单独出现即应列为「疑似加固」，不能仅凭启动耗时下结论。

```bash
unzip -l app.apk | grep '\.so$'      # 41 1234567 lib/arm64-v8a/libjiagu_v1.so  ← 壳
#                                    # 88  234567 lib/arm64-v8a/libappcore.so   ← 业务
unzip -p app.apk assets/ 2>/dev/null | head
```

**取证意义**：加固不是「无法取证」，而是**改变了成本结构**。

静态只能确认「这是哪个应用、声明了什么权限」。要拿到运行时数据（尤其是数据库密钥），就必须走 [04 Frida](mobile-android-frida-dynamic-hooking.md) 的动态路径。

**报告里应写明这一点，让委托方知道结论的边界。**

---

<a id="section-7"></a>

## 三、操作步骤

<a id="section-8"></a>

### 第 1 步：获取并固定 APK

```bash
PKG=com.digiforensics.sample
adb shell pm path $PKG     # package:/data/app/~~Hk2==/com.digiforensics.sample-1a2b3c==/base.apk
adb pull /data/app/~~Hk2==/com.digiforensics.sample-1a2b3c==/base.apk ./base.apk
sha256sum base.apk | tee base.apk.sha256 ; unzip -t base.apk | tail -2    # 期望 No errors detected

# 整个 /data/app/<目录> 取走（split apk 才可能有多个 dex）
APPDIR=$(basename $(dirname $(adb shell pm path $PKG | sed 's/package://' | tr -d '\r')))
adb shell su -c "tar -cf - -C /data/app $APPDIR" > appdir.tar && tar -xvf appdir.tar
```

<a id="section-9"></a>

### 第 2 步：读基本属性（aapt）

```bash
# 环境：Android SDK build-tools（Ubuntu: sudo apt install aapt，或从 Android Studio 的 build-tools 取 aapt2）
aapt dump badging base.apk
# package: name='com.digiforensics.sample' versionCode='148' versionName='12.3.1'
# sdkVersion:'26'                       ← minSdkVersion
# targetSdkVersion:'33'                 ← targetSdkVersion
# application-label:'样本应用'
# uses-permission: name='android.permission.READ_SMS' / ACCESS_FINE_LOCATION / CAMERA / RECORD_AUDIO
# application-debuggable                 ← 出现即 debuggable=true
# launchable-activity: name='com.digiforensics.sample.MainActivity'
```

```bash
# 单独看权限（更干净）/ 完整 XML 树（所有组件与属性）
aapt dump permissions base.apk ; aapt dump xmltree base.apk AndroidManifest.xml
# E: manifest (line=2)
#   A: android:versionCode(0x0101021b)=(type 0x10)0x94      ← 148
#   A: android:debuggable(0x0101000f)=(type 0x12)0xffffffff ← true 的特殊编码
#   E: application ... E: activity (line=42)  A: android:name(0x01010003)="...MainActivity"
#       A: android:exported(0x01010010)=(type 0x12)0xffffffff
```

> **读 AXML 输出的技巧**：`android:debuggable` 与 `exported` 为 `true` 时，aapt 显示为 `0xffffffff` 而不是 `0x1`，因为它把类型编码在高 8 位。看到 `0xffffffff` 就要想到「布尔真」。

<a id="section-10"></a>

### 第 3 步：apktool 重建资源

```bash
apktool d -f -o app-decoded base.apk ; apktool b app-decoded -o app-rebuilt.apk
# 网络安全配置是最高频的取证命中点
cat app-decoded/res/xml/network_security_config.xml
# <base-config cleartextTrafficPermitted="true">   <trust-anchors>
#     <certificates src="system"/>  <certificates src="user"/>   ← ★ 信任用户 CA，可被中间人代理
#   </trust-anchors> </base-config>
```

**apktool 的取证用途**：把二进制 AXML 转成**可读文本**（能精确 `grep`）；读上述 `network_security_config.xml` 判断**是否信任用户 CA**；读 `res/values/strings.xml` 与 `res/values-zh-rCN/` 核对多语言资源；用 **Smali 精确到字节码行**确认调用点；资源哈希可用于判断**是否为重打包**。

<a id="section-11"></a>

### 第 4 步：jadx 反编译 Java

```bash
# 环境：sudo apt install jadx（或用 jadx-gui）
jadx -d app-jadx base.apk --no-res ; ls app-jadx/sources/com/digiforensics/sample/
grep -rn "SQLiteDatabase\|openOrCreateDatabase" app-jadx/sources/ | head   # 库名与是否加密
grep -rn "SecretKeySpec\|Cipher.getInstance"  app-jadx/sources/ | head   # 密钥从哪来
grep -rn "getDeviceId\|ANDROID_ID\|Build.SERIAL" app-jadx/sources/ | head   # 设备信息是否派生 key
```

**三类必查的调用**（它们决定数据能不能拿到）：

`openOrCreateDatabase` / `SQLiteOpenHelper` 决定库文件名与是否加密。

`Cipher.getInstance` / `SecretKeySpec` **决定密钥在哪算出来**。

`getDeviceId` / `ANDROID_ID` / `Build.SERIAL` 说明设备标识参与运算，**这类 key 常由设备信息派生**。

> **关键认识**：如果 jadx 里搜不到 `Cipher`、只看到一个自定义 `Application` 类和一个壳 so，则应优先按加固处理。此时不要在静态上继续投入时间，转 [04](mobile-android-frida-dynamic-hooking.md) 验证。

<a id="section-12"></a>

### 第 5 步：签名验证与身份认定

```bash
# 环境：Android SDK build-tools 的 apksigner
apksigner verify --verbose --print-certs base.apk
# Verified using v1 scheme (JAR signing): true      ← 支持旧签名
# Verified using v2 scheme (APK Signature Scheme v2): true
# Verified using v3 scheme (APK Signature Scheme v3): true    Number of signers: 1
# Signer #1 certificate DN: CN=Sample Dev, O=DigiForensics, C=CN
# Signer #1 certificate SHA-256 digest: 3f9a...（密钥层面身份的权威标识）
# 提取证书（keytool 或 openssl）
unzip -o base.apk META-INF/*.RSA ; keytool -printcert -file META-INF/CERT.RSA
openssl pkcs7 -inform DER -in META-INF/CERT.RSA -print_certs -noout
```

> **签名的取证价值极高**：签名证书的 SHA-256 是唯一能证明「两个 APK 使用同一签名证书与同一私钥」的指标。

但它证明的是**密钥层面的同一性**，**不能直接认定现实中的开发者身份或所用打包工具**。证书可能由他人代管、可能复制自公开模板、也可能被冒用。

涉赌涉诈案件中，常见做法是一个签名下出现多个包名变体（正规壳 + 赌博包）。**把同签名的所有 APK 归为一组，是常见切入点。**

结论应表述为「同签名主体、同一次批量打包行为」，并结合 DN、有效期、包名与安装来源交叉印证。

**v1/v2/v3 签名的取舍意义**：只勾选 v1 的应用兼容性最好（可被 zip 篡改）但可被重签名；开启 v2/v3 后可防篡改。

若一份「官方」应用只用了 v1 签名，是一个值得注意的配置线索 —— 但它只是线索，单独不能证明侧载。 很多内部打包、老旧工具链或第三方应用市场分发的包也只签 v1。

<a id="section-13"></a>

### 第 6 步：加固识别汇总

```bash
# ① so 库 / ② assets 加密文件（体积大的 bin、dat）
unzip -l base.apk | grep -E '\.so$' | awk '{print $NF}'
unzip -l base.apk | awk '$1 > 100000 {print $1, $NF}' | sort -rn | head
# ③ Application 类 / ④ dex 数量与体积
aapt dump xmltree base.apk AndroidManifest.xml | grep -A3 'E: application' | head -8
unzip -l base.apk | grep 'classes.*\.dex'
# ⑤ strings 扫敏感内容（assets + arsc）
mkdir -p unz && cd unz && unzip -q ../base.apk
strings -n 6 resources.arsc assets/* 2>/dev/null | \
  grep -iE 'http://|https://|api|key|secret|aes|password' | sort -u | head -40
```

**加固判定的证据链写法**（报告中应这样表述）：

> 该 APK 经 `apktool` 解包后，assets 目录含 `jiagu_config.dat`（84,112 字节）；`lib/arm64-v8a/` 下含 `libjiagu.so`（312 KB）；`AndroidManifest.xml` 中 `android:name` 指向 `com.digiforensics.shell.StubApplication`，而 `classes.dex` 仅 92 KB 且无业务类名。**上述四项特征共同表明该应用已加固**；静态分析无法获取其数据库密钥初始化逻辑，故转入动态分析。

<a id="section-14"></a>

### 第 7 步：验证

```bash
unzip -t base.apk | tail -2                                 # ① APK 完整性
apksigner verify --verbose base.apk && echo "签名校验通过"   # ② 验证通过才说明未被篡改
adb shell dumpsys package com.digiforensics.sample | grep -E 'versionName|versionCode|firstInstallTime'  # ③ 设备侧交叉验证
aapt dump badging base.apk | grep -E 'versionName|versionCode'
```

---
<a id="section-15"></a>

## 四、常见陷阱

APK 分析的门槛相对较低，这一章的陷阱主要不是技术难题，而是**「看到什么就信什么」的认知捷径**：看到乱码就放弃、看到一行输出就定论、看到同名就认为同源、看到加固就停手。

<a id="section-16"></a>

### 4.1 AXML 与基础属性

<a id="section-17"></a>

#### 陷阱 1：文本编辑器打开 `AndroidManifest.xml` 看到乱码，判定「已损坏或加密」

**现象**：把 APK 解压出来，用编辑器打开 `AndroidManifest.xml`，满屏乱码或空文件，于是记录「Manifest 无法读取，需向委托方索取明文版本」。

**原因**：`AndroidManifest.xml` 在 APK 里**不是文本，是编译后的二进制 AXML**（字符串池 + 资源 ID 池 + 二进制节点树）。这是 Android 打包工具的既定行为，目的是加速运行时解析。**它完好无损，格式就是这样的**。而 `unzip -l` 看到它有大小的、APK 完整性校验也是通过的——这两个事实本身就排除了「文件损坏」的可能。**把格式问题误读成文件问题，是这条陷阱的全部机制。**

**影响**：**代价不只是这一个文件读不了。**

「Manifest 无法读取」会连带影响后面所有依赖它的判断：加固识别（需要看 `android:name` 指向的 Application 类）、组件暴露面（需要看所有 Activity/Service/Receiver 的 `exported`）、网络安全配置（需要定位 `networkSecurityConfig` 引用的资源文件）。

而委托方看到的解释是「文件损坏」，这在技术上是站不住的。

**核查**：**读 AXML 只有工具路径，没有手工路径**。这几条命令各管一段，互为补充：

```bash
# ① 基本属性：一行一条，最快
aapt dump badging base.apk

# ② 权限：独立输出，不受 badging 的输出组织影响
aapt dump permissions base.apk

# ③ 完整 XML 树：所有组件、嵌套关系、全部属性
aapt dump xmltree base.apk AndroidManifest.xml

# ④ 需要可读文本、可 grep、可编辑时：apktool 解码
apktool d -f -o app-decoded base.apk
grep -n 'android:exported\|android:name' app-decoded/AndroidManifest.xml
```

**`aapt` 与 `apktool` 不是二选一**：`aapt` 快，适合逐字段查询；`apktool` 慢，但产出可 grep 的文本。做权限组合分析、组件枚举这类需要多次检索的工作时，它是唯一可用的形态。

两者在关键字段上应当互相印证（见陷阱 2）。

<a id="section-18"></a>

#### 陷阱 2：只看 `aapt dump badging` 的一屏输出就定权限结论

**现象**：`aapt dump badging` 跑完，把输出里出现的权限列表抄进报告，写「该应用申请以下权限，其中包含短信读取」。而实际上完整清点后发现还有 5 个权限没被显示。

**原因**：`badging` 的输出是按类别组织的，包含 `uses-permission` / `uses-feature` / `uses-library` / `uses-implied-permission` 等多个标签，而终端一屏、管道 `head`、日志截断都可能让后半部分根本没被看到。**更隐蔽的是「未显示」与「不存在」在视觉上完全一样**——输出里没有这一行，人就倾向于认为「它没有申请这个权限」。而实际上 `badging` 也不会把 `tools:` 命名空间下的声明、`maxSdkVersion` 限定的权限、以及从依赖库合并进来的权限全部列在 `uses-permission` 标签下。抄一遍屏幕就下结论，本质上是在对一份不完整的清单做完整性判断。

**影响**：「该应用不具备 X 能力」是一个能力认定，其错误会导致定性错误。

漏掉 `READ_SMS`，「应用无法自行读取短信」这个结论会反过来成为被告的抗辩点。漏掉 `RECORD_AUDIO`，「应用无法自行录音」这个前提会被推翻。

**这类错误的严重性在于它是双向的**：不仅报告的结论错，后续所有基于「该应用做不了 X」的推理全部连带失效。

**核查**：**三源交叉清点，各自的盲区不同，必须合并**：

```bash
# ① badging：看整体面貌（可能被输出长度截断）
aapt dump badging base.apk | grep -c 'uses-permission'

# ② permissions：专门看权限，独立完整
aapt dump permissions base.apk | tee perms.txt ; wc -l perms.txt

# ③ xmltree：唯一能看到 tools: 与 maxSdkVersion 限定的形态
aapt dump xmltree base.apk AndroidManifest.xml | grep -B1 -A2 'E: uses-permission' | tee perms-xml.txt

# ④ 设备侧实际授予状态 —— 声明 ≠ 持有
adb shell dumpsys package com.digiforensics.sample | grep -A40 'requested permissions' 
adb shell dumpsys package com.digiforensics.sample | grep -E 'READ_SMS|RECORD_AUDIO|granted='
```

三份清单取并集后再做风险分级，并在报告里写清「共 N 项，来源为 badging + permissions + xmltree 三处合并」。 数量对不上时说明漏了一处——**这个「对不上」本身就是必须先解决的问题**，不能带着它往下走。

<a id="section-19"></a>

#### 陷阱 3：把 AXML 里的 `0xffffffff` 当成「极大值」

**现象**：读 `xmltree` 输出，看到 `android:debuggable(0x0101000f)=(type 0x12)0xffffffff`，报告里写「`debuggable` 被设置为 4294967295，是非法的极大值，应用存在配置异常」。

**原因**：AXML 对布尔属性的编码是**把类型标记放进高 8 位、把布尔值放进低 8 位**。`type 0x12` 是 TYPE_INT_BOOLEAN，所以 `0xffffffff` 读作「类型是布尔、内容是全 1」，**它的语义就是 `true`**。这不是数值 4294967295，而是「布尔真」的一种编码形式。`android:exported` 用的是同一套编码，所以 `exported=(type 0x12)0xffffffff` 等价于 `exported=true`。反过来 `0x0` 才是 `false`。初学者看到一大串 F 时的直觉是「这值有问题」，而真实含义恰恰是最正常不过的 `true`。

**影响**：**它会导致完全反向的结论。**

把 `exported=true` 读成「值非法」，会丢掉「存在导出组件」这一发现 —— 而导出组件是恶意应用可被利用的入口，也是判断该应用是否可被外部调用的直接依据。

同理，把 `debuggable` 判为「配置异常」而不是「调试包」，会丢掉「该应用非正规渠道发布」这条线索的全部价值。

**核查**：**建立 AXML 类型编码的固定读法**：

```bash
# 读法：先看 type 字段，再看值
# (type 0x12) + 0xffffffff → 布尔 true
# (type 0x12) + 0x0        → 布尔 false
# (type 0x10) + 0x94       → 整型 0x94 = 148（versionCode）
# (type 0x03) + "string"   → 字符串

# 快捷路径：这类布尔属性直接看 badging 的具名结论，不要读 xmltree 的原始值
aapt dump badging base.apk | grep debuggable     # 出现即 true，badging 已做正确转换
aapt dump xmltree base.apk AndroidManifest.xml \
  | grep -E 'exported|debuggable' | sed 's/0xffffffff/\bTRUE_TRUE_TRUE/'   # 只为阅读方便
```

只有需要确认「未声明」还是「声明为 false」时才必须读 `xmltree` 原始值。 其余情况用 `badging` 的具名输出——它已经把类型编码转换好了，**去读原始编码值是自己给自己增加误判面**。

<a id="section-20"></a>

### 4.2 身份认定与包完整性

<a id="section-21"></a>

#### 陷阱 4：把签名证书哈希一致读成「同一开发者」

**现象**：三个 APK 的 `apksigner verify --print-certs` 输出的 DN 与 SHA-256 完全一致，报告结论写「三个应用由同一开发者开发」。

**原因**：签名证书证明的是密钥层面的同一性，不是现实主体的同一性。 二者之间隔着一整条现实链条：证书可以由第三方代为申请与保管（常见的开发外包）、可以从公开模板复制（很多个人开发者用同一份生成器）、私钥也可能因泄露或被恶意获取而出现在别人手里。证书哈希相同只能推出「这三个包是用同一个私钥签出来的」——再往后一步就是推测了。而与之相对的是另一侧的脆弱性：用户可见的应用名（`app_name`）、版本号、图标、甚至 `versionCode`，全部可以被任意改写，与证书没有绑定关系，用它们判断身份是拿最不可靠的字段当最可靠的依据。

**影响**：这是「结论超出证据能支撑范围」的典型形态，且在涉赌涉诈案件里代价极高。

「同一开发者」会直接导向对某个具体人的追查，牵涉到传唤、冻结、乃至刑事认定。

一旦密钥泄露或代管的情形出现，**整个追查方向指向错误的人**。

反过来，如果真正的批量打包者用的正是别人代管的证书，那么**追查会停在错误的一环上，而真正的行为人尚未浮出**。

这类错误在复核阶段几乎无法补救。它不是数据错，是法律定性错。

**核查**：把结论严格限定在可观测的范围内，把主体身份识别作为独立待核事项列出：

```bash
# ① 唯一可靠指标：证书指纹
for a in com.digiforensics.*.apk; do
  apksigner verify --print-certs "$a" 2>/dev/null | grep 'SHA-256 digest' | awk -v f="$a" '{print f, $NF}'
done | sort -k2      # 指纹相同 → 同一签名主体

# ② DN / 有效期 / 序列号：这些是「自述信息」，不是「已验证信息」
apksigner verify --print-certs base.apk 2>/dev/null | grep -E 'DN:|valid from|serial'
# 注意：DN 是证书里的一个可被任意填写的内容，自签名证书尤其如此

# ③ 交叉印证的其他维度（这些都不指向"开发者身份"）
aapt dump badging base.apk | grep -E '^package|versionName'      # 包名与版本
adb shell dumpsys package $PKG | grep -E 'installerPackageName|firstInstallTime'  # 安装来源与时间
unzip -p base.apk assets/ | strings | grep -iE 'channel|appid'   # 渠道号（批量打包的强线索）
```

**报告表述模板**：「三个 APK 的签名证书 SHA-256 指纹一致（`3f9a7c2e…`），DN 同为 `CN=Sample Dev, O=DigiForensics, C=CN`。据此认定三者由同一签名主体签发，属同一次批量打包行为。 证书 DN 为自述内容，**本结论不指向签名密钥实际持有人的身份**；主体认定需通过应用商店开发者账号、域名注册、代码托管记录等外部信息另行核实。」

<a id="section-22"></a>

#### 陷阱 5：把「只启用 v1 签名」直接定性为侧载

**现象**：`apksigner verify --verbose` 显示 `v1: true / v2: false / v3: false`，报告直接写「该应用系侧载安装，理由：未启用 v2 签名」。

**原因**：这个推断在技术方向上是对的——v1（JAR 签名）只覆盖 `META-INF` 内的摘要清单，不保护签名文件本身，因此包体被改动后可以重新签名；v2/v3 方案则对整个 APK 做了覆盖，能防住这个操作。但「可被重签名」这个属性**不是侧载的充分条件**。老旧的打包工具链、企业的内部构建系统、某些第三方应用市场的分发流程、以及那些刻意追求最大兼容性的老应用，**都只签 v1 而完全没有侧载行为**。技术属性描述的是「这个包有多容易被改」，而侧载描述的是「这个包是怎么来的」——两者是不同层面的事实。

**影响**：**错误的定性会被当事人一票推翻。**

「侧载」是一个带主观指向的定性（绕过官方渠道）。一旦被推翻，「该应用来源不明」这个前提也跟着松动，**后续所有基于「非正规渠道」的推断都会连带失据**。

这是本主题里最容易被辩方抓住的一类表述。

**核查**：**弱签名方案只作为线索，必须与至少一条独立证据组合**：

```bash
# ① 签名方案（线索，本身不定性）
apksigner verify --verbose base.apk | grep 'Verified using'

# ② 安装来源（独立证据）—— 与包名台账交叉
adb shell dumpsys package $PKG | grep -E 'installerPackageName|installerPackageName'
# null → 无记录到安装来源，与侧载相符，但 APK 内的证据需另找

# ③ 包管理台账（独立证据）
adb pull /data/system/packages.xml extracted/
grep -o "package=\"$PKG\".\{0,200\}" extracted/packages.xml   # 看 installer 属性

# ④ 下载目录残留（独立证据：包在装之前先落地了）
ls -l /sdcard/Download/*.apk /sdcard/Download/*.apkg 2>/dev/null
```

**组合成文的写法**：「该 APK 仅启用 v1 签名方案（未启用 v2/v3），**表明其包体防护能力弱，属可被重签名的形态**。结合设备侧 `installerPackageName` 为 `null`（无安装来源记录）与 `/sdcard/Download/` 中早于安装时间存在的同名安装包，**两条独立证据共同支持「该应用经侧载安装」的判断**。」**单条线索不定性，两条独立来源才成立**——这个结构要让读报告的人看得见。

<a id="section-23"></a>

#### 陷阱 6：只分析 `base.apk`，漏掉 split APK 的其他分片

**现象**：`adb shell pm path` 返回一行，`adb pull` 只拉了那一个文件，`jadx` 反编译后发现主类里很多引用找不到对应定义。

**原因**：Android 从 5.0 起支持 **split APK** 机制——一个应用可以由多个 APK 组成：`base.apk` 承载代码与基础资源，其余分片承载按需下载的语言包（`split_config.zh.apk`）、密度资源（`split_config.xxhdpi.apk`）、以及**动态功能模块**。`pm path` 返回多行时，只有第一行通常是 base，其余分片在设备上以 `base.apk.split_*.apk` 或随机名存放于同一目录。**功能缺失的表现极具迷惑性**——代码引用了某个类，但那个类在这个分片里；反编译产物看起来「逻辑不完整」，分析人员容易把它归因为「代码混淆严重」或「写得很烂」，**而真实原因只是少拉了一个文件。**

**影响**：**这会污染对「这个应用如何工作」的判断。**

混淆与缺失在反编译产物上的表现相似：都表现为看不懂的短类名和跳转。基于一份不完整的分片集去评估「混淆强度」「逻辑复杂度」，得出的结论对完整包并不成立。

动态分析衔接环节的问题更大 —— Hook 脚本里对某个类的引用如果落在未拉取的分片里，运行时就会找不到目标，排查成本远高于重新拉一次。

**核查**：**先枚举分片数量与命名，再决定是否全取**：

```bash
PKG=com.digiforensics.sample
# ① 枚举全部分片（可能多行）
adb shell pm path $PKG | tr -d '\r' | tee apk-paths.txt
wc -l apk-paths.txt

# ② 整目录打包：一次拿走 base + 全部 split + 同目录下的其它分片
APPDIR=$(adb shell pm path $PKG | head -1 | sed 's/package://' | tr -d '\r' | xargs dirname | xargs basename)
adb shell su -c "tar -cf - -C /data/app $APPDIR" > appdir.tar
tar -tf appdir.tar | grep -E '\.apk$|\.dex$'

# ③ 只有 base 时，也要显式确认没有分片
ls -1 appdir/
# 若只有一个 base.apk，报告里写「该应用为单 APK，无 split 分片」
```

**每个分片都要单独哈希固定** —— 它们是独立的证据单元，且分片组合关系本身就是事实（「该应用在设备上由 N 个分片构成」）。

用 `jadx` 或 `apktool` 处理时，要把整个目录作为输入，而不是单个 `base.apk`。

<a id="section-24"></a>

### 4.3 加固识别与分析边界

<a id="section-25"></a>

#### 陷阱 7：加固应用硬做静态分析，把壳代码当成业务逻辑

**现象**：`jadx` 反编译完，搜了几遍 `Cipher`、`SecretKeySpec`、`openOrCreateDatabase` 都没找到，于是花几个小时反复换关键词、换工具，最后在报告里写「该应用代码高度混淆，未能定位数据库加密逻辑」。

**原因**：加固的核心思路是在启动最早阶段用一个壳 `Application` 替换掉真实的 `Application` 类，由壳在运行时解密真实的 DEX 并在内存中加载。于是静态看到的 `classes.dex` 里只有壳的引导代码——没有 `Cipher`、没有 `SQLiteOpenHelper`、只有大量 `native` 方法声明和一个指向 `StubApplication` 的 `android:name`。「搜不到关键调用」不是「混淆」造成的，而是「它们根本不在这个文件里」。 加固的强度与「混淆」无关，混淆只影响可读性，加固影响的是**可见性**。这两个概念被混为一谈，是这条陷阱的核心。

**影响**：浪费的时间只是表面成本，实质损失是「路径判断错误」。

报告写「未能定位加密逻辑」时，通常不会有人接着写「该应用可能已加固，建议改用动态手段」。于是这个技术判断就停在这里了，委托方拿着一个「拿不到数据」的结论，误以为取证到此为止。

而实际上的下一步是明确的：转到动态分析。

更隐蔽的问题是，如果分析者真的在壳代码里找到了某个 `Cipher` 调用（加固不彻底时会有），那很可能属于壳自身的解密逻辑，而非应用的数据库加密逻辑。按它去推导密钥逻辑，会得出一个看似有依据、实际完全错误的结论。

**核查**：加固识不要用四类强信号，命中即转动态，不再在静态投入：

```bash
# ① so 库名（强信号）
unzip -l base.apk | grep -E '\.so$' | awk '{print $NF}'
# libjiagu* / libshell* / libDexHelper / libprotect* / libxxxpacker

# ② assets 里的加密数据文件（强信号，且体积与业务量成正比）
unzip -l base.apk | awk '$1 > 100000 {print $1, $NF}' | sort -rn | head
# jiagu_config.dat / classes0.jar / *.bin

# ③ Application 类名指向壳包（强信号）
aapt dump xmltree base.apk AndroidManifest.xml | grep -A4 'E: application' | grep 'android:name'
# "com.digiforensics.shell.StubApplication" ← 与包名无对应关系即强信号

# ④ DEX 数量与体积比例（强信号）
unzip -l base.apk | grep 'classes.*\.dex'
# 只有一个几十 KB 的 classes.dex + assets 里有大体积加密文件 = 壳

# 兜底判据（不可单独使用）
# 冷启动明显变慢、jadx 主类只有 native 声明 —— 这些是佐证，不是结论
```

**判定标准要写成证据链，而不是单点结论**：

> 加固判定：该 APK 的 `AndroidManifest.xml` 中 `android:name` 指向 `com.digiforensics.shell.StubApplication`（与包名 `com.digiforensics.lottery` 无对应关系）；`lib/arm64-v8a/` 下含 `libjiagu.so`（312 KB）；`assets/` 含 `jiagu_config.dat`（82 KB）；`classes.dex` 仅 92 KB 且无业务类名。**上述四项强信号共同表明该应用已加固**。静态分析无法获取其数据库密钥初始化逻辑，故转入动态分析（见第 04 篇）。本条为基于静态特征的判定，最终确认以动态分析中观测到的内存 DEX 加载行为为准。

**注意最后那句限定。** 加固识别是「据静态特征判定」，不是「证明」。**报告里必须把两者的证据强度区分开** —— 这与陷阱 4 里「签名哈希 vs 开发者身份」是同一条原则。

<a id="section-26"></a>

#### 陷阱 8：把 jadx 反编译产物当作原始源码引用

**现象**：报告或分析笔记里直接写「根据该应用的源码，`encryptKey` 由 `getDeviceId()` 派生」，并附上 jadx 导出的代码片段作为技术依据。

**原因**：**jadx 输出的是反编译产物，不是源码。** 至少四层失真叠加在上面：**① 变量名与类名**——除非开发者显式保留了调试符号，否则 ProGuard/R8 处理后类名变成 `a`、`b`、`c`，方法名变成 `a()`、`b()`，jadx 只能按它自己的规则命名，**这些名字不携带任何原始语义**；**② 控制流重建**——编译器优化后的字节码被反推回结构化代码，异常处理、lambda、switch 的还原都可能有偏差；**③ 常量内联与字符串处理**——编译期确定的表达式可能已被折叠，运行时构造的字符串可能只剩拼接残留；**④ 资源 ID 被替换成整数**——`R.string.x` 变成 `0x7f0e0012`，需要回查 `resources.arsc` 才能还原。更关键的是，jadx 本身会「尽力修复」反编译失败的部分，它可能生成一段逻辑上说得通但与原字节码并不完全等价的代码。而这段代码在报告里被当作原始实现引用，就是把一个推导结果当成了事实。

**影响**：**这是举证能力上的缺陷。**

「该应用的密钥由设备标识派生」是一个需要被对方质疑的技术主张。如果依据是一段反编译产物，那么它无法支撑任何强度的结论 —— 对方的专家完全可以主张「这段代码与原实现不符，你的结论建立在错误的还原上」，而且这个反驳很难抵挡。

更实际的风险是，反编译产物往往读起来「很像对的」，越像越容易忘了他是推导的。

**核查**：区分「定位」与「举证」两个用途，报告里用准确的措辞：

```bash
# 定位用途（合规、可写进报告）：用于确定「往哪里找」
grep -rn "openOrCreateDatabase\|SQLiteOpenHelper" app-jadx/sources/ | head
grep -rn "SecretKeySpec\|Cipher.getInstance" app-jadx/sources/ | head
grep -rn "getDeviceId\|ANDROID_ID\|Build.SERIAL" app-jadx/sources/ | head

# 举证用途（需回到字节码层确认，不能只靠反编译产物）
# ① 回到 smali 精确到字节码指令，确认调用确实存在
grep -rn "Landroid/.*/TelephonyManager;->getDeviceId" app-decoded/smali/
# ② 确认调用点上下文：是在密钥派生链路上，还是在别处（比如埋点）
grep -rn -B8 -A4 "getDeviceId" app-decoded/smali/ | head -40
# ③ 与运行时行为交叉验证（见第 04 篇动态 Hook）
```

**报告措辞对照**：

| 不可接受 | 可接受 |
|---|---|
| 「根据源码，密钥由设备 ID 派生」 | 「在 `app-jadx/sources/` 中定位到 `Cipher.getInstance` 与 `TelephonyManager.getDeviceId` 的调用点（**反编译产物，未经字节码级确认**），二者位于同一类中。该关联为静态分析的线索，密钥派生关系需通过动态 Hook 在运行时确认」 |
| 「该应用使用了 AES-256 加密数据库」 | 「`Cipher.getInstance("AES/GCM/NoPadding")` 调用出现在 `app-jadx/sources/` 位置 X（反编译产物），字符串常量来自 `resources.arsc`」 |

核心原则一句话：反编译产物用于「找路」，字节码与运行时行为用于「定性」。 报告里凡出现「该应用如何实现」的判断，都必须能追到 Smali 或运行时观测，否则只能写成线索。

<a id="section-27"></a>

### 4.4 范围与结论表述

<a id="section-28"></a>

#### 陷阱 9：忽略 `networkSecurityConfig` 信任用户 CA

**现象**：分析完权限、签名、加固，报告写「未发现该应用存在明显安全配置问题」，然后结束。

**原因**：`android:networkSecurityConfig` 指向的 XML 资源文件定义了应用**实际采用的证书校验策略**，而这个文件不在 Manifest 里、在 `res/xml/` 下，必须用 `apktool` 解码才能看到。而它的重要性在于两条方向完全不同的含义：① 若 `<certificates src="user"/>` 出现在信任锚里，说明应用信任用户安装的 CA 证书——这意味着在已授权的取证场景中，其 HTTPS 流量可被通过安装自定义 CA 的方式观察到；② 若 `cleartextTrafficPermitted="true"`，说明应用允许明文 HTTP 通信，流量在网络侧完全暴露。这两个都是「只看 badging 输出永远看不到」的字段——`badging` 不输出资源文件内容，`permissions` 也不输出。分析者在权限清单里没看到危险项，就写下「无明显安全问题」，这个结论的技术依据其实从未被检验过。

**影响**：**这会让「无法获取数据」的原因被完全找错方向。**

加密类应用如果信任用户 CA 且允许明文，那么**在已授权检材上存在一条可观察其通信的合法路径**。

反过来，分析者若认定「该应用做了严格证书校验，无可乘之机」而据此放弃这条路径，**就把一个本可推进的取证方向主动关闭了**。

把它写进报告也构成一个事实主张 —— 「该应用信任用户 CA」这个结论如果错了，报告的技术准确性就受损。

**核查**：**先定位引用，再解码读取，两步都必须做**：

```bash
# ① 从 Manifest 定位引用的资源文件名（可能不止一个：base-config 与 domain-config 分开配）
aapt dump xmltree base.apk AndroidManifest.xml | grep -A2 'networkSecurityConfig'
# 得到 res/xml/network_security_config.xml 或 res/xml/xxx.xml

# ② apktool 解码后读取（这一步不能省）
apktool d -f -o app-decoded base.apk
cat app-decoded/res/xml/network_security_config.xml

# ③ 逐条判读关注点
#    base-config cleartextTrafficPermitted="true"        → 允许明文
#    <certificates src="user"/>                          → 信任用户 CA
#    <certificates src="system"/>                        → 仅信任系统 CA
#    <domain-config> 的 includeSubdomains / 特定域放宽     → 局部放宽
#    <debug-overrides> certificates src="user"/>          → 仅 debug 构建生效

# ④ 声明与资源不一致的情况：usesCleartextTraffic=true 但配置文件里禁止
#    → 以 networkSecurityConfig 为准（它更具体，优先级更高）
grep -n 'usesCleartextTraffic' app-decoded/AndroidManifest.xml
```

**判定结果必须区分「未发现」与「未检查」**：

> **网络安全配置**：已解码 `res/xml/network_security_config.xml`（Manifest 中 `android:networkSecurityConfig` 引用），其中 `base-config` 明确 `cleartextTrafficPermitted="true"`，且信任锚包含 `<certificates src="user"/>`。据此认定该应用允许明文通信且信任用户安装的 CA 证书。
> **未覆盖范围**：① 未做运行时流量验证（需已授权检材 + 代理配置，超出本次范围）；② `debug-overrides` 段落的生效条件依赖构建类型，未从静态信息判定；③ 第三方 SDK 内部可能有自己的网络配置，不在本文件内。

<a id="section-29"></a>

#### 陷阱 10：提取 APK 后未做哈希，把分析对象与检材的同一性丢掉

**现象**：从设备上 `adb pull` 出 `base.apk` 后直接开始反编译，最后在报告里写「对检材中提取的应用 APK 进行分析」。中间没有任何哈希固定环节。

**原因**：提取过程本身可能改变文件内容，而这一点不会被察觉。 `adb pull` 在特定条件下可能得到不完整的文件（传输中断，恰好在 APK 的尾部——而 **APK 的中央目录在文件尾部**，尾部残缺时 `unzip -l` 仍能列出内容但解压会失败）；分析工具（apktool、jadx）**在处理失败时可能修改或产出部分结果**；`apktool b` 重建会生成新 APK。这些环节之后，如果没有一个最初的哈希作为基准，就没有任何东西能证明「我分析的是检材上那个文件」。这个问题看似形式主义，但它决定的是整条证据链的起点——后面所有基于这个 APK 的结论（同一签名、同一次打包、已加固）都建立在这个前提上。

**影响**：举证时无法回应「你怎么证明分析的就是检材里的那个包」。

在涉及重签名、涉赌涉诈这类对方有动机也有能力质疑的场景下，这个质疑一旦提出且无法回答，整份基于 APK 的分析结论都会被打上「来源不明」的标记 —— 而其中恰恰包含了本案最有价值的同签名批打包认定。

代价与投入完全不成比例：两条命令的成本，换一整条证据链的可辩护性。

**核查**：哈希与完整性验证必须前置到任何分析动作之前，且 APK 本身与分片集都要固定：

```bash
PKG=com.digiforensics.sample
# ① 提取前：记录设备侧路径与全部分片
adb shell pm path $PKG | tr -d '\r' | tee apk-paths.txt
APPDIR=$(head -1 apk-paths.txt | sed 's/package://' | xargs dirname | xargs basename)
adb shell su -c "tar -cf - -C /data/app $APPDIR" > appdir.tar

# ② 提取后、分析前：哈希 + 归档完整性，两道验证
sha256sum appdir.tar | tee appdir.tar.sha256
mkdir -p apk-work && tar -xf appdir.tar -C apk-work
find apk-work -name '*.apk' -exec sha256sum {} \; | tee apk-hashes.txt
for a in apk-work/*/*.apk; do unzip -t "$a" | tail -1; done    # 每个分片都验证

# ③ 设备侧抽样交叉验证（证明提取物与设备上的文件一致）
adb shell su -c "md5sum /data/app/$APPDIR/base.apk"
md5sum apk-work/$APPDIR/base.apk

# ④ 分析产物与原件分开存放，原始 APK 目录只读
chmod -R a-w apk-work/            # 防止后续工具误写原件
```

**报告里要写清三层哈希**：原始 tar 包的哈希、解包后每个 APK 的哈希、以及分析工具产出物的哈希。

三者的对应关系是「原件—工作副本—派生分析」的可追溯链条。

第 ③ 步的设备侧交叉验证尤其重要：它证明的是「设备上那个文件的哈希与我手上的一致」，**这一步比任何后续动作都更直接地回答了同一性问题**。

<a id="section-30"></a>

#### 陷阱 11：★ 分析动作越过委托范围——为验证行为而运行或改造应用

**现象**：为了确认某个权限是否真的可用、为了看应用启动后生成哪些文件、为了验证 `allowBackup=true` 的实际效果，在检材上启动了目标应用、装了代理证书、或用 `apktool b` 重建后尝试覆盖安装。

**原因**：这些动作的动机通常是「验证」——但它们每一个都改变了检材状态，且改变是不可逆或难以完全回退的。启动应用会读取配置、可能立即触发一次数据同步、改写 `cache/`、更新数据库、甚至执行一次 `shared_prefs` 写入；安装自定义 CA 证书会修改系统的信任存储，**这是一个全局性变更，影响设备上所有应用的证书校验**；`apktool b` 重建 + 安装则会触发签名校验失败（正常情况下装不上去）——而一旦某个流程真的装上去了，检材上就多了一个被你改动过的应用。更根本的问题是：APK 逆向分析的授权范围是「理解检材能力、发现风险配置、支撑证据解释」，不包括「改变检材以观察行为」。前者是读取，后者是实验。

**影响**：**不可逆，且会污染全部后续结论。**

最严重的情形是启动应用后 `cache/` 与数据库被改写，**而这些改写覆盖掉的恰恰是取证价值最高的部分** —— 报告中「应用最后一次活跃时间」这类字段可能因此被更新为你操作的那一刻。

安装 CA 证书则更严重：**它污染的是设备整体的信任环境**。一旦发生，所有涉及网络配置的分析结论都需要重新评估，且这个变更本身会成为报告中必须解释的异常项。

在法律程序层面，「在未授权改变检材状态下获取的证据」的可采性存在根本争议 —— 这已经不是技术问题了。

**核查**：所有验证都用只读手段完成，「想确认」不构成改变检材的理由：

```bash
# ✗ 绝对不做：启动应用、安装 CA 证书、apktool b 后安装、修改系统设置

# ✓ 只读替代
adb shell dumpsys package $PKG | grep -E 'granted=true|requested permissions'  # 替代"试一下能不能"
adb shell pm path $PKG                                                  # 替代"看安装后是什么样"
aapt dump badging base.apk | grep -E 'debuggable|allowBackup'           # 替代"验证 backup 是否有效"
# networkSecurityConfig 判定纯靠静态读取，不需要实际发流量

# ✓ 需要运行时信息时：只在已 root 的副本或克隆镜像上做，绝不在原检材上
#   前提：需在检查笔录中记录该判断的依据与操作边界
```

**若确实发生了检材变更，必须在报告的单列章节里写全**：动作清单、发生时间（同时记录设备侧与分析机时间及两者时差）、影响范围、以及**「已获取数据是否受此影响」这个判断及其依据**。**主动写出这个限制，远好于让人问出来。**

<a id="section-31"></a>

#### 陷阱 12：把「已识别出的线索」写成「已证明的事实」

**现象**：报告结论部分写「该设备安装了赌博应用并通过侧载渠道安装」，而前面的分析里实际只做到：签名证书指纹相同 + `installerPackageName` 为 `null` + 目录里有安装包残留。

**原因**：技术分析产出的是线索与推断，报告结论是主张，两者之间需要一次显式的定性判断，而这一步经常被跳过。 跳过它的原因很朴素——前面的分析做得足够细致，材料看起来足够充分，写结论时就不自觉地用了断言语气。而且中文里「该设备安装了 X」这种表述本身不带推断标记，它与「该设备疑似安装过 X」在读者眼里几乎没有区别，但在举证时区别是决定性的。与之类似的越界还有几种：把「该应用具备 X 能力」写成「该应用实施了 X 行为」（能力 ≠ 行为）、把「同签名」写成「同一开发者」（密钥 ≠ 人）、把「时间戳显示」写成「行为发生于」（记录 ≠ 事实）。

**影响**：**这是最容易被对方利用的一类表述缺陷。**

断言句在质证时要求对方只需反驳其中一点即可，而带限定词的表述只需承担它所限定的那部分。**一旦一条断言被推翻，基于它的整条推理链都会松动** —— 而这条推理链里往往还挂着其他正确结论。

更实质的问题是：**结论的语气会反向影响决策。**

委托方看到断言句会按已证事实推进后续行动（追缴、冻结、问责），而这些行动基于一个实际只到「线索」强度的判断。

**这个代价不体现在取证本身，体现在案件方向上。**

**核查**：**建立结论表述的强度分级，逐条对应证据强度**：

| 证据状态 | 允许的表述 | 示例 |
|---|---|---|
| 单一线索 | 「疑似 / 具备可能性」 | 「疑似经侧载安装」 |
| 多条独立线索一致 | 「可判定 / 支持……的判断」 | 「三项独立证据共同支持『经侧载安装』的判断」 |
| 直接证据（原始记录、原始数据） | 「已确认 / 认定」 | 「`installerPackageName` 为 `null`，已确认该应用无应用商店安装来源记录」 |
| 外部信息交叉印证 | 「可认定主体」 | 「经应用商店开发者账号信息核实，签名密钥持有者为 X 公司」 |

**报告结论部分逐条标注其证据等级**，并把「本结论不指向……」这类限定句写全：

> 1. **同一签名密钥下的批量变体成立（已确认）**：三个 APK 的证书 SHA-256 指纹完全一致（`3f9a7c2e…`），`apksigner` 复算结果可重现。认定范围为「同一签名主体签发」，不指向密钥实际持有人的身份。
> 2. **侧载安装（可判定）**：① 仅启用 v1 签名方案（`apksigner verify --verbose` 可复算）；② 设备侧 `installerPackageName` 为 `null`；③ `/sdcard/Download/` 中存在早于安装时间 70 秒的同名安装包。**三项独立证据共同支持侧载判断。** 弱签名方案本身不单独构成侧载证据。
> 3. **已加固（据静态特征判定）**：四项强信号（见第 4.3 节）。该判定为静态特征判定，最终确认需动态分析中观测到内存 DEX 加载行为。
> 4. **本结论未涉及的**：未认定签名密钥持有者身份；未认定该应用实施了具体行为；未做运行时流量验证。
<a id="section-32"></a>

## 五、案例示例

<a id="section-33"></a>

### 5.1 三个 APK 的签名证书哈希归并与变体包认定

**场景**

查获一台 Android 12 手机，委托方要求查明设备上某个来源不明的应用是否为赌博软件，并判断其是否为「批量生成的变体包」。

检材中提取到三个 APK：`com.digiforensics.sample.apk`（记账助手）、`com.digiforensics.lottery.apk`（抽奖助手）、`com.digiforensics.chat.apk`（聊天助手）。

三个应用在桌面上名字各异、功能不同、图标不同。

**这正是最容易被误判的地方** —— 委托方看到三个不同名字，自然会以为是三个不同开发者的应用。

**处置过程**

第一步，固定与基本属性：

```bash
$ sha256sum com.digiforensics.*.apk | tee apk-hashes.txt
$ for a in com.digiforensics.*.apk; do echo "===== $a ====="
    aapt dump badging "$a" \
      | grep -E "^package|targetSdkVersion|^application-label|uses-permission"; done
```

| APK | package | versionName | targetSdk | 权限数 | label |
|---|---|---|---|---|---|
| `sample.apk` | `com.digiforensics.sample` | 12.3.1 | 33 | 8 | 记账助手 |
| `lottery.apk` | `com.digiforensics.lottery` | 1.0.4 | **28** | 3 | 抽奖助手 |
| `chat.apk` | `com.digiforensics.chat` | 1.0.4 | **28** | 3 | 聊天助手 |

后两行的 `versionName` 同为 `1.0.4`、`targetSdk` 同为 `28`、权限数同为 `3`。 这是第一条可疑线索 —— 但**版本号与权限数都可被任意改写，不构成证据**。

第二步，签名证书比对 —— **这是本案的决定性证据**：

```bash
$ for a in com.digiforensics.*.apk; do echo "--- $a"
    apksigner verify --print-certs "$a" 2>/dev/null \
      | grep -E 'SHA-256 digest|DN:'; done
```

```text
--- com.digiforensics.sample.apk
Signer #1 certificate DN: CN=Sample Dev, O=DigiForensics, C=CN
Signer #1 certificate SHA-256 digest: 3f9a7c2e4b8d1f6a...
--- com.digiforensics.lottery.apk
Signer #1 certificate DN: CN=Sample Dev, O=DigiForensics, C=CN
Signer #1 certificate SHA-256 digest: 3f9a7c2e4b8d1f6a...   ← 与上完全相同
--- com.digiforensics.chat.apk
Signer #1 certificate DN: CN=Sample Dev, O=DigiForensics, C=CN
Signer #1 certificate SHA-256 digest: 3f9a7c2e4b8d1f6a...   ← 与上完全相同
```

三份证书的 `DN` 与 `SHA-256 digest` 全部一致。

第三步，把这一步做成可复算的形式 —— **归并到唯一值，验证"唯一"这个判断本身**：

```bash
$ for a in com.digiforensics.*.apk; do
    apksigner verify --print-certs "$a" 2>/dev/null | grep 'SHA-256 digest'
  done | awk '{print $NF}' | sort -u
3f9a7c2e4b8d1f6a9c3e5b7d9f1a3c5e7b9d1f3a5c7e9b1d3f5a7c9e1b3d5f7
```

`sort -u` 后只有一行输出 —— 这是「三个包同一签名」的程序化证明。

若输出两行或三行，说明其中某个包的签名被重做过。

第四步，检查签名方案：

```bash
$ apksigner verify --verbose com.digiforensics.lottery.apk
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): false
Verified using v3 scheme (APK Signature Scheme v3): false
```

**只启用 v1。** 对比另外两个包：

```bash
$ for a in com.digiforensics.*.apk; do
    printf '%-34s ' "$a"
    apksigner verify --verbose "$a" 2>/dev/null \
      | grep -oE 'v[123] scheme[^:]*: (true|false)' | tr '\
' ' '; echo
  done
com.digiforensics.sample.apk   v1: true  v2: true  v3: true
com.digiforensics.lottery.apk  v1: true  v2: false v3: false   ← 异常
com.digiforensics.chat.apk     v1: true  v2: false v3: false   ← 异常
```

`sample.apk` 启用了 v1+v2+v3（正常），另两个只启用 v1。

同一签名密钥下，同批打包的两个包与另一个包的签名方案不同 —— 说明它们**不是同一次构建的产物**。

第五步，与设备安装记录交叉：

```bash
$ adb shell dumpsys package com.digiforensics.lottery \
    | grep -E 'versionName|versionCode|installerPackageName'
versionName=1.0.4  versionCode=1  installerPackageName=null
```

`versionName=1.0.4` 与 `aapt` 读出一致（交叉验证通过）；`installerPackageName=null` 确认侧载。

第六步，扫描签名之外的其他硬编码标识：

```bash
$ for a in com.digiforensics.*.apk; do
    printf '%-34s ' "$a"
    unzip -p "$a" classes.dex 2>/dev/null | strings | grep -oE 'https?://[a-z0-9.-]+' \
      | sort -u | tr '\
' ' '; echo
  done
com.digiforensics.lottery.apk  https://cdn.example-lottery.invalid  https://api.example-lottery.invalid
com.digiforensics.chat.apk    https://cdn.example-lottery.invalid  https://api.example-lottery.invalid
com.digiforensics.sample.apk  （无）
```

两个可疑包指向完全相同的一组服务端地址，而正规包没有。 这是独立于签名的第二条归并证据。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 三个 APK 使用同一签名密钥 | 三份证书 `DN` + `SHA-256` 一致，`sort -u` 唯一 | 强 |
| `lottery` 与 `chat` 指向同一组服务端 | `classes.dex` 硬编码 URL 完全相同 | 强（独立第二源） |
| `lottery` 与 `chat` 为侧载安装 | `installerPackageName=null` | 强 |
| `lottery` 与 `chat` 未启用 v2/v3 签名 | `apksigner --verbose`，与 `sample.apk` 形成对照 | 中 |
| 三者非同一次构建产物 | `sample.apk` 为 v1+v2+v3，另两个仅 v1 | 中 |
| **签名密钥的持有者身份** | — | **无法认定**（`CN/O` 可任意填写） |

**能证明的**：三个包出自同一签名密钥；两个可疑包共享同一组服务端；两个可疑包为侧载。

**不能证明的**：
- **不能证明"同一个开发者"。** 签名证书的 `CN`/`O` 字段由签发者自行填写，可以写任何内容
- **不能证明赌博性质。** 应用名"抽奖助手"与 `lottery` 包名是自我声明，实际功能需动态分析
- **不能证明谁制作了这些包**

**未覆盖范围**：DEX 逻辑（加固中，见 5.2）、加固后的运行时行为、服务端归属、签名密钥的泄露可能性、以及 `installerPackageName=null` 之外的安装渠道线索。

**误判对照**

这个案例的误判点非常典型：**用可伪造的字段做身份判断。**

**其一，用应用名或包名判断「是否同一来源」。**

桌面上三个名字（记账助手/抽奖助手/聊天助手）、三个包名、三个图标 —— 这三个字段全部在 APK 的可编辑区域内，改写成本几乎为零。 改一个字符串就得到一个「全新应用」。

正确判据是**签名证书**。理由是它的密码学性质：`SHA-256 digest` 是证书 DER 编码的哈希，任何对该证书的改动（哪怕只改一个字节的 `O` 字段）都会导致哈希完全不同。**要伪造「同一签名」，必须持有对应私钥。**

| 字段 | 可否随意改写 | 适合作身份判据 |
|---|---|---|
| `application-label`（应用名） | ✅ 改一个字符串 | ❌ |
| `package`（包名） | ✅ 改 Manifest | ❌ |
| `versionName` | ✅ 改一串文本 | ❌ |
| `icon` | ✅ 换一张图 | ❌ |
| 权限列表 | ✅ 增删 | ❌ |
| **签名证书 SHA-256** | **❌ 需私钥** | **✅** |

判据的通用形式：任何「同一来源/同一作者」的判断，必须建立在需要私钥才能复现的字段上。

**其二，把「同一签名」读成「同一开发者」。**

`DN: CN=Sample Dev, O=DigiForensics, C=CN` 看起来像是某个真实公司。

判据是 X.509 的 `CN`/`O`/`OU` 字段是 Subject 名称字符串，由申请者自行填写，不经过权威机构核验（自签名证书尤其如此）。攻击者可以写 `CN=Google Inc, O=Google`。

签名证书能证明的是「持有同一把私钥」，不能证明「这把私钥属于谁」。

签发主体的认定必须走外部路径：域名 WHOIS、ICP 备案、应用商店开发者账号、以及 CA 签发链（若为受信任 CA 签发，则 CA 会对申请主体做过至少形式核验）。

按错误判据走的代价：报告写「三个应用由 DigiForensics 公司开发」，委托方可能据此向该公司发函。而这个 `DigiForensics` 与本项目的品牌前缀重名，实为检材中刻意构造的示例值 —— 这正说明 `CN` 字段可以写成任何东西。

其三，把「仅 v1 签名」单独作为侧载或篡改的定性依据。

v1（JAR 签名）只对 `META-INF/` 下的摘要清单做保护，**不保护签名文件本身**，理论上可被移除后重签。判据是**它是线索，不是结论**：

| 现象 | 可能的良性成因 | 本案是否适用 |
|---|---|---|
| 仅 v1 签名 | 早期构建工具链的默认行为 | 可能 |
| 仅 v1 签名 | 开发者主动降级以兼容旧设备 | 可能 |
| 仅 v1 签名 | 第三方重打包工具的产物特征 | 可能 |
| 仅 v1 + 证书与原包不同 | **确属重打包** | ❌ **不适用**（本案证书一致） |

本案的关键点是：证书与 `sample.apk` 完全一致，说明没有被重签。

所以「仅 v1」在这里的正确解读是「**用旧方案打了一个相同的签**」，不是「被篡改过」。**若签名不一致，结论才完全不同。**

按错误判据走的代价：报告写「该 APK 被篡改重打包」，委托方据此追查供应链 —— 而实际只是构建工具链老旧。判据必须是「证书是否变化」，而不是「签名方案是否最新」。

**第四个实操细节**：`aapt` 在新版本中已改名 `aapt2`，且 `dump badging` 的输出格式在版本间有变化。判据是**先确认工具版本**（`aapt version`），并对 `application-label` 用 `-a` 参数或从 `resources.arsc` 解析 —— 直接在 `badging` 输出里 grep `label` 在某些版本会漏掉非英文标签。

<a id="section-34"></a>

### 5.2 加固应用的静态分析边界与明文流量取证入口

**场景**

承接 5.1。委托方在确认 `lottery.apk` 为侧载后提出进一步要求：「请分析这个赌博软件的功能」。

这在技术上遇到直接障碍：该 APK 已加固，DEX 逻辑与密钥初始化代码在运行时才解密。静态分析能拿到的只有壳代码。

这条路径要处理的是**取证方法的边界声明** —— 不是「做不了就交白卷」，而是**明确边界 + 找出替代取证路径**。

**处置过程**

第一步，识别并确认加固，四项特征缺一不可：

```bash
$ unzip -l com.digiforensics.lottery.apk | grep -E '\.so$|assets/|\.dex$'
  312K  lib/arm64-v8a/libjiagu.so          # 加固引擎
   82K  assets/jiagu_config.dat            # 加密配置
  1.4M  classes.dex                       # 单一 DEX
$ aapt dump xmltree com.digiforensics.lottery.apk AndroidManifest.xml \
    | grep -A2 'E: application'
E: application (line=42)
    A: android:name(0x01010003)="com.digiforensics.shell.StubApplication"
```

| 特征 | 本案 | 含义 |
|---|---|---|
| `libjiagu.so` | ✅ 312 KB | 加固引擎 native 库 |
| `assets/jiagu_config.dat` | ✅ 82 KB | 加密的配置/密钥材料 |
| `StubApplication` | ✅ | 真实 Application 被替换为壳 |
| 单一 `classes.dex` | ✅ 1.4 MB | 真实业务 DEX 运行时才解密 |

第二步，**确认静态分析的极限，而不是假设**：

```bash
$ apktool d -f -o lottery-decoded com.digiforensics.lottery.apk >/dev/null
$ jadx -d jadx-out lottery-decoded/classes.dex 2>&1 | tail -3
ERROR: Failed to decompile: classes.dex
# 反编译产物中只有壳类
$ find jadx-out -name '*.java' | head -5
jadx-out/sources/com/digiforensics/shell/StubApplication.java
jadx-out/sources/com/digiforensics/shell/NativeLoader.java
# 无任何业务类
```

`jadx` 报反编译失败，产物中只有 2 个壳类，零业务类。 静态分析到此为止。

第三步，但静态分析仍有高价值产出 —— **Manifest 与资源配置不含加密**：

```bash
$ cat lottery-decoded/res/xml/network_security_config.xml
<network-security-config>
  <base-config cleartextTrafficPermitted="true" />
</network-security-config>
$ grep -oE 'android:name="android\.permission\.[A-Z_]+"' \
    lottery-decoded/AndroidManifest.xml | sort -u
android:name="android.permission.INTERNET"
android:name="android.permission.ACCESS_NETWORK_STATE"
android:name="android.permission.WRITE_EXTERNAL_STORAGE"
```

`cleartextTrafficPermitted="true"` + 只有 3 个权限。 这两项都是壳无法隐藏的信息（Manifest 在加固后依然明文，只是 `Application` 类名被替换）。

第四步，把 `debuggable` 标记作为独立发现：

```bash
$ aapt dump xmltree com.digiforensics.lottery.apk AndroidManifest.xml \
    | grep -A6 'E: application' | grep -i debuggable
A: android:debuggable(0x0101000f)=0xffffffff
```

`debuggable=0xffffffff` 即 `true`。 正式上架应用不应有此标记（Google Play 会拦截）。三个包全部为 `true`。

第五步，`debuggable=true` 本身构成一个取证入口 —— 但这需要委托方的明确授权：

```text
致委托方：

关于 com.digiforensics.lottery.apk 的功能分析，本方现状如下：

一、技术障碍（已实测确认，非推测）：
   该 APK 使用加固保护（libjiagu.so + assets/jiagu_config.dat +
   StubApplication + 单一 classes.dex 四项特征齐全）。jadx 反编译
   classes.dex 失败，静态产物仅含 2 个壳类，零业务类。其数据库密钥
   初始化逻辑、具体业务实现均无法通过静态分析获取。

二、静态分析可得（不受加固影响）：
   - 权限 3 项：INTERNET / ACCESS_NETWORK_STATE / WRITE_EXTERNAL_STORAGE
   - network_security_config: cleartextTrafficPermitted="true"
   - android:debuggable=true
   - 硬编码服务端：cdn.example-lottery.invalid、api.example-lottery.invalid
   - 与 chat.apk 共用同一签名证书与同一组服务端地址

三、若需进一步分析，可选路径（均需贵方书面授权后执行）：
   路径 A：在已 root 的隔离测试机上安装该 APK，通过运行时内存转储
           获取解密后的 DEX。本路径涉及执行被检程序，需贵方书面确认
           授权范围与隔离条件。
   路径 B：不执行程序，仅采集该应用的网络流量。因其允许明文通信，
           在贵方网络出口侧采集即可，无需在分析侧执行。本路径不涉及
           执行被检程序，风险显著低于路径 A。
   路径 C：向服务端发函调取注册用户与交易记录。

建议优先路径 B —— 它不执行被检程序，且能直接回答"该应用是否具备
赌博类功能（充值、提现、赔率、代理层级）"这一委托问题。
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| `lottery.apk` 使用加固保护，四项特征齐全 | `libjiagu.so` + `jiagu_config.dat` + `StubApplication` + 单一 DEX | 强 |
| 静态分析无法获取业务逻辑 | `jadx` 反编译失败，产物仅 2 个壳类 | 强（已实测） |
| 该应用允许明文网络通信 | `cleartextTrafficPermitted="true"` | 强 |
| 该应用仅申请 3 项权限 | Manifest 权限列表 | 强 |
| 该应用 `debuggable=true` | Manifest `android:debuggable=0xffffffff` | 强 |
| **是否为赌博软件** | — | **静态分析无法认定，需路径 A/B/C** |

**能证明的**：加固的存在与形式；权限范围；网络通信配置；调试标记；服务端地址。

**不能证明的**：
- 不能从"包名含 lottery""名字叫抽奖助手"推出赌博性质。 这些是自我声明字段
- **不能从权限少推出功能简单。** 赌博应用可以只用 INTERNET 权限完成全部网络交互
- **不能从加固推出恶意。** 加固同样用于合法的金融、政务应用

**未覆盖范围**：加固后的 DEX 逻辑、数据库结构与密钥、网络通信的实际内容（`cleartextTrafficPermitted=true` 只说明允许明文，不说明实际用了明文）、服务端实现、运行时动态加载的代码。

**误判对照**

这个案例的误判点在于**把「分析不出来」与「没有问题」混为一谈**，以及**在没走完替代路径前就宣告失败**。

其一，从权限数量少推出「功能简单、不可能是赌博应用」。

`lottery.apk` 只申请了 3 项权限，看起来「很干净」。判据是**赌博应用的功能可以完全由服务端实现**：

| 赌博应用常见需求 | 所需权限 | 实际可否免权限 |
|---|---|---|
| 网络通信 | `INTERNET` | 不可免，但只需 1 项 |
| 资金操作 | 无专用权限 | 纯服务端处理 |
| 通讯录读取（拉人头） | `READ_CONTACTS` | 可省略，改由用户手填 |
| 定位 | `ACCESS_FINE_LOCATION` | 可省略 |
| 相册/存储 | `READ/WRITE_EXTERNAL_STORAGE` | 可省略 |

**权限数量与功能复杂度之间没有稳定的相关性。** 一个纯 WebView 壳 + 3 项权限的应用可以实现完整的赌博平台。

**其二，因为加固就写「无法分析」。**

加固确实阻断了静态路径，但**取证路径不只有一条**。判据是**加固的防护层级与绕过成本**：

| 层级 | 加固手段 | 静态是否可用 | 替代路径 |
|---|---|---|---|
| L0 | 无加固 | ✅ 完全可用 | — |
| L1 | 仅 `debuggable` 残留 | ✅ 大部分可用 | — |
| L2 | DEX 字符串加密 | ⚠️ 壳可见 | 流量侧、内存侧 |
| L3 | 完整加固（本案） | ❌ 业务不可见 | **流量侧（本案最优）、内存侧、服务端侧** |

本案在 L3，但 `cleartextTrafficPermitted="true"` 这个**壳无法隐藏的配置**，直接给出了一条不需要执行被检程序的取证路径。

**这是加固带来的分析困境里最实用的一条突破口。** 判据是**先找加固应用仍明文暴露的配置项**（`network_security_config`、`debuggable`、`backup` 允许、`allowBackup`、硬编码 URL），它们往往是后续取证的入口。

**其三，把「从服务端地址推断功能」当成结论。**

`cdn.example-lottery.invalid` 这个域名看起来「不像赌博」，也「不排除赌博」。判据是**域名是自我声明字段**：

| 域名形态 | 实际含义 |
|---|---|
| `cdn.example-lottery.invalid` | 域名注册者自选，`.invalid` 是保留 TLD |
| `xplay8.example.net` | 可能确实是博彩，也可能只是"游戏" |
| `api.digi-forensics-cloud.example.net` | **本次案例中的正经对象存储也被命名为这种形式** |

**域名命名与实际业务无必然关联。** 本案里连"本报告作者"都用了 `example-lottery.invalid` 这种命名 —— 这恰恰说明该字段的可伪造性。

按错误判据走的代价：报告写「从服务端域名看该应用不具备赌博特征」，委托方据此排除嫌疑。而真实功能完全可能在服务端，域名只是一层壳。

**第四个实操细节**：`jadx` 对加固 DEX 报 `Failed to decompile` 时，**不要把它当作工具故障而反复重试或换工具**。

正确做法是先看它的产物里有没有壳类 —— 有壳类说明是 DEX 加密（可绕，换工具无用），一个壳类都没有才可能是工具版本问题。

判据是产物数量：0 个类 = 工具问题，少量壳类 = 加固问题。

<a id="section-35"></a>

## 六、扩展阅读方向

本篇停在「APK 静态读完了」。往下走会遇到三类问题 —— 壳挡住了代码、结论需要跨源验证、发现指向另一种可能。下面几组文章分别接住它们。

**代码层：静态读不到的东西怎么继续往下**

- [Frida 动态 Hook](mobile-android-frida-dynamic-hooking.md) —— 判定加固之后的自然下一步。但它有前提：你要先知道该 hook 什么，而那个答案来自本篇的静态结论。 顺序反了会浪费大量时间。
- [应用私有数据与 SharedPreferences](mobile-android-sharedpreferences.md) —— 回到文件层。`lib/` 里的 so 判定加固，同时 `no_backup/` 里的密钥材料决定动态路径的入口。
- [APFS 容器与快照](../../filesystem/filesystem-apple-fs/filesystem-apple-fs-apfs.md) —— iOS 侧的对照物。签名体系与代码签名是两套模型，对照看能看清"身份认定"这件事在两个平台上的差异。

**身份与完整性：签名结论能支撑多强**

- [哈希与完整性校验](../../fundamentals/fundamentals-concepts/fundamentals-concepts-hashes-and-integrity-verification.md) —— APK 哈希与签名验证是两回事：前者证明字节没变，后者证明持有对应私钥。**本篇第 5 步的验证顺序依赖这个区分。**
- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— **重打包替换的判据清单**。签名与 `versionCode` 同时变、权限被追加、`debuggable` 被打开，这些都在这篇的视野里。
- [证据文件格式](../../fundamentals/fundamentals-chain/fundamentals-chain-dd-e01-aff4-evidence-formats.md) —— APK 作为一种证据载体，其哈希如何进入保管链记录。
- [近似匹配与模糊哈希](../../fundamentals/fundamentals-concepts/fundamentals-concepts-fuzzy-hashing.md) —— 批量 APK 的同源聚类。当一批包只差一个包名时，需要的正是这类工具而不是逐个反编译。

**相邻议题：同一批问题的其他入口**

- [即时通讯取证](mobile-android-instant-messaging-forensics.md) —— 本篇最直接的下游。加固判定直接决定这条链的成本是半小时还是几天。
- [Android 数据存储总览](mobile-android-android-data-storage-overview.md) —— `packages.xml` 与 APK 的 `package` 字段如何交叉验证，以及 `adb backup` 在各版本上的实际可用性。
- [iOS 系统痕迹与 DFU 恢复](../mobile-ios/mobile-ios-dfu.md) —— 应用身份认定的另一条路径：从设备侧系统记录反推装过什么。

**判据与反例：这些「看起来可疑」的东西**

- [SQLite 基础与结构](../mobile-database/mobile-database-sqlite.md) —— 判断"数据库能否读"时，库文件本身的状态往往比权限更关键。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 合规前提的完整表述。APK 分析尤其容易被误用到"绕过"方向上，这篇给的是边界。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md) —— 逆向分析在委托范围上的具体边界。
<a id="section-36"></a>

## 七、命令速查

```bash
# ===== 环境 =====
sudo apt install aapt apktool sqlite3 file binwalk
# jadx / apksigner 来自 Android SDK build-tools 或独立发行版

# ===== 获取 APK =====
PKG=com.digiforensics.sample
adb shell pm path $PKG
adb pull /data/app/~~Hk2==/com.digiforensics.sample-1a2b3c==/base.apk ./base.apk
sha256sum base.apk | tee base.apk.sha256 ; unzip -t base.apk | tail -2   # ★ 第一时间哈希

# ===== 基本属性 =====
aapt dump badging base.apk ; aapt dump permissions base.apk ; aapt dump resources base.apk | head -50
aapt dump xmltree base.apk AndroidManifest.xml      # 布尔 true 显示为 0xffffffff

# ===== 资源重建 =====
apktool d -f -o app-decoded base.apk ; apktool b app-decoded -o app-rebuilt.apk
cat app-decoded/res/xml/network_security_config.xml   # ★ 明文流量/CA 信任
cat app-decoded/res/values/strings.xml; cat app-decoded/res/values-zh-rCN/strings.xml

# ===== 源码反编译（三类必查：库名/密钥来源/设备派生）=====
jadx -d app-jadx base.apk --no-res
grep -rn "openOrCreateDatabase\|SQLiteOpenHelper" app-jadx/sources/   # 库名与是否加密
grep -rn "Cipher.getInstance\|SecretKeySpec"        app-jadx/sources/   # 密钥从哪来
grep -rn "getDeviceId\|ANDROID_ID\|Build.SERIAL"     app-jadx/sources/   # 设备信息是否派生

# ===== 签名（密钥层面身份的唯一权威标识）=====
apksigner verify --verbose --print-certs base.apk   # 看 SHA-256 digest 与 v1/v2/v3 三个 true/false
unzip -o base.apk 'META-INF/*.RSA' ; keytool -printcert -file META-INF/CERT.RSA
openssl pkcs7 -inform DER -in META-INF/CERT.RSA -print_certs -noout

# 批量对比签名（识别批量变体包）
for a in *.apk; do echo -n "$a  "; \
  apksigner verify --print-certs "$a" 2>/dev/null | grep -m1 'SHA-256 digest'; done

# ===== 加固识别 =====
unzip -l base.apk | grep -E '\.so$' | awk '{print $NF}'
unzip -l base.apk | awk '$1 > 100000 {print $1, $NF}' | sort -rn | head     # assets 加密文件
unzip -l base.apk | grep 'classes.*\.dex'                                 # dex 数量与体积
aapt dump xmltree base.apk AndroidManifest.xml | grep -A4 'E: application'  # Application 类
mkdir -p unz && cd unz && unzip -q ../base.apk
strings -n 6 resources.arsc assets/* 2>/dev/null | \
  grep -iE 'http://|https://|api|key|secret|aes|password' | sort -u | head -40

# ===== 与设备记录交叉验证 =====
adb shell dumpsys package com.digiforensics.sample | \
  grep -E 'versionName|versionCode|firstInstallTime|installerPackageName'
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 移动与数据库取证 — APK 逆向与 Manifest 分析」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《APK 逆向与 Manifest 分析》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.vc` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
