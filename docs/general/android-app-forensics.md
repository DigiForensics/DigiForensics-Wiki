---
title: "Android 应用数据取证"
slug: "android-app-forensics"
canonical: "https://www.digiforensics.cn/wiki/android-app-forensics"
license: "CC-BY-SA-4.0"
author: "DyNooob"
updated_at: "2026-05-30T18:09:57+08:00"
source_url: null
source_type: null
category: "手机取证"
space: null
node_path: []
---

# Android 应用数据取证

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/android-app-forensics)

**Android 应用取证是手机取证中最常见、也最容易拉开差距的部分。普通取证软件可以解析常见聊天、短信、通话和浏览器数据，但遇到比赛自制应用、小众应用、加固应用或业务应用时，仍需要手工分析应用沙箱。**

**分析 Android 应用的关键是包名。只要确定包名，就能定位应用目录、数据库、配置文件、缓存和 WebView 数据。很多服务器地址、登录 Token、聊天记录、历史搜索、接口响应和缓存图片，都保存在这些目录中。**

<a id="section-1"></a>

## 一、先理解 Android 应用沙箱

**Android 每个应用都有独立包名，例如：**

```
com.tencent.mm
com.tencent.mobileqq
com.android.chrome
com.eg.android.AlipayGphone
com.example.chat
```

**应用数据常见路径：**

```
/data/data/<package_name>/
/data/user/0/<package_name>/
/sdcard/Android/data/<package_name>/
/sdcard/Android/media/<package_name>/
```

**其中：**

```
/data/data/               传统应用私有目录
/data/user/0/             多用户环境下的实际私有目录
/sdcard/Android/data/     外部存储中的应用数据
/sdcard/Android/media/    应用媒体文件目录
```

**完整镜像或 root 提取通常能看到 **`/data/user/0/`；普通逻辑备份可能只能看到外部存储和部分可备份数据。

<a id="section-2"></a>

## 二、确定应用包名

**确定包名有多种方式。**

**可以从系统包列表查找：**

```
/data/system/packages.xml
/data/system/packages.list
```

**也可以从目录名推断：**

```
/data/user/0/com.example.app/
/sdcard/Android/data/com.example.app/
```

**如果只知道应用中文名，可以在全局搜索应用名、图标、安装包名或相关字符串。比赛自制应用常在包名中保留业务含义，如 **`chat`、`wallet`、`server`、`forensic`、`demo` 等。

**确认包名后，应记录：**

```
应用名称
包名
版本号
安装时间
更新时间
数据目录
是否存在外部存储目录
是否存在 WebView 数据
```

**这些信息既能回答基础题，也能帮助后续定位重点文件。**

<a id="section-3"></a>

## 三、应用目录结构

**典型 Android 应用目录如下：**

```
/data/user/0/<package_name>/
  databases/
  shared_prefs/
  files/
  cache/
  code_cache/
  app_webview/
  no_backup/
```

**各目录含义：**

```
databases/       SQLite 数据库，常保存核心业务数据
shared_prefs/    XML 配置，常保存账号、Token、开关和服务器地址
files/           应用私有文件，可能保存附件、导出文件、加密文件
cache/           缓存，可能保存图片、接口响应、临时文件
code_cache/      代码缓存，可能有动态加载痕迹
app_webview/     内嵌浏览器数据，包括 Cookie、History、LocalStorage
no_backup/       不随系统备份的数据，常保存敏感状态
```

**分析时不要只看 **`databases`。很多关键线索反而在 `shared_prefs`、`files` 和 `app_webview` 中。

<a id="section-4"></a>

## 四、数据库分析

`databases` 是应用数据分析的核心目录。常见文件包括：

```
*.db
*.sqlite
*.sqlite3
*.db-wal
*.db-shm
```

**需要注意：如果数据库存在 WAL 文件，直接复制主库可能看不到最新数据，应尽量同时保留 **`.db`、`.db-wal`、`.db-shm`。

**分析流程：**

```
1. 列出数据库文件
2. 查看表名
3. 查看表结构
4. 按关键词筛选表
5. 抽样查看数据
6. 处理时间戳和编码
7. 记录来源路径和字段
```

**常见表名关键词：**

```
user / account / profile / member
message / msg / chat / conversation / session
friend / contact / group
history / search / browse / url
location / gps / poi / route
file / media / attachment / image / video
order / payment / wallet / bill / recharge
log / event / record / notify
```

**很多比赛题不会直接让你说“表名”，而是问用户昵称、聊天对象、服务器地址、最后登录时间、交易金额、运动区域等。这些答案通常需要从字段含义中推断。**

<a id="section-5"></a>

## 五、SharedPreferences 分析

`shared_prefs` 目录保存 XML 配置，是 Android 取证中非常重要的证据来源。

**常见内容包括：**

```
用户 ID
手机号
昵称
登录 Token
服务器域名
API 地址
开关状态
最近一次登录时间
是否首次启动
加密密钥片段
```

**分析重点字段：**

```
uid
user_id
phone
email
token
auth
session
server
host
url
api
password
secret
key
```

**很多应用不会把密码直接写入数据库，但会在 XML 中保存 Token、refresh token、用户 ID 或服务器地址。这类信息在关联服务器、恢复登录状态和解释应用行为时很有价值。**

<a id="section-6"></a>

## 六、MMKV 与键值存储

**国产应用中常见 MMKV、LevelDB、RocksDB 等键值存储。MMKV 文件常见形式：**

```
*.mmkv
*.crc
```

**MMKV 不一定能直接读取，但可以先用字符串方式观察是否存在明文：**

```
token
uid
phone
url
http
api
session
```

**如果发现可读字符串，应进一步确认它属于哪个应用、哪个文件、字段上下文是什么。不要只因为出现一个 URL 就直接下结论，需要结合路径和其他配置印证。**

<a id="section-7"></a>

## 七、WebView 数据

**很多 App 使用 WebView 展示网页或后台系统。WebView 数据常见路径：**

```
app_webview/
app_webview/Default/
app_webview/Default/Cookies
app_webview/Default/History
app_webview/Default/Local Storage/
app_webview/Default/Session Storage/
```

**可能出现：**

```
登录 Cookie
访问历史
后台域名
LocalStorage 中的 Token
网页表单缓存
接口地址
```

**如果题目问“该用户访问的后台地址是什么”“登录平台域名是什么”“Token 是什么”，WebView 往往是关键位置。**

<a id="section-8"></a>

## 八、files 与 cache 目录

`files` 和 `cache` 目录经常保存业务附件与临时数据。

**可能包含：**

```
聊天图片
语音文件
视频缓存
接口 JSON 响应
下载文件
导出文件
离线地图
压缩包
加密文件
```

**缓存文件名可能没有后缀，需要通过文件头判断类型。例如 JPEG、PNG、MP4、ZIP、SQLite、JSON 都可能被改名保存。**

**分析缓存时要注意来源解释：缓存文件不一定代表用户主动保存，也可能只是浏览、预览、接收或自动加载。**

<a id="section-9"></a>

## 九、已卸载应用与残留

**已卸载应用可能仍留下：**

```
/sdcard/Android/data/<package_name>/
/sdcard/Android/media/<package_name>/
下载目录中的 APK
安装包管理记录
日志中的安装卸载时间
```

**分析已卸载应用时，可结合 **`packages.xml`、系统日志、应用目录残留、浏览器下载记录和文件修改时间进行判断。
