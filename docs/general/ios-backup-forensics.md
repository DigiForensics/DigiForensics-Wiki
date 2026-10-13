---
title: "iOS 手机取证"
slug: "ios-backup-forensics"
canonical: "https://www.digiforensics.cn/wiki/ios-backup-forensics"
license: "CC-BY-SA-4.0"
author: "DyNooob"
updated_at: "2026-05-30T18:11:46+08:00"
source_url: null
source_type: null
category: "手机取证"
space: null
node_path: []
---

# iOS 手机取证

**iOS 设备的数据组织方式与 Android 明显不同。很多 iPhone 取证数据并不是以原始路径直接展示，而是通过备份文件、域名、哈希文件名和 Manifest.db 映射关系保存。理解 iOS 备份结构，是分析 iPhone 检材的基础。**

**在比赛和案件中，iOS 检材常见形态包括：iTunes 备份、取证工具导出的文件系统、应用沙箱目录、系统数据库和媒体目录。不同提取方式能看到的数据范围不同，分析时应先确认检材类型，再决定分析路径。**

<a id="section-1"></a>

## 一、iOS 备份的基本结构

**常见 iTunes 备份目录中可能包含：**

```
Manifest.db
Manifest.plist
Info.plist
Status.plist
多个两级哈希目录
```

**其中：**

```
Info.plist       设备基本信息
Manifest.plist   备份属性、是否加密、版本信息
Manifest.db      备份文件索引和原始路径映射
Status.plist     备份状态
```

**如果备份加密，可能会影响 Keychain、健康数据、Wi-Fi 密码等内容的提取范围。分析前应确认备份是否加密。**

<a id="section-2"></a>

## 二、Manifest.db 的作用

`Manifest.db` 是 iOS 备份分析的核心。它记录了备份文件与原始路径之间的映射关系。

**常见字段包括：**

```
fileID
域名 domain
相对路径 relativePath
文件属性 flags
文件大小
修改时间
```

**iOS 备份中的实际文件名通常是哈希值，不直观。需要通过 Manifest.db 才能知道某个文件原本属于哪个 App、哪个路径。**

**常见 domain：**

```
HomeDomain
MediaDomain
AppDomain-<bundle_id>
AppDomainGroup-group.<name>
SysSharedContainerDomain-systemgroup.com.apple.*
```

**理解 domain 能快速判断文件来源。**

<a id="section-3"></a>

## 三、设备基本信息

**设备信息通常可从 **`Info.plist` 提取，包括：

```
设备名称
产品类型
系统版本
序列号
IMEI
电话号码
ICCID
备份时间
设备唯一标识
```

**常见题目：**

```
该 iPhone 型号是什么？
系统版本是多少？
设备名称是什么？
手机号是多少？
备份时间是什么？
```

**设备型号需要注意：**`Product Type` 可能是类似 `iPhone15,2` 的机型标识，需要进一步转换为具体型号。

<a id="section-4"></a>

## 四、AppDomain 与应用沙箱

**iOS 应用数据通常位于：**

```
AppDomain-<bundle_id>/
AppDomainGroup-group.<name>/
```

**例如：**

```
AppDomain-com.apple.mobilesafari
AppDomain-com.tencent.xin
AppDomainGroup-group.com.tencent.xin
```

**其中 AppGroup 目录很重要。很多应用为了扩展、分享、通知或跨组件通信，会把关键数据放在 Group 容器中。**

**分析应用时应同时检查：**

```
AppDomain
AppDomainGroup
Library/
Documents/
tmp/
Caches/
Preferences/
```

**常见文件类型：**

```
*.sqlite
*.db
*.plist
*.json
Cookies
History
Cache
```

<a id="section-5"></a>

## 五、Safari 与浏览痕迹

**Safari 数据常见位置包括：**

```
History.db
Bookmarks.db
BrowserState.db
Cookies.binarycookies
```

**重点分析：**

```
浏览历史
访问时间
网页标题
搜索关键词
下载记录
书签
Cookie
最近打开标签页
```

**如果题目问“用户访问过哪个网站”“搜索过什么关键词”“后台地址是什么”，Safari 历史和浏览状态数据库是重点。**

**需要注意：浏览时间可能使用 Apple 绝对时间或 WebKit 时间格式，必须正确换算。**

<a id="section-6"></a>

## 六、照片与相册数据库

**iOS 照片不仅存在于媒体文件夹，也由相册数据库管理。常见数据包括：**

```
照片文件
缩略图
相册数据库
EXIF 元数据
位置信息
编辑记录
删除记录
```

**重点数据库可能包括：**

```
Photos.sqlite
```

**分析内容：**

```
拍摄时间
导入时间
位置信息
资源文件名
相册归属
是否收藏
是否隐藏
是否删除
```

**不要只看图片文件本身。相册数据库能提供更多上下文，例如资源是否来自相机、截图、保存、同步或编辑。**

<a id="section-7"></a>

## 七、KnowledgeC 与系统行为痕迹

**iOS 系统中常见行为数据库包括 KnowledgeC 相关数据。它可能记录应用使用、设备状态、位置活动和系统行为。**

**分析价值包括：**

```
应用启动时间
前台使用记录
设备活动状态
用户操作时间线
```

**这类数据适合用于证明某个时间段设备是否被使用、某应用是否打开过、用户行为是否与其他证据时间吻合。**

<a id="section-8"></a>

## 八、短信、通话与通讯录

**常见系统数据库包括：**

```
sms.db
CallHistory.storedata
AddressBook.sqlitedb
```

**可分析：**

```
短信内容
验证码
收发件人
发送接收时间
通话号码
通话类型
通话时长
联系人姓名
联系人备注
```

**验证码短信在账号登录、资金交易、服务器后台访问等场景中非常重要。它常用于证明某账号在某时间发生过登录、验证或交易行为。**

<a id="section-9"></a>

## 九、Keychain 与加密备份

**如果备份未加密，部分敏感数据可能无法完整提取。加密备份通常能包含更多 Keychain 相关内容，例如账号凭据、Wi-Fi 密码或应用 Token。**

**分析时应记录：**

```
备份是否加密
是否有备份密码
能否解析 Keychain
敏感数据是否缺失
```

**不能因为没有看到某项数据就断定不存在，必须结合提取方式说明数据范围。**

<a id="section-10"></a>

## 十、时间格式与时区

**iOS 数据中常见时间格式包括：**

```
Unix 时间戳
毫秒级 Unix 时间戳
Apple Absolute Time
WebKit Time
字符串时间
```

**Apple Absolute Time 以 2001-01-01 00:00:00 UTC 为起点。WebKit Time 常以 1601-01-01 为起点，单位可能是微秒。**

**时间分析必须确认：**

```
时间起点
单位
是否 UTC
是否需要转换为本地时区
```

<a id="section-11"></a>

## 十一、总结

**iOS 取证的核心是理解备份映射和应用沙箱。**`Manifest.db` 负责告诉我们文件来自哪里，AppDomain 和 AppGroup 告诉我们应用数据在哪里，系统数据库则帮助还原设备行为。
