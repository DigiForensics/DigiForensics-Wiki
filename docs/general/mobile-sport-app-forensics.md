---
title: "运动软件取证"
slug: "mobile-sport-app-forensics"
canonical: "https://www.digiforensics.cn/wiki/mobile-sport-app-forensics"
license: "CC-BY-SA-4.0"
author: "DyNooob"
updated_at: "2026-05-30T18:33:40+08:00"
source_url: null
source_type: null
category: "手机取证"
space: null
node_path: []
---

# 运动软件取证

**运动健康类 App 在手机取证和可穿戴设备取证中较为常见。**

>虽然在此次盘古石初赛中，团队怀疑手表题数据在手机中，但随后复盘并未发现。同时发现手边数据有明显加密痕迹，故大概率数据还存在手表中，只是未找到正确方法解密。


**在比赛和案件分析中，这类软件经常用于回答以下问题：**

```
跑步地点在哪里？
运动轨迹是否真实？
平均配速是多少？
心率数据是否异常？
运动记录来自手机还是手表？
截图是否可能伪造？
用户绑定过哪些穿戴设备？
运动数据是否同步到云端或系统健康平台？
```

**运动软件取证不能只看一张截图。截图只能作为线索，不能直接作为最终证据。**

**应当同时结合：**

```
App 数据库
运动记录文件
GPS 轨迹点
心率 / 步频 / 配速数据
设备绑定信息
系统健康数据库
相册截图
云同步痕迹
通知和日志
可穿戴设备数据
```

**Keep、华为运动健康、Zepp、Zepp Life、小米运动健康 / Mi Fitness 这几类 App 都属于运动健康数据入口。实际取证时，不能只根据 App 界面判断，应当回到原始数据库、缓存、配置文件、系统健康数据和可穿戴设备同步痕迹中进行交叉验证。**

<a id="section-1"></a>

## 一、运动软件数据的五个价值维度

<a id="section-2"></a>

### 1. 时间价值

**运动记录通常包含：**

```
运动开始时间
运动结束时间
运动持续时间
暂停时间
同步时间
上传时间
创建时间
修改时间
```

**这些时间可以用来还原用户在某一时间段是否处于运动状态。**

**但需要注意：**

```
运动开始时间 ≠ 数据上传时间
运动结束时间 ≠ 截图保存时间
截图时间 ≠ 真实运动时间
```

**例如，某张 Keep 跑步截图显示 19:32 开始运动，但相册中截图创建时间是 22:10。这只能说明截图在 22:10 左右保存，不能直接说明用户在 19:32 运动。需要继续查看 App 原始数据库或轨迹数据。**

<a id="section-3"></a>

### 2. 空间价值

**户外跑步、骑行、徒步等运动通常会产生位置数据。**

**常见数据包括：**

```
经度
纬度
海拔
GPS 时间
轨迹点序号
速度
距离
配速
定位精度
```

**这些数据可以用于判断：**

```
用户主要运动区域
是否经过某地点
是否接近案发现场
轨迹是否存在跳点
是否可能是手动伪造
```

<a id="section-4"></a>

### 3. 身体状态价值

**运动软件或手表可能记录：**

```
心率
最大心率
平均心率
静息心率
步频
步幅
卡路里
压力
血氧
睡眠
恢复状态
最大摄氧量
```

**这些数据不能直接用于医学判断，但可以辅助判断运动记录是否自然。**

**例如：**

```
跑步 5 公里但全程心率为 0
配速很快但步频数据缺失
轨迹显示移动但心率完全没有变化
公里数很高但无任何 GPS 轨迹
```

**这些都需要进一步核查。**

<a id="section-5"></a>

### 4. 设备关联价值

**运动记录可能来自：**

```
手机 GPS
智能手表
手环
跑步机
第三方平台同步
手动录入
导入数据
```

**所以必须确认数据来源。**

**同一条运动记录，如果能同时在手机 App、系统健康数据库、手表绑定记录、云同步日志中找到对应痕迹，可信度会更高。**

<a id="section-6"></a>

### 5. 反伪造价值

**运动软件常被用于生成打卡截图、运动截图、轨迹截图。在取证中，不能只看截图，而要分析：**

```
截图是否来自真实 App
截图时间是否与运动时间匹配
轨迹点是否连续
配速是否合理
心率是否存在
是否存在原始运动记录
是否存在系统健康同步记录
是否存在云端同步痕迹
```

<a id="section-7"></a>

## 二、常见 App 与包名线索

**不同手机和地区的 App 名称可能不同，取证时应以检材中的 **`packages.xml`、应用列表和沙箱目录为准。

**以下包名仅作为初筛参考：**

| **应用**         | **常见名称**                                | **常见 Android 包名**                | **关注点**                                     |
| ------------------ | --------------------------------------------- | -------------------------------------- | ------------------------------------------------ |
| **Keep**         | **Keep / Keep AI 运动教练**                 | `com.gotokeep.keep`              | **跑步、骑行、课程、运动轨迹、社区动态、截图** |
| **华为运动健康** | **HUAWEI Health / 运动健康**                | `com.huawei.health`              | **华为手表、手环、心率、血氧、睡眠、跑步轨迹** |
| **Zepp**         | **Zepp / Amazfit**                          | `com.huami.watch.hmwatchmanager` | **Amazfit 手表、运动记录、心率、设备管理**     |
| **Zepp Life**    | **Zepp Life / 原 Mi Fit**                   | `com.xiaomi.hm.health`           | **小米手环、体脂秤、睡眠、步数、运动记录**     |
| **Mi Fitness**   | **Mi Fitness / Xiaomi Wear / 小米运动健康** | `com.xiaomi.wearable`            | **小米手表手环、跑步、骑行、健康数据**         |

**分析时可以先搜包名：**

```
find . -iname "*gotokeep*" -o -iname "*huawei*health*" -o -iname "*huami*" -o -iname "*xiaomi*health*" -o -iname "*wearable*" 2>/dev/null
```

**也可以从系统安装信息中查：**

```
grep -Rina "com.gotokeep.keep\|com.huawei.health\|com.huami.watch.hmwatchmanager\|com.xiaomi.hm.health\|com.xiaomi.wearable" ./ 2>/dev/null
```

<a id="section-8"></a>

## 三、运动软件常见数据类型

**运动健康类 App 的数据通常分为九类。**

<a id="section-9"></a>

### 1. 用户账号数据

**常见字段：**

```
uid
user_id
account_id
nickname
phone
email
avatar
gender
birthday
height
weight
login_token
session
refresh_token
```

**作用：**

```
确认账号归属
确认登录状态
关联其他设备和云端数据
```

<a id="section-10"></a>

### 2. 设备绑定数据

**常见字段：**

```
device_id
mac
bluetooth_mac
sn
serial_number
model
firmware
bind_time
last_sync_time
device_name
```

**作用：**

```
判断运动记录是否来自手表或手环
确认设备型号
确认最后同步时间
```

<a id="section-11"></a>

### 3. 运动记录主表

**常见字段：**

```
workout_id
sport_id
track_id
start_time
end_time
duration
distance
calorie
avg_pace
avg_speed
max_speed
avg_heart_rate
max_heart_rate
step_frequency
step_count
source
sync_status
```

**作用：**

```
回答运动时间、距离、时长、配速、卡路里、心率等基础问题
```

<a id="section-12"></a>

### 4. GPS 轨迹点

**常见字段：**

```
track_id
point_index
latitude
longitude
altitude
speed
accuracy
timestamp
distance
```

**作用：**

```
判断运动区域
绘制运动路线
识别轨迹跳点
验证运动真实性
```

<a id="section-13"></a>

### 5. 心率数据

**常见字段：**

```
heart_rate
bpm
hr
time
timestamp
zone
min_hr
max_hr
avg_hr
```

**作用：**

```
判断运动强度
辅助验证是否真实运动
```

<a id="section-14"></a>

### 6. 步数和活动数据

**常见字段：**

```
steps
step_count
active_time
distance
calorie
date
hour
minute
```

**作用：**

```
分析每日活动情况
还原某天是否高频活动
```

<a id="section-15"></a>

### 7. 睡眠和压力数据

**常见字段：**

```
sleep_start
sleep_end
deep_sleep
light_sleep
rem
awake
stress
spo2
```

**作用：**

```
分析健康状态
辅助判断用户作息和活动规律
```

<a id="section-16"></a>

### 8. 图片和分享数据

**常见内容：**

```
运动截图
运动海报
分享图片
社区动态图片
轨迹缩略图
头像
勋章图片
```

**作用：**

```
辅助还原用户是否分享过运动记录
判断截图生成时间和来源
```

<a id="section-17"></a>

### 9. 云同步和接口缓存

**常见内容：**

```
HTTP 缓存
接口返回 JSON
同步队列
上传失败日志
Token
API 地址
```

**作用：**

```
判断数据是否上传云端
判断本地记录是否被同步
恢复接口返回中的运动记录
```

<a id="section-18"></a>

## 四、Android 取证路径

**Android 中运动 App 的数据通常在以下目录：**

```
/data/user/0/<package_name>/
/data/data/<package_name>/
/sdcard/Android/data/<package_name>/
/sdcard/Android/media/<package_name>/
```

**重点目录：**

```
databases/
shared_prefs/
files/
cache/
app_webview/
no_backup/
```

<a id="section-19"></a>

### 1. 查找数据库

```
find . -path "*com.gotokeep.keep*" -type f \( -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" \) 2>/dev/null

find . -path "*com.huawei.health*" -type f \( -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" \) 2>/dev/null

find . -path "*com.huami.watch.hmwatchmanager*" -type f \( -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" \) 2>/dev/null

find . -path "*com.xiaomi.hm.health*" -type f \( -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" \) 2>/dev/null

find . -path "*com.xiaomi.wearable*" -type f \( -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" \) 2>/dev/null
```

**也可以全局查：**

```
find . -type f \( -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" \) 2>/dev/null | grep -Ei "keep|health|huami|zepp|xiaomi|wear"
```

<a id="section-20"></a>

### 2. 查看数据库表

```
sqlite3 app.db ".tables"
sqlite3 app.db ".schema"
```

**如果表很多，可以导出表名：**

```
sqlite3 app.db ".tables" | tr ' ' '\n' | sort
```

<a id="section-21"></a>

### 3. 搜运动关键词

```
sqlite3 app.db ".tables" | tr ' ' '\n' | grep -Ei "sport|run|walk|ride|bike|workout|track|gps|route|heart|sleep|step|health|exercise|activity"
```

**中文 App 中也可能出现拼音或中文字段，可继续搜：**

```
strings app.db | grep -Ei "sport|run|walk|ride|bike|workout|track|gps|route|heart|sleep|step|health|exercise|activity|跑步|运动|轨迹|心率|步数|睡眠"
```

<a id="section-22"></a>

### 4. 查看配置文件

```
find . -path "*shared_prefs*" -name "*.xml" 2>/dev/null
```

**搜索账号、设备、Token：**

```
grep -Rina "uid\|user\|phone\|token\|device\|mac\|bluetooth\|sync\|server\|host\|url" ./ 2>/dev/null
```

<a id="section-23"></a>

### 5. 查找轨迹文件

**有些 App 会保存 GPX、TCX、FIT、JSON 等轨迹或运动文件。**

```
find . -type f \( -iname "*.gpx" -o -iname "*.tcx" -o -iname "*.fit" -o -iname "*.json" -o -iname "*.log" \) 2>/dev/null | grep -Ei "sport|run|track|route|gps|health|keep|zepp|huami|xiaomi"
```

<a id="section-24"></a>

## 五、iOS 取证路径

**iOS 中运动软件数据通常在 App 沙箱、系统健康数据库、相册和备份 Manifest 中。**

**常见结构：**

```
AppDomain-<bundle_id>/
AppDomainGroup-group.<name>/
HomeDomain/
MediaDomain/
HealthDomain/
```

**重点文件：**

```
Manifest.db
Photos.sqlite
Health 数据库
Safari / WebKit 缓存
App 沙箱数据库
```

<a id="section-25"></a>

### 1. 从 Manifest.db 找 App 文件

**iOS 备份文件名通常是哈希名，需要通过 **`Manifest.db` 还原路径。

```
sqlite3 Manifest.db "select domain, relativePath from Files where domain like '%keep%' or domain like '%health%' or domain like '%zepp%' or relativePath like '%sport%' or relativePath like '%health%';"
```

<a id="section-26"></a>

### 2. 查找 App 数据库

```
find . -type f \( -name "*.sqlite" -o -name "*.db" -o -name "*.sqlite3" \) 2>/dev/null | grep -Ei "keep|health|zepp|huami|xiaomi|sport|run"
```

<a id="section-27"></a>

### 3. 系统健康数据

**在 iOS 上，很多运动数据可能同步到 Apple 健康。分析时应关注：**

```
步数
运动距离
锻炼记录
心率
睡眠
体重
能量消耗
数据来源
设备来源
```

**取证重点不是只看数值，而是看数据来源：**

```
来自手机
来自 Apple Watch
来自第三方 App
来自手动输入
来自同步导入
```

**如果记录显示来自第三方 App，还需要回到对应 App 沙箱继续核验。**

<a id="section-28"></a>

## 六、运动记录分析流程

**建议按照下面流程分析。**

<a id="section-29"></a>

### 第一步：确定 App 和账号

```
安装了哪些运动 App
用户登录了哪个账号
账号绑定了手机号还是邮箱
是否存在多个账号
是否有游客模式
```

**常见证据：**

```
shared_prefs
account.db
user.db
profile.json
login cache
WebView Cookies
```

<a id="section-30"></a>

### 第二步：确定设备来源

```
手机记录
手表记录
手环记录
跑步机记录
第三方平台导入
手动录入
```

**重点字段：**

```
source
device
device_id
model
mac
sn
firmware
provider
data_origin
```

<a id="section-31"></a>

### 第三步：找运动主记录

**优先找以下字段：**

```
start_time
end_time
duration
distance
calorie
avg_pace
avg_speed
sport_type
workout_type
```

**如果没有字段名，可以用关键词搜索数据库字符串：**

```
strings app.db | grep -Ei "start|end|duration|distance|calorie|pace|speed|sport|workout|run|ride"
```

<a id="section-32"></a>

### 第四步：找轨迹点

**重点判断是否有：**

```
latitude
longitude
lat
lng
lon
altitude
gps
route
track
```

**搜索：**

```
strings app.db | grep -Ei "latitude|longitude|lat|lng|lon|altitude|gps|route|track"
```

<a id="section-33"></a>

### 第五步：找心率和步频

```
strings app.db | grep -Ei "heart|hr|bpm|step|cadence|stride"
```

**如果存在心率和步频，运动记录可信度通常更高。**

<a id="section-34"></a>

### 第六步：生成时间线

**时间线至少包括：**

```
运动开始时间
运动结束时间
数据写入时间
数据同步时间
截图生成时间
图片修改时间
最后一次 App 打开时间
最后一次设备同步时间
```

<a id="section-35"></a>

## 七、Keep 取证重点

**Keep 的取证重点通常包括：**

```
跑步记录
骑行记录
健身课程
运动截图
社区动态
用户账号
设备同步
第三方健康数据
```

<a id="section-36"></a>

### 1. 常见包名

```
com.gotokeep.keep
```

**取证时先查：**

```
find . -path "*com.gotokeep.keep*" 2>/dev/null
```

<a id="section-37"></a>

### 2. 重点目录

```
/data/user/0/com.gotokeep.keep/databases/
/data/user/0/com.gotokeep.keep/shared_prefs/
/data/user/0/com.gotokeep.keep/files/
/data/user/0/com.gotokeep.keep/cache/
/sdcard/Android/data/com.gotokeep.keep/
/sdcard/Android/media/com.gotokeep.keep/
```

<a id="section-38"></a>

### 3. 重点搜索词

```
grep -Rina "run\|running\|sport\|workout\|route\|track\|gps\|pace\|distance\|calorie\|heart\|bpm" ./com.gotokeep.keep 2>/dev/null
```

**中文关键词：**

```
grep -Rina "跑步\|骑行\|运动\|轨迹\|配速\|心率\|公里\|卡路里" ./com.gotokeep.keep 2>/dev/null
```

<a id="section-39"></a>

### 4. 重点问题

**Keep 取证常见题目：**

```
某次跑步距离是多少？
运动开始时间是什么？
运动地点在哪个区域？
平均配速是多少？
是否有心率数据？
是否生成过运动截图？
是否发布到社区？
是否同步了智能穿戴设备数据？
```

<a id="section-40"></a>

### 5. Keep 截图真伪判断

**分析 Keep 截图时，不要只看图片内容。**

**应检查：**

```
相册数据库中的创建时间
图片 EXIF / PNG 元数据
截图分辨率是否符合设备
状态栏时间是否合理
运动记录数据库中是否存在对应记录
是否存在对应轨迹点
是否存在心率 / 步频 / 卡路里数据
是否存在分享缓存图
```

**如果只有截图，没有 App 原始记录、轨迹点和同步痕迹，证据强度较低。**

<a id="section-41"></a>

## 八、华为运动健康取证重点

**华为运动健康常用于华为手机、华为手表、华为手环的数据管理。**

<a id="section-42"></a>

### 1. 常见包名

```
com.huawei.health
```

**取证时先查：**

```
find . -path "*com.huawei.health*" 2>/dev/null
```

<a id="section-43"></a>

### 2. 重点数据

**华为运动健康重点关注：**

```
华为账号
绑定设备
手表型号
手环型号
设备 SN / MAC
跑步记录
骑行记录
步数
心率
血氧
睡眠
压力
运动轨迹
同步时间
```

<a id="section-44"></a>

### 3. 设备绑定分析

**重点找：**

```
device
wear
watch
band
bluetooth
mac
sn
serial
firmware
sync
```

**命令：**

```
grep -Rina "device\|wear\|watch\|band\|bluetooth\|mac\|serial\|firmware\|sync" ./com.huawei.health 2>/dev/null
```

<a id="section-45"></a>

### 4. 运动轨迹分析

**搜索：**

```
grep -Rina "gps\|track\|route\|latitude\|longitude\|lat\|lng\|distance\|pace" ./com.huawei.health 2>/dev/null
```

**如果数据库较多，可以逐个导出表名：**

```
for db in $(find ./com.huawei.health -type f \( -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" \) 2>/dev/null); do
  echo "===== $db ====="
  sqlite3 "$db" ".tables" 2>/dev/null
done
```

<a id="section-46"></a>

### 5. 常见问题

```
用户绑定的手表型号是什么？
最后一次同步时间是什么？
某天运动步数是多少？
跑步区域在哪里？
平均心率是多少？
睡眠开始和结束时间是什么？
压力异常日期是哪一天？
```

<a id="section-47"></a>

## 九、Zepp / Zepp Life / 小米运动健康取证重点

**这一类 App 名称容易混淆。**

**常见关系：**

```
Zepp              常用于 Amazfit 设备
Zepp Life         原 Mi Fit，常用于小米手环、体脂秤等
Mi Fitness        小米运动健康 / Xiaomi Wear
```

<a id="section-48"></a>

### 1. 常见包名

```
com.huami.watch.hmwatchmanager     Zepp
com.xiaomi.hm.health               Zepp Life / 原 Mi Fit
com.xiaomi.wearable                Mi Fitness / Xiaomi Wear
```

**查找：**

```
find . -path "*com.huami.watch.hmwatchmanager*" 2>/dev/null
find . -path "*com.xiaomi.hm.health*" 2>/dev/null
find . -path "*com.xiaomi.wearable*" 2>/dev/null
```

<a id="section-49"></a>

### 2. 重点数据

```
Amazfit / 小米手环绑定记录
设备型号
蓝牙地址
固件版本
运动记录
睡眠记录
心率记录
体重 / 体脂数据
同步时间
通知权限
```

<a id="section-50"></a>

### 3. 重点搜索词

```
grep -Rina "sport\|workout\|run\|walk\|ride\|track\|gps\|heart\|sleep\|weight\|device\|sync\|bluetooth\|mac" ./ 2>/dev/null
```

<a id="section-51"></a>

### 4. 典型分析方向

```
通过设备绑定记录确认手环型号
通过运动记录确认跑步时间
通过 GPS 轨迹确认运动区域
通过心率曲线判断是否真实佩戴
通过睡眠数据判断用户作息
通过体脂秤数据判断近期体重变化
```

<a id="section-52"></a>

## 十、运动轨迹真实性分析

**运动轨迹是运动软件取证中最容易被误判的部分。**

<a id="section-53"></a>

### 1. 看轨迹是否连续

**正常户外运动轨迹通常表现为：**

```
时间连续
坐标连续
速度变化自然
配速波动合理
暂停点合理
路线符合道路或操场结构
```

**异常轨迹可能表现为：**

```
坐标突然跨越很远
短时间速度异常
轨迹点数量极少
全程直线
没有 GPS 精度字段
没有心率和步频
轨迹与地图道路明显不符
```

<a id="section-54"></a>

### 2. 看配速是否合理

**常见单位：**

```
pace       配速，通常是 分钟/公里
speed      速度，通常是 米/秒 或 公里/小时
distance   距离，可能是 米 或 公里
duration   时长，通常是 秒 或 毫秒
```

**注意单位换算：**

```
1 km = 1000 m
1 hour = 3600 s
配速 = 时长 / 距离
速度 = 距离 / 时长
```

**例如：**

```
1.02 公里
3 分 59 秒
配速约 3'54"/km
```

**如果截图显示距离、时长、配速三者不匹配，需要进一步核查。**

<a id="section-55"></a>

### 3. 看心率和步频

**真实跑步通常会伴随：**

```
心率上升
步频稳定
配速波动
GPS 点连续
```

**如果运动距离很长但没有心率、没有步频、没有轨迹点，这只能说明存在一条运动记录，不能直接证明真实运动。**

<a id="section-56"></a>

### 4. 看来源字段

**重点找：**

```
source
provider
device
manual
import
sync
third_party
```

**如果记录来源是：**

```
manual
import
third_party
```

**要谨慎判断。这可能表示手动录入、第三方导入或同步数据，不一定是本机实时采集。**

<a id="section-57"></a>

## 十一、运动截图取证

**运动截图常见来源：**

```
用户手动截图
App 生成分享海报
社区动态图片
缓存缩略图
相册保存图
聊天转发图
```

**分析步骤如下。**

<a id="section-58"></a>

### 1. 看图片文件本身

```
exiftool image.png
file image.png
identify image.png
```

**关注：**

```
创建时间
修改时间
图片尺寸
颜色空间
软件标记
缩略图
是否有 EXIF
```

<a id="section-59"></a>

### 2. 看相册数据库

**Android 相册和媒体库可能保存：**

```
文件路径
拍摄时间
添加时间
修改时间
宽高
MIME 类型
来源目录
```

**iOS 则重点看：**

```
Photos.sqlite
ZASSET
ZGENERICASSET
ZADDITIONALASSETATTRIBUTES
```

<a id="section-60"></a>

### 3. 看截图内容是否合理

**重点检查：**

```
状态栏时间
电量
运营商
地图样式
距离
时长
配速
步频
卡路里
心率
轨迹线
地图地点
字体和 UI 版本
```

**但 UI 只能作为辅助，不能作为唯一判断依据。**

<a id="section-61"></a>

### 4. 和原始记录比对

**最终应比对：**

```
截图显示的运动时间
App 数据库中的运动时间
轨迹点中的 GPS 时间
相册中的截图时间
系统健康数据中的运动时间
手表同步时间
```

**只有多来源一致，结论才可靠。**

<a id="section-62"></a>

## 十二、常见题目与答案位置

<a id="section-63"></a>

### 题目：用户经常运动的区域是哪里？

**优先看：**

```
GPS 轨迹点
地图缓存
运动记录中的起点 / 终点
相册运动截图
运动轨迹缩略图
```

**分析方法：**

```
提取多次运动轨迹
统计轨迹点聚集区域
结合行政区划和地图判断地点
```

<a id="section-64"></a>

### 题目：用户平均跑步几公里？

**优先看：**

```
运动主记录表 distance 字段
跑步类型记录
统计多次跑步距离平均值
```

**注意：**

```
只统计跑步，不统计骑行、步行、健走
单位可能是米
异常记录需要剔除或说明
```

<a id="section-65"></a>

### 题目：某次运动耗时多久？

**优先看：**

```
start_time
end_time
duration
pause_duration
active_duration
```

**注意：**

```
总时长和运动时长可能不同
暂停时间可能不计入配速
```

<a id="section-66"></a>

### 题目：平均心率是多少？

**优先看：**

```
运动记录主表 avg_heart_rate
心率详情表 heart_rate / bpm
手表同步数据
```

**如果只有每日心率，没有运动心率，需要说明数据来源。**

<a id="section-67"></a>

### 题目：运动是否真实？

**需要综合判断：**

```
是否有运动主记录
是否有连续 GPS 点
是否有心率 / 步频
是否有设备来源
是否有同步时间
是否有截图或分享记录
是否与系统健康数据一致
```

**不能只凭截图下结论。**

<a id="section-68"></a>

## 十三、报告写法示例

<a id="section-69"></a>

### 1. 运动记录描述

```
经分析检材中 com.gotokeep.keep 应用数据，在其本地数据库中发现一条户外跑步记录。该记录显示运动开始时间为 2026 年 X 月 X 日 19:32，运动距离为 1.02 公里，运动时长为 3 分 59 秒，并存在对应 GPS 轨迹点。
```

<a id="section-70"></a>

### 2. 轨迹描述

```
该运动记录包含连续 GPS 轨迹点，轨迹点主要分布于某某区域，起点与终点均位于某某地点附近。轨迹点时间与运动开始、结束时间基本一致。
```

<a id="section-71"></a>

### 3. 设备来源描述

```
该运动记录来源字段显示为智能穿戴设备同步，检材中同时发现该账号绑定某型号手表，最后同步时间与运动记录生成时间接近。
```

<a id="section-72"></a>

### 4. 截图核验描述

```
相册中发现一张运动分享截图，截图显示的距离、时长、配速与 App 数据库中的运动记录一致。截图文件创建时间晚于运动结束时间，符合运动结束后生成或保存分享图的行为。
```

<a id="section-73"></a>

### 5. 谨慎结论

```
该运动记录在 App 本地数据库、GPS 轨迹点、设备绑定信息和相册截图中均存在对应痕迹，可认定该账号于上述时间段生成过该运动记录。是否由本人实际完成运动，还需结合设备佩戴情况、账号使用情况及其他证据进一步判断。
```

<a id="section-74"></a>

## 十四、常见误区

**运动软件取证中常见误区包括：**

```
只看截图，不看原始记录
只看距离，不看轨迹点
只看轨迹，不看心率和设备来源
只看 App，不看系统健康数据库
只看运动时间，不看同步时间
忽略手动录入和第三方导入
忽略单位换算
忽略 UTC 与本地时区
```

**尤其要注意：**

```
截图可以伪造
运动记录可以手动补录
数据可以从第三方平台同步
轨迹可能来自历史导入文件
健康数据可能来自不同设备
```

**因此，结论中应明确数据来源和证据强度。**

<a id="section-75"></a>

## 十五、总结

**运动软件取证的核心不是“看跑了多少公里”，而是判断这条运动数据从哪里来、什么时候生成、是否有轨迹、是否有心率、是否有设备来源、是否能被其他数据印证。**

**完整分析路径可以概括为：**

```
找 App
找账号
找设备
找运动记录
找轨迹点
找心率和步频
找截图和分享图
找同步痕迹
做时间线
做交叉印证
```

**对于 Keep、华为运动健康、Zepp、Zepp Life、小米运动健康这类 App，最有价值的数据通常不是界面上看到的结果，而是隐藏在本地数据库、缓存文件、设备绑定记录和系统健康数据中的原始痕迹。**
