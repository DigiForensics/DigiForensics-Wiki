---
title: "Volume 与绑定挂载取证"
slug: "server-docker-docker-volumes-and-bind-mounts"
canonical: "https://www.digiforensics.cn/wiki/server-docker-docker-volumes-and-bind-mounts"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:49+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "server"
space: "服务器与云取证"
node_path: ["Docker"]
---

# Volume 与绑定挂载取证

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/server-docker-docker-volumes-and-bind-mounts)

<a id="section-1"></a>

## 一、概述

[Docker 取证工件地图](server-docker-docker-artifact-map.md) 反复强调了一件事：**容器内的改动默认不落盘，容器一删就没**。

这条规则有一个例外。而这个例外恰恰是容器取证里最重要的发现来源——**挂载**。

容器可以把宿主机的目录"插"进自己文件系统的任意位置，写进去的东西**实际存放在宿主机上**，与容器本身无关。

于是形成一条清晰的分界：容器内的改动会随容器消失，跨过挂载边界的改动会长期留存。

这直接决定了取证的重点该往哪放。

**攻击者很清楚容器易失这个性质**，所以真正有价值的载荷——挖矿程序、WebShell、导出到本地的数据、植入的凭据——几乎都会落在挂载点上，而不是留在容器里。

只查 `overlay2/<id>/diff/`，**会完整漏掉攻击者真正想保留的部分**。这不是"漏了一部分"，而是漏掉了取证价值最高的那部分。

还有一个被大量人漏掉的事实：**`docker rm` 只删容器，不删卷。**

攻击者用完即弃的容器（`docker run --rm` 或跑完就 `rm`）留下的数据，只要没执行过 `docker volume prune`，就一直躺在 `/var/lib/docker/volumes/` 下。

这就是本篇标题里"金矿"的由来——**用完即弃恰恰留下了东西。**

**在取证流程中的位置**：本篇属于**采集与连接的中间层**。

它不做内容解析，做的是**把容器的挂载关系翻译成宿主机路径**，让分析工作可以转入常规文件系统流程。

上游依赖 [Docker 取证工件地图](server-docker-docker-artifact-map.md) 的路径全景与容器元数据固定；下游是三条并行的取证工作：**bind mount 走标准文件系统流程**（见 [ext4 结构与 inode](../../filesystem/filesystem-unix/filesystem-unix-ext4-inode.md)）、named volume 作为被删容器的残留数据源、以及 **`docker diff` 与删除文件的取回**。

卷里的数据最终要交给业务侧判读——数据库 binlog 证明批量导出、WebShell 检测，都不在本篇范围内。

两类挂载的取证差异是本篇的主结构：

| | **named volume（命名卷）** | **bind mount（绑定挂载）** |
|---|---|---|
| 创建方式 | `docker volume create` / `-v name:/path` | `-v /host/path:/path` 或 `--mount type=bind` |
| 宿主落地位置 | `/var/lib/docker/volumes/<name>/_data` | **就是那个宿主机路径本身** |
| 管理归属 | Docker 自己的目录，Docker 会"管"它 | **宿主机自己的目录，Docker 只是挂上去** |
| 谁在用 | 通常是数据库、上传目录等**应用数据** | 通常是配置、日志、代码目录 |
| 取证要点 | **删了容器数据还在**；可能被多个容器共享 | 直接进常规文件系统流程；**可能被业务方改动过，需区分** |

**涉及的证据形态**：

| 形态 | 具体位置 | 说明 |
|---|---|---|
| 挂载关系 | `containers/<id>/config.v2.json` 的 `MountPoints` | `docker inspect` 的 `.Mounts` 就是它，照着 `Source` 走 |
| 挂载五字段 | `Type` / `Source` / `Destination` / `Mode` / `RW` | **`tmpfs` = 数据只在内存，宿主磁盘上没有**；`Mode` 含 `ro` 即该路径未被写入 |
| 卷数据 | `/var/lib/docker/volumes/<name>/_data/` | **持久化边界**，被删容器的残留常在此 |
| 卷元数据 | `/var/lib/docker/volumes/<name>/` 下的配置文件 | 含挂载点、创建时间、标签 |
| bind mount 目标 | 宿主机上的真实路径 | 走标准文件系统取证流程 |
| 差异记录 | `docker diff` 的 C/A/D 三类 | 在线 CLI 的等价物在磁盘上是 diff 目录的结构痕迹 |

**`mounts` 列表就是取证路线图**。看到 `Source` 是 `/`、`/etc`、`/var/run/docker.sock` 属于高危配置（判定标准见 [容器逃逸与运行时痕迹](../server-k8s/server-k8s-container-escape-and-runtime-artifacts.md)）。

看到 `Mode` 含 `ro` 则是**重要的否定性证据**——那条路径确定没被写入过。

哪些数据会长期留存、容器的哪些路径写进去的东西在宿主机哪个位置、某个挂载点是可写还是只读、被删容器的数据留在哪里。

卷里的文件是谁写的（可能来自正常业务，也可能来自攻击者，**需要内容与时间判读**）；容器运行时是否访问过某文件（卷本身不记录访问行为）；`tmpfs` 挂载里的内容（**停止即失，只能在线取或从内存侧补**）。

**卷里有 WebShell 不代表业务被攻陷，**也可能是正常运维上传的工具——两者需要靠内容与时间区分，见 [4.3 内容判读与归因](#section-30)。

**内容边界**：所有命令面向**已获得合法授权**的目标主机或已制作的只读镜像，目标是发现与固定证据，**不提供任何入侵手段**。

检测到 WebShell 痕迹时，写的是**如何识别与如何排除误报**（见 [网站目录与 WebShell 检测](../server-web/server-web-webshell-detection.md)），不涉及载荷构造。

**读者前提**：需要 [Docker 取证工件地图](server-docker-docker-artifact-map.md) 的容器元数据知识、[镜像层与 overlay2 解析](server-docker-overlay2.md) 的层与写层概念，以及标准的 Linux 文件系统取证流程。

建议先按 [3.1 第 1 步](#section-9) 拿到挂载关系再动手——挂载关系没拿到就进目录遍历，等于在几百 GB 里盲找。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 容器文件系统的分层：哪里会持久，哪里不会

理解挂载的关键，是先把容器内一个路径的"归属"想清楚：

```
容器内看到的：
/app/data/orders.db  ← 容器内 /app 是镜像层，/app/data 是挂载点
     │                      ↑ 写这里不会进容器层
     │
     └──→ 实际落在宿主机的某个真实目录
           named volume : /var/lib/docker/volumes/appdata/_data/orders.db
           bind mount   : /srv/digiforensics/data/orders.db

容器内看到的：
/usr/local/bin/ksync  ← 纯容器层路径，★不挂载
     │
     └──→ 实际落在 /var/lib/docker/overlay2/<id>/diff/usr/local/bin/ksync
           容器删除即消失
```

三条由此推出的推论：

1. **`mounts` 列表就是取证路线图。** `docker inspect` 的 `.Mounts`（磁盘上即 `config.v2.json` 的 `MountPoints`）给出了每个挂载点的 `Source`（宿主机路径）与 `Destination`（容器内路径），照着 `Source` 走就是普通文件系统取证。

2. **未挂载路径的证据强度弱。** `diff/` 里看到的东西，攻击者可以"用完即删"而不留痕迹；卷里看到的东西，**攻击者是主动要它活着的**。

3. **业务数据卷不等于无害。** 攻击者写进业务数据卷的 WebShell 会被业务进程加载执行，其危害等同于站点目录被植入（见[《网站目录与 WebShell 检测》](../server-web/server-web-webshell-detection.md)）。

<a id="section-4"></a>

### 2.2 `Mounts` 字段逐项解读

`docker inspect` 的 `.Mounts` 数组每一项代表一个挂载。**这五个字段必须逐个看**：

| 字段 | 含义 | 取证判据 |
|---|---|---|
| **`Type`** | `volume`（命名卷）/ `bind`（绑定挂载）/ `tmpfs`（内存文件系统）/ `npipe` 等 | 出现 **`tmpfs`** = 数据只在内存，**宿主磁盘上没有，容器停止即失**（当证据处理时要单列） |
| **`Source`** | **宿主机上的实际路径** | ★★★★★ **取证的核心**。看到 `/`、`/etc`、`/var/run/docker.sock` 等即高危 |
| **`Destination`** | 容器内的挂载点路径 | 与镜像的 `Config.Volumes` 对比可发现**运行时多挂的目录** |
| **`Mode`** | 挂载选项字符串，含 `ro`/`rw`、`z`（SELinux）、`Z`、`nocopy` 等 | **`ro`（只读）= 该路径未被写入**，是重要的否定性证据；**`rw` = 可写，攻击者可能写过** |
| **`RW`** | 布尔值，是否可写 | 与 `Mode` 里的 `ro` 对应，`false` 即只读 |

`Mounts` 与磁盘上的字段对应关系，离线读 `config.v2.json` 时注意结构略有不同：

```json
// docker inspect 的 Mounts（在线）
"Mounts": [
  {"Type":"volume","Name":"appdata","Source":"/var/lib/docker/volumes/appdata/_data",
   "Destination":"/data","Driver":"local","Mode":"","RW":true,"Propagation":""},
  {"Type":"bind","Source":"/srv/digiforensics/config","Destination":"/etc/app",
   "Mode":"ro","RW":false,"Propagation":"rprivate"},
  {"Type":"tmpfs","Source":"","Destination":"/run","Mode":"","RW":true}
]
```

```json
// config.v2.json 的 MountPoints（离线，key 是容器内路径）
"MountPoints": {
  "/data": {"Source":"/var/lib/docker/volumes/appdata/_data","Destination":"/data","RW":true,"Type":"volume"},
  "/etc/app": {"Source":"/srv/digiforensics/config","Destination":"/etc/app","RW":false,"Type":"bind"},
  "/run": {"Source":"","Destination":"/run","RW":true,"Type":"tmpfs"}
}
```

> ⚠️ `HostConfig.Binds` 与 `Mounts` 都要看：前者是**用户请求的原始字符串**（`["/:/host", "/srv/data:/data:ro"]`），后者是 Docker 解析后的结果。原始串能看出用户写的**挂载模式与选项**，解析结果更完整。两者不一致时以 `Mounts` 为准，但 `Binds` 里可能有解析后丢失的信息。

<a id="section-5"></a>

### 2.3 named volume 的落盘位置与生命周期

```
/var/lib/docker/volumes/
├── appdata/
│   ├── _data/          ★★★ 实际数据在这里，与普通目录无差别
│   └── metadata.db     ★★  卷的元数据（名称、创建时间、driver、labels、挂载点）
├── pgdata/
│   └── _data/
└── <name>/
```

| 位置 | 内容 | 取证价值 |
|---|---|---|
| `volumes/<name>/_data/` | **真实数据**，普通 ext4 目录 | ★★★★★ |
| `volumes/<name>/metadata.db` | 卷的 `Name`/`CreatedAt`/`Labels`/`Mountpoint` | ★★★★ **卷的创建时间是重要时间锚点** |
| `volumes/metadata.db` | 全局卷元数据（可能在新版 Docker 中存在） | ★★★ |

**生命周期矩阵（决定证据是否还在）**：

| 操作 | 卷内数据 | 结论 |
|---|---|---|
| `docker rm <container>` | **保留** | ★ 删容器**不删卷**，数据仍在 |
| `docker rm --volumes <container>` | **删除** | 匿名卷随容器删除而消失 |
| `docker volume rm <name>` | **删除** | 显式删卷，数据不可恢复 |
| `docker volume prune` | **删除未使用的卷** | **★ 最高危的误删操作**，会连带删掉"已不用但有证据"的卷 |
| `docker run --rm` | 匿名卷随 `--rm` 删除 | 需及时固定 |
| 宿主机重启 | **保留** | 卷是磁盘数据 |

> **取证推论**：`docker volume ls` 列出的是**当前仍存在**的卷。"已删除但未 prune 的卷"这个说法本身不成立——`volume rm` 是直接删目录，不进回收站。所以准确表述是："`docker rm` 删了容器但卷还在，卷数据仍可取证"，而不是"已删除的卷还能恢复"。真正会丢数据的是 `volume rm` 与 `volume prune`，报告里要区分清楚。

<a id="section-6"></a>

### 2.4 `docker diff` 的用法与 C/A/D 语义

`docker diff <container>` 把**容器当前文件系统**与**它所基于的镜像**逐项比较，输出三类变更：

| 标记 | 含义 | 实际含义 | 取证价值 |
|---|---|---|---|
| **`A`** | **Added** | 容器内**新增**的文件或目录 | ★★★★★ **最可疑**：容器启动后新增的东西必然是运行期行为 |
| **`C`** | **Changed** | 内容被**修改** | ★★★★★ 配置文件被改（如 `.bashrc`、`crontab`、应用配置） |
| **`D`** | **Deleted** | 被**删除** | ★★★★ **`D` 项有独立价值**：被删文件的原始内容仍在 lowerdir（镜像层）里，可取回 |

```bash
docker diff digiforensics-app
# A /opt/app/.cache/miner                    ★ 挖矿程序落地
# A /tmp/.X11-unix
# C /etc/crontab
# C /root/.bashrc
# D /usr/share/nginx/html/index.html         ★ 删了业务页面
```

**三条使用要点**：

1. **`docker diff` 不含挂载点内容。** 挂载点的路径会被显示为一条 `A`/`C` 记录指向挂载点本身，**其内容不参与比较**。想看挂载点内容必须去宿主机的 `Source` 路径。
2. `D`（删除）的文件能取回，但不能用 `docker cp`。 关键点：overlay 用 **whiteout 特性文件**（`.wh.<文件名>`）在 upperdir 里"遮住"lower 的同名文件，**被删文件本体从未从镜像层消失**。所以 `docker cp` 会失败（容器里已经没有这个路径了），正确做法是手工遍历 `link` 里的 lowerdir 链定位原文件（见 3.4 的命令）。
3. **它是"相对镜像"的差异，不是"时间序"。** 输出**不含时间戳**，时间线要靠 `State.StartedAt`、文件 mtime、日志三处交叉。

> ⚠️ **不产生输出的三种情况**：容器已被 `rm`；容器与镜像的差异为空（干净容器）；log driver 或存储驱动为特殊实现时行为可能不同。**"没有 diff 输出"不等于"没有活动"**——攻击者完全可以在 volume 里动手，那部分 `docker diff` 根本看不到。

<a id="section-7"></a>

### 2.5 容器内 `/tmp` 为什么不落盘

这是本篇最容易被误解的一点。

容器内任何路径的写入，默认都落在 `overlay2/<id>/diff/`（upperdir）里，包括 `/tmp`。

但有两个例外让"默认"不成立：

| 情况 | 是否落宿主磁盘 | 说明 |
|---|---|---|
| 容器内 `/tmp` 写入 | ✅ 落在 `overlay2/<id>/diff/tmp` | **落盘，但随容器删除而消失** |
| 容器内 `/tmp` 若是 tmpfs 挂载 | ❌ **只在内存** | 需看 `Mounts` 里有没有 `Type: tmpfs` 指向 `/tmp` |
| `docker run` 显式 `-v /host/tmp:/tmp` | ✅ 落在宿主机指定目录 | **此时容器内 `/tmp` 反而是持久的** |

**准确表述**："容器内 `/tmp` 里的数据默认不落盘"这个说法**不准确**。应写成："容器内 `/tmp` 的数据落在一个随容器删除即消失的写层里，容器仍在时可以从 `overlay2/<id>/diff/tmp` 读到；只有当 `/tmp` 被显式挂载为 tmpfs 或挂到宿主目录时，数据才有不同的生命周期。"

这个区分在报告里很关键：在 `diff/tmp` 里找到的挖矿程序，是"容器仍在运行"的证据；若容器已删，则该目录已不存在，必须去 `docker diff` 记录、卷、或内存里另找。

卷里的业务数据往往就是库文件。拿到数据文件之后的引擎识别、时区归一、完整性校验与报告表述，是与容器无关的通用流程，见[数据库取证通用方法](../../mobile/mobile-database/mobile-database-database-forensics-methods.md)。

---

<a id="section-8"></a>

## 三、操作步骤

<a id="section-9"></a>

### 3.1 第 1 步：先拿挂载关系（在线与离线两条路）

```bash
# 在线：逐个容器的 Mounts，一行一个挂载点
for c in $(docker ps -aq); do
  echo "== 容器 $c"
  docker inspect "$c" | jq -r '.[0].Mounts[]? | "\(.Type)\	\(.Source)\	\(.Destination)\	Mode=\(.Mode)\	RW=\(.RW)"'
  docker inspect "$c" | jq -r '.[0].HostConfig.Binds[]? // empty'      # 原始挂载串
done

# 离线：从 config.v2.json 的 MountPoints 取同一批信息
python3 -c "
import json,glob
for f in sorted(glob.glob('/mnt/df/var/lib/docker/containers/*/config.v2.json')):
    d=json.load(open(f))
    print('==', d.get('Name'), d.get('Created'))
    for dest,m in (d.get('MountPoints') or {}).items():
        print(f\"  {m.get('Type')}\	{m.get('Source')}\	{dest}\	RW={m.get('RW')}\")
"
```

**输出按 `Source` 分组，得到三张清单**（这三张清单就是取证路线图）：

| 清单 | 来源 | 接下来做什么 |
|---|---|---|
| **卷清单** | `Type=volume` 的 `Source`（在 `/var/lib/docker/volumes/` 下） | 3.3 |
| **宿主目录清单** | `Type=bind` 的 `Source` | 3.2 |
| **内存挂载清单** | `Type=tmpfs` | **记为"数据不可得"，写进报告** |

<a id="section-10"></a>

### 3.2 第 2 步：bind mount —— 走常规文件系统取证流程

绑定挂载指向的是**宿主机自己的业务目录**，分析手法与[《Linux 服务器取证工件地图》](../server-panel/server-panel-linux-server-artifact-map.md)完全一致：

```bash
# 1) 目录总览与时间线
ls -la /mnt/df/srv/digiforensics/config/
stat -c '%n  mtime=%y  ctime=%z  mode=%a  owner=%U:%G' /mnt/df/srv/digiforensics/config/
find /mnt/df/srv/digiforensics/config -type f \
     -printf '%T@ %TY-%Tm-%Td %TH:%TM %m %u:%g %s %p\
' | sort -n | tail -30

# 2) 异常筛查（非业务文件、可执行落地、隐藏目录）
find /mnt/df/srv/digiforensics/config -name '.*' -type f | head -20
find /mnt/df/srv/digiforensics/config -type f -perm /111 -printf '%m %TY-%Tm-%Td %p\
' | head -20
find /mnt/df/srv/digiforensics/config -type f -newermt '2024-03-17 00:00' | head -40

# 3) 与容器内看到的文件名交叉验证（容器还在时）
docker exec 不做；改用 docker cp 取出（见 3.5），比对哈希
```

**绑定挂载的额外注意点**：

| 注意点 | 说明 |
|---|---|
| **业务方可能自己改过** | bind mount 指向的是业务目录，**改配置可能是正常运维行为**，不能凭"文件变了"定性 |
| **写入者不一定来自容器** | 同一目录宿主机进程也能写。取 `mtime` 并与容器 `StartedAt` 对齐才可关联 |
| **`Mode=ro` 是重要否定证据** | 只读挂载意味着**该路径在容器运行期间不可能被容器写入**，可写进报告作为排除依据 |
| **部分挂载可能遮蔽了底层镜像内容** | 容器内看到的 `/etc/app` 是宿主目录，**镜像层里原本的 `/etc/app` 被遮住了**（可在 lowerdir 里读到被遮蔽的原内容） |

<a id="section-11"></a>

### 3.3 第 3 步：named volume —— 被删容器留下的"金矿"

```bash
# 1) 卷全量清单（含未被任何容器挂载的 dangling 卷）
ls -1 /mnt/df/var/lib/docker/volumes/
docker volume ls
docker volume ls -f dangling=true          # ★ 未被任何容器使用的卷，最可能是"用完即弃"的
docker volume inspect appdata pgdata       # 取 Mountpoint、CreatedAt、Labels

# 2) ★ 卷元数据（创建时间是关键锚点）
for v in /mnt/df/var/lib/docker/volumes/*/; do
  echo "== $v"; ls -l "$v"; cat "$v/metadata.db" 2>/dev/null
done

# 3) 逐个卷扫时间线（★ 从"最近改动"倒查最快）
for v in /mnt/df/var/lib/docker/volumes/*/_data; do
  echo "===== $v"
  find "$v" -type f -printf '%TY-%Tm-%Td %TH:%TM %m %u:%g %s %p\
' 2>/dev/null | sort | tail -15
done

# 4) 高危文件筛查（跨所有卷）
find /mnt/df/var/lib/docker/volumes/*/_data -type f \
     \( -name 'xmrig' -o -name '*.sh' -o -name '*.jsp' -o -name '*.php' \
        -o -name 'authorized_keys' -o -name '*.py' -o -name 'id_rsa' \) \
     -printf '%TY-%Tm-%Td %TH:%TM %m %s %p\
' 2>/dev/null | sort | tail -40

# 5) 可执行文件（挖矿/后门落地）
find /mnt/df/var/lib/docker/volumes/*/_data -type f -perm /111 \
     -printf '%TY-%Tm-%Td %TH:%TM %m %s %p\
' 2>/dev/null | sort | tail -30

# 6) 数据库类卷：直接查可疑外连账号（MySQL/PG 通用思路）
ls -la /mnt/df/var/lib/docker/volumes/pgdata/_data/ 2>/dev/null
```

**卷的 `metadata.db` 值得单独看**：它记录卷的 `CreatedAt`、`Labels`、驱动。**卷的创建时间通常早于或等于攻击窗口**——如果某个卷在入侵时段前后被创建，且名字与业务无关（比如 `miner`、`tmp123`），那它本身就是一条独立线索。

<a id="section-12"></a>

### 3.4 第 4 步：`docker diff` 与删除文件取回

```bash
# 1) 列变更
docker diff digiforensics-app | tee /evidence/docker-diff-app.txt
grep '^A ' /evidence/docker-diff-app.txt     # 新增：最可疑
grep '^C ' /evidence/docker-diff-app.txt     # 修改：配置文件被篡改
grep '^D ' /evidence/docker-diff-app.txt     # 删除：可从镜像层取回

# 2) ★ 取回被删除的文件（D 项）
#    overlay 用 whiteout（.wh.<name>）在 upperdir 遮住 lower 文件，被删文件本体仍在 lowerdir。
#    docker cp 会失败（容器路径已不存在），必须手工遍历 link 里的 lowerdir 链。
UP=$(docker inspect -f '{{.GraphDriver.Data.UpperDir}}' digiforensics-app)
LINK="$(dirname "$UP")/link"          # 与 UpperDir 同级，lowerdir 链，从低到高
cat "$LINK"                            # 例：overlay /var/lib/docker/overlay2/<id>/diff:/var/...:<id>/diff

# 去掉 "overlay " 前缀，逐层由低到高查找
sed 's|^overlay ||' "$LINK" | tr ':' '\
' | while read -r d; do
  [ -f "$d/usr/share/nginx/html/index.html" ] && { echo "找到于 $d"; SRC="$d/usr/share/nginx/html/index.html"; break; }
done

cp --preserve=all "$SRC" /evidence/deleted-index.html

# 对照：upperdir 里的 whiteout 特性文件，是"这里删过东西"的直接物证
ls -la "$(dirname "$UP")/diff/usr/share/nginx/html/" | grep '\.wh\.'
# -rw-r--r-- 1 root root 0 .wh.index.html    ← ★ 该文件曾存在于 lower 层

# 3) 新增文件直接取（在 upperdir 里）
find "$UP" -type f -newermt '2024-03-18 00:00' -printf '%TY-%Tm-%Td %m %s %p\
' | head -20
```

> ⚠️ 对正在运行的容器，`diff/` 里的文件可能正在被写入或已被删除。 正确做法是 `cp` 出来做哈希，不要原地分析；也不要在 `diff/` 里 `rm`/`mv` 任何东西——那会直接毁掉证据并可能让运行中的容器崩溃。

<a id="section-13"></a>

### 3.5 第 5 步：`docker cp` 提取文件

`docker cp` 从容器复制文件到宿主机，**比 `docker exec` 安全**（不执行任何容器内命令）：

```bash
# 从运行中的容器复制
docker cp digiforensics-app:/opt/app/.cache/miner /evidence/miner-from-container
# 从已停止的容器复制（仍可用）
docker cp 4f1c9a2b7e30:/etc/crontab /evidence/crontab-from-container

# 复制整个目录（加 / 以保留目录结构）
docker cp digiforensics-app:/app/logs/. /evidence/app-logs/

# 校验
sha256sum /evidence/miner-from-container | tee /evidence/hashes.txt
file /evidence/miner-from-container
```

| 场景 | 能否用 `docker cp` | 备注 |
|---|---|---|
| 容器运行中 | ✅ | 但文件可能正在写，**建议先 `cp` 后校验** |
| 容器已停止 | ✅ | 读的是 `upperdir`，内容稳定 |
| 容器已 `rm` | ❌ | 只能从 `overlay2` 或卷里找 |
| 需要跨容器取 | ⚠️ | 不能直接从一个容器 cp 到另一个，需先落到分析机 |

> ⚠️ `docker cp` 会在容器与 dockerd 之间产生操作记录（若开启了审计或事件追踪）。**取证时优先用离线读 `upperdir` 的方式**，`docker cp` 是在容器已无法从磁盘还原时的补充手段。

<a id="section-14"></a>

### 3.6 第 6 步：验证环节

| 验证对象 | 方法 | 通过标准 |
|---|---|---|
| 挂载关系完整性 | `.Mounts` 的 `Destination` 集合与镜像 `Config.Volumes` 对比 | 多出的即运行时挂载，**逐个解释** |
| 卷内文件与容器内一致 | `docker cp` 取出的文件 sha256 与卷内同名文件 sha256 比对 | 一致则该文件确实由挂载点提供 |
| 只读挂载未被写入 | `Mode`/`RW` 为 `false`/`ro` | **可作为否定结论写入报告** |
| `docker diff` 的 `D` 项取回成功 | 从 lowerdir 找到的文件的 mtime 早于容器 `StartedAt` | 时间关系自洽 |
| 攻击者写入 vs 业务正常写入 | 文件 mtime 与容器 `StartedAt`、卷 `CreatedAt` 对齐 | 只有落在入侵窗口内的才可关联 |
| 分析未污染证据 | `umount` 后 `sha256sum -c` | 全部 OK |

---
<a id="section-15"></a>

## 四、常见陷阱

卷与挂载的误判集中在两处：一是把「攻击者主动留下的东西」与「系统自动产生的空壳」混为一谈，二是**把「卷没查到」当成「没发生过」**。本章按「先拿挂载关系 → 再判读证据强度 → 最后限定结论」归组，重点讲清卷的生命周期、`docker diff` 的边界，以及哪些路径的数据**物理上就不在磁盘上**。

贯穿全篇的一条主线：**Docker 的卷是一个独立于容器的生命周期对象**。容器删了卷不一定删，卷还在了容器却可能已经不在——这两个方向都会让人写出方向相反的错误结论。

<a id="section-16"></a>

### 4.1 挂载关系与环境判定

<a id="section-17"></a>

#### 陷阱 1：只查 `diff/` 不查卷

**现象**：把 `overlay2/<id>/diff/` 整个遍历一遍，没找到挖矿程序或导出数据，写下「该容器内未见攻击痕迹」。

**原因**：容器内**未挂载路径**的写入才落 `diff/`。一旦路径跨过挂载边界，写入实际发生在宿主机的卷或 bind mount 目录里，`diff/` 里只会多出一条指向挂载点本身的记录，**内容完全不参与比较**。而攻击者恰恰清楚容器易失，所以真正想保留的东西几乎都写在卷上。

**影响**：仅检查可写层会遗漏挂载卷或宿主目录中的数据。

结论「未见攻击痕迹」不仅漏掉载荷，还会连带否定掉后续所有基于「没找到」的判断。

**核查**：先按 `Mounts` 的 `Source` 分成三张清单（卷清单、宿主目录清单、tmpfs 清单），三张都要走一遍。

卷优先查 `dangling` 状态（未被任何容器使用，最可能是「用完即弃」留下的），宿主目录按常规文件系统流程处理，tmpfs 单独列为「数据不可得」。

只查 `diff/` 得出的结论必须写明范围：「在容器可写层检查内未发现」。

<a id="section-18"></a>

#### 陷阱 2：以为 `docker rm` 会删卷

**现象**：看到 `docker ps -a` 里没有某个容器，判定「该容器的数据已不可得」，报告写「攻击痕迹已随容器删除」。

**原因**：**`docker rm <容器>` 不删卷。** 卷是独立的对象，只有三种情况会连带删除：`docker rm --volumes`、匿名卷随 `--rm` 创建的容器一起销毁、以及显式的 `docker volume rm` / `docker volume prune`。普通 `docker rm`（不带 `--volumes`）之后，卷数据完整躺在 `volumes/<name>/_data`。

**影响**：把「容器没了」当成「数据没了」，会直接放弃「被删容器留下的金矿」。

**这是用完即弃型入侵最容易留下完整工具链的地方。** 第五章的案例就是靠这一点把整条数据窃取链还原出来的。

**核查**：容器消失后必须**独立枚举卷**：`docker volume ls` 全量列出，再 `docker volume ls -f dangling=true` 单独挑出未被任何容器使用的。

逐个读 `metadata.db` 拿 `CreatedAt`，与入侵时间窗比对——卷名是随机十六进制且带可疑创建时间的，是「`--rm` 容器匿名卷」的直接特征。

<a id="section-19"></a>

#### 陷阱 3：★ 在目标机执行 `docker volume prune`

**现象**：为了「清理无用资源」，分析员或运维执行了 `docker system prune` 或 `docker volume prune`。

**原因**：直觉上「未被使用的卷」等于「无用的卷」。

但在取证语境下，**未被任何容器使用的卷恰恰最可疑**——正常运维留下的卷通常都还挂载在业务容器上，而攻击者用完即弃的容器删除后，它的卷就成了 dangling 状态。`prune` 会把这些卷当成垃圾清掉。

**影响**：不可逆。卷内数据不进回收站、没有备份、`metadata.db` 的 `CreatedAt` 一并消失。

第五章那个案例的卷 `9c4f7a1e2b` 若在取证前被 `prune`，整条数据窃取证据链**归零且无法补救**，案件只能停在「有入侵迹象但无法证明窃取范围」。

**核查**：`prune`、`volume rm`、`system prune`、`image prune`、`docker rm` 在取证机上一律禁止。

发现可疑卷时正确动作是先把 `volumes/<name>/` 整目录（含 `_data` 与 `metadata.db`）复制到证据区并哈希，再由委托方决定是否清理。确需清理必须先书面记录清理动作、时间与执行人。

<a id="section-20"></a>

#### 陷阱 4：把「已删除的卷」写成可恢复

**现象**：报告里写「已删除的卷数据可尝试恢复」或「卷已进回收站」。

**原因**：`docker volume rm` 是**直接删除目录**，不进任何回收站、不做软链接保留。

所以「已删除但未 prune 的卷」这个说法本身不成立——要么卷还在，要么就没了。

**影响**：给委托方一个不存在的希望。后续一旦发现卷真的不在，报告的严谨性受质疑，且会拖延整个调查对「是否需要向云厂商申请快照」的决策。

**核查**：表述要精确到「**现存卷集合**」与「**缺失卷**」两件事：「容器已删除，其数据是否随卷保留取决于创建时是否使用匿名卷与 `--rm`；现存卷清单中不含对应命名卷，故该卷内容不可得（除非曾做卷备份或存储快照）」。

真正会丢数据的操作是 `volume rm` 与 `volume prune`，这两条要在报告的证据边界里点名。

<a id="section-21"></a>

#### 陷阱 5：把具名卷与匿名卷当成同一类对象

**现象**：`docker volume ls` 列出 20 个卷，报告写「发现 20 个业务数据卷」，并把其中名为 `<name>` 的一个与另一次入侵挂上钩。

**原因**：**这两类卷的创建者意图完全不同。**

具名卷（named volume）由人在 `docker volume create` 或 `-v <name>:<path>` 时显式创建并起名，它必然出现在某份编排文件或某条 `docker run` 命令里，因此它的创建时间通常与业务部署时间吻合。匿名卷则是容器创建时在 `VOLUME` 指令或 `-v /path` 无名形式下自动生成的，名字是一串随机十六进制，且只在容器目录（`config.v2.json`）里留下 `MountPoints` 记录——容器一删，这条记录也没了，于是卷就成了一个**没有归属、没有标签、无人认领的目录**。

**影响**：两类卷混在一起清点，会把「没人认领的随机目录」当成正常业务卷而略过——而随机十六进制命名正是攻击者用完即弃的直接特征。反过来，把具名卷当成匿名卷分析，则会漏查它在 Compose/编排配置里的引用关系，那条引用能直接告诉你哪个业务用了它。

**核查**：按命名形态与 `MountPoints` 引用分两类处理。

```bash
# ① 具名卷：名字可读，且应在编排文件里有引用
docker volume ls --format '{{.Name}}' | grep -vE '^[0-9a-f]{64}$'
# 再到编排配置里反查引用
grep -rn 'volumes:' -A5 /path/to/docker-compose.yml 2>/dev/null

# ② 匿名卷：64 位十六进制命名，需回查容器目录才能确认曾被谁挂载
docker volume ls --format '{{.Name}} {{.CreatedAt}}' | grep -E '^[0-9a-f]{64} '
# 离线读：config.v2.json 的 MountPoints 里是否出现该卷名
grep -rl "9c4f7a1e2b" /var/lib/docker/containers/*/config.v2.json
```

具名卷报「卷 `<name>` 创建于 `<CreatedAt>`，在 `<编排文件>` 中被 `<服务>` 引用」；匿名卷报「匿名卷 `<name>`，创建于 `<CreatedAt>`，创建者容器已删除，其用途无法从现存容器元数据判定」。「无法判定」要写出来，不要用卷里的内容反推它的用途——卷里有什么不等于卷被造出来做什么。

<a id="section-22"></a>

#### 陷阱 6：把 `metadata.db` 里的 `Mountpoint` 当成卷的当前位置

**现象**：从 `volumes/<name>/metadata.db` 读出 `Mountpoint` 字段，报告写「该卷当前挂载于 `<路径>`，因此该路径下的数据属于此卷」，然后直接去那个路径取证。

**原因**：`Mountpoint` 记录的是最后一次被 Docker 挂载时的位置，而 Docker 的卷落盘位置从来不随 `Mountpoint` 变化。

卷的真实数据恒定在 `/var/lib/docker/volumes/<name>/_data`（2.3 节那张目录树），`Mountpoint` 只是那次挂载在宿主机命名空间里的一个呈现路径。当卷不再被任何容器使用时，这个字段就是一个**陈旧值**——它记录的是「上一次运行时它挂在哪儿」，不是「现在它在哪儿」，也不是「它归谁」。

另一半原因是容器重建：`docker compose up` 重建容器时，卷被摘下再挂到新容器上，`Mountpoint` 会被更新或保持不变，**而卷里的数据从头到尾没动过**。所以拿 `Mountpoint` 去对齐时间线，会把「挂载关系变化」误当成「数据变化」。

**影响**：按陈旧 `Mountpoint` 定位，会跑到一个当前根本不挂载该卷的路径下取证。那里可能是空的（**得到一份假的阴性结论**），也可能是另一个业务目录（**把别人的数据当成这个卷的**）。第五章那种「在卷里找到导出文件」的动作若走错路径，整条结论的证据来源就不可追溯了。

**核查**：取数一律走 `_data`，`Mountpoint` 只作参考字段记录。

```bash
# 数据恒定在这里，与是否挂载无关
ls -la /var/lib/docker/volumes/<name>/_data/

# Mountpoint 只在报告里作为「最后一次挂载位置」出现，不作为取证路径
sqlite3 /var/lib/docker/volumes/<name>/metadata.db ".dump" | head -20
# 关注字段：Name / CreatedAt / Mountpoint / Labels / Options
# Mountpoint 的正确用法：「该卷最后一次被 Docker 挂载至 <路径>，该记录不反映数据当前位置」
```

若报告里必须提挂载位置，就与 `Mounts[].Destination` 一起写，并注明这是容器侧路径（容器内路径），而 `_data` 是宿主侧路径。三者的对应关系在 2.2 节那张 `Mounts` 表里。

<a id="section-23"></a>

### 4.2 `docker diff` 与删除文件

<a id="section-24"></a>

#### 陷阱 7：把「`docker diff` 没输出」当成没有活动

**现象**：对某容器执行 `docker diff` 无输出，结论写「容器未被使用」。

**原因**：三种情况都不产生输出——容器已被 `rm`（无法执行）；容器与镜像确实无差异（干净容器）；**容器改动全在挂载点上**。第三种最要命：`diff/` 不含挂载点内容，攻击者在卷里放什么都反映不到 diff 输出上。

**影响**：`docker diff` 的空输出会被读成最有力的阴性证据，而它的实际覆盖面只有「容器层且非挂载路径」这一个很窄的范围。

**核查**：空输出的正确表述是「**该容器在非挂载路径上相对镜像无差异**」。

要让这个结论有意义，必须同时给出三项覆盖说明：① `Mounts` 列出的全部 `Source` 已单独检查；② `Type=tmpfs` 的路径数据不可得；③ 容器若已被 `rm` 则该项检查无法执行。

没有这三项，`docker diff` 空输出不构成任何证据。

<a id="section-25"></a>

#### 陷阱 8：把 `docker diff` 的 `C` 当成「这个文件是攻击者建的」

**现象**：`docker diff` 输出一长串 `C /usr/local/bin/xxx`，其中混着业务自己的工具，报告把 `C` 条目整体列为「攻击者植入的可执行文件」。

**原因**：`C`（Changed）只表示「相对于镜像，这个文件在容器层被写过」，不表示谁写的、为什么写。 一次 `apt-get upgrade`、一次 `pip install`、一个应用在启动时生成配置、一个健康检查脚本更新自身——都会产生 `C` 条目，而且它们全都在容器层里。

真正有判别力的不是状态字母，而是**这个文件与镜像里同名文件的差异**，以及**它是否落在任何挂载点上**（落在挂载点上的内容根本不进 diff 输出）。

**影响**：把一长串 `C` 定性为载荷清单，等于给出一份无法辩护的清单——对方只需指出其中某几个是业务自身生成的，整个定性就垮了。而真正该报的那一个会被淹没。

**核查**：**逐条与镜像层比对，用差异本身定性。**

```bash
# ① 拿到容器层与镜像层的路径（UpperDir / LowerDirs 见 2.4 节）
# ② 同一路径在两层各取一份，算哈希比对
sha256sum /var/lib/docker/overlay2/<upper>/diff/usr/local/bin/xxx
# 对镜像层同路径文件同样取哈希
diff <(xxd /var/lib/docker/overlay2/<lower>/diff/usr/local/bin/xxx) \
     <(xxd /var/lib/docker/overlay2/<upper>/diff/usr/local/bin/xxx) | head

# ③ 时间关系：ctime 是否落在入侵窗口内
stat -c '%n mtime=%y ctime=%z' /var/lib/docker/overlay2/<upper>/diff/usr/local/bin/xxx
```

`diff` 输出为空 → 与镜像一致，`C` 是无意义的状态变更；`diff` 有输出 → **把差异本身作为发现描述**（「镜像内该文件为 `<A>`，容器层为 `<B>`，差异为 `<摘要>`」）。**结论写差异，不写归属。**

<a id="section-26"></a>

#### 陷阱 9：用 `docker cp` 取回被删除的文件

**现象**：看到 `docker diff` 有 `D /usr/share/nginx/html/index.html` 一行，执行 `docker cp <容器>:/usr/share/nginx/html/index.html` 取回，失败后判为「文件本体已被销毁，不可恢复」。

**原因**：overlay 的删除语义是在 upperdir 里放一个 whiteout 特性文件（`.wh.<文件名>`）遮住 lowerdir 的同名文件，被删文件本体从未离开镜像层。

`docker cp` 失败是因为**容器路径已被遮蔽**，不是因为文件不存在。文件还在 lowerdir 链里躺着。

**影响**：这是本篇最典型的「假阴性」。分析员会把「方法用错」当成「证据销毁」，从而放弃取回被篡改的原始文件——而那份原文件恰恰是证明「被删了什么」的最好物证。

**核查**：从 `UpperDir` 定位同级的 `link` 文件取 lowerdir 链，按**从低到高**顺序逐层查找目标路径（注意路径要落到层目录内的完整相对路径，不是从 `link` 条目根部找），命中即取回并哈希。

同时把 upperdir 里的 `.wh.*` 文件一并固定——它是「此处曾删除过文件」的直接物证，也是判断删除动作发生过的依据。

<a id="section-27"></a>

#### 陷阱 10：★ 在运行中容器的 `diff/` 里原地分析

**现象**：为了省事，直接 `cd` 进运行中容器的 `upperdir`，一边浏览一边删掉临时文件，或者对正在写入的文件直接打开分析。

**原因**：`diff/` 是**运行中容器的活文件系统**。里面的文件随时可能在写、被删、被改名；分析工具的读写会改变 mtime 与访问时间。

更重要的是，删除或修改 `diff/` 里的内容会直接影响容器的可见文件系统。

**影响**：两种。① 证据污染：mtime 被改后，「文件何时被创建」这个判据永久失效，而它正是把容器内文件与入侵窗口对齐的唯一依据。② 容器受损：删掉运行中容器依赖的文件可能导致业务崩溃，运维的响应动作又会进一步销毁现场（重启、改配置、清日志）。

**核查**：**一律只读**。需要文件内容就 `cp --preserve=all` 到证据区，先哈希再分析；保留时间戳与权限。

**不要在 `diff/` 里做任何写、删、改名操作**，确有必要时必须先固定整个目录副本并在报告中记录该操作。

<a id="section-28"></a>

#### 陷阱 11：忽略 `tmpfs` 挂载

**现象**：检查完所有卷与 bind mount 后写「所有持久化路径已检查，未发现异常」。

**原因**：`Mounts` 里 `Type=tmpfs` 的项，数据**只在内存**，宿主磁盘上根本不存在对应文件。

这类挂载常用于 `/run`、`/tmp`、`/dev/shm`，而它们恰恰是进程运行时写入最频繁的位置。

**影响**：最直接的问题是**「已全面检查」这句话不成立**——存在一整类路径物理上不可从磁盘获取。报告若不声明，结论的覆盖面被夸大，后续被指出时整份报告的严谨性都要打折。

**核查**：tmpfs 项必须**单独列出并写进报告的「数据不可得」范围**：「容器 `<name>` 的 `/run` 为 tmpfs 挂载，该路径数据仅存在于内存，容器停止后不可从磁盘恢复」。

若容器仍在运行且经委托方同意，可考虑采集容器内的文件快照；容器已停止则该项永久不可得。

<a id="section-29"></a>

#### 陷阱 12：把 bind mount 的相对路径解析当作显然的事

**现象**：`config.v2.json` 里 `MountPoints` 的 `Source` 是 `./data` 或 `../shared/app`，分析员按当前工作目录拼出一个宿主路径去取证，发现该路径不存在，结论写「该 bind mount 源目录不可访问」。

**原因**：相对路径的解析基准是 Docker daemon 的工作目录，而不是你当前所在目录，也不是配置文件所在目录。

`docker run -v ./data:/app` 这条命令里的 `./` 由 **daemon 所在主机上的启动上下文**解析——具体取决于该次 `docker run` 是在哪个目录、哪个 compose 项目里执行的。daemon 重启后即便命令原样重放，基准也可能不同。因此同一个 `./data` 在不同时间可以指向宿主机上的两个完全不同的目录。

而 `Mounts[].Source` 在 `docker inspect` 输出里通常已是绝对路径；只有直接读 `config.v2.json` 的 `MountPoints` 时才会看到相对形式，这正是离线取证最容易踩的地方。

**影响**：把「路径解析错了」写成「源目录不可访问」，会在报告里留下一个**关于证据可得性的错误断言**。更实际的是，你可能会去查一个**别的业务的目录**，并把那里的东西写进本案。

**核查**：相对 `Source` 一律不自行解析，改用其它来源确定真实路径。

```bash
# ① 先确认该字段是否真是相对形式（以 . 开头或非 / 开头）
grep -o '"Source":"[^"]*"' /var/lib/docker/containers/<id>/config.v2.json

# ② 与 HostConfig.Binds 对照（2.2 节提示过两者都要看），Binds 里是用户原始写法
grep -o '"Binds":\[[^]]*\]' /var/lib/docker/containers/<id>/config.v2.json

# ③ 定位真实落点：按内容与时间特征在宿主机上反查，而非按路径猜
find / -xdev -maxdepth 6 -type d -name app -newermt '<窗口起>' ! -newermt '<窗口止>' 2>/dev/null
```

报告表述：「`config.v2.json` 中该挂载 `Source` 为相对形式 `./data`，其解析基准为 Docker daemon 启动上下文，本机无法确定；已通过 `HostConfig.Binds` 与 `<方法>` 定位实际落点为 `<绝对路径>`」。**「无法确定」本身就是一个必须写出的结论**——它划定了这条证据的来源可信度。

<a id="section-30"></a>

### 4.3 内容判读与归因

<a id="section-31"></a>

#### 陷阱 13：把 bind mount 里的改动直接定性为入侵

**现象**：bind mount 指向的目录里有文件在入侵时段被修改，直接判为攻击者行为。

**原因**：bind mount 指向的是**宿主机的业务目录**，写入者不限于容器——宿主机上的运维、发布脚本、同步工具、备份程序都会写。同一时刻主机上可能有多个进程在改同一个目录。

**影响**：这是定性越界。正常运维改配置被写成入侵行为，会让报告的可信度崩塌。

而一旦这份报告要用来追责或定性，这个错误就无法挽回。

**核查**：**必须先做时间对齐**——把文件 mtime 与容器 `Created`/`StartedAt`、卷 `CreatedAt` 对齐，只有关落在入侵窗口内、且写入者可以指向容器的，才作关联。此外要拿业务变更记录（发布单、工单、配置管理系统的操作日志）做排除。判定表述分两级：「该文件在入侵窗口内被修改」是事实，「修改者为该容器」是需要独立证据支撑的推断。

<a id="section-32"></a>

#### 陷阱 14：漏掉 `Mode=ro` 这个否定性证据

**现象**：把 `Mounts` 逐项扫完，只记可疑项（指向 `/`、`/etc` 的可写挂载），只读挂载一律跳过。

**原因**：只读挂载（`Mode` 含 `ro` / `RW: false`）是**结构性的否定证据**——该路径在容器运行期间不可能被容器写入，因此它可以直接用来排除一类假设。这类「不能做什么」的证据在归因时价值极高：它能划出攻击者**必须**走别的路径。

**影响**：漏掉它，等于放弃了缩小时间窗与划定攻击面的最强工具之一。

报告里如果只有「发现了什么」，没有「排除了什么」，结论的强度会低一档。

**核查**：**每个只读挂载都要写成一条否定结论**：「容器 X 的 `/etc/app` 为只读 bind mount（`RW=false`），容器运行期间不可能经该路径写入，故该目录内的文件变更（若有）不来自此容器」。这条同时也是划定时间窗的依据——攻击者要改配置只能通过可写路径或容器外手段。

**注意只读的时效性**：`RW=false` 只覆盖「该容器运行期间」。容器停止后挂载解除，宿主路径恢复为常规目录权限，此时的写入与容器无关。报告里必须带上这个时间限定，否则一条否定结论会被无限外推。

<a id="section-33"></a>

#### 陷阱 15：忽略「挂载遮蔽镜像层内容」

**现象**：容器内 `/etc/app` 里有一个不该出现的文件，判定是攻击者放进去的。

**原因**：如果 `/etc/app` 是挂载点，镜像层里原本就有的 `/etc/app` 内容被整个遮住了。容器内看到的只有宿主目录的内容。攻击者可能是覆盖了宿主文件，也可能是这份镜像原本就带了这个文件——分不清。

**影响**：把镜像自带内容判成入侵载荷，或反过来漏判真正被替换的内容。

两种方向都会错。

**核查**：**从 lowerdir 链读被遮蔽的原内容**——用 2.2 节的 `Mounts[].Destination` 定位挂载点路径，再按 `link` 的层链由低到高查找同路径文件。遮蔽前后的两份内容对比，是判定「挂载点文件是否被替换」的直接依据；两份一致则可排除「容器启动后该文件被改」。

<a id="section-34"></a>

#### 陷阱 16：把卷里的 `.bash_history` 当容器内命令历史

**现象**：在卷里发现 `.bash_history` 或 `.zsh_history`，把里面的命令当作容器内执行过的命令列入攻击链。

**原因**：卷和 bind mount 的内容不区分「谁写的」。 一个被挂进容器的宿主目录里，`.bash_history` 可能是宿主机运维用 `docker exec` 之外的正常方式写的，也可能是攻击者写的。卷内文件不带写入者身份信息。

**影响**：把宿主机运维的正常操作归到攻击者名下，会让攻击链出现虚假环节。

反过来，卷内确实存在攻击者操作痕迹时，把它当噪音忽略又等于漏判。

**核查**：**先判定该路径的挂载类型，再定命令历史的归属**。对 bind mount 指向的宿主目录，其中的 shell 历史属于宿主或该目录的实际使用者；对 named volume 内的 shell 历史，要结合容器元数据（是否存在仍在运行的容器、容器 `Cmd`/`Env`）判断能否归属到容器。无法确定写入者时，报告只写「该文件包含以下命令记录，写入者不可考」。

<a id="section-35"></a>

#### 陷阱 17：不记录卷的 `metadata.db`

**现象**：把卷内容逐个看过去，注意到可疑文件，但没有去读 `volumes/<name>/metadata.db`，报告里所有时间都来自文件 mtime。

**原因**：`metadata.db` 里记录卷的 `Name`、`CreatedAt`、`Labels`、`Mountpoint`、`Options`。`CreatedAt` 是卷级别的、与文件内容无关的独立时间锚点——它不受文件内容被改写、不受 `tar -p` 保留原始时间等操作影响，因而比任何单个文件的 mtime 都更可靠。

**影响**：丢掉这条锚点后，时间线的最前端只能靠文件 mtime 推断。

而攻击者完全可以修改文件时间（`tar` 解包、`cp -p`、解压缩都会保留源时间），文件 mtime 在对抗环境下可信度最低。

**核查**：逐卷读取并记录 `metadata.db` 的 `CreatedAt`，把它作为时间线上的独立节点。判定要点：**卷的创建时间与入侵窗口的关系本身就是一条独立线索**——落在窗口内、名字与业务无关的卷，几乎不需要其他证据就值得单独展开。同时 `Labels` 里可能有非空的业务标识，可用于区分业务卷与临时卷。

<a id="section-36"></a>

### 4.4 阴性发现的表述

<a id="section-37"></a>

#### 陷阱 18：把「本地有导出文件」写成「数据已外传」

**现象**：卷里找到导出的数据文件与导出命令，报告结论直接写「攻击者已将订单数据窃取外传」。

**原因**：卷内存在导出结果，**只能证明数据被导出到了本地**，不证明它离开了这台主机。传输环节是独立的一步，可能经 DNS 隧道、也可能经已建立的外连、也可能根本没有发生——卷内不会有传输记录。

**影响**：这是结论强度凭空提升一档。

委托方据此对外发布数据泄露公告、或按已泄露的口径处置下游（通知监管、通知用户），而事实上可能只是本地暂存。若后续证明数据未外传，报告的可信度与机构的公信力都要付出代价。

**核查**：**结论拆成两步**。「事实」层写「在卷 `_data` 内发现订单数据的导出结果文件 `<文件名>`，含字段 X、Y、Z，共 N 条」；「推断」层写「该文件的存在表明数据已被导出至本地；是否外传至攻击者处需网络侧证据独立确认」。外传需要网络流量、连接日志、DNS 查询记录或云厂商侧流量报告支撑——**没有这些证据，「已外传」只能列为待查项。**

<a id="section-38"></a>

#### 陷阱 19：★ 「未发现」不写范围

**现象**：报告里多处出现「未发现异常」，没有说明查了哪里、没查哪里。

**原因**：在容器场景里，「未发现」几乎总是有洞的——被删除的容器、tmpfs 路径、被遮蔽的镜像层、未反查的 lowerdir、`docker diff` 看不到的挂载点、容器已删因而完全不可得的 `upperdir`。不加限定的「未发现」，在字面上等于「全部检查过且干净」，这在容器环境里从来不是真的。

**影响**：这份报告被采信后，调查即结束。一旦后续在卷里或宿主机上发现本该被覆盖范围内的痕迹，结论被推翻，届时不仅这一条结论作废，整份报告的方法论都会被质疑。

**核查**：**每一处「未发现」都要写成三段式**——「**检查范围**」（具体到哪些路径、哪些卷、哪些容器 ID）+「**检查方式**」（diff 输出、文件遍历、哈希比对）+「**未覆盖范围**」（列出上面那几类）。例如：「在现存 6 个容器的可写层、3 个 named volume 的 `_data`、1 个 bind mount 源目录内检查，未发现与 `<可疑文件名>` 内容哈希一致的文件；**未覆盖**：已删除的两个容器（`config.v2.json`、日志、`upperdir` 均不可得）、容器 `/run` 的 tmpfs 挂载、lowerdir 中被挂载遮蔽的原内容」。

<a id="section-39"></a>

### 4.5 时间基准与跨来源比对

<a id="section-40"></a>

#### 陷阱 20：把卷内文件的 mtime 与容器日志的 UTC 时间直接相减

**现象**：卷里 `appdata/_data/.cache/xmrig/xmrig` 的 mtime 是 `2024-03-18 04:12:03`，容器日志里对应那条是 `"time":"2024-03-18T04:11:12Z"`，报告写「载荷在容器报错后 51 秒落盘」，并据此确认两者同源。

**原因**：两列数字长得几乎一样，但**时区基准完全不同**。ext4 的 mtime 存的是目标机本地时间且**不带时区标记**；容器 JSON 日志的 `time` 字段是 **RFC 3339 UTC，带 `Z`**。国内服务器一般是 UTC+8，同一个动作在两边天然相差 8 小时。**差值计算不会报任何错**——它只会稳定地给出一个看起来合理的秒数。

**影响**：一是印证失效。第五章那种「四个文件时间集中在 109 秒内、且与容器启动窗口吻合」的时间线论证，在 8 小时偏差下会整体错位到不可能的时段，**一条本可锁定的证据被自己算没了**。二是顺序颠倒：8 小时足以让「落盘时刻」看起来早于容器创建时刻，把「先起容器后写载荷」的因果关系倒过来，进而支撑出一条错误的行为链。

**核查**：**跨来源做减法之前，先统一基准。** 卷与 bind mount 目录里的时间用 `TZ=UTC` 渲染，或用 `debugfs` 取原始值后自行标注时区；时间线表格同时保留「原始值 + 时区」和「UTC 换算值」两列。本篇大量使用的 `find -newermt` 类筛选尤其要注意：`-newermt '2024-03-17 20:00'` 这个窗口按**目标机本地时间**解释，若被当成 UTC，整体偏移 8 小时，落在窗口外的文件被静默漏掉且不报任何错——第五章里那个「落在同一时段」的判断就建立在这种筛选之上。稳妥做法是先用 `stat` 抽一个已知文件的 `%y`（它带完整偏移，如 `+0800`）确认目标机时区，再决定窗口怎么写。

<a id="section-41"></a>

#### 陷阱 21：用卷的 `CreatedAt` 划定「数据进入时间」

**现象**：某卷的 `metadata.db` 显示 `CreatedAt` 为 `2024-03-18 04:05`，卷里有个文件的 mtime 是 `04:12`，报告写「该文件于卷创建后 7 分钟被写入，攻击者在创建卷后 7 分钟内完成了投放」。

**原因**：`CreatedAt` 是卷的创建时刻，不是数据进入卷的时刻，两者之间可以相隔任意长时间。

卷被创建后可以长期空置，然后某天被 `docker run -v` 挂进容器、才开始有写入。`CreatedAt` 与文件 mtime 之间的间隔因此只说明「卷存在了 7 分钟以上」，它对「投放时刻」的约束力是**下界而非上界**——真正成立的关系是「文件写入时刻 ≥ 卷创建时刻」，而**这个不等式几乎总成立，提供不了额外信息**。

另一半原因是同一个卷可能被多个容器先后挂载，写入者不止一个；而 `docker compose up` 重建容器时，卷被复用，`CreatedAt` 保持不变。

**影响**：把下界读成上界，会造出一个「攻击窗口极短、动作高度集中」的叙事，而实际上卷可能已经存在数月，本条时间线论证会连带支撑起其它推论——第五章那种「时间集中在 109 秒内」的判断如果建立在这个错误前提上，整条印证链都会翻转。

**核查**：`CreatedAt` 只作下界用，且必须显式声明。

```bash
# 卷创建时刻（下界）
sqlite3 /var/lib/docker/volumes/<name>/metadata.db "select Name,CreatedAt from Volumes;" 2>/dev/null \
  || strings /var/lib/docker/volumes/<name>/metadata.db | grep -i created

# 文件写入时刻
TZ=UTC stat -c '%n mtime=%y' /var/lib/docker/volumes/<name>/_data/<path>
```

报告写法：「卷 `<name>` 创建于 `<CreatedAt>`，该文件写入于 `<mtime UTC>`。`CreatedAt` 仅为数据进入该卷的时间下界，不构成投放窗口的上界；卷在被挂载前可长期空置。」**真正能给出上界的是挂载关系的时间**——容器 `StartedAt` 落在文件 mtime 之后，才说明「该卷在该时刻确实被某个容器持有」。

<a id="section-42"></a>

#### 陷阱 22：把 `overlay2` 的层目录 ID 当成稳定的容器标识

**现象**：报告里用 `<id>` 指代容器（「容器 `<id>` 的可写层内发现挖矿程序」），并把这个 `<id>` 与后续几份交叉材料里的容器编号对应起来。

**原因**：`overlay2/<id>` 里那个 ID 是该容器可写层的目录名，它与容器 ID（64 位十六进制）、与 `config.v2.json` 所在目录名，三者在不同环境下可能对不上。

层 ID 是 overlay2 驱动在创建容器时生成的一次性标识，与容器元数据目录之间**没有可推导的映射关系**——只能通过 `config.v2.json` 里的 `GraphDriver.Data.UpperDir` 字段反查。所以拿层目录 ID 去别处检索「这个容器」，很可能检索不到；而如果两个环境恰好用了同一套 ID 空间，又会检索到**完全无关的另一个容器**。

另一半原因是容器重建：`docker compose up --force-recreate` 会产生新的容器目录与新的层 ID，而卷被复用，所以**「同一个卷」在两次重建后对应两个不同的层目录**。

**影响**：报告里的容器指代一旦错位，后续所有针对该容器的结论（`diff` 输出、`Mounts`、`docker diff` 结果）都会挂到错误的对象上；而这类错误在纸面上完全看不出来——每个 ID 都是合法的十六进制串。反过来，用层 ID 作为跨材料关联键，则可能把两个无关容器错误地合并成同一个行为主体。

**核查**：以容器元数据目录为准，层 ID 只作落地路径使用。

```bash
# ① 容器 ID = 元数据目录名
ls -d /var/lib/docker/containers/*/

# ② 层 ID 只从该容器的 GraphDriver 字段里取，不独立检索
grep -o '"UpperDir":"[^"]*"' /var/lib/docker/containers/<容器ID>/config.v2.json
grep -o '"LowerDir":"[^"]*"' /var/lib/docker/containers/<容器ID>/config.v2.json

# ③ 报告里三个标识并列写清楚，不混用
```

报告写法统一为「容器 `<容器ID>`（可写层 `overlay2/<层ID>`，元数据 `containers/<容器ID>`）」。**任何一处的指代都必须能靠这段对应关系回到源对象。**
<a id="section-43"></a>

## 五、案例示例

<a id="section-44"></a>

### 5.1 容器已删但匿名卷留下完整数据窃取工具链

**场景**

委托方（某公司）报告其订单系统数据疑似被窃取，怀疑攻击者在容器内做了导出。现场为 Ubuntu 22.04，**主机仍在运行**，但运维已执行过 `docker rm` 删除了两个"看起来异常"的容器。镜像 `DigiForensics.dd`（raw，500 GB，ext4 起始扇区 1181696，overlay2 驱动）。已知入侵时间窗为 2024-03-17 20:00 至 2024-03-18 06:00。

这条路径值得先走，是因为**运维的清理动作只删掉了容器，没有删掉卷**。容器目录一旦消失，`config.v2.json` 和 stdout/stderr 日志就永久没了；但攻击者用 `--rm` 起的一次性容器会留下**匿名卷**，而卷里往往装着他们来不及带走的中间产物。

**处置过程**

第 1 步 · 确认容器已被删除这一事实（决定了后面能查什么）

```bash
docker ps -a --no-trunc          # 剩下的容器中没有那两个异常容器
ls -1 /mnt/df/var/lib/docker/containers/ | wc -l
# 6    ← 容器目录里只剩 6 个，与 docker ps 一致
```

这本身就是第一个结论：两个容器已被 `docker rm`，其 `config.v2.json`、stdout/stderr 日志、`upperdir` 全部不可得**。

报告必须先写明这一边界。

第 2 步 · 卷清单——去 `dangling` 里找"用完即弃"的痕迹

```bash
docker volume ls
# DRIVER    VOLUME NAME
# local     appdata
# local     pgdata
# local     9c4f7a1e2b                    ★ 非业务命名的卷，无任何容器使用
docker volume ls -f dangling=true
# local     9c4f7a1e2b                    ★

cat /mnt/df/var/lib/docker/volumes/9c4f7a1e2b/metadata.db
# {"Name":"9c4f7a1e2b","Driver":"local","Mountpoint":"/var/lib/docker/volumes/9c4f7a1e2b/_data",
#  "CreatedAt":"2024-03-18T02:41:19Z","Labels":{},"Options":{}}
```

**发现 1**：卷 `9c4f7a1e2b` 创建于 **2024-03-18 02:41:19**，**落在入侵时间窗内**，且**不被任何容器使用**（dangling）。

卷名是随机十六进制，符合 `--rm` 容器自动创建匿名卷的命名特征。

第 3 步 · 卷内内容——时间线直接对上入侵窗口

```bash
find /mnt/df/var/lib/docker/volumes/9c4f7a1e2b/_data -type f \
     -printf '%TY-%Tm-%Td %TH:%TM %m %u:%g %s %p\
' | sort
# 2024-03-18 02:41:22  644 root root    184  dump.sql
# 2024-03-18 02:43:08  755 root root   7821  dumper                 ★
# 2024-03-18 02:43:09  644 root root   1204  result.csv            ★
# 2024-03-18 02:43:11  644 root root     38  .cmd                  ★
```

`.cmd` 是攻击者自己留下的操作备忘，本案只需把它当作**字符串证据**引用，不复述、不执行：

```bash
cat /mnt/df/var/lib/docker/volumes/9c4f7a1e2b/_data/.cmd
# PGHOST=10.8.3.21 PGDATABASE=orders /usr/bin/psql -c '\copy orders_all to stdout csv'
head -2 /mnt/df/var/lib/docker/volumes/9c4f7a1e2b/_data/result.csv
# order_id,customer,amount,phone
# 100238,张*明,1288.00,138****6621        ← 交付委托方的样例须进一步脱敏，见结论
file /mnt/df/var/lib/docker/volumes/9c4f7a1e2b/_data/dumper
# ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
cp --preserve=all /mnt/df/var/lib/docker/volumes/9c4f7a1e2b/_data/{dumper,result.csv,.cmd,dump.sql} /evidence/
sha256sum /evidence/dumper /evidence/result.csv | tee /evidence/hashes.txt
```

**发现 2**：卷内是一套完整的**数据窃取工具链**——`.cmd` 记录了导出命令（`psql \copy orders_all to stdout csv`）、`dumper` 是被剥符号的 ELF 可执行文件、`result.csv` 是导出的订单数据（含手机号掩码）。四个文件时间集中在 02:41:22 ～ 02:43:11 的 109 秒内。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 攻击者于 2024-03-18 02:41 创建匿名卷并实施数据导出 | 卷 `metadata.db` 的 `CreatedAt` + 卷内四文件时间集中在 109 秒内 | 强 |
| 被窃数据为订单表，含姓名与手机号 | `.cmd` 的 `psql \copy` 命令 + `result.csv` 表头 | 强 |
| 两个"异常容器"已被 `docker rm`，其配置与日志**永久不可得** | `containers/` 目录数与 `docker ps -a` 一致，均无该二容器 | **强（但须作为局限明示）** |
| **数据是否已被外传成功** | 需网络侧日志；卷内无传输记录 | **未决项，不能仅凭本地文件断定** |
| **攻击者最初如何获得 Docker 控制权** | 需 auth.log、dockerd 日志、CI 凭证 | **未决项** |

**本节能证明**：导出动作确实发生过、导出对象的表名与字段结构、导出的数据量级（`result.csv` 1204 字节，约 10 余行）。

**本节不能证明**：数据出网的方向与接收方、导出动作的执行者身份。注意 `result.csv` 里带姓名的行本身属个人信息，交付委托方时应进一步脱敏（保留订单号与字段名，姓名只留姓氏），报告正文也不得整表粘贴。

**误判对照**

最容易出的错有两个，第一个在现场几乎必然发生。

第一个是**把"卷里有导出文件"直接写成"数据已被窃取"**。`result.csv` 只证明数据**被导出到了本地卷**，从"导出"到"外传"之间隔着一次网络传输，本案没有任何本地证据覆盖这一段。

1. **判据**：证明"外传"必须有三选一以上的独立证据——容器日志里有上传记录（本案不可得）、宿主机网络日志/流量镜像里有对应五元组的数据量、卷内存在指向外部地址的传输配置。三者皆无时，正确表述是"已导出至本地卷，是否外传需网络侧独立确认"。
2. **判据**：`CreatedAt` 是卷的创建时刻，`metadata.db` 本身可被改写（它是普通 JSON 文件，不是数据库）。判断"卷在入侵窗内被创建"的强度依据是**它与卷内文件 mtime 互相印证**，而不是 `CreatedAt` 字段本身。要更强的话应把 `metadata.db` 的哈希与其他同批次 JSON 一并固定。
3. **判据**：`dangling` 只说明"当前无容器引用"，不说明"从未被使用"。任何已停止但仍存在的容器、`docker compose` 项目遗留的卷、乃至人工 `docker volume create` 建的卷都会显示为 dangling。反过来，被 `--rm` 的容器创建的卷也显示为 dangling。用 dangling 筛可疑卷是有效起点，但"可疑"的依据必须是命名形态 + 时间窗，不是 dangling 状态本身。

按错误判据走，第 1 条踩中会让委托方拿着"数据已外泄"的结论去对监管和客户做告知义务判断。

一旦后续证明数据并未出网（可能攻击者在本地完成导出后即被阻断），已发出的告知无法收回。

反过来，如果实际已外泄而报告写"未发现外传证据"，委托方会据此关闭事件，泄露面继续扩大。

<a id="section-45"></a>

### 5.2 伪装 PDF 的 WebShell 识别与正常文件排除

**场景**

承接 5.1。数据导出后 51 秒，业务卷 `appdata` 的上传目录出现了一个 `.pdf` 文件。委托方的问题是："这是用户上传的发票，还是投递的后门？"

这个判断不能靠"扩展名是 pdf 就没事"，也不能靠"文件很小就有事"。真正的判据是**文件内部结构与同批次文件的对比**。

**处置过程**

**第 1 步 · 不只搜可疑卷——业务卷必须同步查**

```bash
find /mnt/df/var/lib/docker/volumes/appdata/_data -type f -newermt '2024-03-17 20:00' \
     -printf '%TY-%Tm-%Td %TH:%TM %m %s %p\
' | sort | head -20
# 2024-03-18 02:44:02  644 892  uploads/2024/03/8f2a1c0d9e.pdf     ★ 落在同一时段
# 2024-03-18 02:44:02  644 45   uploads/2024/03/.gitkeep            ★ 同一秒
```

同一秒出现两个文件，且其中一个是 45 字节的 `.gitkeep`——占位文件的作用是保证目录进版本库，不是业务需要。这个组合本身就值得往下看。

第 2 步 · 结构分析：头合法不代表整个文件合法

```bash
# 头尾分别看，不要只看 file 命令的结论
file /mnt/df/var/lib/docker/volumes/appdata/_data/uploads/2024/03/8f2a1c0d9e.pdf
# PDF document, version 1.4, 1 page                  ← file 只认魔数，报"合法"是必然的

# 定位真正的 PDF 结束符 %%EOF
python3 - <<'PY'
p='/mnt/df/var/lib/docker/volumes/appdata/_data/uploads/2024/03/8f2a1c0d9e.pdf'
d=open(p,'rb').read()
i=d.rfind(b'%%EOF')
print('size',len(d),'last %%EOF at',i,'trailing bytes',len(d)-i-5)
print('trailing head:',d[i+5:i+45])
PY
# size 892 last %%EOF at 703 trailing bytes 184     ← %%EOF 之后还挂着 184 字节
```

`file` 说"PDF document"是**必然的**，因为它只看文件开头的 `%PDF-` 魔数。任何在合法 PDF 后面追加数据的文件都会通过 `file` 检查——这就是本判据的意义所在。

**第 3 步 · 追加内容是什么形态**

```bash
python3 - <<'PY'
p='/mnt/df/var/lib/docker/volumes/appdata/_data/uploads/2024/03/8f2a1c0d9e.pdf'
d=open(p,'rb').read(); t=d[d.rfind(b'%%EOF')+5:]
print('PK zip sig:', t[:2]==b'PK\x03\x04')
print('entropy-ish printable ratio: %.2f' % (sum(32<=c<127 for c in t)/len(t)))
PY
# PK zip sig: True
# entropy-ish printable ratio: 0.71              ← 高可打印比例 = 疑似明文脚本被包在 zip 里
```

再取同目录下的正常样本做对照——**没有对照就没有判据**：

```bash
# 同目录历史正常 PDF 的结构
for f in /mnt/df/var/lib/docker/volumes/appdata/_data/uploads/2024/02/*.pdf; do
  python3 -c "
import sys;d=open(sys.argv[1],'rb').read();i=d.rfind(b'%%EOF')
print('%s size=%d trailing=%d'%(sys.argv[1].split('/')[-1],len(d),len(d)-i-5))" "$f"
done
# a1b2c3d4.pdf size=284119 trailing=0
# e5f6a7b8.pdf size=157302 trailing=0            ← 正常 PDF 的 %%EOF 就在文件末尾
```

**结论**

| 对比项 | 正常 PDF（2 月样本） | `8f2a1c0d9e.pdf` | 判别力 |
|---|---|---|---|
| `file` 判定 | PDF document | PDF document | **无判别力**（只看魔数） |
| `%%EOF` 位置 | 文件末尾，trailing = 0 | 第 703 字节，trailing = **184** | **强** |
| trailing 起始特征 | 无 | `PK\x03\x04` | **强** |
| trailing 可打印字符比 | 无 | 0.71 | 中（需结合前一判据） |
| 同秒伴随文件 | 无 | 45 字节 `.gitkeep` | 中（占位文件是伴随特征） |

- **该文件不是合法的单个 PDF**，是一个结构完整的 PDF 加一段附加的 ZIP 容器。这类"多段文件"是本判据的核心：正常的单一格式文件只有一个结束结构。
- 识别结论成立，但"是否为 WebShell"仍需在隔离环境做行为侧确认——静态能证明"这是个伪装文件、里面有非 PDF 载荷"，不能单凭扩展名后缀断言载荷的最终功能。

**误判对照**

最容易出的错是**用 `file` 命令的结论当判据**，写出"经检测该 PDF 文件类型正常，未发现异常"。

1. **判据**：`file` 与魔数检查**只覆盖文件头部**。凡是需要"头部合法、内容异常"的场景——伪装文档、magic 拼接、`polyglot` 文件——全部逃逸。判别力来自**结构完整性**（`%%EOF` 是否在末尾）而非**类型识别**。
2. **判据**：可打印字符比例高**不是**判定载荷为脚本的充分条件。base64 编码的图片、压缩后的字体子集、正常的文档附件都会有高可打印比。必须与"trailing 数据以 `PK` 开头"这一结构事实联合使用。
3. **判据**：`.gitkeep` 与 PDF 同秒出现**只是伴随特征**，不是因果证据。正常的应用上传逻辑里，`.gitkeep` 也可能由应用自身写入。把它写进结论时只能作为"该时刻此目录有程序化写入活动"的佐证，**不能作为"该 PDF 是被投递的"的证据**。

按错误判据走，第 1 条正是漏检 WebShell 最常见的路径。

委托方拿到"文件类型正常"的结论后会关闭这条线，而文件实际留在业务卷中、可被 Web 服务直接访问，形成持续可访问的入口。

这类误判的后果不是"结论错了"，而是风险敞口一直开着而没人知道。

<a id="section-46"></a>

### 5.3 反例 tmpfs 与只读挂载划定的数据不可得边界

**场景**

委托方要求回答："攻击者有没有改过应用的配置文件？有没有办法看到攻击者在内存里做了什么？"

这两个问题看似都能查，实际上**一个的答案是结构性否定，另一个是永久不可得**。把这两类答案写清楚，比多列几条可疑点更有价值。

**处置过程**

```bash
# 1) 对现存容器做 diff（阴性发现也要记录成条目）
docker diff $(docker ps -q | head -1) > /evidence/docker-diff-app.txt
wc -l < /evidence/docker-diff-app.txt
# 3
cat /evidence/docker-diff-app.txt
# A /app/logs
# C /app/config/application.yaml     ★ 配置被改（待查是否被用于回连）
# A /tmp/.X11-unix                   ← 正常（X11 socket 挂载产生的空挂载点）
```

第 2 步 · 挂载表决定"能不能改"和"数据在不在"

```bash
docker inspect $(docker ps -q | head -1) | jq -r '.[0].Mounts[] |
  "\(.Type)\	\(.Source)\	\(.Destination)\	RW=\(.RW)"'
# volume   /var/lib/docker/volumes/appdata/_data   /data          RW=true
# bind     /srv/digiforensics/config               /etc/app       RW=false   ← 只读
# tmpfs                                   /run          RW=true      ← 内存，宿主无数据
```

第 3 步 · 被改的配置文件要拿基线比，不能只看 mtime

```bash
# 业务侧变更记录（问委托方要，不要自己猜）
grep -rn 'application.yaml' /evidence/change-records.txt
# 2024-03-12 CHG-2291 订单服务扩容，新增 upstream 配置    ← 官方变更，早于入侵窗口

# 现有内容里是否含可疑外连地址
grep -nE 'callback|notify|webhook|https?://' /mnt/df/srv/digiforensics/config/application.yaml
# upstream: 10.8.3.40:8080
# notify:   http://notify.digiforensics-internal.svc/hook
```

**结论**

| 问题 | 答案 | 证据 | 强度 |
|---|---|---|---|
| 攻击者能否改 `/etc/app` | **不能** | `RW=false` 只读 bind mount，容器内写操作会返回 `EROFS` | 强（否定性证据，**它缩小了时间窗**） |
| `/run` 里的数据能否从磁盘取回 | **不能** | `Type=tmpfs`，纯内存挂载，宿主磁盘上不存在 | 强（**该路径数据不可得，须写入报告**） |
| `/app/config/application.yaml` 是否被攻击者修改 | **倾向否** | mtime 落在 03-12，对应委托方提供的变更记录 `CHG-2291` | 中（基于 mtime 与业务记录的对应，需基线哈希加强） |
| 攻击者在内存中做过什么 | **不可得** | 主机运行中，未做内存镜像；`tmpfs` 数据与进程内存均在 RAM | 永久不可得（除非本案未做内存采集，需立即补做或说明已错过窗口） |

**本节覆盖范围**：「现存 6 个容器的 `docker diff` 输出 + `docker inspect` 的 `Mounts[]` 字段 + 3 个挂载点」。
**未覆盖范围**：已删除的两个异常容器（`docker rm` 导致 `upperdir` 与 `config.v2.json` 不可得）、`tmpfs` 内的运行时数据、进程内存、已停止容器的工作层。

**误判对照**

这个反例最容易出的错是**把"只读挂载"当成"这条路径绝对安全"**。

1. **判据**：`RW=false` 只证明**容器内无法写入该路径**。它不阻止 (a) 宿主机上的其他进程修改该文件；(b) 通过容器可写层覆盖 `docker-compose.yml` 或 systemd unit 实现**下次启动时**把挂载改成 `RW=true`；(c) 通过 `--privileged` 或挂载 docker.sock 的容器间接改宿主机。正确表述是"**在当前挂载配置下，容器内进程不能写入该路径**"，而不是"该路径未被触及"。
2. **判据**：`docker diff` 输出的 `A /tmp/.X11-unix` **不是入侵痕迹**。X11 socket 挂载（`-v /tmp/.X11-unix:/tmp/.X11-unix`）会在容器内创建对应挂载点，`docker diff` 记为 `A`。这一条如果不排除，会让 `docker diff` 的输出凭空多一个"可疑项"，削弱整份 diff 的可信度。
3. **判据**：**文件 mtime 落在入侵窗内不等于被入侵者修改**。mtime 可被 `touch -d`、`cp -p`、或从归档解包还原改变。判断"是否被改"需要**基线哈希或版本库比对**；本案只有业务变更记录，属于中等强度，不能升格为"确定未被修改"。

按错误判据走，第 1 条踩中，报告会写"配置文件所在目录为只读挂载，未被修改"，而实际上攻击者可能已通过改 `docker-compose.yml` 把挂载放开、待下次重启生效。

这个"待生效"的后门不修，**重启那一刻就是二次入侵**——而报告恰恰给了委托方"这块没问题"的错误安心。

<a id="section-47"></a>

## 六、扩展阅读方向

挂载关系解决的是"数据落在哪"，但内容判读要靠别的知识。下面几组按**你接下来要判读的东西**分组。

**回到存储层：改动的落点与删除语义**

- [镜像层与 overlay2 解析](server-docker-overlay2.md) —— **本篇的另一半**。未挂载路径的改动落在 `diff/`，`docker diff` 的 C/A/D 语义与 whiteout 机制在那一篇展开。
- [Docker 取证工件地图](server-docker-docker-artifact-map.md) —— `config.v2.json` 全字段、采集时机、以及"容器已删除"该怎么表述。

**编排层：K8s 上的挂载是另一套**

- [K8s 取证工件地图](../server-k8s/server-k8s-kubernetes-artifact-map.md) —— PVC/PV、`hostPath` 挂载、Pod 生命周期。集群环境下 named volume 的等价物是 PVC，而 `hostPath` 等价于 bind mount，但落点与生命周期判定完全不同。
- [审计日志与 ConfigMap-Secret](../server-k8s/server-k8s-configmap-secret.md) —— ConfigMap/Secret 常以挂载形式出现在容器内，"谁在什么时候挂载了哪个 Secret"要靠审计日志回答。

**内容判读：卷里的东西到底是什么**

- [网站目录与 WebShell 检测](../server-web/server-web-webshell-detection.md) —— 卷里的 WebShell 会被业务进程加载执行，危害等同于站点目录被植入。这一篇给识别方法与误报排除。
- [WebShell 工具流量特征](../server-web/server-web-webshell-traffic-patterns.md) —— 内容像 WebShell 但不确定时，用流量特征区分是工具自身回调还是漏洞利用。
- [Linux 服务器取证工件地图](../server-panel/server-panel-linux-server-artifact-map.md) —— 数据库 binlog 与慢日志对"批量导出"的证明力。**这是"卷里的数据被读走了"这类结论最硬的旁证。**
- [SQLite 基础与结构](../../mobile/mobile-database/mobile-database-sqlite.md) —— 应用数据卷里最常见的载体；库文件的 freelist 里可能还有已删除的记录。

**跨源与时间：这份数据什么时候被动过**

- [时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md) —— 卷内文件 mtime 与容器启动时间、`json-log` 时间戳的对齐。
- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— **卷内文件时间戳可被改写**，尤其在被 `docker cp` 覆盖的场景下。
- [Linux 系统日志深度分析](../../computer/computer-log/computer-log-system-log-analysis.md) —— 宿主侧 logrotate 与 systemd 日志，**能证明卷在某个时段被访问过**。

**高危配置：这些挂载本身就是发现**

- [容器逃逸与运行时痕迹](../server-k8s/server-k8s-container-escape-and-runtime-artifacts.md) —— `/var/run/docker.sock` 挂载、`--privileged`、`hostPath` 指向 `/` 的识别与误报排除。本篇给出 `Source` 字段的读法，判定标准在那里。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— `docker cp`、`docker diff` 这类会改变容器状态的操作为什么要在副本上做。
- [Nginx 与 Apache 配置取证](../server-web/server-web-nginx-apache.md) —— bind mount 常指向站点目录，配置里的 `alias` 误配与日志路径决定了 WebShell 会落在哪。
<a id="section-48"></a>

## 七、命令速查

```bash
# ===== 1. 挂载关系（在线 / 离线两条路）=====
for c in $(docker ps -aq); do
  echo "== $c"
  docker inspect "$c" | jq -r '.[0].Mounts[]? | "\(.Type)\	\(.Source)\	\(.Destination)\	Mode=\(.Mode)\	RW=\(.RW)"'
  docker inspect "$c" | jq -r '.[0].HostConfig.Binds[]? // empty'
done
python3 -c "
import json,glob
for f in sorted(glob.glob('/mnt/df/var/lib/docker/containers/*/config.v2.json')):
    d=json.load(open(f)); print('==', d.get('Name'))
    for dest,m in (d.get('MountPoints') or {}).items():
        print(f\"  {m.get('Type')}\	{m.get('Source')}\	{dest}\	RW={m.get('RW')}\")
"

# ===== 2. named volume：★ 已删容器留下的金矿 =====
docker volume ls
docker volume ls -f dangling=true        # ★ 未被任何容器使用的卷
docker volume inspect appdata pgdata
cat /mnt/df/var/lib/docker/volumes/<name>/metadata.db   # CreatedAt 是关键锚点
for v in /mnt/df/var/lib/docker/volumes/*/_data; do
  echo "===== $v"
  find "$v" -type f -printf '%TY-%Tm-%Td %TH:%TM %m %u:%g %s %p\
' 2>/dev/null | sort | tail -15
done
find /mnt/df/var/lib/docker/volumes/*/_data -type f \
     \( -name 'xmrig' -o -name '*.sh' -o -name '*.jsp' -o -name '*.php' \
        -o -name 'authorized_keys' -o -name 'id_rsa' \) \
     -printf '%TY-%Tm-%Td %TH:%TM %m %s %p\
' 2>/dev/null | sort | tail -40
find /mnt/df/var/lib/docker/volumes/*/_data -type f -perm /111 \
     -printf '%TY-%Tm-%Td %TH:%TM %m %s %p\
' 2>/dev/null | sort | tail -30
# ⚠️ 禁止：docker volume prune / docker volume rm / docker system prune

# ===== 3. bind mount：走常规文件系统取证 =====
ls -la /mnt/df/srv/digiforensics/config/
stat -c '%n mtime=%y ctime=%z mode=%a owner=%U:%G' /mnt/df/srv/digiforensics/config/
find /mnt/df/srv/digiforensics/config -type f \
     -printf '%T@ %TY-%Tm-%Td %TH:%TM %m %u:%g %s %p\
' | sort -n | tail -30
find /mnt/df/srv/digiforensics/config -type f -perm /111 -printf '%m %TY-%Tm-%Td %p\
' | head
find /mnt/df/srv/digiforensics/config -type f -newermt '2024-03-17 20:00' | head -40

# ===== 4. docker diff（C/A/D）=====
docker diff digiforensics-app | tee /evidence/docker-diff-app.txt
grep '^A ' /evidence/docker-diff-app.txt      # 新增，最可疑
grep '^C ' /evidence/docker-diff-app.txt      # 修改，配置被篡改
grep '^D ' /evidence/docker-diff-app.txt      # 删除，可从 lowerdir 取回
CID=$(docker inspect -f '{{.Id}}' digiforensics-app)
UP=$(docker inspect -f '{{.GraphDriver.Data.UpperDir}}' digiforensics-app)
find "$UP" -type f -newermt '2024-03-18 00:00' -printf '%TY-%Tm-%Td %m %s %p\
' | head -20
# 取回 D 项：遍历 lowerdir 链（不是 docker cp，容器里已无此路径）
cat "$(dirname "$UP")/link"                        # lowerdir 链，从低到高
find "$(dirname "$UP")/diff" -name '.wh.*'         # ★ whiteout 特性文件 = 删除痕迹

# ===== 5. docker cp 提取（优于 exec）=====
docker cp digiforensics-app:/opt/app/.cache/miner /evidence/
docker cp 4f1c9a2b7e30:/etc/crontab /evidence/crontab-from-container
docker cp digiforensics-app:/app/logs/. /evidence/app-logs/
sha256sum /evidence/* | tee /evidence/hashes.txt

# ===== 6. 高危挂载筛查（详见第 06 篇）=====
docker ps -aq | xargs -I{} docker inspect {} | jq -r '.[] | .Mounts[]? |
  select(.Source=="/" or .Source=="/etc" or .Source=="/root" or (.Source|test("docker.sock|containerd.sock"))) |
  "★HIGH-RISK \(.Source) -> \(.Destination)"'
docker ps -aq | xargs -I{} docker inspect {} | jq -r '.[] | .Mounts[]? |
  select(.RW==false) | "只读挂载: \(.Source) -> \(.Destination) （不可能被写入）"'

# ===== 7. 验证 =====
umount /mnt/df && sha256sum -c /evidence/evidence.sha256
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 服务器与 Web 取证 — Volume 与绑定挂载取证」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《Volume 与绑定挂载取证》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-mem.raw` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
