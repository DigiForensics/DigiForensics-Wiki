---
title: "K8s 取证工件地图"
slug: "server-k8s-kubernetes-artifact-map"
canonical: "https://www.digiforensics.cn/wiki/server-k8s-kubernetes-artifact-map"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:51+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "server"
space: "服务器与云取证"
node_path: ["Kubernetes"]
---

# K8s 取证工件地图

<a id="section-1"></a>

## 一、概述

Docker 主机上的取证对象是"一台机器 + 若干容器"，边界清楚。

Kubernetes 集群把这个边界抹掉了。取证对象从一个容器变成一个由 API Server 调度、etcd 存储、kubelet 执行、数十个控制器共同维护的分布式系统。

同一个 Pod 的完整状态被拆散在五个位置——编排层状态（etcd / API Server 内存）、**节点上的实际运行（kubelet）**、**标准输出（CRI 日志）**、凭据与配置（etcd 里的 Secret/ConfigMap）、**谁做了什么（审计日志）**。

这是 K8s 取证最重要的特殊性：编排系统本身就是最大的攻击面，也是最大的证据库。

| 攻击面 | 后果 | 证据位置 |
|---|---|---|
| **API Server 未授权访问** | 接管整个集群：读所有 Secret、建特权 Pod、改 RBAC | 审计日志、API Server 日志 |
| **etcd 明文存储** | 未启用静态加密时**所有 Secret 明文可读**（库口令、镜像仓库凭证、SA token） | `/var/lib/etcd/member/snap/*.db` |
| **Kubelet 10250 端口** | **可读任意 Pod 数据、也可执行命令** | Kubelet 日志 |
| **RBAC 配置过宽** | 一个 ServiceAccount token 泄露即等于泄露其全部权限 | 审计日志 + RoleBinding |

**etcd 里存着所有 Secret 的明文**这一条必须单独强调（前提是集群未启用静态加密，核查见下方）。

即便 Secret 在 API 层面是 base64（**那不是加密**），**未配置静态加密时 etcd 里的值也是最终明文**。拿到这样的 etcd 快照，就等于拿到了整个集群的所有凭据。

这是单份价值最高的证据，也是取证顺序里排第一的那一项。

而 K8s 也有 Docker 取证没有的优势——**审计日志**记录了"谁在何时调用了哪个 API、对什么对象、结果如何"，可用于核查"调用者使用了什么身份、做了哪些 API 操作"。没有它，其余工件只能告诉你"结果是什么"。

**在取证流程中的位置**：本篇是**集群场景的入口与导航**，属于采集环节的前置判定层。

它不解析任何结构，只回答：**证据散在哪些位置、优先级如何、什么必须抢在前面**。容器层的工件见 [Docker 取证工件地图](../server-docker/server-docker-docker-artifact-map.md) 等三篇，**本篇不重复**；深入分析见 [审计日志与 ConfigMap-Secret](server-k8s-configmap-secret.md) 与 [容器逃逸与运行时痕迹](server-k8s-container-escape-and-runtime-artifacts.md)。

涉及的证据形态，以 kubeadm 典型布局为准，**不同发行版与部署方式会有差异，以实际检材为准**：

| 路径 | 内容 |
|---|---|
| `/etc/kubernetes/manifests/` | 静态 Pod 定义（apiserver/etcd/scheduler/controller-manager 的 YAML） |
| **`/etc/kubernetes/pki/`** | 集群 PKI：CA 证书与私钥、apiserver 证书、**kubelet 客户端证书** |
| `admin.conf` / `kubelet.conf` / **`kube-apiserver.yaml`** | kubeconfig（**权限都极大**）；审计策略路径与加密配置 `--encryption-provider-config` |
| `/var/lib/etcd/member/snap/*.db` | etcd 快照，含全部集群状态与 Secret 明文 |
| `/var/lib/etcd/member/wal/` | etcd 预写日志，**含最近写入，即使快照过期也有** |
| `/var/log/kubernetes/audit.log` | API Server 审计日志，K8s 取证最重要的一份日志 |
| `/var/log/pods/<ns>_<pod>_<uid>/<container>/0.log` | **Pod 日志真实文件**（数据源）；`/var/log/containers/*.log` 是软链接 |
| `/var/lib/kubelet/pods/<uid>/` | **Pod 完整目录**：容器 rootfs、configz、volume 挂载 |
| `/var/lib/kubelet/config.yaml` 与 `plugins/` | CSI/credential-provider 插件（含云厂商凭证交换逻辑） |
| `/var/run/secrets/kubernetes.io/serviceaccount/` | **当前 Pod 内的 SA token**（控制平面 Pod 也有） |
| `/run/containerd/containerd.sock` | containerd 的 unix socket，**能访问它 ≈ 节点 root** |

> **Pod 日志的软链接不能当身份依据**：`/var/log/pods/...` 的真实文件路径里带 namespace、pod 名与 UID，是 Pod 身份的直接证据；而 `/var/log/containers/*.log` 的命名规则在不同 CRI 下不一致，**不能只从软链接名推断身份**。

集群里部署过什么、Pod 的完整配置与挂载、etcd 里存着哪些凭据、谁在何时调用了哪些 API、Pod 的标准输出说了什么。

Pod 内部文件系统被改过什么（`kubelet/pods/<uid>/` 下的 rootfs 是运行时视图，不是层结构的权威来源）；etcd 快照时刻之后的状态（WAL 里可能有）。

**"kubectl 查不到"不等于"不存在"**——对象可能已删除，删除事件只在审计日志里。

**内容边界**：所有命令面向**已获得合法授权**的集群或已制作的只读镜像，目标是发现与固定证据，**不提供任何入侵手段**。

高危配置的识别写的是**如何判定为高危、如何排除误报**，不涉及提权或逃逸的实现。

**从检材中读到的凭据只做离线分析**：识别类型、固定哈希、评估暴露面，**不做在线使用**。

**读者前提**：需要 Kubernetes 核心对象（Pod/Deployment/Service/Secret/RBAC）的基本概念、容器运行时基础，以及 [Docker 取证工件地图](../server-docker/server-docker-docker-artifact-map.md) 提供的容器层前提。

如果集群还在线，请先读 [2.1 关键路径速查表](#section-3) 与 [3.1 取证顺序](#section-10)——这个顺序是本领域最贵的经验之一，颠倒一次就可能永久失去审计日志。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 关键路径速查表

以下路径以 kubeadm 部署的典型布局为准；不同发行版与部署方式（kubeadm / 二进制 / 云厂商托管 EKS/ACK 等）会有差异，以实际检材为准。

| 路径 | 内容 | 取证价值 |
|---|---|---|
| `/etc/kubernetes/manifests/` | **静态 Pod 定义**（apiserver/etcd/scheduler/controller-manager 的 YAML） | ★★★★★ |
| `/etc/kubernetes/pki/` | **集群 PKI**：ca.crt/ca.key、apiserver 证书与私钥、**kubelet 客户端证书** | ★★★★★ |
| `/etc/kubernetes/admin.conf` | **集群管理员 kubeconfig**（含 client 证书或 token） | ★★★★★ |
| `/etc/kubernetes/kubelet.conf` | **kubelet 的 kubeconfig**（权限极大） | ★★★★★ |
| `/etc/kubernetes/kube-apiserver.yaml` | API Server 配置（审计策略路径、加密配置 `--encryption-provider-config`） | ★★★★★ |
| `/var/lib/etcd/member/snap/*.db` | etcd 快照文件，含全部集群状态与 Secret 明文 | ★★★★★ |
| `/var/lib/etcd/member/wal/` | etcd 预写日志（**含最近的写入，即使快照过期也有**） | ★★★★ |
| `/var/log/kubernetes/audit.log` | **API Server 审计日志**（K8s 取证最重要的一份日志） | ★★★★★ |
| `/var/log/pods/<ns>_<pod>_<uid>/<container>/N.log` | **Pod 日志原始文件** | ★★★★★ |
| `/var/log/containers/*.log` | **CRI 日志的软链接**（内容与上面相同） | ★★★★ |
| `/var/lib/kubelet/pods/<uid>/` | **Pod 完整目录**：容器 rootfs、configz、volume 挂载 | ★★★★★ |
| `/var/lib/kubelet/config.yaml` | kubelet 配置（**静态 Pod 路径、cgroup 驱动、认证授权**） | ★★★★ |
| `/var/lib/kubelet/plugins/` | CSI/credential-provider 插件（含云厂商云凭证的交换逻辑） | ★★★★ |
| `/var/lib/kubelet/cert/`、`pki/` | kubelet 自己的证书与密钥 | ★★★★ |
| `/var/run/secrets/kubernetes.io/serviceaccount/` | **当前 Pod 内的 SA token**（控制平面 Pod 也有） | ★★★★★ |
| `/run/containerd/containerd.sock` | containerd 的 unix socket（**能访问它 ≈ 节点 root**） | ★★★★★ |
| `/var/log/kubelet.log`、`journalctl -u kubelet` | kubelet 日志（含 Pod 启停、exec、探针记录） | ★★★★ |
| `/var/log/syslog`、`auth.log` | 宿主机系统与 SSH 日志 | ★★★★（见[《Linux 服务器取证工件地图》](../server-panel/server-panel-linux-server-artifact-map.md)） |

> ⚠️ **三条最容易踩空的**：
> 1. 托管集群（EKS/ACK 等）的控制平面在云厂商侧，你拿不到 `apiserver.yaml`、`etcd` 数据目录、审计日志。必须向委托方明确索取控制平面日志与 etcd 备份，否则报告会有大段"数据不可得"。
> 2. **审计日志默认不开启。** API Server 默认 `audit-log-path` 为空，**必须显式配置**。没开就是没开，**不能推定"没发生"**。
> 3. `/var/log/containers/*.log` 是软链接，用 `cat` 能读，但**归档时只 copy 软链接会失效**，要 `-L` 跟随或直接取 `/var/log/pods/` 下的真实文件。

<a id="section-4"></a>

### 2.2 Pod 日志的两条路径（必须讲清）

这是 K8s 日志取证最常被问的一点。

**同一份容器输出，在磁盘上有两个位置**：

```
真实文件（数据源）：
/var/log/pods/<namespace>_<pod-name>_<pod-uid>/<container-name>/0.log
        │                    │                │              │  └── 轮转序号：0.log, 1.log, 2.log
        │                    │                │              └───── 容器名
        │                    │                └──────────────────── Pod UID（重启会变）
        │                    └───────────────────────────────────── Pod 名
        └────────────────────────────────────────────────────────── 命名空间

CRI 软链接（便于按 pod/容器检索）：
/var/log/containers/<pod-name>_<namespace>_<container-name>-<container-id>.log
        └───────┬──────┘└─────┬────┘└──────┬──────┘└─────┬────┘
             Pod 名         命名空间        容器名         容器 ID（前 12 位）
                ↑
        ★ 注意：字段顺序是「Pod名_命名空间」，与 pods 目录的「命名空间_Pod名_UID」相反
        ★ 这里不含 Pod UID，但含容器 ID——容器重启即产生新的软链接
```

| 对比项 | `/var/log/pods/.../N.log` | `/var/log/containers/*.log` |
|---|---|---|
| **性质** | **真实文件**（轮转产生 `0.log`、`1.log`…） | **符号链接**，指向 pods 下的文件 |
| **目录/文件命名** | `<ns>_<pod-name>_<pod-uid>/<ctr>/N.log` | `<pod-name>_<ns>_<ctr>-<container-id>.log` |
| **是否含 Pod UID** | ✅ **含 Pod UID** | ❌ **不含，但含容器 ID** |
| **内容** | 原始输出 | **完全相同**（同一文件） |
| **轮转历史** | ✅ 全部 `N.log` 都在 | ❌ 只有当前那一个 |
| **取证价值** | ★★★★★ | ★★★★ |
| **归档方式** | `cp -p` 直接复制真实文件 | `cp -pL` 跟随软链，或 `cp -a` 只留链接结构 |

**为什么两套命名不对称**：pods 目录按 **Pod UID** 分目录，是为了让"同名 Pod 的每次重启"各自独立留存；containers 目录按 **Pod 名 + 容器 ID** 建链接，是为了让运维能按名字快速找到当前这一份。

```bash
# 验证"同一份数据、两种呈现"
ls -l /var/log/containers/ | head -5
# lrwxrwxrwx ... digiforensics-app_default_web-xm8k2qp4z.log
#   -> /var/log/pods/default_digiforensics-app-6d4f7b2c9d/xm8k2qp4z/web/0.log
#                                  ↑ Pod UID        ↑ 容器 ID  ↑ 容器名
ls -la /var/log/pods/default_digiforensics-app-6d4f7b2c9d/xm8k2qp4z/web/
# -rw-r----- 1 root root 84213 ... 0.log
# -rw-r----- 1 root root 79044 ... 1.log     ← 轮转保留的历史

# 同一 Pod 名有几个 UID 目录 = 重启过几次
ls -d /var/log/pods/*digiforensics-app* | wc -l
# 2     ← 同一 Pod 名对应 2 个不同 UID = 至少重启过一次

# 容器 ID 出现在软链接名里，可直接反查 Pod UID（★ 交叉验证手段）
readlink /var/log/containers/digiforensics-app_default_web-*.log
# /var/log/pods/default_digiforensics-app-6d4f7b2c9d/xm8k2qp4z/web/0.log
```

> ⚠️ 两个路径都不能用 `tail -f` 式的实时跟读做取证，容器运行时日志文件正在被追加。要用 `cp -p` 复制后再分析，并在报告里说明"这是采集时刻的快照"。

<a id="section-5"></a>

### 2.3 etcd：整个集群的单点真相

etcd 是 Kubernetes 的唯一持久化存储。

集群里所有对象——包括 Secret 的明文——都在这里。

```
/var/lib/etcd/
└── member/
    ├── snap/          ★★★ 快照文件 db（v3 存储），取证首选
    │   ├── db
    │   └── *.snap
    ├── wal/           ★★  预写日志，含最近的写入
    │   └── 0000000000000000-0000000000000000-*.wal
    └── snap/*.snap    （旧版本 bolt 格式的快照）
```

**为什么快照是取证首选**：

| 理由 | 说明 |
|---|---|
| **自包含** | 一个 `db` 文件里就有某一时点的全部集群状态 |
| **不受轮转影响** | 不像日志那样被覆盖 |
| **可离线分析** | `etcdutl snapshot status` 直接读（**只读操作**） |
| **覆盖 Secret 明文** | 即使 API 层是 base64，etcd 里也是最终值 |

```bash
# ★ 只读的完整性/状态检查（不改数据，安全）
ETCDCTL_API=3 etcdutl snapshot status /evidence/etcd-snapshot.db
# etcdutl snapshot status /evidence/etcd-snapshot.db
#   Hash:           4a7f2e9b...      ← 逻辑数据摘要（CRC32-Castagnoli），32 位
#   Revision:       184523            ★ etcd MVCC 的 main revision
#   Total Keys:     3471
#   Total Size:     45 MB

# 旧版本集群的兼容命令（etcd 3.3 及更早用 etcdctl）
ETCDCTL_API=3 etcdctl snapshot status /evidence/etcd-snapshot.db -w table
```

> ⚠️ `Hash` 是逻辑数据摘要，不是文件哈希，也不是页结构校验值。
>
> 它是 etcd 遍历数据库里全部 bucket 的 key/value 后算出的 **CRC32-Castagnoli**，宽度只有 32 位。
> **它既不覆盖快照文件的字节，也不代表"文件被截断"**——它只回答"这份数据库的逻辑内容与生成它的那份是否一致"。
> 需要字节级同一性就用 `sha256sum`，两者不可互相替代。
>
> 另：这个命令同时会跑一遍 bbolt 的文件完整性检查（内部 `tx.Check()`），
> 失败时输出的文本是 `snapshot file integrity check failed`。
> `missing hash` 属于**另一个环节**——它出现在快照 restore 时检查文件尾部附加的 SHA-256 是否存在，不是 `snapshot status` 的输出。看到这两个词要分清是哪个阶段报的。

> ⚠️ **`Revision` 是关键字段但不是时间。**
>
> 它是 etcd MVCC 存储层的 **main revision**（主修订号），即这份快照覆盖到的最大版本号。
> 能与审计日志的 `auditID` 交叉验证，但本身不含时间戳。要得到时间必须用审计日志。
>
> **快照的获取时机决定它反映的时刻**——取证时越早抢越接近现场，晚一天可能已经变化很大。

**关于加密的重要认知**：`kube-apiserver.yaml` 里的 `--encryption-provider-config` 指向一个加密配置文件。若配置了静态加密，**etcd 里的 Secret 值是密文**，需要用对应 provider 解密；若未配置，**就是 base64 编码的明文**。**判断依据是配置文件是否存在，不是猜。** 详见[第 05 篇](server-k8s-configmap-secret.md)。

<a id="section-6"></a>

### 2.4 kubelet 目录与 Pod 内的凭据

`/var/lib/kubelet/pods/<pod-uid>/` 是**节点上某个 Pod 的完整目录**：

| 子项 | 内容 | 取证价值 |
|---|---|---|
| `<container>/` | 容器 rootfs 的软链接（指向 containerd 快照） | ★★★★★ |
| `configz/` | **该 Pod 的完整配置**（镜像、命令、挂载、env） | ★★★★★ |
| `volumes/` | **Pod 级卷挂载点**（emptyDir、ConfigMap、Secret） | ★★★★★ |
| `etc-hosts`、`resolv.conf` | 该 Pod 的 DNS 配置 | ★★★ |
| `plugins/` | CSI 插件的 Pod 级数据 | ★★★ |

ConfigMap / Secret / ServiceAccount token 在宿主机的落地位置（理解"为什么容器里能看到凭据"的关键）：

```
/var/lib/kubelet/pods/<uid>/volumes/
├── kubernetes.io~configmap/<cm-name>/<key>     ← ConfigMap 内容以文件形式落盘
├── kubernetes.io~projected/default/
│   ├── default-token        ★★★ 每个 Pod 都有（除非 automountServiceAccountToken: false）
│   ├── ca.crt  namespace   ← 容器内 SA 三件套
└── kubernetes.io~empty-dir/<name>/              ← emptyDir 数据（Pod 删除即清理）
```

SA token 泄露 = 该 ServiceAccount 的全部权限泄露。 token 是 JWT，payload 段只是 base64 编码、可直接还原（签名验证需要集群 CA 公钥，**但读取信息不需要**）：

```bash
cat /mnt/df/var/lib/kubelet/pods/<uid>/volumes/kubernetes.io~projected/default/default-token
# eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwi...In0.XXXX
echo '<token 第二段>' | base64 -d | python3 -m json.tool
# {
#   "kubernetes.io/serviceaccount/namespace": "digiforensics",
#   "kubernetes.io/serviceaccount/service-account.name": "digiforensics-app",
#   "iat": 1710000000, "exp": 2171000000,        ← exp 极长 = 长效 token（K8s 默认设计）
#   "kid": "dfff456c7bcc79297e3776a35a6c6775e91c91b13"
# }
```

> ⚠️ `exp` 极长（十年）是 K8s 的正常设计，不能据此判定为恶意。 判恶意必须结合"**谁在何时从哪拿走了它**"——这正是审计日志要回答的问题（[第 05 篇](server-k8s-configmap-secret.md)）。

<a id="section-7"></a>

### 2.5 静态 Pod：控制平面的"隐形"部分

kubeadm 部署时，apiserver、etcd、scheduler、controller-manager、CNI 并非普通 Pod，而是由 kubelet 直接从 YAML 文件读取启动的静态 Pod，全部位于 `/etc/kubernetes/manifests/`。

**取证意义（四条，逐条对应下表）**：

| 特征 | 取证含义 |
|---|---|
| **不受 RBAC 管辖**，kubelet 直接创建 | `kubectl delete pod` 删不掉（会被重建）；**攻击者改这些文件，kubectl 侧看不到异常** |
| **改文件 = 集群级持久化** | 节点重启后新配置自动生效 |
| **在 API 里呈现为"镜像 Pod"** | 静态 Pod 本体不在 API 中，kubelet 会上报一个同名的 **mirror Pod**，名字为 `<static-pod-name>-<node-name>`，带 `metadata.ownerReferences` 指向 `Node`，且多一个注解 `kubernetes.io/config.mirror`。这是判定"某个 Pod 是不是静态 Pod"的唯一可靠 API 特征 |
| **审计记录可能不完整** | kubelet 直接写文件并上报，创建/修改动作不经 API Server 授权链路，审计日志里往往只看到镜像 Pod 的更新，看不到"谁改了文件" |
| `etcd.yaml` 里的 `dataDir` 与证书路径 | 判断"数据被搬到哪去了"的关键 |
| **文件 `mtime` 是时间锚点** | 静态 Pod YAML 极少变动，**`mtime` 变化即异常** |
| **目录下出现非标准文件名** | ★★ **控制面持久化的首选位置**（见[第 06 篇](server-k8s-container-escape-and-runtime-artifacts.md)） |

```bash
ls -l --time-style=long-iso /mnt/df/etc/kubernetes/manifests/
# -rw-r----- 1 root root 2841 2023-05-11 09:20:14 kube-apiserver.yaml   ← 与其他文件同期 = 正常
# -rw-r----- 1 root root  892 2024-03-18 03:14:52 audit-shim.yaml      ★ ★★ 非标准文件名
cat /mnt/df/etc/kubernetes/manifests/audit-shim.yaml | head -20
# containers:
# - name: shim
#   image: 198.51.100.24:5000/shim:latest        ★ 外部镜像
#   securityContext: {privileged: true}           ★ ★★ 特权
#   volumeMounts: [{mountPath: /var/log/kubernetes}]  ★ ★★ 读取审计日志
```

<a id="section-8"></a>

### 2.6 Kubelet 10250：读端口也是攻击面

| 端口 | 服务 | 风险 |
|---|---|---|
| **10250** | Kubelet **HTTPS 读写 API** | **未授权即可读任意 Pod 数据、exec 进容器** |
| 10255 | Kubelet read-only 端口 | 未授权可读 Pod 信息与日志 |
| 6443 | API Server | 未授权 = 集群完全失守 |
| 2379/2380 | etcd 客户端/对等端口 | **未授权 = 直读所有 Secret** |

**取证含义**：若这些端口对外开放（`ss -tulpn` 可见），攻击者**根本不需要进入集群**就能拿到数据，**日志里也不会有任何记录**。"边界暴露"是独立于入侵的严重发现，必须单独查、单独写。
---

<a id="section-9"></a>

## 三、操作步骤

<a id="section-10"></a>

### 3.1 取证顺序（不可颠倒）

etcd 快照和内存都是**会被覆盖或丢失**的，顺序错了就追不回。

```
1. ★★ 抢 etcd 快照（member/snap/*.db + wal/）
      理由：全集群状态 + Secret 明文，删了就没了
                ↓
2. ★★ 抢 API Server 审计日志（/var/log/kubernetes/audit.log）
      理由：唯一能回答"谁在何时做了什么"的记录
                ↓
3. ★  内存镜像（若在运行）—— 内存里的 SA token、解密中的密钥
                ↓
4. ★  宿主机活体状态 + Pod 日志 + kubelet 目录
                ↓
5.    /etc/kubernetes/ 配置与 PKI（最稳定，可最后取）
                ↓
6.    全盘镜像 → 离线深度分析
```

**理由说明**：etcd 快照是**唯一的凭据全量来源**且**随时可能被 compaction 影响**；审计日志是**行为证据的唯一来源**且**有轮转**；内存易失；`/etc/kubernetes/` 几乎不变，放最后不影响。

<a id="section-11"></a>

### 3.2 第 1 步：抢 etcd 快照（最高优先级）

```bash
# 在 etcd 所在节点（控制平面节点）执行
mkdir -p /evidence/etcd
ls -l --time-style=long-iso /var/lib/etcd/member/snap/
# -rw------- 1 root root 47185920 2024-03-18 06:12:04 db       ★ 快照
# -rw------- 1 root root  8388608 2024-03-18 06:12:04 3e3f...snap

# ★ 只复制，不移动、不压缩（保持原样）
cp -p /var/lib/etcd/member/snap/db /evidence/etcd/etcd-snapshot.db
cp -p /var/lib/etcd/member/wal/*   /evidence/etcd/ 2>/dev/null
sha256sum /evidence/etcd/* | tee /evidence/etcd/hashes.txt

# ★ 立刻做完整性检查（只读，不改数据）
ETCDCTL_API=3 etcdutl snapshot status /evidence/etcd/etcd-snapshot.db
#   Hash: 4a7f2e9b...    Revision: 184523    Total Keys: 3471
# ⚠️ 如果报 "snapshot file integrity check failed"，
#    说明快照文件本身在复制过程中被截断或损坏，需重新复制并记录
#    （注意：这条报的是 bbolt 文件结构坏了，不是 Hash 值对不上）
```

> ⚠️ **etcd 快照必须在 etcd 所在节点上取**。托管集群（EKS/ACK）取不到，必须向云厂商或委托方索取备份。
>
> **一致性的三条边界必须写进报告**：
> ① `member/snap/db` 是 etcd **每 5 分钟默认间隔**落盘的 bbolt 文件，**在复制过程中仍可能被 etcd 原子替换**。复制完成后**必须立刻跑 `snapshot status`**，报 `snapshot file integrity check failed` 就重拷。
> ② **`db` 与 `wal/` 必须一起取且注意顺序**。快照文件的 `consistent_index` 之后的新写入只存在于 WAL 里，**只拷 `db` 会丢掉最后几分钟的变更**（含刚被创建的恶意对象）。
> ③ 优先 `cp` 现有文件而非 `etcdctl snapshot save`：后者是在线操作，会与 etcd 争抢 IO 并可能触发新快照，**本身是改变现场的动作**。

<a id="section-12"></a>

### 3.3 第 2 步：抢审计日志与 API Server 日志

```bash
# 审计日志位置由 kube-apiserver.yaml 的 --audit-log-path 决定，先确认
grep -nE 'audit-log-path|audit-policy-file|audit-log-maxage|audit-log-maxbackup|audit-log-maxsize' \
     /mnt/df/etc/kubernetes/kube-apiserver.yaml
# - --audit-log-path=/var/log/kubernetes/audit.log
# - --audit-policy-file=/etc/kubernetes/audit-policy.yaml
# - --audit-log-maxage=30          ← 保留 30 天
# - --audit-log-maxbackup=10      ← 最多 10 个归档

ls -l --time-style=long-iso /mnt/df/var/log/kubernetes/
cp -p /mnt/df/var/log/kubernetes/audit*.log* /evidence/k8s/ 2>/dev/null
wc -l /evidence/k8s/audit.log
# 2841937    ← 行数决定可分析规模；JSON Lines 格式，约 400~800 字节/行

# API Server 自身日志（含鉴权失败、准入拒绝）
journalctl -u kube-apiserver --since '2024-03-17' 2>/dev/null | grep -iE 'denied|forbidden|unauthorized' | head -40
# 离线读 journal 归档：journalctl --file=/mnt/df/var/log/journal/<id>/system.journal -u kube-apiserver
```

**日志不存在时的正确表述**：`--audit-log-path` 未配置 = 该集群从未记录审计日志。此时报告必须写"该集群未启用 API Server 审计，无法从 API 调用层面确定攻击者行为"，**不能写"未发现异常调用"**——这两者差别极大。审计日志缺失是取证能力的重大局限，**应在报告的局限章节明确列出**。

<a id="section-13"></a>

### 3.4 第 3 步：kubelet 目录与 Pod 日志

```bash
# kubelet 目录：Pod 清单与配置
ls -1 /mnt/df/var/lib/kubelet/pods/ | head -20
ls -la /mnt/df/var/lib/kubelet/pods/<uid>/configz/ 2>/dev/null
cat    /mnt/df/var/lib/kubelet/pods/<uid>/configz/config 2>/dev/null | python3 -m json.tool | head -40

# Pod 级卷（ConfigMap / Secret / emptyDir 都在这里）
find /mnt/df/var/lib/kubelet/pods/<uid>/volumes -maxdepth 3 -type d | head -30
cat /mnt/df/var/lib/kubelet/pods/<uid>/volumes/kubernetes.io~projected/default/default-token 2>/dev/null | head -c 80

# ★ Pod 日志：真实文件优先（含轮转历史与 UID 目录）
ls -la /mnt/df/var/log/pods/default_digiforensics-app-6d4f7b2c9d/xm8k2qp4z/web/
cp -p /mnt/df/var/log/pods/*/*/*/*.log /evidence/podlogs/ 2>/dev/null
# CRI 软链接：内容相同但只有当前一份
ls -l /mnt/df/var/log/containers/ | head
cp -pL /mnt/df/var/log/containers/*.log /evidence/crilogs/ 2>/dev/null   # -L 跟随软链
# 同一 Pod 名有几个 UID 目录 = 重启过几次
ls -d /mnt/df/var/log/pods/*digiforensics-app* | wc -l

# 日志中的可疑关键词（容器内命令输出、下载执行、外连）
grep -aiE 'curl .*\| *(ba)?sh|base64 -d|wget |nc -e|stratum|198\.51\.100|/dev/tcp' \
     /mnt/df/var/log/pods/*/*/*/*.log | head -40
```

<a id="section-14"></a>

### 3.5 第 4 步：`/etc/kubernetes/` 与 PKI

```bash
ls -la /mnt/df/etc/kubernetes/ /mnt/df/etc/kubernetes/manifests/ /mnt/df/etc/kubernetes/pki/
# ★ kubeconfig 里的凭据（同样是可直接使用的凭证）
grep -rn 'client-key-data\|client-certificate-data\|token:' /mnt/df/etc/kubernetes/*.conf 2>/dev/null
# ★★ 静态 Pod：逐个看是否被改 + 是否有非标准文件
stat -c '%n  mtime=%y  ctime=%z' /mnt/df/etc/kubernetes/manifests/*.yaml
ls -1 /mnt/df/etc/kubernetes/manifests/ | grep -vE 'kube-apiserver|kube-controller-manager|kube-scheduler|^etcd.yaml|cni-networking'
#   → 有输出 = 存在非标准静态 Pod，重点查（见 2.5 与第 06 篇）
# ★ 审计策略文件（决定审计日志记什么，详见第 05 篇）
cat /mnt/df/etc/kubernetes/audit-policy.yaml 2>/dev/null
# rules:
# - level: Metadata              ← 只记元数据，Secret 内容不入日志
#   resources: ["secrets"]
# - level: RequestResponse       ← 完整请求与响应
#   verbs: ["create","update","patch","delete"]
```

<a id="section-15"></a>

### 3.6 第 5 步：kubectl 只读取证命令

**前置**：需要有效 kubeconfig（`/etc/kubernetes/admin.conf`），且**只使用下列只读命令**。

```bash
export KUBECONFIG=/etc/kubernetes/admin.conf

# Pod 全景（-o wide 给节点与 IP）
kubectl get pods -o wide --all-namespaces | tee /evidence/k8s/pods-wide.txt
# ★ 筛出非正常状态：Terminating / Error / CrashLoopBackOff / OOMKilled
kubectl get pods -A -o json | python3 -c "
import json,sys
for it in json.load(sys.stdin)['items']:
    flags=[]
    for c in (it.get('status',{}).get('containerStatuses') or []):
        w=(c.get('state') or {}).get('waiting') or {}
        if w.get('reason'): flags.append(w['reason'])
        if c.get('restartCount',0)>3: flags.append('restarts=%d'%c['restartCount'])
        t=(c.get('lastState') or {}).get('terminated') or {}
        if t.get('reason')=='OOMKilled': flags.append('OOMKilled')
    if flags: print(it['metadata']['namespace'], it['metadata']['name'], flags)
"

# 单 Pod 详情（★ Events 段是"为什么起不来"的关键）
kubectl describe pod -n <ns> <pod> | tee /evidence/k8s/describe-pod.txt
# ★★ 崩溃前的日志（当前日志常为空，因为进程已重启）
kubectl logs -n <ns> <pod> --previous --timestamps | tail -100
kubectl logs -n <ns> <pod> -c <ctr> --previous --timestamps     # 多容器 Pod 要指定容器

# Events（★ 默认只保留约 1 小时，超期即无）
kubectl get events --all-namespaces --sort-by=.lastTimestamp | tail -60
kubectl get events -n <ns> --field-selector involvedObject.name=<pod> --sort-by=.lastTimestamp

kubectl get configmap -A -o yaml > /evidence/k8s/configmaps.yaml
kubectl get secret -A                       # ★ 只列名字，不要 -o yaml
```

> ⚠️ `kubectl exec` 会改变容器状态，本篇不将其作为取证手段。 它会在容器内执行命令、可能写入 `bash_history`、可能触发已植入的 payload，并在审计日志里留下 `pods/exec` 记录（**这条记录本身是重要证据，但取它的人不该是你**）。需要容器内文件时改用 `kubectl cp`（同样会留审计记录），或在**离线分析机上**读 kubelet 的 `volumes/` 与 containerd 快照。

<a id="section-16"></a>

### 3.7 第 6 步：验证环节

| 验证对象 | 方法 | 通过标准 |
|---|---|---|
| etcd 快照完整性 | `etcdutl snapshot status` + `sha256sum` | `Hash`/`Revision` 可读、无 integrity 报错；文件 SHA-256 已记录 |
| 审计日志覆盖时段 | `head -1`/`tail -1` 取首末 `requestReceivedTimestamp` | **可分析时段必须写进报告** |
| 审计日志是否被清空 | 文件大小 + 是否存在 `.1` 归档 | 有归档但缺当前文件 = 曾轮转；都无 = 可能未启用 |
| Pod 日志双路径一致 | `md5sum` 真实文件与 `cat` 软链接后的内容 | 相同 → 同一份数据 |
| Pod 重启次数 | `/var/log/pods/` 下同 Pod 名的 UID 目录数 | >1 = 重启过，重启原因是 `kubectl describe` 要查的核心 |
| SA token 归属 | base64 解 payload 读 `serviceaccount/namespace` | 能确定该 token 的权限范围 |
| 静态 Pod 未被改 | 文件 `mtime` 与其他静态 Pod 对比、`manifests/` 无多余文件 | 同期 + 无多余 = 正常 |
| 端口暴露面 | `ss -tulpn \| grep -E '10250\|10255\|6443\|2379'` | 是否有边界暴露 |

---
<a id="section-17"></a>

## 四、常见陷阱

K8s 取证的误判与单机取证不同：这里的每一个「没找到」几乎都有制度性的理由（默认不开启、被轮转、在别的节点、在云侧），而不是分析员漏查。本章按 3.1 的取证顺序归组——先说抢的时机，再说每类工件的具体读法错误，最后收在结论表述与取证能力边界上。

<a id="section-18"></a>

### 4.1 取证时机与不可逆操作

<a id="section-19"></a>

#### 陷阱 1：★ 先重启或升级集群再取证

**现象**：到达现场时集群异常，运维或分析员先做了节点重启、控制面升级、etcd 压缩或故障转移，然后再开始固定证据。

**原因**：这四类操作每一类都会改写或重建现场。节点重装/重置会重建 `/var/lib/kubelet` 与 `/var/log/pods`；etcd 升级改变数据目录结构，compaction 会删除旧版本；**API Server 重启触发日志轮转**；控制面升级会重写 `/etc/kubernetes/manifests/` 里的静态 Pod YAML（哪怕内容等价，mtime 也全变了）。

**影响**：不可逆且影响全局。

日志轮转后旧文件变成归档，compaction 后旧 revision 数据消失，mtime 全变之后「静态 Pod 文件是否被改」这个判据彻底失效——**而它恰恰是控制面持久化的主要检测手段**。

**核查**：严格按 3.1 的顺序，第一件事是 `cp -p` 走 etcd 快照与 WAL，第二件事是 `cp -p` 走审计日志，这两步完成前不要进行任何操作。若已发生重启或升级，报告的局限一节必须逐项写明：哪些工件因何操作而改变、`mtime` 判据是否仍可用、时间线的起点是否只能改用其他来源。

<a id="section-20"></a>

#### 陷阱 2：★ 用 `etcdctl snapshot save` 取快照

**现象**：图省事，直接 `etcdctl snapshot save` 把快照存到证据目录。

**原因**：`snapshot save` 是**对运行中的 etcd 发起的在线操作**——它请求 etcd 生成一份新的快照，会与 etcd 竞争 IO、消耗内存，**并可能触发一次新的快照落盘**。而 `cp -p` 复制 `member/snap/db` 是纯只读的文件复制。

**影响**：两个层面。

一是**改变了现场**：一次在线快照会推进 etcd 的状态，且在高负载集群上可能影响服务稳定性，进而触发运维的进一步处置。

二是**证据可信度**：自己触发的快照与现场自然产生的 `db` 在时间点上不同，严格来说不再是对现场的原始写照。

**核查**：优先 `cp -p` 复制现有的 `member/snap/db` 与 `wal/`，复制完成后立刻跑 `etcdutl snapshot status`——报 `snapshot file integrity check failed` 说明复制期间文件被截断或损坏，需重拷并记录。这条「复制期间文件可能被替换」的说明本身要写进报告，因为它决定了这个工件的一致性声明能到什么强度。

<a id="section-21"></a>

#### 陷阱 3：只拷 `member/snap/db` 而跳过 `wal/`

**现象**：按文章里的路径清单只固定了快照 `db`，把 `wal/` 目录忽略了。

**原因**：快照 `db` 是一个**时点**的状态，而 `consistent_index` 之后的新写入**只存在于 WAL 里**。etcd 默认每 5 分钟落一次快照，也就是说**最近这几分钟的所有变更都不在 `db` 里**——包括刚刚被创建的恶意对象（特权 Pod、新的 RoleBinding、被改的 Secret）。

**影响**：**丢失的恰好是攻击窗口的最后几分钟**。

在入侵正在进行时取证，攻击者刚做的提权动作很可能就在 WAL 里。报告若写「etcd 中未见异常对象」，而对方指出该对象刚创建两分钟，结论就站不住了。

**核查**：`db` 与 `wal/` 一起取、一起哈希、一起记录。分析时明确写出「快照 `Revision` 为 X，WAL 中另有 Y 之后的写入未并入快照」这个边界。第五章的案例里 `db` 与 `wal/` 是一起固定的，这个细节要在报告里复现。

<a id="section-22"></a>

#### 陷阱 4：把「快照里有 Secret」写成「Secret 已泄露」

**现象**：拿到 etcd 快照，确认里面含数据库口令、镜像仓库凭据，报告直接写「所有 Secret 已泄露」。

**原因**：快照里存在 Secret 的**值**，只说明这些凭据**被存放在 etcd 中**（这是 K8s 的正常设计）。是否「泄露」取决于**有没有人把它们取走**——这需要审计日志或网络侧证据，而不是快照本身。快照被扣押在证据盘上，与凭据流向攻击者，是两件事。

**影响**：结论强度凭空提升，且会引发不必要的对外处置动作（比如按凭据泄露标准通报）。

反过来，若这份快照后来从证据流转出去，那才是真正的泄露事件——报告里应该提示这一点。

**核查**：把发现写成两条：① **工件事实**——「etcd 快照 `Revision` X 含 N 个 Secret 对象，明文可读，构成**高价值敏感资产**」；② **行为结论**——「哪些 Secret 在何时被哪个身份读取过，须以审计日志的 `get`/`list secrets` 记录确定，未取得审计日志时该行为不可判定」。同时在报告中提示委托方：**处置完毕后应轮换全部 Secret**，并说明理由是快照已脱离原保管环境。

<a id="section-23"></a>

#### 陷阱 5：用 `etcdutl snapshot status` 的 `Hash` 当成内容哈希做比对

**现象**：`etcdutl snapshot status` 输出里的 `Hash: 4a7f2e9b...` 被抄进报告，当成快照文件的完整性凭据，与另一份同源快照的 `Hash` 直接比对，判定「两个快照是同一份」或「不是同一份」。

**原因**：这个 `Hash` 是 etcd 对逻辑数据算出的 CRC32-Castagnoli 摘要，宽度只有 32 位。 它的生成方式是遍历数据库里所有 bucket 的 key/value 逐个喂进 CRC 累加器——不读文件字节、不涉及 bbolt 页结构。也就是说：

- 它**不是**文件摘要。同一份数据库被 `snapshot save` 重新导出一次，逻辑内容一致时 `Hash` 会一致，但文件字节不同（页布局、free list 顺序都会变）。
- 它**不是**完整性校验。文件被截断、页损坏时报的是 `snapshot file integrity check failed`（来自另一条独立的检查路径），不是 `Hash` 对不上。
- 它**只有 32 位**。拿它做两份文件的同一性判据，碰撞概率并不低，"不一致"完全可能是碰撞而不是内容真的不同。

**影响**：**用它做「两个快照是否同一份」的判据，结论无意义。** 委托方常见的要求是「验证交付快照与我们的是同一份」，报告却给出一个 32 位逻辑摘要，形式上像哈希比对，实质上什么都没比。据此判定「不是同一份」，还可能推动一次不必要的重新取证；反过来若两份不同快照碰巧 `Hash` 相同，就得出「已验证同一份」的错误结论——这是更危险的方向。

**核查**：**三个层次的校验分开做、分开记。**

| 层次 | 工具 | 记录内容 | 记录局限 |
|---|---|---|---|
| 逻辑内容 | `snapshot status` 的 `Hash` | 这份库的 key/value 内容是否与生成它时一致 | 文件字节是否相同 |
| 文件结构 | `snapshot status` 是否报 `integrity check failed` | bbolt 文件有没有被截断 / 页损坏 | 内容是否与别处一致 |
| 字节同一性 | `sha256sum` | 两个文件是不是逐字节相同 | 内容语义是否正确 |

```bash
# 逻辑层 + 结构层：etcd 自己的只读检查
ETCDCTL_API=3 etcdutl snapshot status /evidence/DigiForensics-etcd.db
# 关注 Revision / Total Keys / Total Size，
# 以及是否输出 "snapshot file integrity check failed"

# 字节层：文件摘要，用于与其他副本比对
sha256sum /evidence/DigiForensics-etcd.db > DigiForensics-etcd.db.sha256
```

报告里两行分列：`逻辑/结构检查：通过（Revision X, Total Keys Y，无 integrity 报错）` 与 `文件 SHA-256: <值>`。

<a id="section-24"></a>

### 4.2 工件读法

<a id="section-25"></a>

#### 陷阱 6：以为未加密时 Secret 是明文文本

**现象**：对 etcd 快照（或 Secret 的 YAML）执行 `strings` / `grep` 想找数据库口令，没找到，写下「未发现数据库凭据」。

**原因**：Secret 的值在 API 层面与存储层面都是 base64 编码，不是明文文本。 即使集群没启用静态加密，值也是 base64——`strings` 能搜到的只是键名，不是值。要判断是否加密，唯一依据是 `--encryption-provider-config` 指向的配置文件**是否存在**，不是猜。

**影响**：这一条会产生彻底相反的两类错误结论。

搜不到就写「未发现凭据」，或者反过来把 base64 串当明文解读后误当成可读口令写进报告。

**核查**：先查 `kube-apiserver.yaml` 里的 `--encryption-provider-config`——配置了静态加密则 etcd 里是密文，需用对应 provider 解密；未配置则是 base64 编码的明文。取值一律走 `etcdutl` 解析或 `base64 -d`，**报告里贴凭据一律脱敏**。

<a id="section-26"></a>

#### 陷阱 7：把 audit.log 当普通文本 grep

**现象**：`grep -i suspicious /var/log/kubernetes/audit.log` 找可疑调用，搜不到就认为没有异常 API 调用。

**原因**：**审计日志是 JSON Lines**——一行一个 JSON 对象，关键字段嵌在结构里而不是裸文本。单个关键词几乎必然出现在别的字段中（URL、UA、注解），而真正要找的「某身份对某资源的某动词」这种组合，裸 grep 根本表达不了。一行 400–800 字节，直接按行匹配等于放弃了结构化字段的价值。

**影响**：一次 grep 的「无结果」会被当成覆盖了整个日志的阴性结论，而实际上只是没做解析。

**核查**：**按 JSON 逐行解析**，用 `user.username` + `verb` + `objectRef.resource` + `sourceIPs` + `responseStatus.code` 组合筛选。[第 05 篇](server-k8s-configmap-secret.md)给出了完整的评分脚本。裸 grep 只适合快速看一眼日志的整体样貌。

<a id="section-27"></a>

#### 陷阱 8：审计日志未启用却写「未发现异常调用」

**现象**：`--audit-log-path` 未配置或文件不存在，报告的「行为分析」一节写「未发现异常 API 调用」。

**原因**：**API Server 默认不开启审计日志**，必须显式配置。这不是「日志恰好被清空了」，而是**该集群从未记录过**。两个事实在证据价值上完全不同。

**影响**：这是本主题最贵的表述错误——它把**取证能力的缺失**写成了**阴性发现**。委托方读到「未发现异常调用」，会认为 API 层是干净的，从而排除掉整条编排层攻击线。而真实情况下，攻击者用任何 SA 做的任何操作都没有留下记录。

**核查**：报告必须写成能力声明而非发现：「该集群未启用 API Server 审计，无法从 API 调用层面确定攻击者行为；攻击路径与操作序列不可考」。同时列入「取证局限」清单，并说明补救途径——云厂商托管集群可向云侧索取控制平面日志。

<a id="section-28"></a>

#### 陷阱 9：只读 `/var/log/containers/` 就以为拿到了全部 Pod 日志

**现象**：把 `/var/log/containers/*.log` 全拷走，得出「Pod 日志已固定」，时间线也从最早那一份开始画。

**原因**：containers 目录里**全部是符号链接**，且**每个 Pod 容器只有当前那一份**——轮转产生的历史（`1.log`、`2.log`）在 `/var/log/pods/<ns>_<pod>_<uid>/<ctr>/` 下，而 containers 目录不指向它们。

**影响**：**丢掉的是轮转历史，也就是更早时段的行为**。

第五章的案例里，03-17 深夜的首次数据导出就在 `1.log` 里。只看 containers 目录会完全错过，把攻击起点从 03-17 23:10 误判成 03-18 02:36——**时间线整整错了三个多小时，因果关系也随之改变**。

**核查**：以 `/var/log/pods/` 下的真实文件为主，路径含 **Pod UID**，同名 Pod 的不同 UID 目录各自独立。`containers/` 目录只作交叉验证用（其链接名里的容器 ID 可反查 Pod UID），归档时必须 `cp -pL` 跟随软链，否则拷过去的是失效链接。

<a id="section-29"></a>

#### 陷阱 10：忽略同名 Pod 的多个 UID 目录

**现象**：`/var/log/pods/` 下按 Pod 名找到一个目录就开始分析，把同名 Pod 的其他 UID 目录当作重复项忽略。

**原因**：pods 目录按 Pod UID 分目录，UID 每次 Pod 重建都会变。 同名 Pod 有两个 UID 目录，意味着它至少重建过一次——而**重建前的日志属于另一个 UID 目录**，是完全独立的一份。

**影响**：重建是重要的时间事件——可能是 OOMKilled 后重启（内存异常）、配置错误导致的 CrashLoopBackOff、或者节点故障迁移。

**它把时间线切成两段，两段的日志分处两地**。只看最新那段，等于把崩溃原因（只在 `--previous` 日志里）漏掉。

**核查**：`ls -d /var/log/pods/*<pod-name>* | wc -l` 统计 UID 目录数，逐个按 UID 分析日志；再对每个 UID 取第一行与最后一行时间，确定各段覆盖窗口。重建原因要用 `kubectl describe` 的 `Last State`（含 `Reason`、`Exit Code`）配合 `--previous` 日志确定。

<a id="section-30"></a>

#### 陷阱 11：把 SA token 的长 `exp` 当成异常

**现象**：解出 projected token 的 payload，看到 `exp` 是十年后的时间，判为「攻击者制作的长效后门 token」。

**原因**：ServiceAccount token 默认就是长有效期的——它由控制器签发、不自动轮换（未启用 token 投影与轮换机制时），`exp` 通常是签发时间加约十年。**这是 K8s 的正常设计，不是恶意特征。**

**影响**：把一个所有 Pod 都一样的正常值当成后门特征，会让报告的凭据分析部分失去可信度——一旦对方指出「我们集群所有 token 都是这样」，这一节就整体作废。

**核查**：token 的价值在于回答「这个 token 属于谁、能干什么、谁在何时拿走了它」。判恶意必须落在行为证据上：审计日志里该 SA 的操作序列、RoleBinding 被修改的记录、以及 token 文件所在 Pod 是否为异常创建。token 本身只提供身份与权限范围，不提供恶意性。

<a id="section-31"></a>

#### 陷阱 12：跳过静态 Pod 的 mtime 与文件名检查

**现象**：只查 `/etc/kubernetes/manifests/` 里几个标准文件的内容，没看出问题，就认为控制面未被篡改。

**原因**：静态 Pod 由 kubelet 直接从这些 YAML 读取并创建，不受 RBAC 管辖。 这意味着攻击者可以直接往这个目录放一个新的 YAML——它不需要任何 API 权限，`kubectl get pods` 里只会看到一个「镜像 Pod」，**看不出是谁放的**。而这些文件极少变动，mtime 与其他文件同期 = 正常；出现不同步的 mtime 或非标准文件名 = 异常。

**影响**：控制面持久化是集群里最隐蔽的一类存在——它不受 RBAC 管辖、节点重启后自动拉起、API 侧记录不完整。

漏掉它意味着报告里「未发现持久化机制」的结论直接不成立。

**核查**：两条同时做——① `stat` 每个 YAML 的 `mtime`，与其他静态 Pod 文件对比；② 列出目录下所有文件，**过滤掉已知的标准文件名**（`kube-apiserver`、`kube-controller-manager`、`kube-scheduler`、`etcd.yaml`、CNI 相关），剩下的每一个都要逐行读内容，重点看 `image` 来源、`privileged`、`hostPath`、`command`/`args`、挂载了哪些敏感目录。

<a id="section-32"></a>

#### 陷阱 13：只看当前静态 Pod 目录，漏掉被删除的持久化残留

**现象**：`ls /etc/kubernetes/manifests/` 看到四个标准文件，mtime 都是一年前，报告写「未发现控制面持久化」。

**原因**：攻击者放置的 YAML 会在被删除后留下可恢复的痕迹，而目录清单不反映历史。 kubelet 只按当前存在的文件创建静态 Pod，文件一删镜像 Pod 随之消失——`kubectl get pods` 里什么都看不到，目录 `ls` 也干净了。但 ext4 的目录项在文件被 unlink 之后，如果所在 inode 尚未被复用，目录块里可能仍留有该文件名的残留字节；同样，上一代 Pod 的 rootfs 会被 kubelet 在清理时删除，但 containerd 快照层的删除是异步的，在一段时间内仍可从 `/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/` 下找到对应层。

**影响**：结论强度被环境行为支撑——「目录里没有」被当成「从来没放过」。而这个判据恰好在攻击者主动清理的场景下最不可靠：清理恰恰是攻击者会做的事。报告若因此写成阴性发现，而后续在快照层或残留目录块里发现了痕迹，这份报告的整段结论都会被重估。

**核查**：**三处一起查，不看单一目录清单。** ① 目录内当前文件与 mtime（陷阱 11）；② containerd 快照层目录里与静态 Pod 数量不符的孤儿层，按层目录的 mtime 排序找出异常时间段；③ ext4 上该目录的空闲块与 inode 情况（需要空闲空间较多、对抗性低时才可行）。

```bash
# ① 当前 manifests 目录
ls -la --time-style=full-iso /mnt/df/etc/kubernetes/manifests/
# ② 孤儿快照层：kubelet 通常会清理，残留说明有静态 Pod 曾被创建
ls -lat /mnt/df/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/ | head -20
# ③ kubelet 对该 Pod 的清理痕迹
find /mnt/df/var/lib/kubelet/pods/ -maxdepth 1 -newermt '2024-03-17' -printf '%T@ %p\
' 2>/dev/null | sort -n
```

阴性结论写成：「`/etc/kubernetes/manifests/` 当前含 `<N>` 个文件，均为标准文件名且 mtime 同期；containerd 快照层中与静态 Pod 数量不匹配的孤儿层 `<M>` 个（最早 mtime `<时间>`）；**未覆盖**：已 unlink 文件的 ext4 残留目录块、跨节点的其他节点目录」。

<a id="section-33"></a>

#### 陷阱 14：用 Pod 日志首行时间当作 Pod 创建时间

**现象**：`/var/log/pods/<ns>_<name>_<uid>/<ctr>/0.log` 第一行是 `2024-03-18 09:12:03 ...`，报告据此写「该 Pod 于 03-18 09:12 创建」。

**原因**：日志首行时间是「第一条被记录的输出的时间」，不是进程启动时间。 应用启动到第一行输出之间通常有一段初始化（加载配置、连数据库、框架预热），可能几秒也可能几分钟；而反过来，`0.log` 是**当前正在写的那一份**，它前面还有 `1.log`、`2.log`（按 2.4 与陷阱 16 的说明，序号越大越早），更早的启动输出在那里。取首行当作创建时间，会得到一个**偏晚且可能偏到错误切片上**的值。

**影响**：创建时间是行为链的起点，也是判断「崩溃—重启」因果关系的关键锚点。用它和漏洞利用时间、`kubectl` 事件时间做比对时，差值会被当成可疑的时间戳篡改或时区错误，继续往下推演出一整串错误结论。更常见的情况是拿这个时间与 `creationTimestamp` 对不上，分析员于是怀疑其中一个被改过。

**核查**：**创建时间从 API 元数据取，不用日志推断。** 在 etcd 快照里按 Pod UID 找该对象读 `metadata.creationTimestamp`；离线读单个 Pod 时用 `kubectl --dry-run=server` 之外的方式从快照解析。日志时间只用来确定「该时段有无输出」，并且必须写清是哪一份切片的首行。

```bash
# 从快照里按 UID 读 creationTimestamp（UID 才是主键，见陷阱 9）
grep -o '"uid":"[^"]*"[^}]*"creationTimestamp":"[^"]*"' /evidence/etcd-extract.json | head
```

结论句式：「该 Pod（UID `<uid>`）`creationTimestamp` 为 `<T1>`（取自 etcd 快照）；日志 `0.log` 首行为 `<T2>`，两者相差 `<Δ>`，属应用启动延迟，**不以日志首行作为创建时间**」。

<a id="section-34"></a>

#### 陷阱 15：在 etcd 快照里搜 ConfigMap 内容，搜不到就写「未硬编码凭据」

**现象**：对快照执行 `strings` 后 grep `password|jdbc:` 等关键字，无命中，报告写「该集群未见硬编码数据库凭据」。

**原因**：**三个层面同时限制了这道判据。** ① 值在 etcd 里是 protobuf/bbolt 的二进制编码，`strings` 未必能吐出完整可读的串，且 ConfigMap 的值在 API 层本就是**明文**（不是 base64），但二进制布局会把长字符串按块切开，跨块的密钥被 `strings` 丢弃。② ConfigMap 与 Secret 之外还有大量凭据落点：`/var/lib/kubelet/pods/<uid>/volumes/` 下的投射文件、Pod spec 里的 `env`（值在 API 对象里）、以及镜像内固化的配置。③ 集群若启用了 Secret 静态加密，Secret 值在快照里是 `k8s:enc:` 开头的密文，`strings` 同样搜不到。

**影响**：一次工具能力不匹配的「无结果」被写成资产层面的阴性结论。而这份清单是委托方轮换凭据的直接依据——**漏掉的正是最需要轮换的那批**。

**核查**：**解析快照而不是 grep 它。** 用 `etcdutl` 把键值导出成 JSON 后逐个解析 `data`/`stringData`，ConfigMap 的值直接可读，Secret 按 2.5 的三种加密状态分别处理；同时覆盖 ConfigMap 与 Secret 两类，以及 kubelet 的投射卷落点。判据写清覆盖范围：「在快照 `Revision` X 覆盖的全部对象中解析 ConfigMap N 个、Secret M 个；**未覆盖**：Pod spec `env` 中的明文值、镜像内固化配置、已删除对象的历史版本」。

<a id="section-35"></a>

### 4.3 结论表述与取证边界

<a id="section-36"></a>

#### 陷阱 16：不查 10250 / 2379 等端口的暴露面

**现象**：报告通篇在讲入侵过程，没有一个字提到集群端口的对外暴露情况。

**原因**：kubelet 的 10250（读写）、10255（只读）、API Server 的 6443、etcd 的 2379/2380，**任意一个未授权可达都足以造成严重后果**——10255 可读 Pod 数据、6443 可接管集群、2379 可直读所有 Secret。而这类暴露是**独立于入侵的架构问题**：即便这次入侵是从内部发起的，端口暴露本身仍是必须单独报告的严重发现。

**影响**：漏报一项与入侵无关、但严重性可能更高的发现。

委托方的整改优先级会因此排错——他们可能只清理了入侵路径，却把敞开的 2379 端口留在那里。

**核查**：**无条件单独检查并单独成节**：`ss -tulpn` 筛出这些端口，判断监听地址是 `0.0.0.0`/`::` 还是具体内网 IP，结合网络策略与安全组判断是否真正可达。**即使全案未发现入侵记录，这一条也要写**——它是独立的架构风险，不依附于入侵结论。

<a id="section-37"></a>

#### 陷阱 17：把「本地存在数据」写成「已外传」

**现象**：在 Pod 日志里看到导出命令、在卷里找到导出结果，结论直接写「数据已被窃取外传」。

**原因**：这些证据能证明的是「**数据被导出到了集群内的某个位置**」。传输到集群外是独立的一步，需要网络流量、连接记录、DNS 查询日志或云侧流量报告来证明。**Pod 规格与卷内文件里不会有传输记录。**

**影响**：结论强度凭空提升。

委托方据此对外做数据泄露通报、或按已泄露的口径通知用户与监管，而事实上数据可能还停在集群内。若后续证明未外传，机构的公信力要付出代价。

**核查**：拆成两层。事实层：「在 `<卷名>` 卷内发现订单表导出结果，含 N 条记录，字段 X、Y、Z」。推断层：「该文件表明数据已被导出至集群内；是否外传至攻击者处需网络侧或云侧流量证据独立确认，本地证据不支持该结论」。

<a id="section-38"></a>

#### 陷阱 18：把静态 Pod 的审计记录缺失当成「没操作过」

**现象**：审计日志里查不到攻击者创建静态 Pod 的记录，于是排除掉「持久化」这一发现。

**原因**：kubelet 是直接写 YAML 文件并上报镜像 Pod 的，创建/修改动作不经 API Server 的授权链路。 审计日志里往往只能看到镜像 Pod 的状态更新，看不到「谁改了这个文件」——因为根本没有对应的 API 请求。

**影响**：这会让「审计日志里没有记录」被误用为排除依据，从而丢掉已在文件系统上找到的物证。

那个 YAML 文件本身就是最硬的证据。

**核查**：审计日志是行为证据，文件系统是物证，两者不能互相替代。 发现可疑静态 Pod YAML 后，物证（文件内容、mtime、其中的镜像与挂载）足以支撑结论；审计日志的缺失只说明「该动作不经 API 层，无法归因到具体 API 身份」，需要在归因一节写成「写入者的 API 身份不可考」而不是反过来否定发现。

<a id="section-39"></a>

#### 陷阱 19：★ 把「未发现」写成绝对结论

**现象**：报告末尾出现「未发现其他异常」这句话，没有限定范围。

**原因**：在 K8s 环境里，「未发现」几乎总是有洞的。已知必然存在缺口的地方至少六处：**已删除 Pod 的日志与 `configz`**（Pod 删除时 `/var/lib/kubelet/pods/<uid>/` 与日志目录会被清理）、**`emptyDir` 卷数据**（随 Pod 生命周期清理）、**tmpfs 挂载**（只在内存）、**托管集群的控制平面侧工件**、**未启用的审计日志**、已被 compaction 掉的 etcd 历史 revision。不加限定的「未发现」在字面上等于「全部检查过且干净」。

**影响**：调查会因此收尾。

一旦后续在云侧日志或另一个节点上发现本应被覆盖范围内的痕迹，这份报告连同其中所有真实发现的可信度一起被推翻。

**核查**：**每一处「未发现」写成三段式**——检查范围（具体到路径、Pod UID、节点、命名空间）+ 检查方式（命令或解析方法）+ **未覆盖范围**。示例：「在 `node-1` 与 `node-2` 的 `/var/log/pods/` 全量日志、`/var/lib/kubelet/pods/` 全量 `configz`、etcd 快照 `Revision` 189247 内全部对象内检查，未发现除 `audit-shim` 外的第二个静态 Pod 定义；**未覆盖**：`node-3` 的 Pod 日志（镜像未包含该分区）、已删除 Pod 的 `configz` 与日志、`emptyDir` 卷内容、审计日志未覆盖的 03-16 22:00 之前时段」。

<a id="section-40"></a>

### 4.4 日志轮转与时间基准

<a id="section-41"></a>

#### 陷阱 20：把日志轮转序号当成时间顺序

**现象**：`/var/log/pods/<ns>_<name>_<uid>/<ctr>/` 下有 `0.log`、`1.log`、`2.log` 三个文件，报告把 `0.log` 当成最早的一段、`2.log` 当成最新的一段，按这个顺序重建了该容器的时间线。

**原因**：**序号与时间方向是相反的。** kubelet 与容器运行时按体积切分日志（kubelet 的 `containerLogMaxSize`，默认 10Mi），切出的文件以递增序号命名，而**序号越大的是越早的**——`0.log` 是当前正在写的最新一份，`2.log` 是最早被切出去的历史。若节点上的日志轮转由 logrotate 接管（`/etc/logrotate.d/` 下另有配置），命名形态又会不同。**无论哪种形态，序号都不承载时间语义。**

**影响**：顺序一旦倒过来，**整条时间线会被整体镜像**。本案最典型的是「先崩溃后重启」还是「先重启后崩溃」——日志说反了，Pod 重启的因果解释就完全颠倒，重启原因（OOM、探针失败、应用崩溃）会归到错误的动作上。`--previous` 取崩溃前日志这个动作也因此可能取到崩溃之后的片段，让分析员在错误的区间里找根因。

**核查**：**顺序只能从内容确定，不从文件名确定。** 逐个文件读首行与末行的时间戳，按时间重排后再建时间线；序号只用来做两件事——**发现缺口**（序号不连续说明中间切片已被删除或从未生成，这本身是要写进报告的结论）与**确认容量边界**。另外两处必须同时确认：① 节点上是否有 logrotate 在二次轮转这批文件（那会引入 `.1`/`.gz` 后缀与另一套命名）；② 静态 Pod 的日志不在这个目录下，路径与轮转规则都不同（见陷阱 11 与陷阱 15），不能拿这套序号逻辑套上去。

<a id="section-42"></a>

#### 陷阱 21：把单节点的单个 UID 目录当作该 Pod 的全部日志

**现象**：在 `node-1` 上找到 `/var/log/pods/default_digiforensics-app-6d4f7b2c9d/web/` 这一个目录，合并完里面的所有切片，报告写「该 Pod 的应用日志已全部分析」。

**原因**：同一个 Pod UID 的日志可能分散在多个节点上。 Pod 在存活期间可以被重新调度——节点故障、驱逐（`taints`/`taints` 变更）、节点维护都会让同一 UID 的 Pod 在新节点上重新落地，kubelet 会在**新节点上创建一个同样以 UID 命名的目录**。两份目录里的容器 ID 不同（容器重建会换 ID），内容是同一次 Pod 生命周期的不同阶段。只取一台机器上的那份，得到的可能是**空白的那一份**——如果调度方向恰好相反。

**影响**：时间线出现一个没有解释的空洞，而空洞会被读成「那个时段应用没输出任何东西」，也就是「没活动」。第五章 5.2 讲的双路径取全解决的是同一节点内的归档问题，这里是**跨节点的同一 UID**——两个层次的问题容易被混为一谈，交叉引用时要写清。

**核查**：按 UID 在全部节点上搜集，而不是按节点逐台处理。 先在集群所有节点列出全部 UID 目录，找出同一 UID 出现的位置，再按时间合并。

```bash
# 在每台节点上按 UID 列出（对全部节点重复执行）
ls -d /var/log/pods/*_<pod-uid>_* 2>/dev/null

# 同一 UID 落在多台节点时，逐台取首末时间再合并
for n in node-1 node-2 node-3; do
  printf "%s: " "$n"
  find /mnt/df-$n/var/log/pods/default_digiforensics-app-6d4f7b2c9d -name '*.log' \
    -exec head -1 {} \; -exec tail -1 {} \; 2>/dev/null | sed -n '1p;$p'
done
```

报告句式：「Pod UID `<uid>` 的日志在本集群 `<N>` 个节点上存在副本（`node-1`、`<node-2>`），已全部取得并按行内时间合并；**未覆盖**：已随节点下线一并清除的节点本地数据」。若某些节点未纳入采集镜像，要像陷阱 15 的示例那样明确写出缺哪几台。

<a id="section-43"></a>

#### 陷阱 22：用快照的 `Revision` 当成时间点排序事件

**现象**：把审计日志里的事件按时间排序时，把 etcd `Revision` 也当作一个时间维度——某对象的 `Revision` 比另一个高，就判定它「后发生」，并据此把两次 RBAC 修改排成先后。

**原因**：`Revision` 是单调递增的版本号，不是时钟。 2.3 的警告框写得很直接：它「是 etcd 的全局单调递增版本号，能与审计日志的 `auditID` 交叉验证，但**本身不含时间戳**」。递增的方向只保证「谁在先写入」，而写入顺序与事件发生顺序之间隔着 API Server 的处理队列；并发请求的落库顺序可能与客户端发起顺序不同。**它能排序「写入」，不能排序「发生」。**

**影响**：因果关系被写反。两次权限变更的先后顺序直接决定「攻击者先被授予权限再提权」还是「先提权再授予」，而这个顺序决定归因是否成立。用 `Revision` 排出来的顺序一旦颠倒，整条提权链的叙述就反了，而这在质证时是可被当场推翻的。

**核查**：`Revision` 只用于两件事——对齐与校验。 ① 对齐：确认某个对象在审计日志的某次操作后确实存在于快照里（对象的 `mod_revision` ≥ 该操作的 `auditID` 对应时刻）；② 校验：快照的 `Revision` 与 `Total Keys` 是这份快照的静态属性，写进报告作为工件描述。时间一律取 `requestReceivedTimestamp`（无该字段时取 `stageTimestamp`，并注明）。

```bash
# 涉及顺序时，以时间戳为准；Revision 仅作交叉核对
grep '"resource":"clusterrolebindings"' /evidence/k8s/audit.log | python3 -c "
import json,sys
for line in sys.stdin:
    d=json.loads(line)
    print(d.get('requestReceivedTimestamp'), d.get('stageTimestamp'), d.get('verb'),
          (d.get('objectRef') or {}).get('name'), 'auditID=', d.get('auditID'))
" | sort
```

报告里凡涉及先后因果的，一律写「依 `requestReceivedTimestamp` 排序」；`Revision` 出现在工件说明里，不出现在时间线里。

<a id="section-44"></a>

#### 陷阱 23：用采集时刻的 Pod 列表去证明事发时刻的 Pod 状态

**现象**：取证时 `kubectl get pods -A` 显示某命名空间下有 3 个 Pod，其中没有可疑对象，报告写「事发时该命名空间内无异常 Pod」。

**原因**：Pod 是短生命周期对象，`kubectl get` 的快照几乎不携带历史。 恶意 Pod 创建完、运行十几分钟、删除——`kubectl get` 看到的是一个干净现场，而这是攻击链里最常见的一种形态。更隐蔽的是**同名重建**：一个 Deployment 的 Pod 被反复重建，`get` 看到的名字始终是 `web-6d4f-x7b2c` 这个形式，`x7b2c` 之类的后缀每次都不同，但人眼扫过去会当成同一个。而按陷阱 13 已经讲过的，删掉的 Pod 的 `/var/lib/kubelet/pods/<uid>/` 与日志目录会随之被 kubelet 清理，连文件系统侧的物证都可能一并消失。

**影响**：「当前没有」被写成「当时没有」，把整条持久化攻击线从结论里抹掉。更麻烦的是这类阴性表述会引导调查方向——委托方会认为问题在别处，从而不去查审计日志和 etcd 历史。

**核查**：Pod 是否曾经存在，只由审计日志的 `pods` 相关记录与 etcd 快照的 `Revision` 范围回答。 `kubectl get` 只用于确认当前状态，且要标明查询时刻与 context。

```bash
# 事发时段的 Pod 生命周期事件（create/delete）
grep '"resource":"pods"' /evidence/k8s/audit.log | python3 -c "
import json,sys
for line in sys.stdin:
    d=json.loads(line); o=d.get('objectRef') or {}
    if d.get('verb') in ('create','delete','deletecollection'):
        print(d.get('requestReceivedTimestamp'), d.get('verb'), o.get('namespace'), o.get('name'), d.get('responseStatus',{}).get('code'))
"
```

阴性句式：「截至 `<查询时间>` 该命名空间在跑 `<N>` 个 Pod；事发时段（`<起>`–`<止>`）内 Pod 的创建与删除事件依审计日志共 `<M>` 条，已删除 Pod 的 rootfs 与日志不在本次检材范围内」。

<a id="section-45"></a>

### 4.5 时间基准与字段语义


<a id="section-46"></a>

## 五、案例示例

<a id="section-47"></a>

### 5.1 业务 SA 提权到集群级权限并落地静态 Pod

**场景**

委托方（某公司）报告其 K8s 集群（kubeadm 自建，3 节点）中 `digiforensics` 命名空间疑似被入侵，怀疑数据被窃取。**集群仍在运行**，运维未做任何处置。委托方已提供**控制平面节点的镜像** `DigiForensics.dd`（raw，300 GB，ext4 起始扇区 2048，containerd 运行时）。异常起于 2024-03-18 凌晨。

这条路径值得先走，是因为 K8s 现场有一条别的板块没有的硬规则：先抢 etcd 快照和审计日志，再做任何其他事。集群还在跑意味着下一条审计事件随时可能覆盖现场，而 etcd 快照一旦错过就只能靠 etcd 自身的 compaction 窗口存活性来赌。

**处置过程**

**第 1 步 · 按 3.2 抢 etcd 快照**

```bash
cp -p /mnt/df/var/lib/etcd/member/snap/db /evidence/etcd/etcd-snapshot.db
cp -p /mnt/df/var/lib/etcd/member/wal/* /evidence/etcd/ 2>/dev/null
ETCDCTL_API=3 etcdutl snapshot status /evidence/etcd/etcd-snapshot.db
#   Hash: 8f3c1a9b...   Revision: 189247   Total Keys: 4102   Total Size: 50 MB
```

**第 2 步 · 按 3.3 确认审计日志**

```bash
head -1 /evidence/k8s/audit.log.1 | python3 -c "import json,sys;d=json.load(sys.stdin);print(d['requestReceivedTimestamp'],d['user']['username'])"
# 2024-03-16T22:00:11Z system:serviceaccount:kube-system:replicaset-controller get pods
```

**可分析时段**：`2024-03-16 22:00` 至今。**审计日志已启用且保留 30 天**，这是本案的幸运之处。

**第 3 步 · Pod 全景与两份"自白书"**

```bash
kubectl get pods -A -o wide | grep -viE 'Running|Completed'
# digiforensics  x7b2c-dumper-9c4f7a2b1x   Running          node-2  198.51.100.24   ★ 镜像来自外网 IP
# digiforensics  web-6d4f7b2c9d-x7b2c      CrashLoopBackOff                    ★ 反复崩溃

kubectl describe pod -n digiforensics x7b2c-dumper-9c4f7a2b1x | sed -n '/^Containers:/,/^Conditions:/p'
#     Image: 198.51.100.24:5000/dumper:latest          ★ 攻击者私库镜像
#     Command: ["/bin/sh","-c","psql -h 10.8.3.21 -d orders -c '\copy orders_all to stdout csv' > /data/out.csv"]
#     Mounts:  Mounts from: exfil-volume (rw)           ★ 名为 exfil 的卷

kubectl describe pod -n digiforensics web-6d4f7b2c9d-x7b2c | sed -n '/Last State/,/^Ready/p'
# Last State:  Terminated  Reason: OOMKilled  Exit Code: 137
kubectl logs -n digiforensics web-6d4f7b2c9d-x7b2c --previous --timestamps | tail -4
# 2024-03-18T02:38:44.903Z INFO  heap usage 1.9GB/2GB
# 2024-03-18T02:38:45.117Z ERROR result cache exhausted, falling back to disk spill   ★ 数据外泄到本地磁盘
```

`dumper` Pod 的 `Command` 是攻击者自己写下的明文导出命令，在本案中只作为**字符串证据**引用与登记，用于确认导出对象与落盘路径，不做任何复现。

**发现 1**：Pod 规格本身就是**两份完整的自白书**。

`dumper` Pod 的 `Command` 是**明文的 `psql \copy` 导出命令**且挂了名为 `exfil-volume` 的卷。`web` Pod 曾 **OOMKilled** 且日志显示"回退到磁盘暂存"，**这解释了数据为什么落到了卷里**（与[第 03 篇](../server-docker/server-docker-docker-volumes-and-bind-mounts.md)的卷内时间线对应）。

第 4 步 · Pod 日志双路径取全（只读 containers 会漏证据）

```bash
ls -d /mnt/df/var/log/pods/digiforensics_web-6d4f7b2c9d-*
# ...-8a1c3f5d7e9    ← UID 1
# ...-6d4f7b2c9d    ← UID 2     ★ 同名不同 UID = 至少重启过一次
grep -a 'copy\|export' /mnt/df/var/log/pods/digiforensics_web-6d4f7b2c9d-6d4f7b2c9d/*/web/1.log | head -3
# 2024-03-17 23:10:04 INFO  dump requested for table orders_all
```

**发现 2**：`1.log`（03-17 23:10）里存在更早的导出行为——**说明数据窃取在 03-17 深夜就已开始**，比 03-18 凌晨的 Pod 创建更早。

若只看 `/var/log/containers/` 的当前软链接，这部分证据会被完全漏掉。

第 5 步 · SA token 与静态 Pod（本案最严重的发现）

```bash
T=$(cat /mnt/df/var/lib/kubelet/pods/6d4f7b2c9d-*/volumes/kubernetes.io~projected/default/default-token 2>/dev/null | head -1)
echo "$T" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -c "
import json,sys; d=json.load(sys.stdin)
print('namespace:', d['kubernetes.io/serviceaccount/namespace'])
print('sa name  :', d['kubernetes.io/serviceaccount/service-account.name'])"
# namespace: digiforensics
# sa name  : digiforensics-app     ★ 业务 SA，不是新建的专用账号

ls -1 /mnt/df/etc/kubernetes/manifests/ | grep -vE 'kube-apiserver|kube-controller-manager|kube-scheduler|^etcd.yaml|cni-networking'
# audit-shim.yaml      ★ ★★ ★★ 非标准静态 Pod
grep -E 'image:|privileged|mountPath|command:' /mnt/df/etc/kubernetes/manifests/audit-shim.yaml
#   image: 198.51.100.24:5000/shim:latest        ★ 攻击者镜像
#   command: ["/bin/sh","-c","sleep infinity; tail -F /var/log/kubernetes/audit.log"]
#     mountPath: /var/log/kubernetes              ★ ★★ 读取审计日志
#   privileged: true                              ★ ★★ 特权
```

**发现 3（最严重）**：攻击者在 `/etc/kubernetes/manifests/` 放了一个名为 `audit-shim.yaml` 的**静态 Pod**：**特权运行、读取审计日志**。由于静态 Pod 不受 RBAC 管辖、节点重启后自动拉起，这是典型的**控制面持久化 + 审计规避**（痕迹识别与判定见[第 06 篇](server-k8s-container-escape-and-runtime-artifacts.md)，本案只做痕迹认定，不涉及手法）。加上 SA 是业务 SA `digiforensics-app`——这解释了攻击者为何能长期驻留且不易被发现。

第 6 步 · 审计日志分析（交由[第 05 篇](server-k8s-configmap-secret.md)的脚本）

```bash
python3 audit_score.py /evidence/k8s/audit.log --top 20
```

| 时间 (UTC) | 用户 | 动词 | 资源 | 来源 IP | 分值 | 命中规则 |
|---|---|---|---|---|---|---|
| 2024-03-18T02:36:44Z | `sa:digiforensics:digiforensics-app` | create | pods | 198.51.100.24 | 95 | 建 Pod + 挂 exfil-volume + 外部镜像 |
| 2024-03-18T02:40:19Z | 同上 | **update** | **clusterrolebindings** | 198.51.100.24 | **100** | **RBAC 提权，最高危** |
| 2024-03-18T03:14:52Z | 同上 | create | pods (static) | 198.51.100.24 | 90 | 写 `/etc/kubernetes/manifests` |
| 2024-03-17T23:12:08Z | 同上 | get/list | secrets | 198.51.100.24 | 80 | 读 Secret |

**发现 4**：先提权到 cluster-admin（02:40），再落地不受 RBAC 管辖的静态 Pod（03:14）——与第 5 步发现的 `audit-shim` 物证形成闭环。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 攻击者自 2024-03-17 23:10 起导出订单数据 | Pod 日志 `1.log` + 审计日志最早相关记录 | 强 |
| 03-18 02:36 创建 dumper Pod 执行数据导出 | 审计日志 create pods + Pod `Command` 原文 | **强（双源）** |
| 使用业务 SA `digiforensics-app` 而非专用账号 | 审计日志 `user.username` + token payload | 强 |
| 该 SA 于 02:40 被提升为集群级权限 | 审计日志 `update clusterrolebindings` | **强** |
| 在 `/etc/kubernetes/manifests/` 落地特权静态 Pod | `audit-shim.yaml` 内容 + mtime 03-14 | **强（物证）** |
| 攻击者镜像来自私库 `198.51.100.24:5000` | Pod 与静态 Pod 镜像字段 | 强 |
| 数据落到 `exfil-volume` 卷 | Pod `Mounts` + 卷内文件 | 强 |
| **etcd 快照含全部 Secret，已固定** | `etcdutl snapshot status` 通过，Revision 189247 | 强（**构成独立的凭据泄露面**） |
| **数据是否已外传成功** | Pod 规格与卷内无传输记录 | **未决项，不能仅凭本地文件断定** |
| **攻击者最初如何获得该 SA 的 token** | 需查 SA 的 RoleBinding 与 Secret 读取记录 | **未决项** |

**本节能证明**：完整攻击链的时间顺序（提权 → 落地 → 导出）、执行主体是哪个 SA、持久化物证在哪个路径。

**本节不能证明**：token 的初始泄露渠道、`198.51.100.24` 是否为攻击者自有基础设施、导出数据是否出网。

**误判对照**

最容易出的错是把"用业务 SA 提权"当成"攻击者从外部攻破了 K8s"。这两个结论差了一个量级——前者可能只是一次内部凭据泄露或一个被攻破的 CI 账号，后者才是集群边界失守。

1. **判据**：`user.username` 是 `system:serviceaccount:...`，说明请求**携带了集群内签发的凭据**。在没有 `authentication.k8s.io/user` 层面异常记录、也没有 API Server 外部暴露面证据的情况下，**不能推出"外部攻破"**。报告应写"持 SA 凭据者在集群内执行了提权操作"。
2. **判据**：`audit-shim.yaml` 的**存在**证明"有非标准静态 Pod"，但 `command` 里写着 `tail -F /var/log/kubernetes/audit.log` 只证明它**读取**审计日志，**不证明它修改或删除了审计日志**。要主张"审计被篡改"，必须有审计日志自身的缺口证据——审计记录的时间不连续、`requestReceivedTimestamp` 跳变、或 `audit.log` 与 `audit.log.1` 的轮转边界异常。本案**未做该验证，报告不得写"审计日志已被规避"**。
3. **判据**：`privileged: true` 证明该 Pod 运行时拥有特权，**不等于已被用于访问宿主机设备**。静态 Pod 清单文件里的字段是**声明**，实际使用痕迹需查节点上的设备访问记录、进程树或该 Pod 的日志。判据同"配置 ≠ 使用"。

按错误判据走，第 1 条踩中，委托方会按"集群被外部攻破"启动全面边界加固与对外披露，而真正的入口可能只是一张被误提交到 Git 仓库的 kubeconfig。

**加固方向完全错位，且真正的泄露渠道不会被修掉。**

第 2 条踩中则更麻烦：主张"审计被规避"而后续无法自证，会让整份报告的严谨性受质疑，反过来削弱那些本来成立的强结论。

<a id="section-48"></a>

### 5.2 Pod 重启导致的日志证据断裂与双路径取全

**场景**

承接 5.1。委托方追问："我们最早发现异常是 03-18 凌晨，但 `kubectl logs` 看到的日志最早只有 02:38。是不是你们判断的'03-17 23:10 已经开始'这个时间不可信？"

这个质疑是合理的——如果只看 `kubectl logs`，那条 23:10 的记录确实不存在。取证的关键在于：现场有两条不同的日志路径，证据只在其中一条上。

**处置过程**

第 1 步 · 先搞清 Pod 重启了几次、每次的 UID

```bash
kubectl get pod -n digiforensics web-6d4f7b2c9d-x7b2c -o jsonpath='{.status.containerStatuses[*].restartCount}{"\
"}'
# 2
ls -1d /mnt/df/var/log/pods/digiforensics_web-6d4f7b2c9d-*
# digiforensics_web-6d4f7b2c9d-x7b2c-6d4f7b2c9d    ← UID 2（当前）
# digiforensics_web-6d4f7b2c9d-x7b2c-8a1c3f5d7e9    ← UID 1（第一次）
```

`restartCount: 2` 与两个 UID 目录**互相印证**。如果只有 UID 2 一个目录而 `restartCount` 是 2，那反而说明**有日志已被轮转或清理**——这是必须立刻警觉的信号。

**第 2 步 · 两条路径的差异**

```bash
# 路径 A：/var/log/containers/ —— 只有当前容器的软链接
ls -l /mnt/df/var/log/containers/ | grep web-6d4f7b2c9d
# web-6d4f7b2c9d-digiforensics_web-6d4f7b2c9d-x7b2c-web.log
#   -> /var/log/pods/...-6d4f7b2c9d/.../1.log         ★ 只指当前 UID

# 路径 B：/var/log/pods/<ns>_<name>_<uid>/ —— 按 UID 分目录，历史全留
find /mnt/df/var/log/pods/digiforensics_web-6d4f7b2c9d-8a1c3f5d7e9/ -name '*.log' -printf '%p\
'
# .../web/0.log
# .../web/1.log
```

路径 A 是软链接，指向当前 UID；路径 B 保留每一个 UID 的完整目录。

**第 3 步 · 在路径 B 上取到更早的记录**

```bash
grep -a 'copy\|export' /mnt/df/var/log/pods/digiforensics_web-6d4f7b2c9d-8a1c3f5d7e9/web/1.log
# 2024-03-17T23:10:04.117Z INFO  dump requested for table orders_all
# 2024-03-17T23:10:07.402Z INFO  dump completed, 184203 rows -> /data/spill/orders_all.csv
grep -a 'copy\|export' /mnt/df/var/log/pods/digiforensics_web-6d4f7b2c9d-8a1c3f5d7e9/web/0.log
# 2024-03-17T22:41:55.008Z INFO  dump requested for table customers
# 2024-03-17T22:41:57.330Z INFO  dump completed, 90112 rows -> /data/spill/customers.csv
```

`0.log` 比 `1.log` 还早——导出 `customers` 表的动作发生在 22:41，比委托方自报的异常起点还早 19 分钟，也早于审计日志里第一条可疑记录（23:12）。

第 4 步 · 为什么 Pod 会重启两次（把 OOM 与退出码对上）

```bash
kubectl describe pod -n digiforensics web-6d4f7b2c9d-x7b2c | grep -A2 'Last State'
# Last State:  Terminated
#   Reason:  OOMKilled
#   Exit Code: 137                              ← 137 = 128+9 = SIGKILL，典型 OOM
kubectl get pod -n digiforensics web-6d4f7b2c9d-x7b2c -o jsonpath='{.spec.containers[*].resources}{"\
"}'
# {"limits":{"memory":"2Gi"}}                 ← 限 2Gi
```

**结论**

- 数据导出行为的实际起点为 2024-03-17 22:41:55（`0.log` 中的 `customers` 表导出），比 5.1 表格中的 23:10 还早，**报告里的时间线要据此前移**。
- 攻击窗口的**下界**已可确定：22:41:55 之前无该行为记录（`0.log` 是该容器首启日志，覆盖了完整生命周期）。窗口上界受审计日志保留策略限制，**03-16 22:00 之前不可分析**。
- Pod 两次重启均为 OOMKilled（Exit 137）+ 内存 limit 2Gi。结合 `2.log` 里的 `result cache exhausted, falling back to disk spill`，**导出行为本身是内存溢出的诱因**——这解释了为什么攻击者需要借 `exfil-volume` 把数据落到磁盘。

**未覆盖范围**：「该 Pod 三个 UID 目录下的全部 6 个日志文件（0/1/2.log × 3 UID）」，已全查；**未覆盖**已删除 Pod（`dumper` Pod 若已被删则日志不可得）、节点级 containerd 日志、API Server 侧请求体审计。

**误判对照**

这个案例最容易出的错有两个方向，第二个是本案的真正价值点。

1. 把"日志只到 02:38"写成"攻击从 02:38 才开始"。`kubectl logs` 默认只读当前容器的日志，**重启前的容器内容不在这里**。判据：只要 `restartCount > 0` 或 `/var/log/pods/` 下存在多于一个 UID 目录，`kubectl logs` 的输出就**必然不完整**，时间下界不可由它确定。
2. **把"日志完整"当成"攻击完整"**。本案找到了 22:41 的记录，但**这只能证明"最早的可见行为在 22:41"**。判据：`0.log` 覆盖首启，说明该 Pod 生命周期内**这个文件名下**没有更早记录；但攻击者完全可以 (a) 在此 Pod 创建之前就用其他 Pod 做过同样的事，(b) 导出到别的卷或别的节点。本案的 `dumper` Pod 是 02:36 才创建的，**它证明的是"另一次导出"，不是"唯一一次导出"**。
3. **判据**：`Exit Code: 137` 不能一律读成"内存不足导致崩溃"。137 只能证明进程收到 SIGKILL，原因可能是 OOM、也可能是 `kubectl delete pod`、也可能是节点驱逐。区分依据是 `Reason` 字段：只有 `Reason: OOMKilled` 才指向内存，本案两项都有，才成立。

按错误判据走，第 1 条踩中，报告的时间线会整体后移 3 小时以上。

委托方会据此把"03-17 22:00–03-18 06:00 当班的两名运维"列为重点排查对象，而真正相关的登录可能更早——**真凶反而被排除**。

第 2 条踩中则会让委托方以为"清理掉 dumper Pod 和这个 web Pod 就结束了"，漏掉其他节点上的同类 Pod。

<a id="section-49"></a>

### 5.3 反例 etcd 快照含全部 Secret 的凭据泄露面

**场景**

委托方在 5.1 结束后提出一个很实际的问题："etcd 快照你们已经取走了。里面有多少 Secret？这些 Secret 现在还有效吗？我们要不要全部轮换？"

这个问题的答案决定了整改的工作量级别，也是委托方最需要一份明确数字的地方。

**处置过程**

第 1 步 · 统计 Secret 数量与类型（不打印明文）

```bash
ETCDCTL_API=3 etcdutl snapshot status /evidence/etcd/etcd-snapshot.db
#   Revision: 189247   Total Keys: 4102

# 从快照恢复出的只读副本上枚举（不要在生产 etcd 上直接跑重查询）
ETCDCTL_API=3 etcdctl --endpoints=file:///evidence/etcd/replica.etcd get \
  "" --prefix --keys-only \
  | grep -E '^/registry/secrets/' | wc -l
# 47

# 按类型分组，只看 key 路径，不解 base64
ETCDCTL_API=3 etcdctl --endpoints=file:///evidence/etcd/replica.etcd get \
  "" --prefix --keys-only \
  | grep -E '^/registry/secrets/' \
  | sed -E 's#^/registry/secrets/([^/]+)/([^/]+)/.*#\1#' | sort | uniq -c
#     9 kubernetes.io/service-account-token   ← 这些是 SA token，变化快
#    11 Opaque                                 ← 用户自建：数据库密码、API Key、第三方密钥
#    27 kubernetes.io/dockerconfigjson        ← 镜像仓库拉取凭证
```

**第 2 步 · 判断哪些是真正需要轮换的**

关键区分是"etcd 里有"和"etcd 里有且现在还有效"：

```bash
# 判断依据：Secret 的 data 字段时间戳 vs 攻击窗口
# 攻击窗口 2024-03-17 22:41 — 2024-03-18 03:20
# 分类规则：
#   (a) 创建于攻击窗口之前 → 攻击者可能已读取其明文 → 必须轮换
#   (b) 创建于攻击窗口之后 → 不在泄露面内
#   (c) type=service-account-token → 由 controller 自动轮换，需单独确认
```

委托方侧提供的应用配置清单显示：11 个 `Opaque` Secret 中，**8 个**为 2024-02 至 2024-03-17 之间创建（生产数据库、支付网关、内部 API、对象存储、邮件服务等），**全部落在泄露面内**。

第 3 步 · 交叉验证：审计日志里读 Secret 的记录能对上几个

```bash
python3 audit_score.py /evidence/k8s/audit.log --verb get,list --resource secrets \
  | awk '{print $2,$4,$5}' | sort | uniq -c | sort -rn | head
# 47 2024-03-17T23:12:08Z sa:digiforensics:digiforensics-app 198.51.100.24   ← 一次性 list 全部
#  9 2024-03-18T02:41:33Z sa:digiforensics:digiforensics-app 198.51.100.24
```

审计日志里那条 `23:12:08 list secrets` **一次性覆盖了 47 个 Secret**，与快照里枚举出的总数**完全一致**——这交叉印证了"全部 Secret 已被读取"，而不是"部分被读取"。

**结论**

| 结论 | 依据 | 强度 |
|---|---|---|
| etcd 快照含 **47 个 Secret** 的明文数据（base64 非加密） | 快照枚举 + `Revision 189247` | 强 |
| 攻击者于 2024-03-17 23:12:08 一次性读取**全部 47 个** | 审计日志 `list secrets` 记录 | **强（审计日志直接证据）** |
| 其中 8 个 `Opaque` Secret 创建于攻击窗口前，必须轮换 | 创建时间与应用配置清单比对 | 强（**需委托方侧确认创建时间**） |
| 27 个 `dockerconfigjson` 泄露面为镜像仓库拉取凭证 | 类型枚举 | 强（**是否已失效需仓库侧确认**） |
| 9 个 `service-account-token` 需单独判断 | 类型枚举 | 中（token 有过期与轮换机制，不能等同于长期有效凭据） |

**限定范围**：本次结论覆盖「从 Revision 189247 快照枚举出的 47 个 Secret 键路径 + 审计日志中的 2 条相关记录」。
**未覆盖范围**：**未解密验证**每个 Secret 的具体内容（避免不必要的敏感数据扩散）；**未确认**任何 Secret 的当前有效性（需联系各依赖方）；**未覆盖** etcd 历史版本（compaction 前的旧数据是否仍可恢复，需查 `etcdctl` compaction 记录）；**未覆盖** 集群外部可能存在的 Secret 副本（Helm values、CI 变量、云厂商密钥管理服务）。

**误判对照**

这个反例最容易出的错是把"etcd 里存着 47 个 Secret"直接写成"47 个凭据已泄露"。

1. **判据**：`list secrets` 读的是**键路径与元数据**，Secret 的 `data` 字段虽是 base64 但**确实在响应体里**——所以"读到"与"可解密"在本案是同一件事，**这一点与其他存储不同，不构成推脱理由**。但"读到"与"**使用过**"是两件事：审计日志里没有任何一条针对**具体 Secret 名称**的 `get` 记录（只有那条全量 `list`），因此报告不得声称"攻击者使用了某个具体凭据登录了某系统"。
2. **判据**：`service-account-token` **不能与静态凭据等同**。这 9 个 token 由 token controller 签发，有 `expirationSeconds` 过期与自动轮换；即便 23:12 被读到，多数在数小时到一天内已轮换。把它们与 8 个 `Opaque` 混在一起写"必须全部立即轮换"会显著放大整改范围，且会让委托方对真正紧急的那 8 个反而降低优先级。正确表述是"8 个静态凭据需立即轮换，9 个 SA token 需按过期时间分别评估"。
3. **判据**："未解密 Secret 内容"不能写成"未评估 Secret 内容"。本节为避免敏感数据扩散只做键路径枚举，这是取证中的常规做法，**但报告必须同时写明已做清点、只是未解内容**，否则"未做"和"做了但没看"在委托方眼里是一回事，轮换决策会因信息不足而搁置。

按错误判据走，第 2 条踩中的代价是整改优先级被稀释。

8 个静态凭据里包含生产数据库与支付网关，**轮换窗口以小时计**。如果这份报告让人先把注意力放在 9 个可能早已过期的 token 上，泄露窗口就被拉长了。

第 3 条踩中则更隐蔽：委托方看到"未评估"就可能暂缓整个轮换计划。

<a id="section-50"></a>

## 六、扩展阅读方向

本篇是集群的地图，不解析结构。

往下走有四条路——把凭据挖出来、把身份对上、把配置判危险、把视野落回节点与网络。

**审计与凭据：最高价值的两类工件**

- [审计日志与 ConfigMap-Secret](server-k8s-configmap-secret.md) —— 审计策略的四个级别、审计日志的分析方法、ConfigMap/Secret 的类型与加密配置，以及"某个 Secret 是什么时候被谁读走的"怎么查。**本篇说它最重要，这一篇说怎么用。**
- [Volume 与绑定挂载取证](../server-docker/server-docker-docker-volumes-and-bind-mounts.md) —— 集群里 `emptyDir` 与 PVC 的清理时机决定了证据能存活多久，**PVC/PV 侧的判定方法在这一篇**。

**高危配置：本篇只列路径，判定在那一篇**

- [容器逃逸与运行时痕迹](server-k8s-container-escape-and-runtime-artifacts.md) —— `hostPath`、特权 Pod、`hostNetwork`、DaemonSet、异常 RBAC 的识别与**误报排除**。读完它之后你会知道 `config.v2.json` 里哪些字段是高危信号。
- [Docker 取证工件地图](../server-docker/server-docker-docker-artifact-map.md) —— 节点侧的工件全景，以及 `containerd` 与 Docker 的差异。
- [镜像层与 overlay2 解析](../server-docker/server-docker-overlay2.md) —— 集群里拉取的镜像落在哪些层，**镜像的构建指令本身就是供应链证据。**

**主机与网络：集群之外的那部分**

- [Linux 服务器取证工件地图](../server-panel/server-panel-linux-server-artifact-map.md) —— 节点的 `/var/log/syslog`、`auth.log`、站点目录。控制平面 Pod 里的异常往往先在节点日志上留下痕迹。
- [Linux 系统日志深度分析](../../computer/computer-log/computer-log-system-log-analysis.md) —— 节点侧日志的读法与轮转处理。
- [网络流量与 PCAP 取证](../../memory/memory-network/memory-network-pcap.md) —— 微服务架构中数据外泄常发生在集群内部，公网抓包完全看不到东西向流量。本篇的取证对象是集群，网络侧是它的另一半。
- [Linux 与 Android 内存取证](../../memory/memory-artifact/memory-artifact-linux-android.md) —— 停止即失的那部分证据（进程、连接、内存内容）只能从内存侧补。

**结论与规范**

- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 取证顺序不可颠倒的原则出处。etcd 快照为什么排第一、审计日志为什么不能等，这篇给的是依据。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md) —— 从检材读到的凭据能用到什么程度。本篇的边界声明在工程侧，法律侧在这一篇。
- [证据保管链与委托证明](../../fundamentals/fundamentals-chain/fundamentals-chain-chain-of-custody-and-authorization.md) —— etcd 快照、PKI 私钥这类工件的交接记录要求最高，因为它们本身就是凭据。
<a id="section-51"></a>

## 七、命令速查

```bash
# ===== 0. 取证顺序：etcd 快照 → 审计日志 → 内存 → Pod/日志 → /etc/kubernetes → 镜像 =====

# ===== 1. ★★ 抢 etcd 快照（只读，不影响 etcd）=====
ls -l --time-style=long-iso /var/lib/etcd/member/snap/ /var/lib/etcd/member/wal/
cp -p /var/lib/etcd/member/snap/db /evidence/etcd/etcd-snapshot.db
cp -p /var/lib/etcd/member/wal/* /evidence/etcd/ 2>/dev/null
sha256sum /evidence/etcd/* | tee /evidence/etcd/hashes.txt
ETCDCTL_API=3 etcdutl snapshot status /evidence/etcd/etcd-snapshot.db   # Hash/Revision/Keys
# 旧集群兼容：ETCDCTL_API=3 etcdctl snapshot status <db> -w table

# ===== 2. ★★ 抢审计日志与 API Server 日志 =====
grep -nE 'audit-log-path|audit-policy-file|audit-log-maxage|audit-log-maxbackup' \
     /mnt/df/etc/kubernetes/kube-apiserver.yaml
ls -l --time-style=long-iso /mnt/df/var/log/kubernetes/
cp -p /mnt/df/var/log/kubernetes/audit*.log* /evidence/k8s/
head -1 /evidence/k8s/audit.log.1 | python3 -c "import json,sys;d=json.load(sys.stdin);print(d['requestReceivedTimestamp'],d['user']['username'])"  # 时段下限
cat /mnt/df/etc/kubernetes/audit-policy.yaml
journalctl -u kube-apiserver --since '2024-03-17' 2>/dev/null | grep -iE 'denied|forbidden|unauthorized' | head -40

# ===== 3. ★ kubelet 目录与 Pod 日志（双路径）=====
ls -1 /mnt/df/var/lib/kubelet/pods/ | head
cat /mnt/df/var/lib/kubelet/pods/<uid>/configz/config 2>/dev/null | python3 -m json.tool | head -40
find /mnt/df/var/lib/kubelet/pods/<uid>/volumes -maxdepth 3 -type d | head -30
cat /mnt/df/var/lib/kubelet/pods/<uid>/volumes/kubernetes.io~projected/default/default-token 2>/dev/null | head -c 60
# 真实文件（含轮转与 UID 目录 = 重启次数）
ls -la /mnt/df/var/log/pods/<ns>_<pod>_<uid>/<ctr>/
cp -p /mnt/df/var/log/pods/*/*/*/*.log /evidence/podlogs/
ls -d /mnt/df/var/log/pods/*<pod-name>* | wc -l          # 同名 Pod 有几个 UID = 重启过几次
# CRI 软链接（内容相同，只有当前一份；归档必须 -L）
ls -l /mnt/df/var/log/containers/ | head
cp -pL /mnt/df/var/log/containers/*.log /evidence/crilogs/
grep -aiE 'curl .*\| *(ba)?sh|base64 -d|stratum|/dev/tcp|198\.51\.100' /mnt/df/var/log/pods/*/*/*/*.log | head -40

# ===== 4. ★ 静态 Pod 与 PKI =====
ls -l --time-style=long-iso /mnt/df/etc/kubernetes/ /mnt/df/etc/kubernetes/manifests/ /mnt/df/etc/kubernetes/pki/
stat -c '%n mtime=%y ctime=%z' /mnt/df/etc/kubernetes/manifests/*.yaml
# ★ 非标准静态 Pod = 控制面持久化（详见第 06 篇）
ls -1 /mnt/df/etc/kubernetes/manifests/ | grep -vE 'kube-apiserver|kube-controller-manager|kube-scheduler|^etcd.yaml|cni-networking'
grep -nE 'image:|hostPath|privileged|command:' /mnt/df/etc/kubernetes/manifests/*.yaml
grep -rnE 'client-key-data|client-certificate-data|token:' /mnt/df/etc/kubernetes/*.conf

# ===== 5. kubectl 只读取证（不要 exec）=====
export KUBECONFIG=/etc/kubernetes/admin.conf
kubectl get pods -o wide --all-namespaces | grep -viE 'Running|Completed'
kubectl describe pod -n <ns> <pod> | tee /evidence/k8s/describe-pod.txt   # Events + Last State
kubectl logs -n <ns> <pod> --previous --timestamps | tail -100             # ★ 崩溃前日志
kubectl logs -n <ns> <pod> -c <ctr> --previous --timestamps
kubectl get events -A --sort-by=.lastTimestamp | tail -60
kubectl get secret -A                        # ★ 只列名字，不要 -o yaml

# ===== 6. 端口暴露面（无入侵记录也要单独查）=====
ss -tulpn | grep -E ':(10250|10255|6443|2379|2380|6443)\b'

# ===== 7. 验证 =====
ETCDCTL_API=3 etcdutl snapshot status /evidence/etcd/etcd-snapshot.db
umount /mnt/df && sha256sum -c /evidence/evidence.sha256
```

> **本篇延伸**：审计日志的字段语义与评分脚本见[第 05 篇](server-k8s-configmap-secret.md)；静态 Pod、特权配置、异常 RBAC 的完整判定清单见[第 06 篇](server-k8s-container-escape-and-runtime-artifacts.md)。

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 服务器与 Web 取证 — K8s 取证工件地图」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《K8s 取证工件地图》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-mem.raw` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
