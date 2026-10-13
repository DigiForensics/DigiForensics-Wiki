---
title: "K8s 审计日志与 ConfigMap/Secret"
slug: "server-k8s-configmap-secret"
canonical: "https://www.digiforensics.cn/wiki/server-k8s-configmap-secret"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:48+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "server"
space: "服务器与云取证"
node_path: ["Kubernetes"]
---

# K8s 审计日志与 ConfigMap/Secret

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/server-k8s-configmap-secret)

<a id="section-1"></a>

## 一、概述

Secret 泄漏是容器化架构里后果最重、也最难彻底根治的事故原因之一。 根因不是加密做得不好，而是 K8s 的设计目标从来不是"防泄漏"，而是"防误显"：

- 默认情况下 Secret 的值是 **base64 编码，不是加密**——`echo 'TXlQYXNzd29yZDEyMw==' | base64 -d` 就能还原。
- 是否启用 etcd 静态加密须以本集群 `EncryptionConfiguration` 为准（判据见陷阱 10）；未配置时 etcd 快照里躺着的是同一批明文。
- 每个 Pod 默认自动挂载自己的 ServiceAccount token，**一次误配置或一次 SSRF 就可能把它带出集群**。
- 应用普遍用 ConfigMap / 环境变量接收数据库口令、第三方 API Key，**一旦打进日志或前端就等于公开**。

而"谁在什么时候读了哪个 Secret"这个问题的答案，只存在于 API Server 审计日志里。

这是 K8s 取证中用于分析 API 调用行为的日志，也是本篇的一半。另一半是 ConfigMap / Secret 本身：类型有哪几种、值存在哪、怎么读，以及**三种常见的"以为加密了其实没加密"的误判**。

**在取证流程中的位置**：本篇属于**分析环的核心证据源**，跨采集与分析两环——审计日志要先抢（会被轮转覆盖），分析时又要作为主证据反复查询。

它与 [K8s 取证工件地图](server-k8s-kubernetes-artifact-map.md) 的 etcd 快照构成凭据取证的完整链条：**快照告诉你有什么凭据，审计日志告诉你谁动过它们。** 只有快照时无法归因，只有日志时看不到凭据内容。

**必须先建立的判断框架**：

| 问题 | 答案在哪 | 若答案是"没有" |
|---|---|---|
| 攻击者做了什么 API 调用？ | **审计日志** | 只能靠其他日志侧面推断，**必须写明局限** |
| Secret 的值是什么？ | etcd 快照 / API 响应 / Pod 内投影文件 | 数据不可得 |
| 集群是否启用了静态加密？ | `--encryption-provider-config` 指向的文件 | **值为 base64 明文** |
| 某个 ServiceAccount 有多大权限？ | RoleBinding + `kubectl auth can-i` | 不可判定 |

**涉及的证据形态**：

| 形态 | 具体位置 | 结构特征 |
|---|---|---|
| 审计日志 | `/var/log/kubernetes/audit.log` | **每行一条 JSON**，回答"谁/何时/调了什么/结果如何"四问 |
| 审计策略 | `/etc/kubernetes/audit-policy.yaml` | **级别决定你能看到多少**，见 [2.2 审计级别](#section-4) |
| 加密配置 | `/etc/kubernetes/encryption-config.yaml` | **`secret:` 字段就是密钥本体**；`identity: {}` 兜底项会让部分 Secret 仍是明文 |
| 密钥挂载 | `/var/run/secrets/kubernetes.io/serviceaccount/token` | **启用自动挂载的 Pod 都有**；受 `automountServiceAccountToken` 控制，有效期内可直接使用 |
| 宿主机对应位置 | `/var/lib/kubelet/pods/<uid>/volumes/kubernetes.io~projected/default/` | projected 卷的实际落点 |
| ConfigMap / Secret 对象 | etcd 中，`data` 或 `stringData` 字段 | Secret 的 `data` 是 base64，不是加密 |

> **审计级别是本篇最实际的门槛**。
>
> `None` 完全不记录；`Metadata` 只记元数据（生产集群常用此级别）；`Request` 加请求体，**能看到创建了什么**；`RequestResponse` 加响应体，**能看到读到了什么**，但体积可达 GB 级/天。
>
> 动手前先确认实际级别，否则会对着一片空白解释"没有异常"。

**Secret 的三种加密状态**（本篇最需要讲清、也最容易被误判的一点）：未加密（默认）、etcd 静态加密已启用、存储后端加密。**三者的判据与还原方式完全不同**，而且——"启用了加密"不等于"所有 Secret 都加密了"，因为配置里的 `identity: {}` 兜底项会让旧格式写入的 Secret 仍是明文，**必须逐个检查值的开头，不能假设一致**。

某个 ServiceAccount 在什么时候读了哪些 Secret、调了哪些 API、结果如何；集群有没有启用静态加密；某个 SA 的权限边界；某次异常操作是哪个 Pod 发起的。

审计级别为 `Metadata` 时**看不到请求体与响应体**；`sourceIPs[0]` **通常不是攻击者的真实 IP**（用 token 调 API 时它是 Pod IP 或节点 IP）；已经轮转掉的时段；审计日志只记录 API 调用，不记录 API Server 内部处理。

**内容边界（本篇的红线）**：从检材读到的 Secret、token、加密密钥**只做离线分析**——识别类型、固定哈希、评估暴露面，**不做在线使用，不尝试用检材中的凭据访问任何系统**。读到明文口令时**报告必须脱敏**。`encryption-config.yaml` 里的 `secret:` 字段就是密钥本体，拿到它等于能解开集群里所有加密的 Secret——取证时必须单独固定、单独编号，并提示委托方**处置完毕后立即轮换**。

**读者前提**：需要 Kubernetes 的 RBAC、ConfigMap/Secret、ServiceAccount 概念，以及 JSON 与日志分析能力。**建议先做 [3.1 第 1 步](#section-10)**——分析脚本的很多输出会因级别不足而空着，事先知道这一点能省掉大量误判。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 审计日志：API 调用行为的证据来源

API Server 是**所有 API 调用的唯一入口**。配置了审计后，每一次调用都会产生一条 JSON 记录，记录认证、鉴权、准入、执行的全过程。

**审计日志回答四个问题，缺一不可**：

| 问题 | 字段 |
|---|---|
| **谁** | `user.username`、`user.groups`、`user.extra`（含 Pod 绑定的 SA 与 Pod 名） |
| **何时** | `requestReceivedTimestamp`、`stageTimestamp`、`annotations["authorization.k8s.io/decision"]` |
| **调了什么** | `verb`、`objectRef.resource` / `subresource`、`objectRef.namespace`、`objectRef.name` |
| **结果如何** | `responseStatus.code`、`responseStatus.message`、`annotations` 里的授权依据 |

<a id="section-4"></a>

### 2.2 审计级别：决定你能看到多少

`/etc/kubernetes/audit-policy.yaml` 里每条规则有四级，**差别巨大**：

| 级别 | 记录内容 | 体积 | 取证价值 |
|---|---|---|---|
| **`None`** | **完全不记录** | 0 | 无 |
| **`Metadata`** | **只记元数据**（谁、何时、调了哪个对象、结果码） | 小 | ★★★★ 生产集群常用此级别，**须以本机 `audit-policy.yaml` 实际配置为准** |
| **`Request`** | 元数据 + **请求体**（`requestObject`） | 中 | ★★★★★ **能看到创建了什么** |
| **`RequestResponse`** | 元数据 + 请求体 + **响应体**（`responseObject`） | **大（可达 GB 级/天）** | ★★★★★ **能看到读到了什么** |

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages:
  - RequestReceived            # ★ 省略此阶段可减少约 40% 记录量
rules:
  - level: None
    users: ["system:kube-proxy", "system:unsecured"]
    verbs: ["watch"]
    resources: ["endpoints", "services"]
  - level: RequestResponse     # ★ 敏感操作记全量
    verbs: ["create", "update", "patch", "delete"]
    resources: ["secrets", "configmaps", "clusterrolebindings", "rolebindings"]
  - level: Metadata            # ★ 其余一律只记元数据
  - level: Request
    resources: ["pods", "pods/exec", "pods/log"]
```

> ⚠️ **这是"证据不足"最常见的根因**：生产集群为性能普遍用 `Metadata` 级别，结果是审计日志只能告诉你"某人在某时列了一次 secrets"，看不到他读到了什么。此时必须靠 etcd 快照与 Pod 配置间接推断，报告里要写清"Secret 内容未入审计日志"这一局限。

> ⚠️ `omitStages: [RequestReceived]` 的副作用：省掉该阶段后日志里不再有 `requestReceivedTimestamp`，只剩 `stageTimestamp`，无法计算请求耗时。取证脚本必须**兼容两种情况**（3.3 已处理）。

<a id="section-5"></a>

### 2.3 关键字段的取证含义

| 字段 | 取证含义 | 注意 |
|---|---|---|
| `user.username` | **主体标识**。`system:serviceaccount:<ns>:<name>` = Pod 用的 SA | **SA 泄露的定案字段** |
| `user.extra[...pod-name]` | **★ SA 调 API 时能定位到具体哪个 Pod** | 仅 SA token 认证时存在；**把"API 调用"与"具体容器"关联起来的关键** |
| `sourceIPs[0]` | 来源 IP。SA token 从 Pod 内发起时是 **Pod IP** | ★ **不要把 Pod IP 当攻击者 IP** |
| `userAgent` | 客户端标识 | `kubectl/v1.x` = 人工操作；伪造或无版本号 = 脚本 |
| `verb` + `objectRef.resource` | **行为的原子描述** | 如 `create pods`、`create pods/exec`、`update clusterrolebindings` |
| `objectRef.name` | 对象名 | 能精确定位"改了哪个 RoleBinding" |
| `responseStatus.code` | 200 成功 / 403 拒绝 / 101 exec 成功 | **大量 403 说明在枚举试探** |
| `annotations["authorization.k8s.io/reason"]` | 授权依据，含"由哪个 RoleBinding 允许" | **判断权限来源与提权链的关键** |
| `requestObject` / `responseObject` | 请求/响应体 | 仅 `Request` / `RequestResponse` 级别才有 |
| `stage` | `RequestReceived` / `ResponseStarted` / `ResponseComplete` | **同一请求会有多条 stage 记录，必须去重**，见 4 |
| `auditID` | 单次请求的全局 ID | ★ 可与 etcd 的 `Revision` 交叉验证时序 |

<a id="section-6"></a>

### 2.4 ConfigMap 与 Secret：类型与落地

| 类型 | 用途 | 取证关注 |
|---|---|---|
| `Opaque`（**默认**） | 任意键值对。**最常见，也最危险** | **常含数据库口令、第三方 Key** |
| `kubernetes.io/dockerconfigjson` | **镜像仓库凭证** | 泄露即可**向私库推送投毒镜像** |
| `kubernetes.io/tls` | TLS 证书与私钥 | 泄露即**冒充服务端** |
| `kubernetes.io/service-account-token` | SA token（**系统自动创建**） | 与 Pod 挂载的是同一套 |
| `kubernetes.io/basic-auth` | 用户名口令 | 一般不推荐使用 |
| `kubernetes.io/ssh-auth` | SSH 私钥 | 泄露即横向移动凭据 |

**Secret 在 Pod 内的三种消费方式**（决定它出现在哪）：

| 方式 | 容器内形态 | 落盘位置 |
|---|---|---|
| **环境变量 `env`** | 进程环境 | 只在 `/proc/<pid>/environ`，不落文件 |
| **卷挂载 `volumeMounts`** | 文件 | `/var/lib/kubelet/pods/<uid>/volumes/kubernetes.io~secret/<name>/<key>` |
| **投射卷 `projected`** | 文件（含 SA 三件套） | `.../kubernetes.io~projected/default/` |

> ⚠️ **环境变量方式的 Secret 不落文件**，只在容器进程环境里，**容器停止后若未落盘就彻底消失**（见[第 01 篇](../server-docker/server-docker-docker-artifact-map.md)的取证时机）。

<a id="section-7"></a>

### 2.5 ⚠️ 核心认知：Secret 的"三种加密状态"

这是本篇最需要讲清、也最容易被误判的一点。

| 状态 | 判断依据 | 值的外观 | 还原方法 |
|---|---|---|---|
| **① 未加密（默认）** | `--encryption-provider-config` 未配置或文件不存在 | `"password": "TXlQYXNzd29yZDEyMw=="` | `base64 -d` |
| **② etcd 静态加密已启用** | 配置指向的 `EncryptionConfiguration` **且文件存在** | `"password": "k8s:enc:...:keyname:data:..."` | 需 decrypt 流程（见下） |
| **③ 存储后端加密** | etcd 侧开启静态加密或磁盘加密 | 落盘已是密文，与 ② 外观不同 | 需 etcd / 存储侧密钥 |

```yaml
# /etc/kubernetes/encryption-config.yaml（启用静态加密时）
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources: ["secrets"]
    providers:
      - aescbc:                # 或 aesgcm / secretbox
          keys:
            - name: key1
              secret: <base64 编码的 32 字节密钥>
      - identity: {}           # ★ 兜底：回退为不加密
```

> ⚠️ **`identity: {}` 兜底项的含义**：它在列表**最后**时，用该密钥加密的数据可解密，但以其他方式（如旧版本）写入的 Secret 仍是明文。所以"启用了加密"不等于"所有 Secret 都加密了"。**必须逐个检查值的开头，不能假设一致。**

**判断流程（报告里要照此写）**：

```bash
# 1) 是否配置了加密
grep -n 'encryption-provider-config' /mnt/df/etc/kubernetes/kube-apiserver.yaml
ls -l /mnt/df/etc/kubernetes/encryption-config.yaml 2>/dev/null || echo "★ 无加密配置 → Secret 为 base64 明文"

# 2) 逐个检查值的形态
echo 'TXlQYXNzd29yZDEyMw==' | base64 -d; echo        # → MyPassword123 （状态①）
```

> ⚠️ `encryption-config.yaml` 里的 `secret:` 字段就是密钥本体，拿到它等于能解开集群里所有加密的 Secret。取证时该文件必须单独固定、单独编号，并在报告中提示委托方**处置完毕后立即轮换**。

三种状态的判定口径与"哪些密文不值得花时间解"的取舍，与数据库侧一致，见[数据库与配置文件加密](../../crypto/crypto-app/crypto-app-database-configuration-decryption.md)。

<a id="section-8"></a>

### 2.6 SA token 泄漏的完整链条

**这是 K8s 环境里最高价值的凭据**，因为它不像口令那样可以"改了就没事"——**泄露的 SA token 在有效期内可直接使用**。

```
① token 从哪来
   /var/run/secrets/kubernetes.io/serviceaccount/token   （容器内，每个 Pod 都有）
   /var/lib/kubelet/pods/<uid>/volumes/kubernetes.io~projected/default/  （宿主机对应位置）
        ↓
② 怎么流出去
   应用把 token 打进日志 / 报错栈 / 前端 / 第三方 SDK
   容器被攻破后直接 cat
   写进 ConfigMap / 环境变量后被 image 打进镜像
        ↓
③ 泄露后能干什么
   ★ 完全等同于该 ServiceAccount 在 RBAC 里的全部权限
   绑定 cluster-admin 的 SA token 泄露 = 集群完全失守
        ↓
④ 取证怎么确认
   审计日志里出现该 SA 的可疑操作 → 拿到 auditID
   → 回到 2.3 的 user.extra 拿到 pod-name / pod-uid
   → 定位到具体是哪个容器发起的
```

> ⚠️ **`sourceIPs` 的陷阱必须讲清**：当攻击者用 SA token 调 API 时，`sourceIPs[0]` 通常是 **Pod 的节点 IP 或 Pod IP**，**不是攻击者的真实 IP**。定位真实来源要靠 `user.extra` 里的 Pod 信息 + 节点上的应用日志 + 网络侧记录。

---

<a id="section-9"></a>

## 三、操作步骤

<a id="section-10"></a>

### 3.1 第 1 步：确认审计日志可用并确定分析时段

```bash
grep -nE 'audit-log-path|audit-policy-file|audit-log-maxage|audit-log-maxbackup|audit-log-maxsize' \
     /mnt/df/etc/kubernetes/kube-apiserver.yaml
ls -l --time-style=long-iso /mnt/df/var/log/kubernetes/
cp -p /mnt/df/var/log/kubernetes/audit*.log* /evidence/k8s/
wc -l /evidence/k8s/audit.log

# ★ 取时段边界（★ 报告里必须写"可分析时段"，超出部分不能下否定结论）
for f in /evidence/k8s/audit.log.1 /evidence/k8s/audit.log; do
  echo -n "$f 最早 "; head -1 "$f" | python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('requestReceivedTimestamp') or d.get('stageTimestamp'))"
  echo -n "$f 最晚 "; tail -1 "$f" | python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('requestReceivedTimestamp') or d.get('stageTimestamp'))"
done
```

**审计策略决定"能证明到哪一层"**：

| 策略里出现的情况 | 报告能得出的最强结论 |
|---|---|
| `level: Metadata` | 只能说"**某主体在某时访问了名为 X 的 Secret**"，**不能说它读到了什么** |
| `level: Request` | 能说"**创建/修改了什么对象**"（有 `requestObject`），读操作看不到内容 |
| `level: RequestResponse` | 能说"**创建了什么、读到了什么**"，证据力最强 |
| 未配置 `--audit-log-path` | **该集群从未记录审计**，只能靠其他日志推断，**必须在局限中说明** |

<a id="section-11"></a>

### 3.2 第 2 步：审计日志分析脚本（本文核心）

脚本目标：读 JSON Lines 格式的 `audit.log`，按可疑度打分排序，输出 Top N 可疑请求。评分规则针对容器环境的高危行为设计，分三层：资源类（改什么）、行为类（怎么改）、上下文类（请求体里写了什么）。

```python
#!/usr/bin/env python3
# K8s 审计日志可疑行为分析器（离线、只读）
# 用法:
#   python3 audit_score.py audit.log --top 30
#   python3 audit_score.py audit.log --user 'system:serviceaccount:ns:app' --top 50
#   python3 audit_score.py audit.log --since 2024-03-18T00:00:00Z --ip 198.51.100.24
import json, sys, re, argparse
from collections import defaultdict

# ---------- 资源类规则：(正则, 分值, 说明) ----------
# 资源类只取最匹配的一条，避免堆叠虚高。
RULES = [
    # RBAC 提权：改完即集群管理员
    (r"clusterrolebindings|clusterroles",      45, "触及集群级RBAC"),
    (r"rolebindings|roles",                     20, "触及命名空间级RBAC"),
    # 凭据读取
    (r"^secrets?$",                            40, "访问Secret"),
    (r"^configmaps?$",                         12, "访问ConfigMap"),
    # 容器执行：进容器即可读可改容器内一切
    (r"^pods/(exec|attach|portforward)$",      50, "进入容器(pods/exec)"),
    (r"^pods$",                                15, "访问Pod"),
    (r"^pods/(log|eviction|ephemeralcontainers)$", 10, "访问Pod子资源"),
    # 节点代理：等价于脱离容器隔离
    (r"^nodes$|^nodes/(proxy|log|exec)$",      30, "访问节点"),
    (r"^persistentvolumes?$|^storageclasses?$", 12, "访问存储对象"),
    # 元数据枚举 = 踩点
    (r"^serviceaccounts?$",                    25, "访问ServiceAccount"),
    (r"^namespaces?$",                         10, "访问命名空间"),
    (r"^events?$",                              5, "访问Event"),
    # 准入与签名：绕过供应链防护
    (r"^validatingwebhookconfigurations$|^mutatingwebhookconfigurations$", 25, "触及准入控制器"),
    (r"^csidrivers?$",                         20, "触及CSI驱动"),
    # 常见的持久化载体
    (r"^daemonsets?$",                         30, "部署DaemonSet"),
    (r"^cronjobs?$|^jobs$",                    15, "部署定时任务"),
]

# 上下文类规则：在请求体上匹配，命中即叠加
DANGER_KEYS = [
    (r'"privileged"\s*:\s*true',                          30, "privileged:true"),
    (r'"hostPath"\s*:',                                   30, "hostPath挂载"),
    (r'"/var/run/docker\.sock"|"containerd\.sock"',       40, "挂载运行时socket"),
    (r'"path"\s*:\s*"/etc/kubernetes',                    40, "挂载/etc/kubernetes"),
    (r'"path"\s*:\s*"/"',                                 20, "挂载宿主机根目录"),
    (r'"hostNetwork"\s*:\s*true',                         20, "hostNetwork:true"),
    (r'"hostPID"\s*:\s*true',                             20, "hostPID:true"),
    (r'"hostIPC"\s*:\s*true',                             15, "hostIPC:true"),
    (r'"cluster-admin"',                                  40, "绑定cluster-admin"),
    (r'"image"\s*:\s*"[^"]*(?::\d+|[0-9]{1,3}(\.[0-9]{1,3}){3})', 15, "镜像指向IP/非标端口仓库"),
]

WRITE_VERBS = {"create", "update", "patch", "delete", "deletecollection"}
READ_SENSITIVE_RE = re.compile(r"secrets?|nodes?|serviceaccounts?")
SYSTEM_SA_RE = re.compile(r"^system:(serviceaccount:kube-system|node|controller)")
# 需要纳入分析的 stage；同一请求的多条 stage 记录由 auditID 去重后择优保留
KEEP_STAGES = ("ResponseComplete", "ResponseStarted", "RequestReceived", "")

def score_event(d):
    """对单条审计事件打分，返回 (总分, 命中规则列表)"""
    hits, score = [], 0
    obj = d.get("objectRef") or {}
    res, sub = obj.get("resource") or "", obj.get("subresource") or ""
    key = f"{res}/{sub}" if sub else res
    verb = d.get("verb") or ""
    user = (d.get("user") or {}).get("username") or ""

    if (d.get("stage") or "") not in KEEP_STAGES:
        return 0, []

    # 1) 资源类
    for pat, w, why in RULES:
        if re.search(pat, key) or re.search(pat, res):
            score += w
            hits.append(why)
            break

    # 2) 行为类：读是常态，写才是行为
    if verb in WRITE_VERBS:
        score += 10
        hits.append(f"写操作({verb})")
    elif verb in ("get", "list", "watch") and READ_SENSITIVE_RE.search(res):
        score += 8
        hits.append("敏感读操作")

    # 3) 系统 SA 做写操作 = 权限被异常使用（凭据被盗的典型表现）
    if verb in WRITE_VERBS and SYSTEM_SA_RE.search(user):
        score += 20
        hits.append("系统SA执行写操作(权限异常)")

    # 4) 鉴权拒绝密集出现 = 枚举试探
    if (d.get("responseStatus") or {}).get("code") in (401, 403):
        score += 6
        hits.append("鉴权拒绝")

    # 5) 请求体高危字段（仅 Request / RequestResponse 级别才有）
    ro = d.get("requestObject")
    if isinstance(ro, dict):
        blob = json.dumps(ro, ensure_ascii=False)
        for pat, w, why in DANGER_KEYS:
            if re.search(pat, blob):
                score += w
                hits.append(why)

    # 6) 主体加权
    if user.startswith("system:serviceaccount:") and "kube-system" not in user:
        score += 8
        hits.append("业务SA身份")
    if user in ("system:anonymous", ""):
        score += 60
        hits.append("匿名/未认证身份")

    # 7) 直接创建 Pod（非常规子资源）= 绕过控制器手工起容器
    if res == "pods" and not sub and verb == "create":
        score += 5
        hits.append("直接创建Pod(可能绕过控制器)")

    return score, hits

def main():
    ap = argparse.ArgumentParser(description="K8s 审计日志可疑行为分析")
    ap.add_argument("logfile")
    ap.add_argument("--top", type=int, default=20, help="输出前 N 条")
    ap.add_argument("--min-score", type=int, default=30, help="分值下限")
    ap.add_argument("--user", help="只分析某主体（子串匹配）")
    ap.add_argument("--ip", help="只分析某来源 IP")
    ap.add_argument("--since", help="起始时间，如 2024-03-18T00:00:00Z")
    ap.add_argument("--out", help="完整结果写入 JSON 文件")
    args = ap.parse_args()

    total, bad = 0, 0
    actors = defaultdict(lambda: {"n": 0, "score": 0})
    ips = defaultdict(int)
    best = {}                     # auditID -> 记录；同一请求保留分值最高（信息最全）的那条

    with open(args.logfile, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue

            ts = d.get("requestReceivedTimestamp") or d.get("stageTimestamp") or ""
            if args.since and ts and ts < args.since:
                continue
            user = (d.get("user") or {}).get("username") or ""
            if args.user and args.user not in user:
                continue
            sip = (d.get("sourceIPs") or ["-"])[0]
            if args.ip and sip != args.ip:
                continue

            s, hits = score_event(d)
            actors[user]["n"] += 1
            actors[user]["score"] += s
            ips[sip] += 1
            if s < args.min_score or not hits:
                continue

            obj = d.get("objectRef") or {}
            rec = {
                "score": s, "ts": ts, "user": user, "verb": d.get("verb"),
                "res": f"{obj.get('resource','')}/{obj.get('subresource','')}".strip("/"),
                "ns": obj.get("namespace", "-"), "name": obj.get("name", "-"),
                "ip": sip, "ua": (d.get("userAgent") or "")[:40],
                "code": (d.get("responseStatus") or {}).get("code"),
                "pod": ((d.get("user") or {}).get("extra") or {})
                        .get("authentication.kubernetes.io/pod-name", ["-"])[0],
                "auditID": d.get("auditID", "-"),
                "reason": (d.get("annotations") or {})
                          .get("authorization.k8s.io/reason", "")[:60],
                "hits": hits,
            }
            # 同一 auditID 的多条 stage 记录只保留分值最高的一条
            key = d.get("auditID") or f"{ts}|{user}|{verb}|{key}|{rec['name']}"
            if key not in best or rec["score"] > best[key]["score"]:
                best[key] = rec

    scored = sorted(best.values(), key=lambda x: -x["score"])

    print(f"# 分析 {args.logfile}")
    print(f"# 总记录 {total} 条，解析失败 {bad} 条，"
          f"超过阈值({args.min_score}) 的请求 {len(scored)} 条\
")

    print(f"## Top {args.top} 可疑请求\
")
    print("| 分值 | 时间(UTC) | 用户 | 动词 | 资源 | 命名空间/名称 | 来源IP | 代码 | Pod | 命中规则 |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for e in scored[:args.top]:
        print(f"| **{e['score']}** | {e['ts']} | `{e['user']}` | {e['verb']} | "
              f"`{e['res']}` | {e['ns']}/{e['name']} | {e['ip']} | {e['code']} | "
              f"{e['pod']} | {'; '.join(e['hits'])}")

    print("\
## 主体聚合（按累计分值排序，前 10）\
")
    print("| 用户 | 请求数 | 累计分值 |")
    print("|---|---|---|")
    for u, st in sorted(actors.items(), key=lambda kv: -kv[1]["score"])[:10]:
        print(f"| `{u}` | {st['n']} | {st['score']} |")

    print("\
## 来源 IP 分布（前 10）\
")
    for ip, c in sorted(ips.items(), key=lambda kv: -kv[1])[:10]:
        print(f"- `{ip}` : {c} 条")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(scored, f, ensure_ascii=False, indent=2)
        print(f"\
完整结果（{len(scored)} 条）已写入 {args.out}")

if __name__ == "__main__":
    main()
```

**运行与结果解读**（下表分值取自对 8 条样例记录的实际运行结果）：

```bash
python3 audit_score.py /evidence/k8s/audit.log --top 30 --min-score 30 \
  --out /evidence/k8s/suspicious.json

# 只想看某个 SA 干了什么
python3 audit_score.py /evidence/k8s/audit.log \
  --user 'system:serviceaccount:digiforensics:digiforensics-app' --top 50
```

```
# 总记录 8 条，解析失败 0 条，超过阈值(30) 的请求 7 条

| 分值 | 时间(UTC) | 动词 | 资源 | 命名空间/名称 | 来源IP | 代码 | 命中规则 |
|---|---|---|---|---|---|---|---|
| **138** | 2024-03-18T03:14:52.101Z | create | `pods` | digiforensics/audit-shim | 10.8.3.17 | 201 | 访问Pod; 写操作(create); privileged:true; hostPath挂载; 挂载宿主机根目录; hostPID:true; 业务SA身份; 直接创建Pod(可能绕过控制器) |
| **114** | 2024-03-18T02:35:10.000Z | list | `secrets` | digiforensics/- | 198.51.100.24 | 403 | 访问Secret; 敏感读操作; 鉴权拒绝; 匿名/未认证身份 |
| **103** | 2024-03-18T02:40:19.442Z | update | `clusterrolebindings` | -/digiforensics-app-cluster-admin | 10.8.3.17 | 200 | 触及集群级RBAC; 写操作(update); 绑定cluster-admin; 业务SA身份 |
| **68**  | 2024-03-17T23:10:41.330Z | create | `pods/exec` | digiforensics/web-6d4f-x7b2c/web | 10.8.3.17 | 101 | 进入容器(pods/exec); 写操作(create); 业务SA身份 |
| **56**  | 2024-03-17T23:12:08.006Z | get | `secrets` | digiforensics/db-credentials | 10.8.3.17 | 200 | 访问Secret; 敏感读操作; 业务SA身份 |
| **53**  | 2024-03-18T02:36:44.220Z | create | `pods` | digiforensics/x7b2c-dumper | 10.8.3.17 | 201 | 访问Pod; 写操作(create); 镜像指向IP/非标端口仓库; 业务SA身份; 直接创建Pod(可能绕过控制器) |
| **50**  | 2024-03-18T02:35:09.000Z | create | `pods` | digiforensics/web-6d4f-x7b2c | 10.8.3.11 | 201 | 访问Pod; 写操作(create); 系统SA执行写操作(权限异常); 直接创建Pod(可能绕过控制器) |
```

> ⚠️ **三条读结果的纪律**：
> ① **分值是排序辅助，不是定性结论。** 每个高分条目都**必须回到原始 JSON 逐条核实**（看 `requestObject`、`annotations.reason`、`responseObject`），才能写进报告。
> ② `responseObject` 里可能有真实凭据。 在 `RequestResponse` 级别下，读 Secret 的记录**包含明文**。分析输出不要打印 `responseObject` 全文，只在确有必要时定向提取并脱敏。
> ③ `sourceIPs` 是 Pod IP 不是攻击者 IP（见 2.6），报告里不能写成"攻击者来源 IP"。

<a id="section-12"></a>

### 3.3 第 3 步：ConfigMap 与 Secret 的取证

```bash
export KUBECONFIG=/etc/kubernetes/admin.conf

# ConfigMap：★ 值常是明文，重点找硬编码凭据与外网地址
kubectl get configmap -A -o yaml > /evidence/k8s/configmaps.yaml
grep -nE 'password|passwd|secret|token|apikey|api_key|private_key|access_key' \
     /evidence/k8s/configmaps.yaml | head -30
grep -nA3 'jdbc:|mongodb://|redis://' /evidence/k8s/configmaps.yaml | head -20   # 硬编码库连接

# Secret：★ 只列元信息，不要 -o yaml 打印值
kubectl get secret -A -o custom-columns=\
'NS:.metadata.namespace,NAME:.metadata.name,TYPE:.type,AGE:.metadata.creationTimestamp' \
  | tee /evidence/k8s/secrets-index.txt
kubectl get secret -A -o custom-columns='NS:.metadata.namespace,NAME:.metadata.name,TYPE:.type' \
  | grep -E 'dockerconfigjson|tls' | head -30        # ★ 按高危类型筛

# 单独确认镜像仓库凭证（泄露即可向私库推投毒镜像）
kubectl get secret -n <ns> <reg-cred> -o jsonpath='{.data.\.dockerconfigjson}' \
  | base64 -d | python3 -c "
import json,sys,base64
for reg,cfg in (json.load(sys.stdin).get('auths') or {}).items():
    s=base64.b64decode(cfg.get('auth','')).decode()
    u,p=s.split(':',1) if ':' in s else ('?','?')
    print(f'仓库 {reg}  用户 {u}  口令长度 {len(p)}')
" 2>/dev/null

# 该 SA 的实际权限（★ 判断 token 泄露影响面）
kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>
```

<a id="section-13"></a>

### 3.4 第 4 步：验证环节

| 验证对象 | 方法 | 通过标准 |
|---|---|---|
| 审计日志时段 | 首末记录的时间戳字段 | **可分析时段写入报告** |
| 审计级别 | `audit-policy.yaml` 的 `level` | **能证明到哪一层要写明** |
| Secret 加密状态 | `grep encryption-provider-config` + 文件是否存在 + **值的 `k8s:enc:` 前缀** | **逐个确认，不能假设一致** |
| SA 权限范围 | `kubectl auth can-i --list --as=...` + RoleBinding 列举 | **token 泄露影响面可量化** |
| token 泄漏 | 日志中 grep `eyJhbGciOiJ` 前缀 | 命中即为凭据泄漏证据 |
| 脚本结论 | 回到原始 JSON 核实 `requestObject` / `annotations.reason` | 每条高分都能说清"做了什么" |
| 时间线一致性 | 审计 `auditID` ↔ etcd `Revision` ↔ Pod `creationTimestamp` | 三者可对齐 |

---
<a id="section-14"></a>

## 四、常见陷阱

这一篇的误判几乎全部围绕两个字：**假**。base64 当成加密、脚本分值当成结论、行数当成请求数、`sourceIPs` 当成攻击者 IP——每一处都是「看起来现成、实则不成立」。本章按「审计级别能证明到哪一层 → 脚本输出怎么用 → 凭据怎么读 → 结论怎么写」四段归组。

<a id="section-15"></a>

### 4.1 审计级别与证据边界

<a id="section-16"></a>

#### 陷阱 1：用裸 grep 和行数统计审计日志

**现象**：`grep -i secret audit.log | wc -l` 得到一个数，据此判断 Secret 被读取的频次；再 `grep` 某个可疑 IP，没命中就认为该 IP 与本案无关。统计请求数时直接数行数。

**原因**：三个层面同时出错。① **审计日志是 JSON Lines**——一行一个 JSON 对象，主体、动词、资源、结果码、来源 IP 全嵌在结构里，裸 grep 既无法表达「某身份对某资源的某动词」这种组合条件，又会被 URL、注解、`userAgent` 里的偶然匹配干扰。② **同一次请求会产生多条 stage 记录**（`RequestReceived`、`ResponseStarted`、`ResponseComplete` 各一条），不去重的话分值和计数被**乘以 2–3 倍**；脚本里保留多个 stage 正是为了取 `responseObject` 最全的那条。③ 策略里常配 `omitStages: [RequestReceived]` 做减负，此时日志里没有 `requestReceivedTimestamp`，只剩 `stageTimestamp`——脚本若只取前者会静默跳过大量行，日志覆盖范围被高估。

**影响**：**一次 grep 的结果被当成了全量分析。**

数字看着精确、结论看着有据，实则既漏掉真正符合条件的组合，又引入一批假匹配。报告里「共 N 次 Secret 访问」这句话可能是错的。

更隐蔽的是第③点：如果脚本因 `KeyError` 跳过记录，分析员会以为看完了整个时段，实际漏掉了一部分。

**核查**：**逐行 JSON 解析**，用 `user.username` + `verb` + `objectRef.resource`/`subresource` + `sourceIPs[0]` + `responseStatus.code` 组合筛选（3.2 的脚本已实现）。按 `auditID` 分组，保留信息最全的那一条再去统计请求数。时间字段写成「优先 `requestReceivedTimestamp`，回退 `stageTimestamp`」，并在报告时段说明里注明用的是哪个字段、策略里是否存在 `omitStages`——两个字段的时间含义不同（请求到达 vs 阶段处理）。裸 grep 只用于快速看一眼日志样貌。

<a id="section-17"></a>

#### 陷阱 2：审计级别是 `Metadata` 却断言「读到了什么」

**现象**：审计策略是 `Metadata` 级别，日志里有一条 `get secrets db-credentials`，报告写「攻击者读取了数据库凭据 Secret」。

**原因**：`Metadata` 级别**只记元数据**——谁、何时、调了哪个对象、结果码。它没有 `requestObject`（请求体）也没有 `responseObject`（响应体）。这条记录只能支撑「**某主体在某时访问了名为 X 的 Secret**」，支撑不了「读到了什么内容」。

**影响**：**结论强度凭空提升一级**。「访问了 Secret 对象」和「读到了凭据值」之间隔着一步，后者才是泄漏成立的前提。若实际是 `Metadata` 级别而报告写成后者，一旦对方展示策略文件，结论即被推翻。

**核查**：先读 `audit-policy.yaml`，再定结论的上限，三者对应三种强度：① `Metadata` → 只能写「确认访问行为，不能确认内容」；② `Request` → 有 `requestObject`，能说清「创建/修改了什么对象」，读操作仍看不到内容；③ `RequestResponse` → 能说清「读到了什么」，证据力最强。**级别必须写进报告的证据说明里**，它是本篇所有相关结论的强度上限。

<a id="section-18"></a>

#### 陷阱 3：审计日志未启用却写「未发现异常调用」

**现象**：`--audit-log-path` 未配置，报告的行为分析一节写「未发现异常 API 调用」。

**原因**：API Server **默认不开启审计日志**。这不是「日志被清空了」，而是**该集群从未记录过**。

**影响**：把**取证能力的缺失**写成**阴性发现**。

委托方读到会认为 API 层干净，从而排除整条编排层攻击线——而攻击者用任何 SA 做的任何操作都没留下记录。

**核查**：写成能力声明：「该集群未启用 API Server 审计，无法从 API 调用层面确定攻击者行为；操作序列与攻击路径不可考」，并列入「取证局限」清单，明确补救途径（托管集群可向云侧索取控制平面日志；自建集群只能从 Pod 日志、应用日志等侧证）。

<a id="section-19"></a>

### 4.2 脚本输出的用法

<a id="section-20"></a>

#### 陷阱 4：把脚本分值直接当结论

**现象**：把 Top N 表格原样贴进报告，写成「分值 103 的行为为 RBAC 提权，判定为攻击」。

**原因**：分值是**排序辅助**，规则里有一批「系统 SA 做写操作 +20」「业务 SA 身份 +8」这类**身份加权项**，设计上就会给正常业务主体抬分。一条 138 分的记录里可能只有一部分命中项真正可疑。

**影响**：把启发式输出当定性结论。一旦有一条高分记录被核实为正常运维，整份报告的评分体系一起失信。

**核查**：**每条高分条目都必须回到原始 JSON 逐条核实**——看 `requestObject` 里到底写了什么、`annotations["authorization.k8s.io/reason"]` 里的授权依据、`responseStatus.code`。评分表在报告里的正确位置是「线索清单」，定性结论在「核实后的发现」——两者分成两节，不要混在一起。

<a id="section-21"></a>

#### 陷阱 5：只看单条高分记录，不看主体行为链

**现象**：审计里找到一条 `pods/exec`，判定为「攻击者进入了容器」，报告结束。

**原因**：`pods/exec` 本身**不说明问题**——运维排查、发布流水线、监控探针都会用 exec。「读 Secret → 提权 → 建特权 Pod」这样的一条链才是定性依据。

**影响**：把运维的正常 exec 判成攻击，会让报告从一开始就站不住。

反过来，只盯最高分的那一条，往往会漏掉真正的链。那条高分建 Pod 记录，如果不做主体聚合，根本看不出它和前面的 exec、Secret 读取是同一个 SA 干的。

**核查**：**用脚本的主体聚合功能看全量**，把同一主体的全部请求按时间排出，看**动词与资源的组合序列**。判定依据是模式：正常运维是零散的单点操作，攻击是「枚举 → 读取凭据 → 提权 → 落地持久化」的有序递进。**主体聚合的分数是去重后的累计**，用于横向比较不同主体，不要把绝对值当作严重性度量。

<a id="section-22"></a>

#### 陷阱 6：把 `sourceIPs` 当攻击者 IP

**现象**：审计里某条记录的 `sourceIPs[0]` 是 `198.51.100.24`，报告写「攻击者 IP 为该地址」。

**原因**：当攻击者使用 SA token 调 API 时，`sourceIPs[0]` 通常是 Pod IP 或节点 IP，不是攻击者的真实地址。 SA token 是从 Pod 内带出去的，请求从集群内部发起。只有匿名/未认证的外部请求，`sourceIPs` 才是真正的外部来源。

**影响**：这是本篇最容易造成错误归因的一处。

**IP 是后续追查、通报、关联黑名单的核心字段**，一旦写错，整份报告的归因方向就跑偏了。

第五章的案例里，攻击行为的 `sourceIPs` 恰恰是 Pod IP `10.8.3.17`。把它当成攻击者 IP，就是把受害节点指成了攻击者。

**核查**：**区分两类记录**。有 SA 身份的记录，`sourceIPs` 只用于「这次调用是从哪个 Pod 发起的」，攻击者归属要靠 `user.extra` 里的 `pod-name`/`pod-uid` 定位到具体容器，再结合该容器的应用日志与网络侧记录追；只有匿名或未认证身份的记录，`sourceIPs` 才是外部来源，**但仍需确认它不是跳板或代理出口**。

<a id="section-23"></a>

#### 陷阱 7：用脚本的 `best` 去重逻辑统计请求数，得数偏小

**现象**：脚本对同一 `auditID` 只保留分值最高的那一条记录，输出「总记录 8,436 条，阈值以上请求 312 条」。分析员把 312 当成「312 次请求」，与委托方核对的 API 调用次数对不上。

**原因**：**日志条数、请求数、被计分的请求数是三个不同的量。** 一次 API 请求会产生 `RequestReceived`、`ResponseStarted`、`ResponseComplete` 等多条 stage 记录，各条携带的字段不同——请求体只在其中某些阶段、`responseObject` 只在 `ResponseComplete`。脚本保留信息最全的那条是**为了分析方便**，代价是**一条记录代表的是多次 stage 而不是多次请求**。而「阈值以上」这个筛选条件又砍掉了一批：分值低于 `--min-score` 的请求根本不进 `best`，它们是真实发生过的调用，只是没被这条规则选中。

**影响**：请求数是评估攻击活动强度的基础量级指标，偏小会让整条行为链显得零散，甚至被读成「攻击者只做了零星几次尝试」，从而低估严重性。这类数字一旦进了报告的时间线摘要，后文的节奏判断（慢速踩点 vs 集中爆发）会跟着歪。

**核查**：**报告里不要用计分结果当请求总数。** 请求总数要用原始日志统计——按 `auditID` 去重后的**去重记录数**，再单独给一个「其中命中可疑规则 N 条」：

```bash
# 总请求数：按 auditID 去重
grep -o '"auditID":"[^"]*"' /evidence/k8s/audit.log | sort -u | wc -l
# 对照原始行数与去重后条数，差值就是 stage 放大倍数
wc -l < /evidence/k8s/audit.log
```

三个数（原始行数、去重请求数、命中数）分别写入报告并注明各自口径，**不要让其中一个冒充另一个**。

<a id="section-24"></a>

#### 陷阱 8：只用脚本的 `userAgent` 判人工 vs 脚本

**现象**：`userAgent` 是 `kubectl/v1.29.2` 的记为人工操作，是空值或 `python-requests` 的记为自动化脚本，报告按这个二分法给主体分类。

**原因**：`userAgent` 是客户端自报字段，与请求实际来源之间没有绑定关系。 它由发起方的 HTTP 客户端库设置，任何人都可以自定义；`kubectl` 也可以被包装成脚本调用，而自定义 User-Agent 的自动化工具照样能声明成 `kubectl/v1.29.2`。2.3 把这个字段的取证含义写成「客户端标识；伪造或无版本号 = 脚本」，前半句是事实，后半句**只是一个启发式倾向，不是判据**。

**影响**：用它做归因，会把「谁在操作」这个问题导向错误的主体画像。在反例场景里，攻击者用某个工具发起调用，如果恰好复用了与运维相同的客户端标识，两类记录会混在一起——报告却以为已经把人和自动化分开了。

**核查**：`userAgent` 只作辅助线索，不单独支撑归因。 归因要靠能交叉的字段：`user.username`（身份）、`user.extra` 里的 `pod-name`/`pod-uid`（哪个容器发起）、`sourceIPs`（网络位置），以及同一主体的行为序列特征。判定「同一主体是否同一人操作」时，看的是**行为模式的连续性**（时间间隔、操作序列、路径风格），不是 UA 字符串。

<a id="section-25"></a>

### 4.3 凭据的读取与处理

<a id="section-26"></a>

#### 陷阱 9：★ 把凭据明文写进证据目录和报告

**现象**：两种典型做法。一是「为了全面看看有哪些凭据」，直接 `kubectl get secret -A -o yaml > /evidence/secrets-all.yaml` 存进证据目录，「方便查阅」；二是「为了证明攻击者确实读到了密码」，把审计记录里 `responseObject` 的完整 JSON 粘进报告。

**原因**：两种做法动机不同，错误同源。`kubectl get secret -o yaml` 会把每个 Secret 的**全部键值对连同 base64 值一起输出**（见陷阱 8：base64 不是加密），等于把整个集群的凭据明文写进一个文件；而在 `RequestResponse` 级别下，读 Secret 的记录其 `responseObject` 里含明文凭据。第二种的隐蔽之处在于它是**「为了增强证据力」而主动泄露**——取证员的本意是让结论更硬，结果把结论的支撑材料变成了新的泄露源。

**影响**：三重。① **证据文件本身就是攻击者的目标**，比 etcd 快照更集中、更易取用；② 报告或中间产物一旦外流，凭据泄露的范围从「内部存储」扩大到「所有拿到报告的人」，而报告往往要进诉讼或对外沟通环节，明文口令的责任很难界定；③ 存进证据目录的明文文件会随着证据链流转（备份、上传、移交）一路扩散，**而每一份副本都不在保管链记录里**。

**核查**：**只列元信息**——命名空间、名称、类型、创建时间，`custom-columns` 输出存成索引表。报告里**贴凭据一律脱敏**（如 `MyPa********3456`），完整值留在受控环境。存在性、键名、长度、形态（是否为 `k8s:enc:` 前缀）就是结论所需的全部信息，值本身不是。 确需留存原始值时单独加密保管并单独登记哈希；确需验证轮换结果时在受控环境内完成。

<a id="section-27"></a>

#### 陷阱 10：把 Secret 的 base64 当成加密

**现象**：在报告里写「Secret 已加密存储，攻击者即便拿到 etcd 快照也无法解密」。

**原因**：**base64 是编码，任何人可逆**，不是加密。`echo <串> | base64 -d` 就能还原默认值。K8s 的设计目标是「防误显」（API 层不直接返回明文、YAML 里看着是一串乱码），**从来不是防泄漏**。**若集群未配置 etcd 静态加密**（判据见下方核查），etcd 快照里躺的就是同一批值。

**影响**：**给委托方一个虚假的安全感**，可能直接导致「存储侧已加密，无需处置」的错误决策。

而这类结论如果事后被推翻，损失的不只是这一条，而是他们基于它做出的所有处置决定。

**核查**：**判断依据是配置，不是值的观感**——看 `kube-apiserver.yaml` 里 `--encryption-provider-config` 指向的文件是否存在。正确的表述是：「该集群 Secret 未启用静态加密，值以 base64 编码存储，任何可读取 etcd 快照的主体均可还原为明文」——这是一条**独立于入侵的重大架构发现**。

<a id="section-28"></a>

#### 陷阱 11：假设「启用静态加密」就全是密文

**现象**：确认了 `--encryption-provider-config` 存在且文件可读，报告写「Secret 已加密」。

**原因**：`EncryptionConfiguration` 的 providers 列表里常有 **`identity: {}` 兜底项**。它的语义是「用前面 providers 加密的数据可解密，但**以其他方式写入的数据保持原样**」——历史写入的 Secret、或其他组件写入的值，仍是未加密的。「启用了加密」不等于「所有 Secret 都加密了」。

**影响**：漏掉未加密的那部分 Secret，就会在轮换清单里划掉它们。

第五章的案例正是靠**值的 `k8s:enc:` 前缀**逐个确认，才得出「该集群未启用静态加密」这个结论。只看配置文件存在与否，就会得出相反的判断。

**核查**：**逐个检查值的开头**——以 `k8s:enc:` 开头的是密文，base64 形态的是未加密。报告里要写清「N 个 Secret 中，M 个加密、K 个未加密」，而不是一个笼统的「已加密」。

<a id="section-29"></a>

#### 陷阱 12：凭据源只枚举 Secret

**现象**：全量枚举 Secret、逐个核对读取记录，报告里凭据风险面只列 Secret，统计出「共 12 个凭据对象」。

**原因**：**高危凭据不止在 Secret 里**。① **ConfigMap** 中明文硬编码的库连接串与口令更常见——开发人员把 `jdbc:`、`mongodb://`、含口令的 URI 直接写进 ConfigMap 是极其普遍的做法，而这类内容从头到尾没有被当作 Secret 管理过。② **Secret 的高危类型**容易被当成「不是凭据」而略过：`kubernetes.io/dockerconfigjson` 是**镜像仓库凭证**（泄露即可向私库推送投毒镜像）、`kubernetes.io/tls` 是**证书与私钥**（泄露即可冒充服务端）、`kubernetes.io/ssh-auth` 是 **SSH 私钥**（横向移动凭据）；`Opaque` 只是默认类型。

**影响**：漏检镜像仓库凭据的代价尤其大——它把入侵从「一个 Pod 被攻破」升级为「攻击者可以污染整个供应链」，**这条风险要单独写、单独建议轮换**。

漏掉 ConfigMap 明文口令则会让委托方的轮换清单不完整。而「明文口令写在 ConfigMap 里」本身就是一条独立发现，说明该团队缺少凭据管理规范。

**核查**：**ConfigMap 与 Secret 一起枚举**，对 ConfigMap 重点检索 `password`/`passwd`/`token`/`api_key`/`private_key`/`access_key` 以及 `jdbc:`/`mongodb:///`redis:// 这类连接串前缀；**Secret 按类型分桶统计**（3.3 的 `custom-columns` 输出已含 `TYPE` 列）后分述风险。判断某类型是否被读取时，**注意 `list` 与 `get` 的差别**——`list secrets` 一次就能拿到整个命名空间的 Secret 列表与值，危害面远大于单个 `get`。

<a id="section-30"></a>

#### 陷阱 13：只统计「读 Secret」，不评估该 SA 的权限上限

**现象**：报告里列出攻击者读取过的 Secret 清单，列出待轮换凭据若干条，结束。

**原因**：SA token 的危害面不是它读了多少 Secret，而是它被 RBAC 授予了多少权限。 一个绑定 `cluster-admin` 的 SA token，即便只读了一个 Secret，**其可用权限也等于整个集群**——包括创建任意 Pod、修改 RBAC、读取任意命名空间的所有 Secret。漏掉权限评估，就低估了泄露的实际影响。

**影响**：委托方可能只轮换了「已确认被读」的少数几个凭据，而攻击者手上那个 token 在整个有效期内可以访问未被读取过的所有资源，整改清单因此不完整。

**核查**：对涉及的每个 SA，用 `kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>` 列出实际权限，再结合 RoleBinding/ClusterRoleBinding 找出授权来源。这样才能得出可量化的结论：「该 SA 因被绑定 `cluster-admin` 而具有集群完全控制权；已读取 1 个 Secret，但可访问范围为全集群全部 Secret」。同时要检查该 SA 是否可创建 Pod、可挂载 hostPath——那决定了它能否直接落地到节点上。

<a id="section-31"></a>

#### 陷阱 14：`list secrets` 与 `get secrets` 按同一危害度统计

**现象**：统计攻击者对凭据的访问次数时，把 `get secrets` 和 `list secrets` 的记录混在一起计数，得出「共读取 Secret 12 次」，据此判断凭据外泄规模。

**原因**：**这两者的语义差别很大。** `get` 指定一个对象名，取回那一个对象；`list` 不指定对象名，返回的是该命名空间（或全部命名空间）下 Secret 的列表，并且会连带返回每个对象的 `data` 字段——一次 `list secrets` 就足以把整个命名空间的凭据一次性拖走。用 3.3 的脚本看，`list secrets` 那条记录的 `objectRef.name` 是空的（输出里显示为 `/`），只有 `verb` 和 `resource` 有值。一个没有对象名的记录不是「读了一个匿名对象」，而是「读了所有对象」。

**影响**：把一次全量拖取按单次操作计，外泄规模被系统性低估。更麻烦的是泄露清单也会跟着短——按「读了几次」倒推「涉及几个 Secret」时，`list` 那一条根本不对应任何具体的 Secret 名，于是真正被拖走的那批凭据可能一个都没进轮换清单。

**核查**：统计时把 `verb=list` 单独成类，且不按对象名计数。 判定影响范围的做法是：以 `list` 发生时的命名空间为范围，列出该范围内**全部** Secret，而不是只列 `objectRef.name` 出现在日志里的那些。

```bash
# 找出所有 list 操作及其命名空间（objectRef.name 为空即全量）
grep '"verb":"list"' /evidence/k8s/audit.log | python3 -c "
import json,sys
for line in sys.stdin:
    d=json.loads(line); o=d.get('objectRef') or {}
    if o.get('resource')=='secrets':
        print(o.get('namespace'), '| name=', repr(o.get('name')), '| code=', d.get('responseStatus',{}).get('code'))
"
```

报告里写成「该主体于 `<时间>` 对命名空间 `<ns>` 执行 `list secrets`，**返回该命名空间下全部 Secret 对象**（结果码 `<code>`），影响范围为该命名空间全部凭据」，而不是「读取了 1 个 Secret」。

<a id="section-32"></a>

#### 陷阱 15：拿到 ConfigMap 的值就认为「凭据已泄漏给攻击者」

**现象**：在 etcd 快照里看到一个 ConfigMap 含数据库连接串，报告写「攻击者已获取数据库凭据，可直接连接生产库」。

**原因**：**这需要两段独立的证据，而快照只提供了第一段。** 第一段是「该凭据存在于集群内、可被有权限的主体读取」；第二段是「某个主体在什么时间、以什么方式读取了它」。ConfigMap 的值在 API 层是明文（这是它的正常形态），因此只要攻击者有一次 `get configmaps` 的权限，他就能读到它——但「他有过这个权限」不等于「他读过这个对象」，更不等于「他已经把值带出去了」。**会不会被日志记录取决于审计级别**：策略是 `Metadata` 时，日志里只有「访问过名为 X 的 ConfigMap」，没有任何内容。

**影响**：把「资产暴露」写成「已被获取」。这两条对应的整改动作差别很大——前者是架构缺陷与权限收敛，后者要立刻轮换凭据、改密码、追查外泄路径。写重了会引发不必要的生产变更，写轻了会让攻击者带着仍然有效的凭据留在集群里。

**核查**：**两段证据分开写，各自标注强度。** 资产侧：「`<ns>/<cm-name>` 的 ConfigMap 含明文数据库连接串，该对象对 `<ns>` 内具备 `get configmaps` 权限的主体可读，属**高风险资产配置**」。行为侧：「审计日志（`<级别>`）中检索到该主体的 `get/list configmaps` 记录 `<N>` 条，**其中能否确认读到了该对象的具体内容取决于审计级别**；未取得 `RequestResponse` 级别日志时，内容获取行为不可判定」。轮换建议按资产侧给，行为侧的置信度另行标注。

<a id="section-33"></a>

### 4.4 结论表述与阴性边界

<a id="section-34"></a>

#### 陷阱 16：把「日志里没搜到 token」写成「未发生 token 泄漏」

**现象**：`grep -acE 'eyJhbGciOiJSUzI1NiI'` 全量 Pod 日志无命中，报告写「未发现 ServiceAccount token 泄漏」。

**原因**：token 的泄露路径远不止日志一种。它可能被打进**前端页面**（浏览器缓存、CDN 缓存）、写进**镜像**（构建时 `COPY`）、传到**第三方 SDK**、出现在**崩溃上报**里，或直接被攻击者在容器内 `cat` 走而**根本不在日志里**——最后这一种恰恰是最常见的情形。「日志无命中」与「未泄漏」之间没有推理关系。

**影响**：token 泄漏是一个需要**凭据轮换**的结论。写成不带范围的阴性发现，委托方会跳过轮换，而攻击者手里的长效 token（默认有效期很长）仍然可用。

**核查**：阴性发现必须限定范围：「在 `<N>` 个 Pod 的 `<M>` 份日志中检索 JWT 前缀，未发现 token 被写入日志；**未覆盖**：容器内直接读取（无日志痕迹）、前端/CDN 缓存、镜像内固化、崩溃上报与第三方 SDK」。**并给出独立的处置建议**——该 SA 的 token 已经出现在过攻击者的可达位置（容器内），轮换应当默认执行，而不是以「日志无命中」为依据免掉。

<a id="section-35"></a>

### 4.5 对象标识与历史语义

<a id="section-36"></a>

#### 陷阱 17：按 Pod 名而不是 Pod UID 关联审计记录

**现象**：审计日志里某个 Pod 名下出现多次可疑 API 调用，报告把它串成一条连续的攻击行为链，并定性「该 Pod 被持续渗透」。

**原因**：Pod **名字是可复用的标识，UID 才是唯一身份**。Deployment 滚动更新、Pod 被驱逐后重建，都会分配新的 Pod 名；而审计日志里 SA 发起的调用，其 Pod 关联信息在 `user.extra` 里同时包含 `authentication.kubernetes.io/pod-name` 与 `authentication.kubernetes.io/pod-uid`。**同名不同 UID 就是两个完全独立的 Pod**——各自有独立的生命周期、日志、文件与可写层。把同名 Pod 的记录接成一条链，等于凭空造出一段并不存在的持续攻击。

**影响**：这条错误会同时污染两个结论。

一是行为定性：把「一个应用在反复重建」误判成「一个 Pod 遭持续渗透」，整改方向完全不同——前者指向应用自身的健康问题，后者指向攻击面。

另一个更容易被忽略的连带损失是**同一 UID 的记录并不只在一个节点上**。Pod 存活期间可能被重新调度到别的节点，`/var/log/pods/<namespace>_<name>_<uid>/` 在它待过的每个节点各有一份。只查一个节点、只按名字查，都会得到一段不完整的行为链。

**核查**：**关联一律以 `pod-uid` 为主键**，`pod-name` 只用于展示和人工阅读。跨节点取证时按 UID 把同名目录在各节点的副本拼起来看，而不是按名字只查一台机器。若某个 Pod 名在日志里出现多个 UID，要在报告里明确写成「`<Pod 名>` 在该时段内存在 N 个不同 UID 的实例，行为记录按 UID 分别归属」，**不要合并成一条**。

<a id="section-37"></a>

#### 陷阱 18：拿 `kubectl get` 的当期输出当历史证据

**现象**：现场执行 `kubectl get secret -o yaml` 找不到目标 Secret，报告写「该 Secret 未在集群中存在」，并据此排除「凭据被创建过」的可能。

**原因**：`kubectl get` 读的是 **API Server 的当前态**，它不保留任何历史。Secret 被删除后对象即消失，ConfigMap 被覆盖后只能看到新值——API Server 与 etcd 都不是对象历史库（etcd 的 watch 事件是瞬时的，不落盘）。而「创建过又删除」恰恰是本案最常见的形态，**删除动作本身会留在审计日志里**（`verb: delete` + `objectRef`），那才是回答「是否存在过」的地方。此外当期查询还受两个与历史无关的因素影响：RBAC 权限不足时返回的是 Forbidden（有明确报错，不会静默返回空），而 context 或 namespace 选错时你看到的是**另一个集群或另一个命名空间的当前态**。

**影响**：把「现在没有」写成「从来没有」，正好与真实情况相反。

它会直接抹掉凭据曾经被创建或被读取这一事实，而那可能正是泄露链条的起点。

取证记录里若没有写清 `kubectl config current-context` 与 `--namespace`，事后连「当时查的是哪个集群」都无法复核。

**核查**：判断「某对象是否曾经存在」的唯一有效来源是审计日志（`verb` 为 `create`/`update`/`delete` 且 `objectRef` 匹配的记录），辅以删除前取得的 etcd 快照。`kubectl get` 的用途严格限定为「现在是什么」。查询本身要作为证据登记：先记录 `kubectl config current-context` 与目标 namespace，再执行并保存完整输出（含表头与 `STATUS` 列），并说明该输出只代表查询时刻的状态。

<a id="section-38"></a>

#### 陷阱 19：用审计日志的保留期推断攻击「起止于」某个窗口

**现象**：审计日志最早一条是 `2024-03-16T22:00:11Z`，最晚一条是 `2024-03-18T06:11:52Z`，报告据此写「攻击行为发生于 3 月 16 日至 18 日」，并把 22:00 当成攻击起始时点。

**原因**：日志的时间范围是采集与轮转策略的结果，不是事件的时间范围。 3.1 里那个「可分析时段」是分析员自己写的限定语——它描述「这批文件能回答哪段时间的问题」，而不是「事情发生在这段时间」。轮转会把更早的记录变成 `.1` 归档，保留期到了就彻底删除；`audit.log.1` 存在只说明归档发生过，不说明归档覆盖到 22:00 之前。若只解析了 `audit.log` 而没把 `.1`、`.gz` 一起并进来，可分析时段还会进一步缩窄。

**影响**：这是把「证据边界」当成「事实边界」的典型错误，而且方向对结论不利。 把 22:00 当攻击起点，等于宣称「在那之前没有攻击」；委托方可能据此认为入侵由某个 22:00 之后触发的漏洞引发，而访问凭据的第一步可能发生在保留期之外。时间线越短，越容易得出「单点突破」这种过于整齐的叙事。

**核查**：**可分析时段与事件时段分两栏写。** 前者是能力边界，后者要靠跨工件证据推断。归档档位必须一并纳入：

```bash
ls -l /evidence/k8s/audit.log*                 # 交付件的全部档位
ls -l /mnt/df/var/log/kubernetes/audit.log*    # 节点侧原始档位
# 逐档确认时间覆盖，写进报告
for f in /evidence/k8s/audit.log*; do
  printf "%s  %s → %s\
" "$f" \
    "$(head -1 "$f" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("requestReceivedTimestamp") or d.get("stageTimestamp"))')" \
    "$(tail -1 "$f" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("requestReceivedTimestamp") or d.get("stageTimestamp"))')"
done
```

句式：「审计日志可分析时段为 `<起>`–`<止>`（覆盖 `audit.log`、`.1` 及归档档位）；**未覆盖时段内是否存在 API 调用不可判定**，事件实际起点需结合 Pod 日志、容器 rootfs 与应用侧日志推断」。**时段起点永远不能被表述为攻击起点。**

<a id="section-39"></a>

#### 陷阱 20：把当前 RBAC 配置当成事发时的配置

**现象**：事发时该 SA 只有 `viewer` 权限，取证时执行 `kubectl auth can-i --list --as=...` 显示它是 `cluster-admin`（或者反过来），报告直接采用当前查到的结果作为事发时权限的结论。

**原因**：RBAC 是集群状态，它和审计日志一样有时间维度。 `kubectl auth can-i` 读的是当前生效的 Role/ClusterRole 与各类 Binding 的组合；事发当时的组合可能完全不同——要么是攻击者自己在事发前后改了绑定，要么是管理员事后做了调整。当前态与历史态是两个独立的事实，各自需要各自的证据。

**影响**：两个方向都会出错，且无法预判。若当前权限比事发时宽（事后提权或事后收敛），报告会把当前的宽权限写成「攻击者当时的权限」，影响面被放大；若当前权限比事发时窄（事后已回收），则会把危害写小，而攻击者当时拿到的权限实际上足以完成整个攻击链。

**核查**：**当前态与事发态分开取证、分别标注。** 当前态用 `kubectl auth can-i --list --as=...`（只读，记录查询时间）；事发态从审计日志重建——以该主体的操作为锚点，找 `create`/`update`/`patch` 的 `rolebindings` 与 `clusterrolebindings` 记录，读其 `requestObject` 的原文：

```bash
grep -E '"(rolebindings|clusterrolebindings)"' /evidence/k8s/audit.log | python3 -c "
import json,sys
for line in sys.stdin:
    d=json.loads(line); o=d.get('objectRef') or {}
    if d.get('verb') in ('create','update','patch'):
        ro=d.get('requestObject') or {}
        print(d.get('requestReceivedTimestamp'), d.get('verb'), o.get('resource'), o.get('name'),
              '| roleRef=', ro.get('roleRef'), '| subjects=', ro.get('subjects'))
"
```

句式：「截至取证时（`<查询时间>`）该 SA 具备 `<权限>`；事发时（`<时间>`）的绑定状态依审计日志 `clusterrolebindings` 记录原文为 `<原文>`，**若日志未覆盖该变更时刻，事发时权限状态不可判定**」。

<a id="section-40"></a>

#### 陷阱 21：把 Secret 的 `type` 当成「是否敏感」的唯一依据

**现象**：枚举 Secret 时把 `Opaque` 之外的类型（`kubernetes.io/tls`、`kubernetes.io/ssh-auth`、`kubernetes.io/dockerconfigjson`）单列成「高危类型」，`Opaque` 的十几个归为「普通凭据」，报告写「高危 Secret 共 N 个」。

**原因**：`type` 只是一条元数据约定，它描述的是「这个对象该被哪套控制器消费」，不是「它的值有多敏感」。 `Opaque` 是**默认类型**，意味着客户端自己塞进去的任意键值对——数据库口令、第三方 API Key、云厂商 AK/SK 全在里面，它是覆盖面最广的一类；而 `kubernetes.io/tls` 里若只是一张自签证书没有私钥，敏感度可能低于一个塞满生产口令的 `Opaque`。按类型分桶的统计会系统性地高估非 Opaque、低估 Opaque。

**影响**：轮换清单按这个桶排序，最需要处理的一批（`Opaque` 里的生产数据库口令、云 AK）被排在后面甚至没被单独提示；而 `dockerconfigjson` 那类被反复强调的高危项，本案里可能根本没有涉及。整改资源被错配，而真正的关键凭据没被点名。

**核查**：**分桶按内容的敏感度，而不是按 `type`。** 判断口径是值的内容形态与用途：是否含口令/私钥/AK-SK、指向生产还是测试、是否可横向影响其他系统、有效期如何。`type` 只用来补充说明这个值的**消费方式**（比如 `dockerconfigjson` 意味着泄露后可向对应仓库推送镜像，这是影响路径的判断，不是敏感度的判断）。报告里两者分开写：`type` 归类一行，敏感度评估一行。

<a id="section-41"></a>

### 4.6 边界判定：证据能证明到哪一层

<a id="section-42"></a>

#### 陷阱 22：把「无法读取响应体」写成「攻击者拿不到内容」

**现象**：审计级别是 `Metadata`，报告写「因日志级别限制，攻击者无法确认读取到 Secret 内容」。

**原因**：审计级别限制的是你能看到什么，不是攻击者能拿到什么。 级别只决定哪些字段被写入日志文件；API Server 本身照常把响应体返回给请求方——只要 RBAC 允许，`get secrets` 就会把值原样返回。`Metadata` 级别下你看不到 `responseObject`，是因为**它没被记录**，不是因为它**没被返回**。3.2 脚本里那个「读 Secret 的记录含明文」的警告，说的正是 `RequestResponse` 级别下会发生什么。

**影响**：这是一个方向性错误的结论，会误导风险评估——委托方可能认为「既然攻击者拿不到内容，那泄露就只到元数据层面」，因而把处置降级。而真实情况是凭据很可能已经被完整取走，你的日志只是没记下来。**「我没看到」被写成了「他没有」。**

**核查**：**把「不可见」和「不存在」彻底分开。** 正确句式：「审计级别为 `<Metadata>`，日志中不含 `requestObject` 与 `responseObject`，因此**本次分析无法确认该主体读到的具体内容**；该主体是否取得凭据值，须由 etcd 快照、Pod 内投影文件、网络侧记录或应用日志独立判定」。同时把凭据轮换的建议**建立在资产侧**（这些 Secret 存在、有权限读它们的主体出现过）而不是建立在「没看到内容」上。


<a id="section-43"></a>

## 五、案例示例

<a id="section-44"></a>

### 5.1 审计评分排序与提权请求的原文核实

**场景**

委托方报告其 K8s 集群发生疑似数据泄露，怀疑有人读取了数据库凭据。集群仍在运行，API Server 审计已启用（`RequestResponse` 级别，保留 30 天）。已固定 `DigiForensics-audit.log`（1.87 GB）、`audit.log.1`（482 MB）、etcd 快照 `DigiForensics-etcd.db`、控制平面节点镜像 `DigiForensics.dd`（raw，300 GB，ext4 起始扇区 2048）。

这条路径值得先走，是因为**审计级别决定了本案能走多远**。`RequestResponse` 级别会记录请求体与响应体的完整内容——这意味着 `clusterrolebindings` 那次 `update` 的**原文**（到底绑了谁到哪个角色）能被读出来，而不是只能靠"改了集群级 RBAC"这条规则去推测。级别若只是 `Metadata`，本案最强的一条结论就只能写成"发生了集群级 RBAC 变更"，无法指名。

**处置过程**

**第 1 步 · 确认分析时段与审计级别**

```bash
head -1 /evidence/k8s/audit.log.1 | python3 -c "import json,sys;print(json.load(sys.stdin)['requestReceivedTimestamp'])"
tail -1 /evidence/k8s/audit.log   | python3 -c "import json,sys;print(json.load(sys.stdin)['requestReceivedTimestamp'])"
grep -E 'level:|resources:' /mnt/df/etc/kubernetes/audit-policy.yaml
# audit.log.1 最早 2024-03-16T22:00:11Z   audit.log 最晚 2024-03-18T06:11:52Z
# level: RequestResponse   resources: ["secrets","configmaps","clusterrolebindings","rolebindings"]
```

**可分析时段**：`2024-03-16 22:00` – `2024-03-18 06:11`。Secret 相关操作记的是 `RequestResponse`，意味着**能确认读到了什么**——这是本案最关键的前提。

**第 2 步 · 跑评分脚本**（评分规则与 3.2 的样例实测一致）

| 分值 | 时间(UTC) | 动词 | 资源 | 命名空间/名称 | 来源IP | 代码 | 命中规则 |
|---|---|---|---|---|---|---|---|
| **138** | 2024-03-18T03:14:52Z | create | `pods` | digiforensics/audit-shim | 10.8.3.17 | 201 | 访问Pod; 写操作; privileged:true; hostPath挂载; 挂载宿主机根目录; hostPID:true; 业务SA |
| **114** | 2024-03-18T02:35:10Z | list | `secrets` | digiforensics/- | 198.51.100.24 | 403 | 访问Secret; 敏感读操作; 鉴权拒绝; 匿名身份 |
| **103** | 2024-03-18T02:40:19Z | update | `clusterrolebindings` | -/digiforensics-app-cluster-admin | 10.8.3.17 | 200 | 触及集群级RBAC; 写操作; 绑定cluster-admin; 业务SA |
| **68**  | 2024-03-17T23:10:41Z | create | `pods/exec` | digiforensics/web-6d4f-x7b2c/web | 10.8.3.17 | 101 | 进入容器(pods/exec); 业务SA |
| **56**  | 2024-03-17T23:12:08Z | get | `secrets` | digiforensics/db-credentials | 10.8.3.17 | 200 | 访问Secret; 敏感读操作; 业务SA |
| **53**  | 2024-03-18T02:36:44Z | create | `pods` | digiforensics/x7b2c-dumper | 10.8.3.17 | 201 | 访问Pod; 写操作; 镜像指向IP仓库; 业务SA |

**主体聚合**：

| 用户 | 请求数 | 累计分值 |
|---|---|---|
| `system:serviceaccount:digiforensics:digiforensics-app` | 6 | 481 |
| `system:anonymous` | 1 | 114 |
| `system:serviceaccount:kube-system:replicaset-controller` | 1 | 50 |

**发现 1**：**两条异常主体形态明确**——① 业务 SA `digiforensics-app` 累计分值是系统控制器的 9.6 倍，行为呈"exec 进容器 → 读 Secret → 绑 cluster-admin → 建特权 Pod"的完整攻击链；② `system:anonymous` 从外网 IP 列举 secrets 且被 403 拒绝，是入侵前的踩点行为。"单一主体极端突出" + "匿名主体出现在时间线早期"是入侵的典型组合特征。

第 3 步 · 回到原始 JSON 核实（脚本给的是线索，不是结论）

```bash
# ★ 核实 02:40:19 那条提权请求的完整内容
grep '2024-03-18T02:40:19' /evidence/k8s/audit.log | head -1 | python3 -c "
import json,sys
d=json.loads(sys.stdin.readline())
print('主体/IP  :', d['user']['username'], d['sourceIPs'], '  ← ★ Pod IP，不是攻击者 IP')
print('Pod      :', d['user']['extra'].get('authentication.kubernetes.io/pod-name'))
print('授权依据 :', d['annotations'].get('authorization.k8s.io/reason'))
ro = d.get('requestObject', {})
print('★ roleRef :', ro.get('roleRef'))
print('★ subjects:', ro.get('subjects'))
"
# ★ roleRef : {'kind': 'ClusterRole', 'name': 'cluster-admin', 'apiGroup': 'rbac.authorization.k8s.io'}
# ★ subjects: [{'kind': 'ServiceAccount', 'name': 'digiforensics-app', 'namespace': 'digiforensics'}]
```

**发现 2（决定性）**：这条 `clusterrolebindings` 的 `update` 请求，其 `requestObject` 明确写着把 `digiforensics-app` 这个 SA 绑定到 `cluster-admin`。在 `RequestResponse` 级别下这是完整原文，不是推断。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 业务 SA `digiforensics-app` 于 02:40:19 被绑定到 `cluster-admin` | 审计日志 `requestObject.roleRef/subjects` **原文** | **强（原文直接证据）** |
| 该 SA 于 03-14:52 创建了 `audit-shim`（`privileged:true` + hostPath + hostPID） | 审计日志 `requestObject` 字段逐项命中 | 强（**声明已核实，实际使用未核实**） |
| 23:10:41 通过 `pods/exec` 进入 `web` 容器 | 审计日志 `create pods/exec` | 强 |
| 02:35:10 有匿名主体从外网列举 secrets，**被 403 拒绝** | `user.username=system:anonymous` + `responseStatus.code=403` | 强（**拒绝即未成功**） |
| 分值 481 : 50 的主体差距表明异常主体高度集中 | 主体聚合表 | 中（**分值是启发式权重，不是概率**） |
| **02:35 那次匿名请求与本案入侵是同一主体** | 时间接近 | **不成立——无证据，见误判对照** |

**本节能证明**：提权动作的**原文内容**（谁绑到哪个角色）、时间、执行身份。
**本节不能证明**：执行者是人还是被控服务、SA 凭据的初始来源、10.8.3.17 这个 IP 的性质。

**误判对照**

这个案例最容易出的错有两条，**第一条几乎必然发生**。

1. 把 `sourceIPs` 里的 `10.8.3.17` 写成"攻击者 IP"。这是 K8s 审计里最经典的误读：`sourceIPs` 记录的是发起请求的网络源，对 Pod 内发起的 API 调用而言就是 Pod IP。脚本输出里已经标了 `← ★ Pod IP，不是攻击者 IP`。正确做法是顺着 `user.extra` 里的 `authentication.kubernetes.io/pod-name` 反查是哪个 Pod，再去看那个 Pod 是什么时候、用什么镜像起的。把 Pod IP 写进报告的"攻击者来源"栏，等于给委托方一份指向自己内网的错误线索。
2. **把分值当成概率或置信度**。`138 分`与`103 分`之间的差距**不能**表述为"前者可能性是后者 1.34 倍"。分值是**规则命中数的加权**，用于排序，不用于定量。正确表述是"按规则加权排序，03:14 的静态 Pod 创建为本案最高优先级条目"。同理，分值 114 的匿名请求排第二，不代表它比 103 的提权更严重——它被 403 拒绝了，没有产生任何效果。
3. **把 403 拒绝的匿名请求并入攻击链**。它时间上确实早，但 `system:anonymous` **没有被授予任何权限**，`responseStatus.code: 403` 证明请求失败。正确表述是"该匿名探测未成功，但说明外网可直达 API Server 且存在未认证访问尝试"——这是一条**配置风险发现**（`--anonymous-auth=true` 且未用 NetworkPolicy 拦截），**不是同一攻击链的一环**。要判定两者同源，需要 IP 层或时序层的独立证据，本案没有。

按错误判据走，第 1 条踩中的代价最直接。

委托方拿着"攻击者来自 10.8.3.17"去做封禁，而 10.8.3.17 是**自己集群里的业务 Pod**。封禁它等于自己打自己。

更糟的是，真正的外部来源（02:35 那次匿名请求的 198.51.100.24）反而被降级成了"未成功的失败尝试"。那个 IP 就这样留在了边界上。

<a id="section-45"></a>

### 5.2 数据库凭据 Secret 被读取与存储形态确认

**场景**

承接 5.1。委托方最关心的问题是："数据库密码真的被读走了吗？怎么证明？还有——它在 etcd 里是加密存的吗？"

第三个问题尤其重要：如果集群启用了 etcd 静态加密，那么任何拿到 etcd 快照的人（包括取证方自己）都无法直接解密，泄露面与响应完全不同。

**处置过程**

第 1 步 · 在授权的取证环境内还原 Secret 内容（报告一律脱敏）

```bash
grep '2024-03-17T23:12:08' /evidence/k8s/audit.log | head -1 | python3 -c "
import json,sys,base64
d=json.loads(sys.stdin.readline()); so = d.get('responseObject',{})
print('Secret:', so.get('metadata',{}).get('name'), '/', so.get('type'))
for k,v in (so.get('data') or {}).items():
    # ★ 仅在授权的取证环境内还原；报告一律脱敏
    val = base64.b64decode(v).decode('utf-8','replace')
    print(f'  {k} → {val[:4]}{\"*\"*8}{val[-4:]}  (长度 {len(val)})')
"
# db-credentials / Opaque
#   password → MyPa************3456  (长度 20)
```

**发现 3**：数据库凭据 Secret 被读取，**密码明文可得**（报告中脱敏）。值是 base64 而非 `k8s:enc:` 前缀——说明**该集群未启用 etcd 静态加密**。

第 2 步 · 用 etcd 快照交叉验证存储形态

```bash
ETCDCTL_API=3 etcdutl snapshot status /evidence/k8s/DigiForensics-etcd.db
#   Hash: 8f3c1a9b...   Revision: 189247
grep -c 'encryption-provider-config' /mnt/df/etc/kubernetes/kube-apiserver.yaml
# 0    ← ★ 未配置静态加密
```

**双源印证**：从快照中按 `/registry/secrets/<ns>/<name>` 取出的值与审计日志 `responseObject` 里的值**是同一份**（base64 值与审计里还原出的 20 位密码一致）。**两条独立证据互相印证，结论强度显著提升。**

第 3 步 · 泄露面扩展：这个 SA 还能读到什么

```bash
# 审计日志里该 SA 触及的全部资源类型
python3 audit_score.py /evidence/k8s/audit.log --user 'system:serviceaccount:digiforensics:digiforensics-app' \
  | awk -F'|' '{print $4}' | sort | uniq -c | sort -rn
#      2 secrets
#      1 clusterrolebindings
#      1 pods
#      1 pods/exec

# 但 cluster-admin 绑定之后，权限面是全集群——审计日志只能证明"实际用了什么"
# 全集群 Secret 清单需从快照枚举（见 3.5）
ETCDCTL_API=3 etcdctl --endpoints=file:///evidence/etcd/replica.etcd get "" --prefix --keys-only \
  | grep -cE '^/registry/secrets/'
# 47
```

第 4 步 · 查 token 是否被打进日志（阴性发现也要记录成条目）

```bash
# 在审计日志与节点日志范围内做一次针对性检索
grep -acE '"authorization":"Bearer eyJ' /evidence/k8s/audit.log /evidence/k8s/audit.log.1
# 0
# 0    ← 范围内未发现明文 token 落盘
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 数据库密码 Secret 于 23:12:08 被读取，**明文可得** | 审计日志 `responseObject.data`（`RequestResponse` 级别） | **强** |
| 该 Secret 在 etcd 中**以明文 base64 存储，未启用静态加密** | 值无 `k8s:enc:` 前缀 + `kube-apiserver.yaml` 无 `encryption-provider-config` | **强（双源）** |
| 凭据值与快照中一致 | 快照值与审计 `responseObject` 交叉比对 | 强 |
| SA 绑定 cluster-admin 后，**潜在可读范围为全集群 47 个 Secret** | 快照枚举 + RBAC 授予内容 | 强（**潜在范围，不等于已读**） |
| 审计日志中**实际被读的具体 Secret 只有一个** | 审计日志中该 SA 的 `secrets` 记录为 2 条（1 次 list、1 次 get） | 强（**须限定范围**） |
| 在 `audit.log` 与 `audit.log.1` 两个文件内未发现明文 token 落盘 | 定向检索 0 命中 | 中（**限于两个文件的内容，见未覆盖范围**） |

**未覆盖范围**：「`/evidence/k8s/` 下两个审计文件」与「`kube-apiserver.yaml` 单个配置文件」。**未覆盖**：应用侧日志（Pod 日志、APM 采集）、CI/CD 变量、Helm values 文件、云厂商密钥管理服务、`/var/log/` 下其他组件日志，以及**攻击者 Pod 内已经消失的 shell 历史**。

**脱敏要求**：`db-credentials` 的密码在报告中**只写前 4 后 4**，本节即按此处理。完整值仅保存在 `/evidence/` 下的受限目录，**不进报告正文、不进邮件正文、不进工单系统**。

**误判对照**

最容易出的错是把"潜在可读范围 47 个"写成"47 个凭据已泄露"，以及**把"未启用静态加密"当成纯粹的坏消息**。

1. **判据**："**RBAC 授予的权限范围**"与"**审计日志记录的实际访问**"必须分开写。本案审计日志里该 SA 对 `secrets` 的操作只有 2 条（02:35 那次 list 是 `system:anonymous` 且被拒），实际被读取的只有 `db-credentials` 一个。正确表述是"该 SA 在 02:40 之后具备读取全集群 47 个 Secret 的权限；审计日志范围内，实际被读取的为 1 个"。"具备权限"与"已使用"混淆，会让委托方把 47 个全部当已泄露处理，白白触发一轮全量凭据轮换，并挤占真正紧急的那一个。
2. **判据**：未启用静态加密是**风险发现**，不是本案的攻击证据。报告里应作为"**加固建议**"列出，并明确"**该配置本身与本次入侵无因果关系**"。若把它写成入侵成因，委托方可能反过来质疑"那你们取证时不是也拿到了明文密码吗"——这句话会把讨论带向授权与数据处理合规，而不是入侵分析。正确姿态是：如实说明已获取、已脱敏、仅在授权环境内使用。
3. **判据**：`grep -c 'Bearer eyJ'` 返回 0 **不能写成"未发生凭据泄露"**。审计日志的 `RequestResponse` 级别通常会对 `Authorization` 头做脱敏（`audit-policy.yaml` 里的 `omitStages` 或注解级别设置），**这个 0 很可能来自平台的脱敏而非攻击者没留痕迹**。正确表述是"在两个审计文件内未发现明文 token，因平台可能对敏感请求头做了脱敏，本项为**不具排除力**的阴性发现"。

**按错误判据走的代价**：第 1 条踩中，47 个 Secret 全量轮换会产生数小时的运维冻结（要同步重启所有依赖服务），而真正已泄露的 `db-credentials` 反而被这轮大动作淹没、响应变慢——**泄露窗口被自己的整改流程拉长了**。第 3 条踩中则会让报告显得"排除了 token 泄露"，而实际上这项检查根本没能力排除；一旦后续在别处发现 token 落盘，被推翻的恰恰是这条看似谨慎的结论。

<a id="section-46"></a>

### 5.3 反例 分值高的条目未必是真实攻击

**场景**

委托方拿到评分表后提出异议："排第一的 138 分是 03:14 创建 `audit-shim` 那个 Pod。但我们运维在 03:20 做过一次紧急处置，往 `manifests` 目录里加过一个临时调试 Pod（因为控制面 API 不通）。这个 138 分是不是我们自己人干的？"

这是一个非常合理的质疑。本案的处置时序确实与攻击时序高度重叠，**人为动作与攻击动作在审计日志里长得一模一样**。这类混叠必须处理，不能靠"分值高所以是攻击者"来压过去。

**处置过程**

第 1 步 · 把该 Pod 的完整原文调出来，与已知人为动作逐项对

```bash
grep '2024-03-18T03:14:52' /evidence/k8s/audit.log | head -1 | python3 -c "
import json,sys
d=json.loads(sys.stdin.readline())
ro=d.get('requestObject',{})
c=ro.get('spec',{}).get('containers',[{}])[0]
print('pod 名    :', ro['metadata']['name'])
print('镜像      :', c.get('image'))
print('命令      :', c.get('command'))
print('特权      :', ro['spec'].get('containers',[{}])[0].get('securityContext'))
for v in ro['spec'].get('volumes',[]):
    if v.get('hostPath'): print('hostPath  :', v['hostPath'].get('path'), v['hostPath'].get('type'))
print('hostPID   :', ro['spec'].get('hostPID'))
"
# pod 名    : audit-shim
# 镜像      : 198.51.100.24:5000/shim:latest          ← ★ 关键差异点
# 命令      : ['/bin/sh','-c','sleep infinity; tail -F /var/log/kubernetes/audit.log']
# 特权      : {'privileged': True}
# hostPath  : /var/log/kubernetes                     ← 读审计日志，不是调试配置
# hostPath  : /                                    ← 挂宿主机根
# hostPID   : True
```

第 2 步 · 与委托方 03:20 的调试动作做对比

委托方提供的运维操作记录（03:20，由另一名工程师执行）显示，那次动作是通过 SSH 直接在节点上 `vi` 编辑 YAML 文件的：

```bash
# 运维的自述：走 SSH 编辑文件，没有走 API
# → 因此该动作根本不会产生 create pods 的审计记录
# 反过来印证：审计里 03:14:52 那条确实是走 API Server 发的请求
```

| 对比项 | 03:14:52 审计记录 | 03:20 运维调试动作 |
|---|---|---|
| 发起方式 | **走 API Server**（有审计记录） | SSH 直接编辑文件（无审计记录） |
| 镜像 | `198.51.100.24:5000/shim:latest` | 官方镜像 |
| 命令 | `sleep infinity; tail -F .../audit.log` | 调试脚本 |
| hostPath | `/var/log/kubernetes`、`/` | 无 |
| 主体 | `sa:digiforensics:digiforensics-app` | 运维个人账号 |

**五项全部不同。**

第 3 步 · 但 03:20 那次动作本身也要留档（它是反向的干扰源）

运维改完文件后，如果 kubelet 拉起过那个 Pod，它会留下一条由 kubelet 发起的、看起来无害的审计记录：

```bash
grep -E '"username":"system:node:node-1"' /evidence/k8s/audit.log \
  | python3 -c "import json,sys;[print(json.loads(l)['requestReceivedTimestamp'],json.loads(l)['verb'],json.loads(l)['objectRef'].get('name')) for l in sys.stdin if 'pods' in json.loads(l)['objectRef'].get('resource','')]"
# 2024-03-18T03:21:07Z create pods debug-static-1
```

这条记录**必须写进报告**——它是排查"为什么有些记录不是攻击"时绕不开的一条，也是证明取证过程未被人为清洗的旁证。

**结论**

- 03:14:52 的 `audit-shim` 判定为攻击者行为，非运维误操作。判据是五项独立特征全部不匹配，且发起方式为 API 请求（运维那次是 SSH 编辑文件，不进审计）。
- 委托方 03:20 的调试动作在审计日志中表现为 `system:node:node-1` 名下的 03:21:07 记录，已单独标注为"委托方自述的处置动作"。
- **这条对照反过来证明了一件事**：本案攻击者通过 API Server 发起的所有请求都留下了完整审计记录，**审计日志对本次攻击的覆盖是完整的**（03-16 22:00 至 03-18 06:11 期间无缺口，见 5.1 第 1 步的首末时间戳连续性）。

**误判对照**

这个反例针对的误判形态很特殊：**不是"把攻击当正常"，而是"把自己的操作当攻击"**。它带来两种对称的错误。

1. **判据**：认定审计记录属实时，必须**双向排除**——既要排除"这是攻击者伪装成运维动作"，也要排除"这是运维动作被记成攻击"。可用的客观判据有四类：**发起通道**（API 请求 vs SSH/直接改文件）、**凭据类型**（SA token vs 个人账号 vs node 身份）、**镜像来源**（外部 IP 私库 vs 官方仓库）、**行为内容**（读审计日志 vs 读配置）。**任意一类一致都不足以判定，必须多类同时不匹配。**
2. **判据**：**分值高不构成排除人为操作的理由**。评分脚本的规则里有"hostPath 挂载宿主机根目录"这类通用高危项，**它对攻击者和运维的错误操作一视同仁**。分值只用于排序"该先看哪条"，不用于回答"这条是谁干的"。后者只能靠原文逐项比对。
3. **判据**：**运维的自述本身也要与客观记录交叉验证**。本案正是靠"SSH 编辑文件不会产生 `create pods` 审计记录"这一机制性事实，确认了 03:14:52 那条**不可能**是运维 03:20 的动作（时间也不同）。若没有这条机制性推理，仅凭运维口头说"那不是我们干的"，就采信或否认，报告都不成立。

**按错误判据走的代价**：若把运维的调试 Pod 判为攻击，报告会把委托方自己的工程师列为可疑人，劳动关系风险立刻产生，且这条错误记录会污染整条时间线（03:20 之后的所有动作都要重新解释）。反过来，若不加辨别地把 138 分那条直接写成"攻击者最高危行为"，一旦委托方事后拿出运维记录质疑，**交付方的专业性会先于技术结论受到质疑**——而这类质疑一旦成立，整份报告的其他部分都会被连带打折。

<a id="section-47"></a>

## 六、扩展阅读方向

本篇是 K8s 凭据取证的两条主线：审计日志与 Secret 对象。往下走有四类延伸——日志机制本身、凭据体系的全貌、权限模型、以及运行时痕迹。

**审计机制：日志从哪来、存多久、会不会丢**

- [K8s 取证工件地图](server-k8s-kubernetes-artifact-map.md) —— **审计日志在整体工件里的位置与优先级**。它会被轮转覆盖，抢在前面是本领域需要遵守的采集要求。
- [Linux 系统日志深度分析](../../computer/computer-log/computer-log-system-log-analysis.md) —— **审计日志本质上是另一种服务日志**，轮转、压缩、时区基准的处理方法可以完全借用。
- [时间线重建](../../computer/computer-log/computer-log-linux-timeline-reconstruction.md) —— 审计日志的多源时间戳如何与节点日志、应用日志合并成一条可辩护的顺序。

**凭据体系：Secret 之外还有什么**

- [数据库与配置文件加密](../../crypto/crypto-app/crypto-app-database-configuration-decryption.md) —— "哪些密文不值得花时间解"这个取舍，与数据库侧一致。三种加密状态的判定口径在这一篇有更一般的表述。
- [内存中的凭据与密钥](../../memory/memory-artifact/memory-artifact-memory-credentials-and-keys.md) —— 集群里某次运行时内存里出现的凭据，**这是审计日志永远看不到的那部分。**
- [通用密码恢复](../../crypto/crypto-app/crypto-app-passware-and-password-recovery.md) —— 凭据类材料的处置规范与脱敏要求。本篇只做离线分析与暴露面评估，恢复类工作有独立的授权与最小化要求。

**权限模型：审计日志要靠 RBAC 才读得懂**

- [容器逃逸与运行时痕迹](server-k8s-container-escape-and-runtime-artifacts.md) —— 异常 RBAC、特权 Pod、`hostPath` 的判定标准。审计日志里看到一次 `create pods`，这个 Pod 危不危险要靠那一篇的判据。
- [Linux 服务器取证工件地图](../server-panel/server-panel-linux-server-artifact-map.md) —— 节点侧的视角。控制平面 Pod 里的异常往往先在节点日志上留下痕迹。

**相邻议题：同一问题的其他载体**

- [证据保管链与委托证明](../../fundamentals/fundamentals-chain/fundamentals-chain-chain-of-custody-and-authorization.md) —— etcd 快照、PKI 私钥、`encryption-config.yaml` 这类工件本身就是凭据，交接记录要求最高。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md) —— 审计日志的留存要求、凭据轮换的处置流程。
- [网络流量与 PCAP 取证](../../memory/memory-network/memory-network-pcap.md) —— `sourceIPs[0]` 不可信时，真实来源要靠网络侧记录来补。这一篇给的是流量证据的分级与表述方法。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 抢日志的时机纪律，以及"读到凭据之后不要做什么"的依据。
<a id="section-48"></a>

## 七、命令速查

```bash
# ===== 1. 确认审计可用与时段（先做，决定报告能证明到哪一层）=====
grep -nE 'audit-log-path|audit-policy-file|audit-log-maxage' /mnt/df/etc/kubernetes/kube-apiserver.yaml
cp -p /mnt/df/var/log/kubernetes/audit*.log* /evidence/k8s/
head -1 /evidence/k8s/audit.log | python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('requestReceivedTimestamp') or d.get('stageTimestamp'))"
cat /mnt/df/etc/kubernetes/audit-policy.yaml       # level 决定能证明到哪一层

# ===== 2. ★ 审计日志评分分析（脚本见正文 3.2）=====
python3 audit_score.py /evidence/k8s/audit.log --top 30 --min-score 30 --out /evidence/k8s/suspicious.json
python3 audit_score.py /evidence/k8s/audit.log --user 'system:serviceaccount:<ns>:<sa>' --top 50
python3 audit_score.py /evidence/k8s/audit.log --since 2024-03-18T00:00:00Z --ip 10.8.3.17

# 回原始 JSON 核实高分条目（★ 脚本给线索，这里给结论）
grep '2024-03-18T02:40:19' /evidence/k8s/audit.log | head -1 | python3 -c "
import json,sys
d=json.loads(sys.stdin.readline())
print('主体:', d['user']['username'], '| Pod:', d['user']['extra'].get('authentication.kubernetes.io/pod-name'))
print('授权依据:', d['annotations'].get('authorization.k8s.io/reason'))
print('roleRef:', (d.get('requestObject') or {}).get('roleRef'))
print('subjects:', (d.get('requestObject') or {}).get('subjects'))
"

# ===== 3. Secret 加密状态（★ 三种状态，见正文 2.5）=====
grep -n 'encryption-provider-config' /mnt/df/etc/kubernetes/kube-apiserver.yaml
ls -l /mnt/df/etc/kubernetes/encryption-config.yaml 2>/dev/null || echo "★ 无加密配置 → base64 明文"
# ⚠️ encryption-config.yaml 本身是解密密钥，单独固定，报告提示轮换

# ===== 4. ConfigMap / Secret 取证 =====
export KUBECONFIG=/etc/kubernetes/admin.conf
kubectl get configmap -A -o yaml > /evidence/k8s/configmaps.yaml
grep -nE 'password|passwd|secret|token|apikey|api_key|private_key' /evidence/k8s/configmaps.yaml | head -30
grep -nA3 'jdbc:|mongodb://|redis://' /evidence/k8s/configmaps.yaml | head -20

# ★ 只列元信息，不要 -o yaml 打印明文
kubectl get secret -A -o custom-columns='NS:.metadata.namespace,NAME:.metadata.name,TYPE:.type' \
  | tee /evidence/k8s/secrets-index.txt
kubectl get secret -A -o custom-columns='NS:.metadata.namespace,NAME:.metadata.name,TYPE:.type' \
  | grep -E 'dockerconfigjson|tls' | head -30

# ===== 5. SA 权限与 token 泄漏 =====
kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>          # ★ 泄露影响面
grep -anE 'eyJhbGciOiJSUzI1NiI|serviceaccount/token' /mnt/df/var/log/pods/*/*/*/*.log 2>/dev/null | head
find /mnt/df/var/lib/kubelet/pods -path '*kubernetes.io~projected*' -name '*token*' 2>/dev/null | head

# ===== 6. 交叉验证与收尾 =====
ETCDCTL_API=3 etcdutl snapshot status /evidence/k8s/DigiForensics-etcd.db
umount /mnt/df && sha256sum -c /evidence/evidence.sha256
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 服务器与 Web 取证 — K8s 审计日志与 ConfigMap/Secret」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《K8s 审计日志与 ConfigMap/Secret》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-audit.log` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
