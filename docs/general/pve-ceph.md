---
title: "PVE + Ceph 集群取证"
slug: "pve-ceph"
canonical: "https://www.digiforensics.cn/wiki/pve-ceph"
license: "CC-BY-SA-4.0"
author: "DyNooob"
updated_at: "2026-05-30T17:57:51+08:00"
source_url: null
source_type: null
category: "集群取证, 服务器取证"
space: null
node_path: []
---

# PVE + Ceph 集群取证

**PVE，全称 Proxmox Virtual Environment，是基于 Debian 的开源虚拟化平台。它常用于搭建服务器集群，支持 KVM 虚拟机、LXC 容器、Ceph 分布式存储和 Web 管理面板。**

**在取证比赛中，如果拿到的是 PVE 宿主机镜像，不要急着找网站。第一步应该看：**

```
/etc/pve/
```

**这个目录通常保存着 PVE 的核心配置。**

<a id="section-1"></a>

## 一、判断是否为 PVE

**可以检查以下路径：**

```
ls /etc/pve
ls /var/lib/pve-cluster
ls /var/log/pve
```

**如果存在：**

```
/etc/pve/corosync.conf
/etc/pve/storage.cfg
/etc/pve/qemu-server/
```

**基本可以判断为 PVE 环境。**

**离线分析时也可以用：**

```
find /mnt -name "corosync.conf" -o -name "storage.cfg" -o -path "*/qemu-server/*.conf" 2>/dev/null
```

**命令意义：**

```
corosync.conf       PVE 集群配置
storage.cfg         PVE 存储配置
qemu-server/*.conf  KVM 虚拟机配置
lxc/*.conf          LXC 容器配置
```

<a id="section-2"></a>

## 二、集群信息

**PVE 集群配置通常在：**

```
/etc/pve/corosync.conf
```

**查看命令：**

```
cat /etc/pve/corosync.conf
```

**重点关注：**

```
cluster_name
node name
nodeid
ring0_addr
```

**这些字段常用于回答：**

```
集群名称是什么？
集群有几个节点？
节点名称是什么？
节点 IP 是什么？
```

**可以快速提取：**

```
grep -E "cluster_name|name:|nodeid|ring0_addr" /etc/pve/corosync.conf
```

<a id="section-3"></a>

## 三、存储信息

**PVE 存储配置在：**

```
/etc/pve/storage.cfg
```

**查看命令：**

```
cat /etc/pve/storage.cfg
```

**常见存储类型包括：**

```
dir
lvm
lvmthin
zfspool
nfs
rbd
cephfs
```

**如果看到 **`rbd`，一般说明使用了 Ceph RBD 存储。

**示例：**

```
rbd: ceph-store
    pool vmdata
    content images
```

**这里可以提取：**

```
存储名称：ceph-store
Ceph pool：vmdata
存储内容：images
```

**快速提取：**

```
grep -E "dir:|lvm:|lvmthin:|zfspool:|nfs:|rbd:|cephfs:|pool|path|content" /etc/pve/storage.cfg
```

<a id="section-4"></a>

## 四、虚拟机配置

**PVE 虚拟机配置通常位于：**

```
/etc/pve/qemu-server/
```

**例如：**

```
/etc/pve/qemu-server/100.conf
/etc/pve/qemu-server/101.conf
```

**查看：**

```
cat /etc/pve/qemu-server/100.conf
```

**重点字段：**

```
name
memory
cores
net0
scsi0
virtio0
sata0
ide2
```

**常见题目：**

```
虚拟机 ID 是什么？
虚拟机名称是什么？
虚拟机内存是多少？
CPU 核心数是多少？
网卡 MAC 是什么？
虚拟机磁盘存在哪里？
```

**批量提取：**

```
for f in /etc/pve/qemu-server/*.conf; do
  echo "===== $f ====="
  grep -E "^(name|memory|cores|net|scsi|virtio|sata|ide|boot):" "$f"
done
```

<a id="section-5"></a>

## 五、LXC 容器配置

**PVE 也可能跑 LXC 容器，配置在：**

```
/etc/pve/lxc/
```

**查看：**

```
ls /etc/pve/lxc/
cat /etc/pve/lxc/*.conf
```

**重点字段：**

```
hostname
memory
cores
net0
rootfs
mp0
```

<a id="section-6"></a>

## 六、PVE 网络配置

**网络配置常见：**

```
/etc/network/interfaces
```

**查看：**

```
cat /etc/network/interfaces
```

**重点关注：**

```
address
gateway
bridge-ports
vmbr0
vmbr1
```

<a id="section-7"></a>

## 七、Ceph 配置

**Ceph 配置常见路径：**

```
/etc/ceph/ceph.conf
/var/lib/ceph/
```

**查看：**

```
cat /etc/ceph/ceph.conf
```

**重点字段：**

```
fsid
mon_host
public_network
cluster_network
```

**常见问题：**

```
Ceph fsid 是什么？
mon 节点 IP 是什么？
public network 是什么？
cluster network 是什么？
```

**如果系统可运行 Ceph 命令，可以查看：**

```
ceph -s
ceph osd tree
ceph osd pool ls
rbd ls -p <pool_name>
rbd info -p <pool_name> <image_name>
rbd snap ls -p <pool_name> <image_name>
```

<a id="section-8"></a>

## 八、常见排错

<a id="section-9"></a>

### 1. `/etc/pve/` 目录为空

**不一定说明没有 PVE。PVE 的配置实际由 **`pmxcfs` 管理，离线挂载时可能看到的是空目录。

**继续检查：**

```
ls /var/lib/pve-cluster/
ls /var/log/pve/
grep -Rina "corosync\|qemu-server\|storage.cfg" /etc /var 2>/dev/null
```

<a id="section-10"></a>

### 2. 只看到虚拟机配置，看不到磁盘文件

**可能原因：**

```
磁盘在 Ceph RBD
磁盘在 NFS
磁盘在 LVM-thin
磁盘在其他节点
磁盘所在数据盘未挂载
```

**此时应看：**

```
cat /etc/pve/storage.cfg
cat /etc/pve/qemu-server/*.conf
```

**把 **`scsi0`、`virtio0` 中的存储名称和 `storage.cfg` 对上。

<a id="section-11"></a>

## 九、总结

**PVE 取证的核心路径是：**

```
/etc/pve/corosync.conf      集群
/etc/pve/storage.cfg        存储
/etc/pve/qemu-server/*.conf 虚拟机
/etc/pve/lxc/*.conf         容器
/etc/network/interfaces     网络
/etc/ceph/ceph.conf         Ceph
```

**分析 PVE 时，先确定宿主机和虚拟机关系，再进入虚拟机磁盘或容器内部找业务数据。**
