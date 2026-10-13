---
title: "Linux 服务器日志取证"
slug: "linux-log-forensics"
canonical: "https://www.digiforensics.cn/wiki/linux-log-forensics"
license: "CC-BY-SA-4.0"
author: "DyNooob"
updated_at: "2026-05-30T18:00:43+08:00"
source_url: null
source_type: null
category: "服务器取证"
space: null
node_path: []
---

# Linux 服务器日志取证

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/linux-log-forensics)

**服务器日志可以还原系统被使用、被攻击、被登录和被修改的过程。**

**在比赛中，特别是取证、溯源类比赛，日志题常见问题包括：**

```
攻击者 IP 是什么？
SSH 登录成功时间是什么？
哪个用户执行了 sudo？
WebShell 上传时间是什么？
访问后台的 IP 是什么？
异常请求路径是什么？
```

<a id="section-1"></a>

## 一、系统日志位置

**Debian / Ubuntu 常见：**

```
/var/log/auth.log
/var/log/syslog
/var/log/kern.log
/var/log/dpkg.log
```

**CentOS / RedHat 常见：**

```
/var/log/secure
/var/log/messages
/var/log/yum.log
```

**systemd journal：**

```
/var/log/journal/
```

<a id="section-2"></a>

## 二、SSH 登录日志

**Ubuntu：**

```
grep -i "Accepted" /var/log/auth.log
grep -i "Failed password" /var/log/auth.log
grep -i "session opened" /var/log/auth.log
```

**CentOS：**

```
grep -i "Accepted" /var/log/secure
grep -i "Failed password" /var/log/secure
```

**重点字段：**

```
登录时间
用户名
来源 IP
认证方式
```

**提取登录成功 IP：**

```
grep -i "Accepted" /var/log/auth.log | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq -c | sort -nr
```

<a id="section-3"></a>

## 三、sudo 日志

```
grep -i "sudo" /var/log/auth.log
```

**关注：**

```
执行用户
执行命令
执行时间
工作目录
```

**提取 sudo 命令：**

```
grep -i "COMMAND=" /var/log/auth.log
```

<a id="section-4"></a>

## 四、Web 日志

**Nginx：**

```
/var/log/nginx/access.log
/var/log/nginx/error.log
```

**Apache：**

```
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/httpd/access_log
/var/log/httpd/error_log
```

**搜索可疑请求：**

```
grep -Rina "upload\|shell\|cmd\|eval\|base64\|select\|union\|../" /var/log/nginx /var/log/apache2 2>/dev/null
```

**提取访问最多的 IP：**

```
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -nr | head
```

**提取访问路径：**

```
awk -F\" '{print $2}' /var/log/nginx/access.log | awk '{print $2}' | sort | uniq -c | sort -nr | head -50
```

<a id="section-5"></a>

## 五、压缩日志

**日志可能被轮转压缩：**

```
auth.log.1
auth.log.2.gz
access.log.1
access.log.2.gz
```

**读取 gzip 日志：**

```
zgrep -i "Accepted" /var/log/auth.log.*.gz
zgrep -i "shell\|upload\|cmd" /var/log/nginx/*.gz
```

<a id="section-6"></a>

## 六、命令历史

**常见历史文件：**

```
/root/.bash_history
/home/*/.bash_history
/home/*/.zsh_history
```

**查看：**

```
cat /root/.bash_history
cat /home/*/.bash_history
```

**搜索危险命令：**

```
grep -Rina "wget\|curl\|chmod\|nc\|bash -i\|python\|perl\|base64\|rm -rf" /root /home 2>/dev/null
```

<a id="section-7"></a>

## 七、定时任务

**系统级：**

```
cat /etc/crontab
ls -lah /etc/cron.*
```

**用户级：**

```
crontab -l
ls -lah /var/spool/cron/
ls -lah /var/spool/cron/crontabs/
```

<a id="section-8"></a>

## 八、时间线分析

**可以提取最近修改文件：**

```
find /var/www /www/wwwroot -type f -printf "%TY-%Tm-%Td %TH:%TM:%TS %p\n" 2>/dev/null | sort
```

**也可以找最近 7 天修改文件：**

```
find /var/www /www/wwwroot -type f -mtime -7 2>/dev/null
```

**查找某时间之后修改的文件：**

```
find /var/www /www/wwwroot -type f -newermt "2026-05-01 00:00:00" 2>/dev/null
```

<a id="section-9"></a>

## 九、服务日志

**查看 systemd 服务：**

```
systemctl list-units --type=service
```

**查看某服务日志：**

```
journalctl -u nginx
journalctl -u ssh
journalctl -u docker
```

**离线 journal 读取：**

```
journalctl --directory=/mnt/var/log/journal
journalctl --directory=/mnt/var/log/journal -u ssh
```

<a id="section-10"></a>

## 十、总结

**日志分析不要只看一个文件，应交叉验证：**

```
auth.log / secure       谁登录了服务器
syslog / messages       服务和系统事件
access.log              谁访问了网站
error.log               程序异常和路径泄露
history                 用户执行过什么命令
crontab                 是否存在持久化任务
journalctl              systemd 服务日志
```
