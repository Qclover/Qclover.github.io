---
layout: post
title:  Clickjacking attack and Combat
noToc: true
date:   2019-01-27 22:30:00 +0800
tags: WEB安全 clickjack
cover: '../assets/clickjack.png' 
---

# Clickjacking attack and Combat

HTTP安全头通过告诉浏览器如何操作来帮助减轻攻击和安全漏洞，从而提供了另一层安全性。在这篇文章中，我们将更深入地探讨x-frame-options（xfo），这是一个HTTP的头部，有助于保护您的访问者免受点击劫持攻击。

## 1.什么是X-Frame-Options？

`x-frame-options`（XFO），是一个HTTP响应头，也称为HTTP安全头，自2008年以来一直存在。在2013年，它正式发布为[RFC 7034](https://tools.ietf.org/html/rfc7034)，但不是互联网标准。此标题告诉您的浏览器在处理您网站的内容时的行为方式。其成立的主要原因是通过不允许在帧中呈现页面来**提供点击劫持保护**。这可以包括在页面的呈现`<frame>`，`<iframe>`或`<object>`。iframe用于将第三方内容嵌入并隔离到网站中。使用iframe的内容示例可能包括社交媒体共享按钮，Google地图，视频播放器，音频播放器，第三方广告，甚至一些OAuth实施。 

## 2.点击劫持

**点击劫持***是一种恶意技术，欺骗***网络用户点击与用户认为他们点击的内容不同的内容***，从而可能***在点击看似无害的网页时***泄露机密信息***。〜维基百科**

点击劫持攻击基本上意味着欺骗用户通过框架页面点击某些东西来执行一些恶意攻击，比如，当攻击者在窗口中使用透明iframe诱骗用户点击CTA（例如按钮或链接）到另一个具有相同外观窗口的服务器时发生攻击。从某种意义上说，攻击者**劫持了原始服务器的点击并将其发送到另一台服务器**。这是对访问者本身和服务器的攻击。 

以下是点击劫持的几种可能漏洞或用图。

- 诱骗用户公开其社交网络个人资料信息
- 在Facebook上分享或喜欢链接
- 点击Google Adsense广告即可生成每次点击付费收入
- 让用户在Twitter或Facebook上关注某人
- 下载并运行恶意软件（恶意软件），允许远程攻击者控制其他计算机
- 在Facebook粉丝页面上获得喜欢或在Google Plus上获得+1
- 播放YouTube视频以获取观看次数

点击劫持很容易实现，如果您的网站只需单击即可完成操作，那么很可能是点击劫持。它可能不像跨站点脚本或代码注入攻击那样常见，但它仍然存在另一个漏洞。有时看到视觉效果会很有帮助。

### Flash点击劫持

攻击者通过Flash构造出了点击劫持，在完成一系列复杂的动作之后，最终控制了用户的摄像头，原理：黑客在Flash游戏页面内嵌了一个iframe，通过游戏选项按钮诱导用户去点击按钮，从而最终实现Flash点击劫持！每次点击完成之后按钮的位置都是可变化的、移动的。

### 图片覆盖攻击（XSIO）

点击劫持的本质就是一种视觉欺骗，通过这种思想，黑客可以完成很多劫持，例如：钓鱼网站的实现，通过图片覆盖导致链接到一些未知的网站，从而达到黑客正真的目的。原理：通过调整图片的style使得图片能够覆盖在他所指定的任意位置。

XSIO不同于XSS，它利用的是图片的style，或者能够控制CSS。如果应用没有限制style的position为absolute的话，图片就可以覆盖到页面上的任意位置，形成点击劫持。

### 拖拽劫持与数据窃取

目前很多浏览器都开始支持Drag&Drop的API。对于用户来说，拖拽他们的操作更加简单。浏览器拖拽的对象可以是一个连接，也可以是一段文字，还可以从一个窗口拖拽到另外一个窗口，因此拖拽不受同源策略的影响。

“拖拽劫持”的思路是诱使用户从隐藏的不可见iframe中拖拽出攻击者希望得到的数据，然后放到攻击者能够控制的另外一个页面，从而窃取数据。

### ClickJacking 3.0：触屏劫持（TapJacking）

触屏，从手机OS的角度来看，触屏实际上就是一个事件，手机OS捕捉这些事件，并执行相应的动作。

一次触屏操作，可能会对应一下几个事件的发生：

（1）touchstart，手指触摸屏幕时发生；

（2）Touchend，手指离开屏幕时发生；

（3）Touchmove，手指滑动时发生；

（4）Touchcancel，系统可取消touch事件

## 3.点击劫持攻击

点击劫持（ClickJacking）是一种视觉上的欺骗手段。大概有两种方式，一是攻击者使用一个透明的iframe，覆盖在一个网页上，然后诱使用户在该页面上进行操作，此时用户将在不知情的情况下点击透明的iframe页面；二是攻击者使用一张图片覆盖在网页，遮挡网页原有位置的含义。

![cjack]({{site.baseurl}}/assets/images/cjack.png)

**0x1:iframe覆盖（嵌入iframe框）**

直接举个示例

假如我们在百度有个贴吧，想偷偷让别人关注它。于是我们准备一个页面： 

```html
<!DOCTYPE HTML>
<html>
<meta http-equiv="Content-Type" content="text/html; charset=gb2312" />
<head>
<title>点击劫持</title>
<style>
     html,body,iframe{
         display: block;
          height: 100%;
          width: 100%;
          margin: 0;
          padding: 0;
          border:none;
     }
     iframe{
          opacity:0;
          filter:alpha(opacity=0);
          position:absolute;
          z-index:2;
     }
     button{
          position:absolute;
          top: 315px;
          left: 462px;
          z-index: 1;
          width: 72px;
          height: 26px;
     }
</style>
</head>
     <body>
          那些不能说的秘密
          <button>查看详情</button>
          <iframe src="http://tieba.baidu.com/f?kw=%C3%C0%C5%AE"></iframe>
     </body>
</html>
```

![clickjack]({{site.baseurl}}/assets/images/clickjack.png)

PS：页面看起来就这样，当然真正攻击的页面会精致些，不像这么简陋。

网址传播出去后，用户手贱点击了查看详情后，其实就会点到关注按钮。

PS：可以把iframe透明设为0.3看下实际点到的东西。

 ![cjack2]({{site.baseurl}}/assets/images/cjack2.png)



这样贴吧就多了一个粉丝了。 

**0x2:粘贴劫持**

假设你现在是一个黑客，并且你已经建了一个论坛，在注册页面设置两处常见的要求“Enter your email”栏以及”Retype your email”栏。然后悄悄地在”Retype your email”栏放个隐藏iframe，此位置会加载另一个正常网站的设置页面表单。 

<https://security.love/XSSJacking/index2.html> 

![zhantianjack]({{site.baseurl}}/assets/images/zhantianjack.png)

**当用户在你的网站上注册时，大多数人会先输入一遍邮箱，然后复制第一栏中的邮箱再粘贴到第二栏中（小编默默躺枪）——**就在这个过程中，用户剪切板中的内容已经神不知鬼不觉地被插入到那个正常网站设置页面中。如果这家正常网站相应表单字段存在XSS漏洞，则攻击代码就能发挥作用。受害者根本就不知道整个过程是怎么进行、何时进行的。

攻击中所利用的粘贴劫持技术，是将XSS payload粘贴到其他域名的文本栏框架。由于这些框架的位置可以改变，并且不可见，因此可以利用点击劫持让用户觉得他还在访问他“正在”访问的那个网站。事实上，他已经触发了Self-XSS漏洞，黑客可得到他的敏感信息。

通过XSS劫持攻击，黑客可以盗取该用户的cookie、收件箱信息、配置详情，修改配置文件设置（比如手机号、邮箱号）或是执行其他恶意操作。

**0x3:拖放劫持**

在这里引用曾看到过的一篇文章，关于该类攻击文章大概是这样描述的：

以下是一个易受点击劫持攻击的一个网站

![cj-site]({{site.baseurl}}/assets/images/cj-site.png)

而我们一般会做的攻击是**欺骗用户通过Clickjacking评论Blog Post,此时报告的严重性一般是：低~中**

继续挖掘.......

通过Brutforcing或者Traveling(暴力猜解)http://victim.com,假设我们找到一个像[**http://victim.com/api/user.json**](http://victim.com/api/user.json) 记录用户信息的东西，并且没有X-Frame-Options头。

![cj-site2]({{site.baseurl}}/assets/images/cj-site2.png)

此时可用的攻击方式为：

1）**将** *http://victim.com* **（博客文章）和**[*http://victim.com/api/user.json* **（用户**](http://victim.com/api/user.json%28User) **RestAPI正文）链接在一起，通过博客发表评论泄露机密数据。**  **（用户**](http://victim.com/api/user.json%28User) **RestAPI正文）链接在一起，通过博客发表评论泄露机密数据。** 

2）在我的vps服务器上搭建了恶意html，在上面（博客文章）和（API主体）都设置了框架。

**Note:SOP（同源策略）仅在两个帧具有相同原点时才允许拖放行为，即（http://victim.com）** 

<iframe height=498 width=510 src='https://youtu.be/MMntLY_ddgs' frameborder=0 'allowfullscreen'></iframe>

*服务器上的malicious.html* 



- 现在我们可以看到，我们能够泄漏/窃取敏感的东西，比如（API、CSRF令牌等从API）**~严重性：高**

- 之所以称之为~ClickContentJacking（CCJ）〜的原因，我们在这里欺骗用户使用拖放行为窃取网站内容。内容可以是任何东西它可以是JSON，XML，JS或HTML正文。为了演示Purposed我使用了JSON。

- **这就是文章该部分的提到的内容**

  **PS:**当我看到这篇文章的（CCJ）时，可能是之前没有遇到过类似的拖放劫持攻击，不能较好的知道该POC是怎样的，若你读到这篇文章的该部分，假设你有想法希望可以在评论中一起**讨论**或在在我[联系方式](https://qclover.cn/about.html)中联系我。

  **0x4:组合利用方式**

  在挖掘xss时，你可能会遇到self-xss，那么这时你可以考虑self_xss+点击劫持或csrf+self-xss

## 3.2 clickjacking的利用框架 

1）首先，为了快速生成clickjacking的poc框架，我在gayhub上找到了这个

<https://github.com/samyk/quickjack>

2）可以通过截图的方式方便的把需要劫持的部分网页截取出来，这个工具也提供在线的使用

<http://samy.pl/quickjack/quickjack.html>

通过截取之后按下“I‘am done“按钮就会生成对应的截取代码

3）可以使用burp自带的工具进行生成poc,参考以下链接：

https://support.portswigger.net/customer/en/portal/articles/2363105-using-burp-to-find-clickjacking-vulnerabilities

4)可以使用CJExploiter，CJExploiter是一个支持拖放的点击劫持漏洞利用辅助工具。首先在本地用浏览器打开“index.html”，输入目标的URL并点击“View Site”。你可以自定义JS，最后点击“Exploit it”，你就能得到POC了。可参考https://www.freebuf.com/sectool/104892.html

## 4.防御

X-Frame-Options指令 

`x-frame-options`头有三种不同的指令，可以在其中选择。这些必须作为HTTP标头发送，因为如果在META标记中找到，浏览器将忽略。同样重要的是要注意某些指令仅在某些浏览器中受支持。请参阅本文后面的浏览器支持。虽然不需要在整个站点上发送此响应标头，但最佳做法是至少在需要它的页面上启用它。 

1.DENY指令 

无论网站尝试什么，DENY指令都会完全禁用框架中页面的加载。下面是如果启用此标头请求将会是什么样子。

```
x-frame-options: DENY
```

这可能是锁定网站的好方法，但它也会破坏很多功能。

**当前使用DENY指令的站点示例**

- Facebook的
- GitHub上

2.SAMEORIGIN指令 

SAMEORIGIN指令允许将页面加载到与页面本身相同的原始帧中。

```
x-frame-options: SAMEORIGIN
```

只要包含在框架中的网站与提供页面的网站相同，您仍然可以在框架中使用该页面。这可能是三者中最常用的指令。它在功能和安全性之间取得了良好的平衡。

同样重要的是要注意，如果浏览器或插件无法可靠地确定内容的来源和框架是否具有相同的来源，则必须将其视为DENY。

**当前使用SAMEORIGIN指令的站点示例**

- 推特
- 亚马逊
- 易趣
- LinkedIn

3.允许来自uri指令 

ALLOW-FROM *uri*指令允许页面仅加载到指定原点和/或域的框架中。下面是如果启用此标头请求将会是什么样子。

```
x-frame-options: ALLOW-FROM https://domain.com/
```

这允许您将站点锁定为仅受信任的来源。但要小心这个指令。如果您应用它并且浏览器不支持它，那么您将没有任何点击劫持防御

**在Nginx上启用**

要`x-frame-options`在Nginx上启用标头，只需将其添加到服务器块配置中即可。

```
add_header x-frame-options "SAMEORIGIN" always;
```

**在Apache上启用**

要在Apache上启用，只需将其添加到您的`httpd.conf`文件（Apache配置文件）。

```
header always set x-frame-options "SAMEORIGIN"
```

**在IIS上启用**

要在IIS上启用，只需将其添加到您站点的`Web.config`文件中即可。

```
<system.webServer>
    ...

    <httpProtocol>
        <customHeaders>
            <add name="X-Frame-Options" value="SAMEORIGIN" />
        </customHeaders>
    </httpProtocol>

    ...
</system.webServer>
```

X-Frame-Options浏览器支持

![x-frame-option]({{site.baseurl}}/assets/images/x-frame-option.png)